package proxy

import (
	"bytes"
	"context"
	"crypto/tls"
	"encoding/base64"
	"encoding/binary"
	"io"
	"net/http"
	"net/http/httptest"
	"net/url"
	"path/filepath"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/gorilla/websocket"

	"github.com/NitinGavhane/proxyforge/internal/ca"
	"github.com/NitinGavhane/proxyforge/internal/flows"
	"github.com/NitinGavhane/proxyforge/internal/pipeline"
	"github.com/NitinGavhane/proxyforge/internal/store"
)

// newWSEcho starts a gorilla WebSocket echo server. With authority non-nil it
// speaks TLS with a certificate chaining to that CA.
func newWSEcho(t *testing.T, authority *ca.CA) (rawURL string, clientTLS *tls.Config) {
	t.Helper()
	up := websocket.Upgrader{CheckOrigin: func(*http.Request) bool { return true }}
	h := func(w http.ResponseWriter, r *http.Request) {
		c, err := up.Upgrade(w, r, nil)
		if err != nil {
			return
		}
		defer c.Close()
		for {
			mt, msg, err := c.ReadMessage()
			if err != nil {
				return
			}
			if err := c.WriteMessage(mt, msg); err != nil {
				return
			}
		}
	}
	if authority == nil {
		srv := httptest.NewServer(http.HandlerFunc(h))
		t.Cleanup(srv.Close)
		return srv.URL, nil
	}
	leaf, err := authority.Mint("127.0.0.1")
	if err != nil {
		t.Fatal(err)
	}
	srv := httptest.NewUnstartedServer(http.HandlerFunc(h))
	srv.TLS = &tls.Config{Certificates: []tls.Certificate{leaf}, MinVersion: tls.VersionTLS12}
	srv.StartTLS()
	t.Cleanup(srv.Close)
	return srv.URL, &tls.Config{RootCAs: authority.Pool(), MinVersion: tls.VersionTLS12, ServerName: "127.0.0.1"}
}

// wsDialThrough dials originURL (an http(s) test-server URL, converted to
// ws(s)) through the engine's proxy endpoint.
func wsDialThrough(t *testing.T, proxySrv *httptest.Server, originURL string, clientTLS *tls.Config) *websocket.Conn {
	t.Helper()
	wsURL := strings.Replace(originURL, "https://", "wss://", 1)
	wsURL = strings.Replace(wsURL, "http://", "ws://", 1)
	proxyURL, _ := url.Parse(proxySrv.URL)
	d := &websocket.Dialer{
		Proxy:            http.ProxyURL(proxyURL),
		HandshakeTimeout: 10 * time.Second,
	}
	if clientTLS != nil {
		d.TLSClientConfig = clientTLS
	}
	c, resp, err := d.Dial(wsURL+"/chat?room=1", nil)
	if err != nil {
		if resp != nil {
			body, _ := io.ReadAll(resp.Body)
			t.Fatalf("dial: %v (status %d body %q)", err, resp.StatusCode, body)
		}
		t.Fatalf("dial: %v", err)
	}
	t.Cleanup(func() { c.Close() })
	return c
}

func waitWSCount(t *testing.T, st *store.Store, flowID int64, want int64) {
	t.Helper()
	deadline := time.Now().Add(3 * time.Second)
	for time.Now().Before(deadline) {
		f, err := st.GetFlow(context.Background(), flowID)
		if err == nil && f.WSCount == want {
			return
		}
		time.Sleep(15 * time.Millisecond)
	}
	f, _ := st.GetFlow(context.Background(), flowID)
	t.Fatalf("ws_count = %d, want %d", f.WSCount, want)
}

func firstFlow(t *testing.T, st *store.Store) *flows.Flow {
	t.Helper()
	rows, err := st.ListFlows(context.Background(), store.Filter{})
	if err != nil || len(rows) == 0 {
		t.Fatalf("flows: %v %+v", err, rows)
	}
	f, err := st.GetFlow(context.Background(), rows[0].ID)
	if err != nil {
		t.Fatal(err)
	}
	return f
}

func TestWebSocketPlainThroughProxy(t *testing.T) {
	wsURL, _ := newWSEcho(t, nil)
	authority := newAuthority(t) // enables plaintext-tunnel parsing + capture
	st, err := store.Open(filepath.Join(t.TempDir(), "ws.pf.sqlite"))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { st.Close() })
	eng := &Engine{Pipeline: pipeline.New(st, flows.NewBus(), nil), CA: authority}
	proxySrv := httptest.NewServer(eng)
	t.Cleanup(proxySrv.Close)

	c := wsDialThrough(t, proxySrv, wsURL, nil)

	if err := c.WriteMessage(websocket.TextMessage, []byte("hello proxy")); err != nil {
		t.Fatalf("write: %v", err)
	}
	_, msg, err := c.ReadMessage()
	if err != nil {
		t.Fatalf("read: %v", err)
	}
	if string(msg) != "hello proxy" {
		t.Fatalf("echo = %q", msg)
	}
	bin := []byte{0, 1, 2, 0xff, 0xfe, 'a', 0}
	if err := c.WriteMessage(websocket.BinaryMessage, bin); err != nil {
		t.Fatalf("write bin: %v", err)
	}
	mt, got, err := c.ReadMessage()
	if err != nil || mt != websocket.BinaryMessage || !bytes.Equal(got, bin) {
		t.Fatalf("bin echo: mt=%d %x err=%v", mt, got, err)
	}
	_ = c.WriteControl(websocket.CloseMessage,
		websocket.FormatCloseMessage(websocket.CloseNormalClosure, "bye"), time.Now().Add(time.Second))
	_ = c.Close()

	time.Sleep(100 * time.Millisecond) // let the close handshake finish
	f := firstFlow(t, st)
	if f.Request.Scheme != "ws" {
		t.Errorf("scheme = %q, want ws", f.Request.Scheme)
	}
	if f.Request.Path != "/chat?room=1" {
		t.Errorf("path = %q", f.Request.Path)
	}
	if f.Response == nil || f.Response.Status != 101 {
		t.Fatalf("handshake response: %+v", f.Response)
	}
	// 4 app frames each way + close frames → count once both taps finish
	msgs, err := st.ListWSMessages(context.Background(), f.ID, 100, 0)
	if err != nil {
		t.Fatal(err)
	}
	var c2sText, s2cText, c2sBin, s2cBin, closes int
	for _, m := range msgs {
		switch {
		case m.Direction == flows.DirC2S && m.Opcode == 1 && string(decodeB64(m.PayloadB64)) == "hello proxy":
			c2sText++
		case m.Direction == flows.DirS2C && m.Opcode == 1:
			s2cText++
		case m.Direction == flows.DirC2S && m.Opcode == 2:
			c2sBin++
		case m.Direction == flows.DirS2C && m.Opcode == 2:
			s2cBin++
		case m.Opcode == 8:
			closes++
		}
	}
	if c2sText != 1 || s2cText != 1 || c2sBin != 1 || s2cBin != 1 || closes < 1 {
		t.Errorf("frame tallies wrong: text %d/%d bin %d/%d close %d (%d msgs)",
			c2sText, s2cText, c2sBin, s2cBin, closes, len(msgs))
	}
	if f.WSCount == 0 {
		t.Errorf("ws_count not updated")
	}
}

func TestWebSocketWSSThroughMITM(t *testing.T) {
	authority := newAuthority(t)
	wsURL, clientTLS := newWSEcho(t, authority)
	st, err := store.Open(filepath.Join(t.TempDir(), "wss.pf.sqlite"))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { st.Close() })
	eng := &Engine{
		Pipeline:      pipeline.New(st, flows.NewBus(), nil),
		CA:            authority,
		UpstreamRoots: authority.Pool(),
	}
	proxySrv := httptest.NewServer(eng)
	t.Cleanup(proxySrv.Close)

	c := wsDialThrough(t, proxySrv, wsURL, clientTLS)
	if err := c.WriteMessage(websocket.TextMessage, []byte("secret over wss")); err != nil {
		t.Fatalf("write: %v", err)
	}
	_, msg, err := c.ReadMessage()
	if err != nil || string(msg) != "secret over wss" {
		t.Fatalf("echo: %q err=%v", msg, err)
	}
	_ = c.WriteControl(websocket.CloseMessage,
		websocket.FormatCloseMessage(websocket.CloseNormalClosure, ""), time.Now().Add(time.Second))
	_ = c.Close()

	time.Sleep(100 * time.Millisecond)
	f := firstFlow(t, st)
	if f.Request.Scheme != "wss" || !f.MITM {
		t.Errorf("scheme=%q mitm=%v", f.Request.Scheme, f.MITM)
	}
	if f.TLSClient == "" || f.TLSServer == "" {
		t.Errorf("TLS versions missing: %q/%q", f.TLSClient, f.TLSServer)
	}
	msgs, _ := st.ListWSMessages(context.Background(), f.ID, 100, 0)
	found := false
	for _, m := range msgs {
		if m.Direction == flows.DirC2S && string(decodeB64(m.PayloadB64)) == "secret over wss" {
			found = true
		}
	}
	if !found {
		t.Errorf("wss frame not captured: %+v", msgs)
	}
}

func TestWebSocketLargeFrames(t *testing.T) {
	wsURL, _ := newWSEcho(t, nil)
	authority := newAuthority(t)
	st, _ := store.Open(filepath.Join(t.TempDir(), "wsbig.pf.sqlite"))
	t.Cleanup(func() { st.Close() })
	eng := &Engine{Pipeline: pipeline.New(st, flows.NewBus(), nil), CA: authority}
	proxySrv := httptest.NewServer(eng)
	t.Cleanup(proxySrv.Close)

	c := wsDialThrough(t, proxySrv, wsURL, nil)
	big := bytes.Repeat([]byte("0123456789abcdef"), 128*1024) // 2 MiB
	if err := c.WriteMessage(websocket.TextMessage, big); err != nil {
		t.Fatalf("write big: %v", err)
	}
	_, got, err := c.ReadMessage()
	if err != nil || !bytes.Equal(got, big) {
		t.Fatalf("big echo: len=%d err=%v", len(got), err)
	}
	_ = c.WriteControl(websocket.CloseMessage,
		websocket.FormatCloseMessage(websocket.CloseNormalClosure, ""), time.Now().Add(time.Second))
	_ = c.Close()

	time.Sleep(150 * time.Millisecond)
	f := firstFlow(t, st)
	// gorilla fragments large messages into 4096-byte frames (opcode 1 then
	// opcode-0 continuations) — page through ALL frames and sum bytes per
	// direction.
	var c2s, s2c int
	offset := 0
	for {
		msgs, err := st.ListWSMessages(context.Background(), f.ID, 500, offset)
		if err != nil || len(msgs) == 0 {
			break
		}
		for _, m := range msgs {
			if m.Opcode >= 8 { // control frames (close/ping/pong) carry no app bytes
				continue
			}
			switch m.Direction {
			case flows.DirC2S:
				c2s += m.Size
			case flows.DirS2C:
				s2c += m.Size
			}
		}
		if len(msgs) < 500 {
			break
		}
		offset += len(msgs)
	}
	if c2s != len(big) || s2c != len(big) {
		t.Errorf("captured bytes c2s=%d s2c=%d, want %d each", c2s, s2c, len(big))
	}
}

func TestWebSocketOriginRejectsUpgrade(t *testing.T) {
	var rejected atomic.Bool
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if strings.EqualFold(r.Header.Get("Upgrade"), "websocket") {
			rejected.Store(true)
			http.Error(w, "no websocket here", http.StatusForbidden)
			return
		}
		w.WriteHeader(200)
	}))
	t.Cleanup(srv.Close)

	// CA present so the plaintext CONNECT tunnel is parsed (not spliced
	// opaquely) and the rejection is relayed + recorded.
	authority := newAuthority(t)
	st, _ := store.Open(filepath.Join(t.TempDir(), "wsrej.pf.sqlite"))
	t.Cleanup(func() { st.Close() })
	eng := &Engine{Pipeline: pipeline.New(st, flows.NewBus(), nil), CA: authority}
	proxySrv := httptest.NewServer(eng)
	t.Cleanup(proxySrv.Close)

	proxyURL, _ := url.Parse(proxySrv.URL)
	d := &websocket.Dialer{Proxy: http.ProxyURL(proxyURL), HandshakeTimeout: 5 * time.Second}
	_, resp, err := d.Dial("ws"+strings.TrimPrefix(srv.URL, "http")+"/ws", nil)
	if err == nil {
		t.Fatal("dial should fail when origin rejects the upgrade")
	}
	if resp == nil || resp.StatusCode != http.StatusForbidden {
		t.Fatalf("client did not see the origin's rejection: resp=%v err=%v", resp, err)
	}
	if !rejected.Load() {
		t.Error("origin never saw the handshake")
	}
	f := firstFlow(t, st)
	if f.Response == nil || f.Response.Status != http.StatusForbidden {
		t.Errorf("rejection not recorded on flow: %+v", f.Response)
	}
	if f.Request.Scheme != "ws" {
		t.Errorf("scheme = %q, want ws", f.Request.Scheme)
	}
}

// --- wsTap unit tests (handcrafted frames) ---

func encodeFrame(opcode int, payload []byte, masked bool, fin bool) []byte {
	var b bytes.Buffer
	b0 := byte(opcode)
	if fin {
		b0 |= 0x80
	}
	b.WriteByte(b0)
	b1 := byte(len(payload))
	var ext []byte
	switch {
	case len(payload) > 65535:
		b1 = 127
		ext = make([]byte, 8)
		binary.BigEndian.PutUint64(ext, uint64(len(payload)))
	case len(payload) > 125:
		b1 = 126
		ext = make([]byte, 2)
		binary.BigEndian.PutUint16(ext, uint16(len(payload)))
	}
	if masked {
		b1 |= 0x80 // mask bit must survive the length switch above
	}
	b.WriteByte(b1)
	b.Write(ext)
	mask := []byte{0x11, 0x22, 0x33, 0x44}
	if masked {
		b.Write(mask)
		maskedPayload := make([]byte, len(payload))
		for i, c := range payload {
			maskedPayload[i] = c ^ mask[i%4]
		}
		b.Write(maskedPayload)
	} else {
		b.Write(payload)
	}
	return b.Bytes()
}

func TestWsTapFrames(t *testing.T) {
	var out bytes.Buffer
	var got []flows.WSMessage
	sink := func(m flows.WSMessage) { got = append(got, m) }

	input := bytes.NewBuffer(nil)
	input.Write(encodeFrame(1, []byte("text frame"), true, true))
	input.Write(encodeFrame(2, []byte{0xde, 0xad, 0xbe, 0xef}, true, true))
	big := bytes.Repeat([]byte("z"), 70000) // extended 32-bit length path
	input.Write(encodeFrame(2, big, true, true))
	// fragmented: first frame fin=0, continuation fin=1
	input.Write(encodeFrame(1, []byte("part1-"), true, false))
	input.Write(encodeFrame(0, []byte("part2"), true, true))
	// close
	input.Write(encodeFrame(8, []byte{0x03, 0xe8}, true, true))

	err := wsTap(&out, input, flows.DirC2S, sink)
	if err != nil {
		t.Fatalf("tap: %v", err)
	}
	if len(got) != 6 {
		t.Fatalf("frames = %d, want 6", len(got))
	}
	if string(got[0].Payload) != "text frame" || got[0].Opcode != 1 || !got[0].FIN {
		t.Errorf("frame0: %+v", got[0])
	}
	if !bytes.Equal(got[1].Payload, []byte{0xde, 0xad, 0xbe, 0xef}) {
		t.Errorf("frame1 payload: %x", got[1].Payload)
	}
	if len(got[2].Payload) != 70000 || got[2].Size != 70000 {
		t.Errorf("extended-length frame: len=%d size=%d", len(got[2].Payload), got[2].Size)
	}
	if got[3].FIN || got[3].Opcode != 1 || string(got[3].Payload) != "part1-" {
		t.Errorf("fragment first: %+v", got[3])
	}
	if !got[4].FIN || got[4].Opcode != 0 || string(got[4].Payload) != "part2" {
		t.Errorf("fragment continuation: %+v", got[4])
	}
	if got[5].Opcode != 8 {
		t.Errorf("close frame: %+v", got[5])
	}
	// forwarded bytes must be byte-identical (still masked)
	if !bytes.Equal(out.Bytes(), func() []byte {
		want := bytes.NewBuffer(nil)
		want.Write(encodeFrame(1, []byte("text frame"), true, true))
		want.Write(encodeFrame(2, []byte{0xde, 0xad, 0xbe, 0xef}, true, true))
		want.Write(encodeFrame(2, big, true, true))
		want.Write(encodeFrame(1, []byte("part1-"), true, false))
		want.Write(encodeFrame(0, []byte("part2"), true, true))
		want.Write(encodeFrame(8, []byte{0x03, 0xe8}, true, true))
		return want.Bytes()
	}()) {
		t.Errorf("forwarded bytes differ from input (%d vs %d)", out.Len(), 70000)
	}
}

func TestWsTapCompressionMarker(t *testing.T) {
	frame := encodeFrame(1, []byte("compressed?"), false, true)
	frame[0] |= 0x40 // set RSV1
	var out bytes.Buffer
	var got []flows.WSMessage
	_ = got
	err := wsTap(&out, bytes.NewReader(frame), flows.DirS2C, func(m flows.WSMessage) { got = append(got, m) })
	if err != nil {
		t.Fatal(err)
	}
	if len(got) != 1 || !got[0].Compressed || got[0].FIN != true {
		t.Fatalf("compressed marker: %+v", got)
	}
	if !bytes.Equal(out.Bytes(), frame) {
		t.Error("RSV1 frame not forwarded byte-identically")
	}
}

func decodeB64(s string) []byte {
	b, err := base64.StdEncoding.DecodeString(s)
	if err != nil {
		return nil
	}
	return b
}
