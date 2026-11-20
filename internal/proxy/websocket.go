// WebSocket proxying (M4): h1 Upgrade handshakes are relayed to the origin
// and both directions are spliced with frame-level capture (RFC 6455).
//
// Policy: permessage-deflate negotiation is stripped from both handshakes so
// captured frames are readable; RSV1 is still recorded if an origin sends
// compressed frames anyway.
package proxy

import (
	"bufio"
	"context"
	"crypto/tls"
	"encoding/binary"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/url"
	"strconv"
	"strings"
	"sync/atomic"
	"time"

	"github.com/NitinGavhane/proxyforge/internal/flows"
)

// wsFrameCap bounds captured payload bytes per frame (forwarding is never
// truncated — only capture is).
var wsFrameCap = flows.MaxBodyBytes

func isWebSocketUpgrade(r *http.Request) bool {
	up := r.Header.Get("Upgrade")
	if !strings.EqualFold(strings.TrimSpace(up), "websocket") {
		return false
	}
	for _, v := range r.Header.Values("Connection") {
		if strings.Contains(strings.ToLower(v), "upgrade") {
			return true
		}
	}
	return false
}

// handleWebSocket hijacks the client connection, relays the upgrade
// handshake to the origin, then splices both directions while capturing
// frames.
func (e *Engine) handleWebSocket(w http.ResponseWriter, r *http.Request, target url.URL, host string, port int, mitmTarget mitmInfo, isMITM bool) {
	started := time.Now()
	hj, ok := w.(http.Hijacker)
	if !ok {
		http.Error(w, "ProxyForge: websocket hijack unsupported", http.StatusInternalServerError)
		return
	}
	clientConn, brw, err := hj.Hijack()
	if err != nil {
		return
	}
	defer clientConn.Close()
	_ = clientConn.SetDeadline(time.Time{})
	_ = brw.Writer.Flush()

	scheme := "ws"
	originScheme := "http"
	if isMITM {
		originScheme = mitmTarget.Scheme // https in TLS tunnels, http in plaintext
	} else if target.Scheme == "wss" || target.Scheme == "https" {
		originScheme = "https"
	}
	if originScheme == "https" {
		scheme = "wss"
	}
	if port == 0 && isMITM {
		port = mitmTarget.Port
	}
	addr := net.JoinHostPort(host, strconv.Itoa(portOr(scheme, port)))

	// Capture model for the handshake exchange.
	f := &flows.Flow{
		Started:    started,
		ClientAddr: remoteIP(r.RemoteAddr),
		ServerAddr: addr,
		Origin:     flows.OriginProxy,
		MITM:       isMITM,
		Request: &flows.Request{
			Method:      r.Method,
			Scheme:      scheme,
			Host:        host,
			Port:        port,
			Path:        target.RequestURI(),
			HTTPVersion: r.Proto,
			Headers:     flows.FromHTTP(r.Header),
		},
	}
	f.InScope = e.inScope(f.Request)
	if isMITM {
		f.TLSClient = mitmTarget.TLSVersion
	}

	// Dial the origin (honoring upstream chaining), TLS for wss.
	raw, err := e.dialUpstream(addr)
	if err != nil {
		f.Err = "ws dial: " + err.Error()
		f.Finished = time.Now()
		e.saveIfInScope(f)
		fmt.Fprintf(clientConn, "HTTP/1.1 502 Bad Gateway\r\nContent-Length: 0\r\n\r\n")
		return
	}
	defer raw.Close()
	var originConn net.Conn = raw
	if originScheme == "https" {
		tlsCfg := &tls.Config{ServerName: host, MinVersion: tls.VersionTLS12}
		if e.UpstreamRoots != nil {
			tlsCfg.RootCAs = e.UpstreamRoots
		}
		originConn = tls.Client(raw, tlsCfg)
		_ = originConn.SetDeadline(time.Now().Add(15 * time.Second))
		if err := originConn.(*tls.Conn).Handshake(); err != nil {
			f.Err = "ws tls: " + err.Error()
			f.Finished = time.Now()
			e.saveIfInScope(f)
			fmt.Fprintf(clientConn, "HTTP/1.1 502 Bad Gateway\r\nContent-Length: 0\r\n\r\n")
			return
		}
		_ = originConn.SetDeadline(time.Time{})
		f.TLSServer = tls.VersionName(originConn.(*tls.Conn).ConnectionState().Version)
	}

	// Relay the handshake: origin-form request minus hop-by-hop — except
	// Connection/Upgrade, which ARE the mechanism — and minus the
	// permessage-deflate offer (captured frames stay readable).
	// NewRequest + Write emits origin-form ("GET /path HTTP/1.1").
	upReq, err := http.NewRequest(r.Method, originScheme+"://"+addr+target.RequestURI(), nil)
	if err == nil {
		for _, hd := range f.Request.Headers {
			key := http.CanonicalHeaderKey(hd.Key)
			if strings.EqualFold(hd.Key, "Sec-WebSocket-Extensions") {
				continue
			}
			if hopByHop[key] && key != "Connection" && key != "Upgrade" {
				continue
			}
			upReq.Header.Add(hd.Key, hd.Value)
		}
		err = upReq.Write(originConn)
	}
	if err != nil {
		f.Err = "ws handshake write: " + err.Error()
		f.Finished = time.Now()
		e.saveIfInScope(f)
		return
	}

	originBR := bufio.NewReader(originConn)
	resp, err := http.ReadResponse(originBR, upReq)
	if err != nil {
		f.Err = "ws handshake read: " + err.Error()
		f.Finished = time.Now()
		e.saveIfInScope(f)
		return
	}
	defer resp.Body.Close()

	f.Response = &flows.Response{
		Status:      resp.StatusCode,
		StatusText:  resp.Status,
		HTTPVersion: resp.Proto,
		Headers:     flows.FromHTTP(resp.Header),
	}
	if resp.StatusCode != http.StatusSwitchingProtocols {
		// relay the failure verbatim to the client
		f.DurationMS = time.Since(started).Milliseconds()
		f.Finished = time.Now()
		e.saveIfInScope(f)
		_ = resp.Write(brConnWriter{clientConn})
		return
	}

	// 101: confirm to the client with the origin's handshake fields
	// (extensions stripped), then splice with frame capture.
	var hb strings.Builder
	hb.WriteString("HTTP/1.1 101 Switching Protocols\r\n")
	for _, hd := range f.Response.Headers {
		if strings.EqualFold(hd.Key, "Sec-WebSocket-Extensions") {
			continue
		}
		hb.WriteString(hd.Key)
		hb.WriteString(": ")
		hb.WriteString(hd.Value)
		hb.WriteString("\r\n")
	}
	hb.WriteString("\r\n")
	if _, err := io.WriteString(clientConn, hb.String()); err != nil {
		f.Err = "ws confirm: " + err.Error()
		f.Finished = time.Now()
		e.saveIfInScope(f)
		return
	}

	// Persist the flow now (handshake complete) so live UI shows it; frame
	// messages stream in as they are captured. Out-of-scope sockets are
	// proxied opaquely with no frame capture.
	if !f.InScope {
		e.Scope.CountOutOfScope()
		e.spliceWSOpaque(clientConn, brw.Reader, originConn, originBR)
		return
	}
	if err := e.Pipeline.Save(context.Background(), f); err != nil {
		return
	}
	flowID := f.ID

	var msgCount atomic.Int64
	sink := func(m flows.WSMessage) {
		m.FlowID = flowID
		if err := e.Pipeline.SaveWS(context.Background(), &m); err != nil {
			return
		}
		msgCount.Add(1)
	}

	done := make(chan error, 2)
	go func() {
		done <- wsTap(originConn, brw.Reader, flows.DirC2S, sink) // client → origin
	}()
	go func() {
		done <- wsTap(brConnWriter{clientConn}, originBR, flows.DirS2C, sink) // origin → client
	}()
	err1 := <-done
	// Close both sides so the second direction unblocks.
	_ = clientConn.Close()
	_ = originConn.Close()
	<-done

	_ = err1
	_ = e.Pipeline.CloseWS(context.Background(), flowID, time.Now(), time.Since(started), msgCount.Load())
}

// spliceWSOpaque pipes an out-of-scope WebSocket without capturing frames.
func (e *Engine) spliceWSOpaque(client net.Conn, clientBR *bufio.Reader, origin net.Conn, originBR *bufio.Reader) {
	defer client.Close()
	defer origin.Close()
	done := make(chan struct{})
	go func() { io.Copy(origin, clientBR); close(done) }()
	io.Copy(client, originBR)
	<-done
}

// brConnWriter writes directly to the client conn (reads come from the
// buffered reader).
type brConnWriter struct{ net.Conn }

func (c brConnWriter) Write(p []byte) (int, error) { return c.Conn.Write(p) }

func portOr(scheme string, port int) int {
	if port != 0 {
		return port
	}
	if scheme == "wss" {
		return 443
	}
	return 80
}

// wsTap reads RFC 6455 frames from src, forwards the exact bytes to dst, and
// calls sink per frame with the unmasked payload (capture-capped). Returns
// on EOF/error/close.
func wsTap(dst io.Writer, src io.Reader, dir string, sink func(flows.WSMessage)) error {
	br, ok := src.(*bufio.Reader)
	if !ok {
		br = bufio.NewReader(src)
	}
	var out []byte // pending bytes to forward (header pieces)
	for {
		out = out[:0]
		var hdr [2]byte
		if _, err := io.ReadFull(br, hdr[:]); err != nil {
			if err == io.EOF || err == io.ErrUnexpectedEOF {
				return nil // connection ended (possibly without a close frame)
			}
			return err
		}
		out = append(out, hdr[:]...)
		fin := hdr[0]&0x80 != 0
		compressed := hdr[0]&0x40 != 0 // RSV1 (permessage-deflate)
		opcode := int(hdr[0] & 0x0f)
		masked := hdr[1]&0x80 != 0
		length := uint64(hdr[1] & 0x7f)
		var ext [8]byte
		switch length {
		case 126:
			if _, err := io.ReadFull(br, ext[:2]); err != nil {
				return err
			}
			length = uint64(binary.BigEndian.Uint16(ext[:2]))
			out = append(out, ext[:2]...)
		case 127:
			if _, err := io.ReadFull(br, ext[:8]); err != nil {
				return err
			}
			length = binary.BigEndian.Uint64(ext[:8])
			out = append(out, ext[:8]...)
		}
		var maskKey [4]byte
		if masked {
			if _, err := io.ReadFull(br, maskKey[:]); err != nil {
				return err
			}
			out = append(out, maskKey[:]...)
		}
		if _, err := dst.Write(out); err != nil {
			return err
		}

		// stream the payload: forward raw bytes, capture unmasked (capped)
		var captured []byte
		if length <= uint64(wsFrameCap) {
			captured = make([]byte, 0, min(length, uint64(1<<16)))
		}
		pos := uint64(0)
		chunk := make([]byte, 32*1024)
		for pos < length {
			n := uint64(len(chunk))
			if rem := length - pos; rem < n {
				n = rem
			}
			if _, err := io.ReadFull(br, chunk[:n]); err != nil {
				return err
			}
			if _, err := dst.Write(chunk[:n]); err != nil {
				return err
			}
			if captured != nil {
				unc := make([]byte, n)
				if masked {
					for i := uint64(0); i < n; i++ {
						unc[i] = chunk[i] ^ maskKey[(pos+i)%4]
					}
				} else {
					copy(unc, chunk[:n])
				}
				captured = append(captured, unc...)
			}
			pos += n
		}
		sink(flows.WSMessage{
			TS:         time.Now().UnixMilli(),
			Direction:  dir,
			Opcode:     opcode,
			FIN:        fin,
			Compressed: compressed,
			Size:       int(length),
			Payload:    captured,
		})
		if opcode == 8 { // close
			return nil
		}
	}
}
