package proxy

import (
	"context"
	"crypto/tls"
	"io"
	"net/http"
	"net/http/httptest"
	"net/url"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/NitinGavhane/proxyforge/internal/ca"
	"github.com/NitinGavhane/proxyforge/internal/flows"
	"github.com/NitinGavhane/proxyforge/internal/pipeline"
	"github.com/NitinGavhane/proxyforge/internal/store"
)

func stringsReader(s string) io.Reader { return strings.NewReader(s) }

// newTLSUpstreamH2 is an HTTPS origin speaking HTTP/2 (when h2 true) whose
// certificate chains to the engine's CA.
func newTLSUpstreamH2(t *testing.T, authority *ca.CA, h2 bool, h http.HandlerFunc) *httptest.Server {
	t.Helper()
	leaf, err := authority.Mint("127.0.0.1")
	if err != nil {
		t.Fatalf("mint server leaf: %v", err)
	}
	srv := httptest.NewUnstartedServer(h)
	protos := []string{"http/1.1"}
	if h2 {
		protos = []string{"h2", "http/1.1"}
	}
	srv.TLS = &tls.Config{
		Certificates: []tls.Certificate{leaf},
		MinVersion:   tls.VersionTLS12,
		NextProtos:   protos,
	}
	srv.EnableHTTP2 = h2
	srv.StartTLS()
	t.Cleanup(srv.Close)
	return srv
}

// h2Client talks HTTP/2 to the engine's MITM endpoint (when forceH2).
func h2Client(t *testing.T, proxySrv *httptest.Server, authority *ca.CA, forceH2 bool) *http.Client {
	t.Helper()
	proxyURL, _ := url.Parse(proxySrv.URL)
	tr := &http.Transport{
		Proxy:             http.ProxyURL(proxyURL),
		TLSClientConfig:   &tls.Config{RootCAs: authority.Pool(), MinVersion: tls.VersionTLS12},
		ForceAttemptHTTP2: forceH2,
	}
	return &http.Client{Transport: tr, Timeout: 15 * time.Second}
}

func newH2Engine(t *testing.T, authority *ca.CA) (*httptest.Server, *store.Store) {
	t.Helper()
	st, err := store.Open(filepath.Join(t.TempDir(), "h2.pf.sqlite"))
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
	return proxySrv, st
}

func TestH2BothLegs(t *testing.T) {
	authority := newAuthority(t)
	var upstreamProto atomic.Int64
	up := newTLSUpstreamH2(t, authority, true, func(w http.ResponseWriter, r *http.Request) {
		upstreamProto.Store(int64(r.ProtoMajor))
		_, _ = w.Write([]byte("h2 payload"))
	})
	proxySrv, st := newH2Engine(t, authority)
	client := h2Client(t, proxySrv, authority, true)

	resp, err := client.Get(up.URL + "/over-h2")
	if err != nil {
		t.Fatalf("get: %v", err)
	}
	body, _ := io.ReadAll(resp.Body)
	resp.Body.Close()
	if string(body) != "h2 payload" {
		t.Fatalf("body = %q", body)
	}
	if upstreamProto.Load() != 2 {
		t.Fatalf("upstream leg was HTTP/%d, want 2", upstreamProto.Load())
	}
	if resp.ProtoMajor != 2 {
		t.Fatalf("client leg was HTTP/%d, want 2", resp.ProtoMajor)
	}
	f := singleFlow(t, st)
	if !f.MITM {
		t.Fatal("flow not marked MITM")
	}
	if f.Request.HTTPVersion != "HTTP/2.0" {
		t.Errorf("request version = %q, want HTTP/2.0", f.Request.HTTPVersion)
	}
	if f.Response == nil || f.Response.HTTPVersion != "HTTP/2.0" {
		t.Fatalf("response version = %+v", f.Response)
	}
	if f.TLSClient == "" || f.TLSServer == "" {
		t.Errorf("TLS versions missing: %q/%q", f.TLSClient, f.TLSServer)
	}
	if string(f.Response.Body) != "h2 payload" {
		t.Errorf("captured body = %q", f.Response.Body)
	}
}

func TestH2DownstreamH1Upstream(t *testing.T) {
	authority := newAuthority(t)
	up := newTLSUpstreamH2(t, authority, false, func(w http.ResponseWriter, r *http.Request) {
		if r.ProtoMajor != 1 {
			t.Errorf("upstream unexpectedly spoke HTTP/%d", r.ProtoMajor)
		}
		_, _ = w.Write([]byte("h1 origin"))
	})
	proxySrv, st := newH2Engine(t, authority)
	client := h2Client(t, proxySrv, authority, true)

	resp, err := client.Get(up.URL + "/mismatch")
	if err != nil {
		t.Fatalf("get: %v", err)
	}
	io.Copy(io.Discard, resp.Body)
	resp.Body.Close()
	f := singleFlow(t, st)
	if f.Request.HTTPVersion != "HTTP/2.0" {
		t.Errorf("downstream = %q, want HTTP/2.0", f.Request.HTTPVersion)
	}
	if f.Response.HTTPVersion != "HTTP/1.1" {
		t.Errorf("upstream = %q, want HTTP/1.1", f.Response.HTTPVersion)
	}
}

func TestH1DownstreamH2Upstream(t *testing.T) {
	authority := newAuthority(t)
	up := newTLSUpstreamH2(t, authority, true, func(w http.ResponseWriter, r *http.Request) {
		if r.ProtoMajor != 2 {
			t.Errorf("upstream did not use h2: HTTP/%d", r.ProtoMajor)
		}
		_, _ = w.Write([]byte("h2 origin"))
	})
	proxySrv, st := newH2Engine(t, authority)
	client := h2Client(t, proxySrv, authority, false) // client insists on h1

	resp, err := client.Get(up.URL + "/mismatch2")
	if err != nil {
		t.Fatalf("get: %v", err)
	}
	io.Copy(io.Discard, resp.Body)
	resp.Body.Close()
	f := singleFlow(t, st)
	if f.Request.HTTPVersion != "HTTP/1.1" {
		t.Errorf("downstream = %q, want HTTP/1.1", f.Request.HTTPVersion)
	}
	if f.Response.HTTPVersion != "HTTP/2.0" {
		t.Errorf("upstream = %q, want HTTP/2.0", f.Response.HTTPVersion)
	}
}

func TestH2PostBody(t *testing.T) {
	authority := newAuthority(t)
	var upBody []byte
	up := newTLSUpstreamH2(t, authority, true, func(w http.ResponseWriter, r *http.Request) {
		upBody, _ = io.ReadAll(r.Body)
		w.WriteHeader(202)
	})
	proxySrv, st := newH2Engine(t, authority)
	client := h2Client(t, proxySrv, authority, true)

	payload := `{"grant":"token","scope":"admin"}`
	resp, err := client.Post(up.URL+"/oauth/token", "application/json",
		stringsReader(payload))
	if err != nil {
		t.Fatalf("post: %v", err)
	}
	resp.Body.Close()
	f := singleFlow(t, st)
	if string(f.Request.Body) != payload || string(upBody) != payload {
		t.Errorf("bodies: captured=%q upstream=%q", f.Request.Body, upBody)
	}
	if f.Response.Status != 202 {
		t.Errorf("status = %d", f.Response.Status)
	}
}

func TestH2ConcurrentStreams(t *testing.T) {
	authority := newAuthority(t)
	up := newTLSUpstreamH2(t, authority, true, func(w http.ResponseWriter, r *http.Request) {
		time.Sleep(2 * time.Millisecond)
		_, _ = w.Write([]byte("ok"))
	})
	proxySrv, st := newH2Engine(t, authority)
	client := h2Client(t, proxySrv, authority, true)

	const n = 100
	var wg sync.WaitGroup
	for i := 0; i < n; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			resp, err := client.Get(up.URL + "/s")
			if err == nil {
				io.Copy(io.Discard, resp.Body)
				resp.Body.Close()
			}
		}()
	}
	wg.Wait()
	deadline := time.Now().Add(3 * time.Second)
	for {
		cnt, _ := st.CountFlows(context.Background())
		if cnt == n || time.Now().After(deadline) {
			if cnt != n {
				t.Fatalf("captured %d/%d flows over h2", cnt, n)
			}
			break
		}
		time.Sleep(10 * time.Millisecond)
	}
}

func TestH2PerHostDowngrade(t *testing.T) {
	authority := newAuthority(t)
	up := newTLSUpstreamH2(t, authority, true, func(w http.ResponseWriter, r *http.Request) {
		_, _ = w.Write([]byte("downgraded"))
	})
	st, err := store.Open(filepath.Join(t.TempDir(), "dg.pf.sqlite"))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { st.Close() })
	eng := &Engine{
		Pipeline:       pipeline.New(st, flows.NewBus(), nil),
		CA:             authority,
		UpstreamRoots:  authority.Pool(),
		H2DisableHosts: []string{"127.0.0.1"},
	}
	proxySrv := httptest.NewServer(eng)
	t.Cleanup(proxySrv.Close)
	client := h2Client(t, proxySrv, authority, true) // client WANTS h2

	resp, err := client.Get(up.URL + "/forced-h1")
	if err != nil {
		t.Fatalf("get: %v", err)
	}
	if resp.ProtoMajor != 1 {
		t.Fatalf("client leg negotiated HTTP/%d despite downgrade list", resp.ProtoMajor)
	}
	io.Copy(io.Discard, resp.Body)
	resp.Body.Close()
	f := singleFlow(t, st)
	if f.Request.HTTPVersion != "HTTP/1.1" {
		t.Errorf("flow version = %q, want HTTP/1.1", f.Request.HTTPVersion)
	}
}

func TestTrailersCapturedBothDirections(t *testing.T) {
	authority := newAuthority(t)
	var reqTrailer atomic.Value
	up := newTLSUpstreamH2(t, authority, true, func(w http.ResponseWriter, r *http.Request) {
		body, _ := io.ReadAll(r.Body)
		r.Body.Close()
		if v := r.Trailer.Get("X-Req-Trailer"); v != "" {
			reqTrailer.Store(v)
		}
		w.Header().Set("Trailer", "X-Sum") // declare response trailer
		w.WriteHeader(200)
		_, _ = w.Write(body)
		w.Header().Set("X-Sum", strconv.Itoa(len(body))) // emitted as trailer
	})
	proxySrv, st := newH2Engine(t, authority)
	client := h2Client(t, proxySrv, authority, true)

	req, _ := http.NewRequest("POST", up.URL+"/trailer", stringsReader("abcdef"))
	req.Header.Set("Content-Type", "text/plain")
	req.Header.Set("Trailer", "X-Req-Trailer") // declare request trailer
	req.Trailer = http.Header{"X-Req-Trailer": []string{"req-value"}}
	resp, err := client.Do(req)
	if err != nil {
		t.Fatalf("post: %v", err)
	}
	body, _ := io.ReadAll(resp.Body)
	resp.Body.Close()
	if string(body) != "abcdef" {
		t.Fatalf("body = %q", body)
	}

	f := singleFlow(t, st)
	if got, _ := reqTrailer.Load().(string); got != "req-value" {
		t.Errorf("request trailer not forwarded: %q", got)
	}
	if v, ok := f.Request.Trailer.Get("X-Req-Trailer"); !ok || v != "req-value" {
		t.Errorf("request trailer not captured: %+v", f.Request.Trailer)
	}
	if v, ok := f.Response.Trailer.Get("X-Sum"); !ok || v != "6" {
		t.Errorf("response trailer not captured: %+v", f.Response.Trailer)
	}
	if resp.Trailer.Get("X-Sum") != "6" {
		t.Errorf("client did not receive trailer: %+v", resp.Trailer)
	}
}
