package proxy

import (
	"bufio"
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"fmt"
	"io"
	"log/slog"
	"math/big"
	"net"
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

// tlsUpstream is an HTTPS test origin whose certificate chains to the given
// CA (so the engine can trust it via UpstreamRoots).
type tlsUpstream struct {
	srv  *httptest.Server
	host string
	port int
}

func newTLSUpstream(t *testing.T, authority *ca.CA, h http.HandlerFunc) *tlsUpstream {
	t.Helper()
	leaf, err := authority.Mint("127.0.0.1")
	if err != nil {
		t.Fatalf("mint server leaf: %v", err)
	}
	srv := httptest.NewUnstartedServer(h)
	srv.TLS = &tls.Config{
		Certificates: []tls.Certificate{leaf},
		MinVersion:   tls.VersionTLS12,
	}
	srv.StartTLS()
	t.Cleanup(srv.Close)
	u, _ := url.Parse(srv.URL)
	port, _ := strconv.Atoi(u.Port())
	return &tlsUpstream{srv: srv, host: u.Hostname(), port: port}
}

// newMITMEngine builds an engine with a real CA whose proxy endpoint is an
// httptest server; the client trusts only the engine's root.
func newMITMEngine(t *testing.T, authority *ca.CA) (*httptest.Server, *store.Store, *http.Client) {
	t.Helper()
	st, err := store.Open(filepath.Join(t.TempDir(), "mitm.pf.sqlite"))
	if err != nil {
		t.Fatalf("store: %v", err)
	}
	t.Cleanup(func() { st.Close() })
	eng := &Engine{
		Pipeline:      pipeline.New(st, flows.NewBus(), slog.Default()),
		CA:            authority,
		UpstreamRoots: authority.Pool(),
	}
	proxySrv := httptest.NewServer(eng)
	t.Cleanup(proxySrv.Close)
	proxyURL, _ := url.Parse(proxySrv.URL)
	client := &http.Client{
		Transport: &http.Transport{
			Proxy:           http.ProxyURL(proxyURL),
			TLSClientConfig: &tls.Config{RootCAs: authority.Pool(), MinVersion: tls.VersionTLS12},
		},
		Timeout: 10 * time.Second,
	}
	return proxySrv, st, client
}

func newAuthority(t *testing.T) *ca.CA {
	t.Helper()
	c, err := ca.Load(filepath.Join(t.TempDir(), "ca"), ca.Options{})
	if err != nil {
		t.Fatalf("ca: %v", err)
	}
	return c
}

func TestMITMHTTPSGetCaptured(t *testing.T) {
	authority := newAuthority(t)
	var seenPath, seenMethod string
	up := newTLSUpstream(t, authority, func(w http.ResponseWriter, r *http.Request) {
		seenPath, seenMethod = r.URL.RequestURI(), r.Method
		w.Header().Set("X-From-Origin", "yes")
		_, _ = w.Write([]byte("secret payload over tls"))
	})
	_, st, client := newMITMEngine(t, authority)

	resp, err := client.Get(up.srv.URL + "/vault?x=1")
	if err != nil {
		t.Fatalf("get: %v", err)
	}
	body, _ := io.ReadAll(resp.Body)
	resp.Body.Close()
	if string(body) != "secret payload over tls" || resp.Header.Get("X-From-Origin") != "yes" {
		t.Fatalf("client got %q hdr=%v", body, resp.Header)
	}
	if seenPath != "/vault?x=1" || seenMethod != "GET" {
		t.Errorf("origin saw %s %s", seenMethod, seenPath)
	}

	f := singleFlow(t, st)
	if !f.MITM {
		t.Errorf("flow not marked MITM")
	}
	if f.Request.Scheme != "https" || f.Request.Host != up.host || f.Request.Port != up.port {
		t.Errorf("request meta: %+v", f.Request)
	}
	if f.Request.Path != "/vault?x=1" {
		t.Errorf("path = %q", f.Request.Path)
	}
	if f.Response == nil || f.Response.Status != 200 || string(f.Response.Body) != "secret payload over tls" {
		t.Fatalf("response: %+v", f.Response)
	}
	if f.TLSClient == "" || f.TLSServer == "" {
		t.Errorf("TLS versions not recorded: %q/%q", f.TLSClient, f.TLSServer)
	}
	if f.Err != "" {
		t.Errorf("flow error: %q", f.Err)
	}
}

func TestMITMHTTPSPostBodyCaptured(t *testing.T) {
	authority := newAuthority(t)
	var upBody []byte
	up := newTLSUpstream(t, authority, func(w http.ResponseWriter, r *http.Request) {
		upBody, _ = io.ReadAll(r.Body)
		w.WriteHeader(201)
	})
	_, st, client := newMITMEngine(t, authority)

	payload := `{"user":"admin","pass":"hunter2"}`
	resp, err := client.Post(up.srv.URL+"/api/login", "application/json",
		strings.NewReader(payload))
	if err != nil {
		t.Fatalf("post: %v", err)
	}
	resp.Body.Close()

	f := singleFlow(t, st)
	if string(f.Request.Body) != payload {
		t.Errorf("captured req body = %q", f.Request.Body)
	}
	if string(upBody) != payload {
		t.Errorf("origin saw body = %q", upBody)
	}
	if f.Response.Status != 201 {
		t.Errorf("status = %d", f.Response.Status)
	}
}

func TestMITMConcurrentOverOneTunnel(t *testing.T) {
	authority := newAuthority(t)
	up := newTLSUpstream(t, authority, func(w http.ResponseWriter, r *http.Request) {
		time.Sleep(2 * time.Millisecond)
		_, _ = w.Write([]byte("ok"))
	})
	_, st, client := newMITMEngine(t, authority)

	const n = 20
	var wg sync.WaitGroup
	for i := 0; i < n; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			resp, err := client.Get(up.srv.URL + "/c")
			if err == nil {
				io.Copy(io.Discard, resp.Body)
				resp.Body.Close()
			}
		}()
	}
	wg.Wait()
	deadline := time.Now().Add(2 * time.Second)
	for {
		cnt, _ := st.CountFlows(context.Background())
		if cnt == n || time.Now().After(deadline) {
			if cnt != n {
				t.Fatalf("captured %d/%d", cnt, n)
			}
			return
		}
		time.Sleep(10 * time.Millisecond)
	}
}

func TestPassThroughTunnelOpaque(t *testing.T) {
	authority := newAuthority(t)
	up := newTLSUpstream(t, authority, func(w http.ResponseWriter, r *http.Request) {
		_, _ = w.Write([]byte("pinned content"))
	})

	st, err := store.Open(filepath.Join(t.TempDir(), "pt.pf.sqlite"))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { st.Close() })
	eng := &Engine{
		Pipeline:    pipeline.New(st, flows.NewBus(), slog.Default()),
		CA:          authority, // CA present but host is on the pass-through list
		PassThrough: []string{"127.0.0.1"},
	}
	proxySrv := httptest.NewServer(eng)
	t.Cleanup(proxySrv.Close)
	proxyURL, _ := url.Parse(proxySrv.URL)

	// The handshake must terminate at the ORIGIN, not at the engine — proven
	// by the tunnel flow and the absence of any decrypted flow.
	client := &http.Client{
		Transport: &http.Transport{
			Proxy:           http.ProxyURL(proxyURL),
			TLSClientConfig: &tls.Config{RootCAs: authority.Pool(), MinVersion: tls.VersionTLS12},
		},
		Timeout: 10 * time.Second,
	}
	resp, err := client.Get(up.srv.URL + "/pinned")
	if err != nil {
		t.Fatalf("get through tunnel: %v", err)
	}
	body, _ := io.ReadAll(resp.Body)
	resp.Body.Close()
	if string(body) != "pinned content" {
		t.Fatalf("tunnel body = %q", body)
	}

	// The tunnel record is written when the tunnel closes; drop the idle
	// keep-alive connection and wait briefly for the record.
	client.CloseIdleConnections()
	deadline := time.Now().Add(2 * time.Second)
	var rows []store.FlowRow
	for time.Now().Before(deadline) {
		rows, _ = st.ListFlows(context.Background(), store.Filter{})
		if len(rows) == 1 {
			break
		}
		time.Sleep(10 * time.Millisecond)
	}
	if len(rows) != 1 {
		t.Fatalf("rows = %d, want exactly the tunnel entry", len(rows))
	}
	row := rows[0]
	if !row.Tunnel || row.MITM {
		t.Fatalf("expected tunnel row: %+v", row)
	}
	if row.Method != "CONNECT" {
		t.Errorf("tunnel method = %q", row.Method)
	}
	if row.ReqSize == 0 || row.RespSize == 0 {
		t.Errorf("tunnel byte counts not recorded: req=%d resp=%d", row.ReqSize, row.RespSize)
	}
	f, _ := st.GetFlow(context.Background(), row.ID)
	if !f.Tunnel {
		t.Errorf("full flow lost tunnel flag")
	}
}

// Without a CA the engine falls back to an opaque tunnel: traffic still
// flows (client validates the ORIGIN's certificate directly) and a tunnel
// flow is recorded instead of a decrypted one.
func TestCONNECTNoCAFallsBackToTunnel(t *testing.T) {
	authority := newAuthority(t) // only used for the origin cert
	up := newTLSUpstream(t, authority, func(w http.ResponseWriter, r *http.Request) {
		_, _ = w.Write([]byte("opaque"))
	})

	st, _ := store.Open(filepath.Join(t.TempDir(), "noca.pf.sqlite"))
	t.Cleanup(func() { st.Close() })
	eng := &Engine{Pipeline: pipeline.New(st, flows.NewBus(), slog.Default())} // no CA
	proxySrv := httptest.NewServer(eng)
	t.Cleanup(proxySrv.Close)
	proxyURL, _ := url.Parse(proxySrv.URL)
	client := &http.Client{
		Transport: &http.Transport{
			Proxy:           http.ProxyURL(proxyURL),
			TLSClientConfig: &tls.Config{RootCAs: authority.Pool(), MinVersion: tls.VersionTLS12},
		},
		Timeout: 5 * time.Second,
	}
	resp, err := client.Get(up.srv.URL + "/")
	if err != nil {
		t.Fatalf("tunnel fallback failed: %v", err)
	}
	body, _ := io.ReadAll(resp.Body)
	resp.Body.Close()
	if string(body) != "opaque" {
		t.Fatalf("body = %q", body)
	}
	client.CloseIdleConnections()
	deadline := time.Now().Add(2 * time.Second)
	var rows []store.FlowRow
	for time.Now().Before(deadline) {
		rows, _ = st.ListFlows(context.Background(), store.Filter{})
		if len(rows) == 1 {
			break
		}
		time.Sleep(10 * time.Millisecond)
	}
	if len(rows) != 1 || !rows[0].Tunnel || rows[0].MITM {
		t.Fatalf("expected exactly one opaque tunnel row: %+v", rows)
	}
}

// --- chained upstream proxy (HTTP CONNECT) ---

type chainProxy struct {
	ln       net.Listener
	connects atomic.Int64
	plain    atomic.Int64
}

func newChainProxy(t *testing.T) *chainProxy {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	cp := &chainProxy{ln: ln}
	go func() {
		for {
			conn, err := ln.Accept()
			if err != nil {
				return
			}
			go cp.handle(conn)
		}
	}()
	t.Cleanup(func() { ln.Close() })
	return cp
}

func (cp *chainProxy) handle(conn net.Conn) {
	defer conn.Close()
	br := bufio.NewReader(conn)
	req, err := http.ReadRequest(br)
	if err != nil {
		return
	}
	if req.Method == http.MethodConnect {
		cp.connects.Add(1)
		target, err := net.DialTimeout("tcp", req.Host, 5*time.Second)
		if err != nil {
			fmt.Fprintf(conn, "HTTP/1.1 502 Bad Gateway\r\n\r\n")
			return
		}
		defer target.Close()
		fmt.Fprintf(conn, "HTTP/1.1 200 Connection Established\r\n\r\n")
		done := make(chan struct{})
		go func() { io.Copy(target, br); close(done) }()
		io.Copy(conn, target)
		<-done
		return
	}
	cp.plain.Add(1)
	// absolute-form plain HTTP: forward
	outReq, _ := http.NewRequest(req.Method, req.URL.String(), req.Body)
	for k, vs := range req.Header {
		for _, v := range vs {
			outReq.Header.Add(k, v)
		}
	}
	resp, err := http.DefaultTransport.RoundTrip(outReq)
	if err != nil {
		fmt.Fprintf(conn, "HTTP/1.1 502 Bad Gateway\r\n\r\n")
		return
	}
	defer resp.Body.Close()
	resp.Write(conn)
}

func (cp *chainProxy) URL() string { return "http://" + cp.ln.Addr().String() }

func TestChainedHTTPProxyPlain(t *testing.T) {
	var reached atomic.Bool
	up := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		reached.Store(true)
		_, _ = w.Write([]byte("via chain"))
	}))
	t.Cleanup(up.Close)

	cp := newChainProxy(t)
	st, _ := store.Open(filepath.Join(t.TempDir(), "chain.pf.sqlite"))
	t.Cleanup(func() { st.Close() })
	eng := &Engine{
		Pipeline:      pipeline.New(st, flows.NewBus(), slog.Default()),
		UpstreamProxy: mustURL(t, cp.URL()),
	}
	proxySrv := httptest.NewServer(eng)
	t.Cleanup(proxySrv.Close)

	client := &http.Client{
		Transport: &http.Transport{Proxy: http.ProxyURL(mustURL(t, proxySrv.URL))},
		Timeout:   10 * time.Second,
	}
	resp, err := client.Get(up.URL + "/x")
	if err != nil {
		t.Fatalf("get via chain: %v", err)
	}
	body, _ := io.ReadAll(resp.Body)
	resp.Body.Close()
	if string(body) != "via chain" || !reached.Load() {
		t.Fatalf("chain broken: body=%q reached=%v", body, reached.Load())
	}
	if cp.plain.Load() != 1 {
		t.Errorf("chain proxy saw %d plain requests, want 1", cp.plain.Load())
	}
	if singleFlow(t, st).Request.Scheme != "http" {
		t.Errorf("scheme not http")
	}
}

func TestChainedHTTPProxyMITM(t *testing.T) {
	authority := newAuthority(t)
	up := newTLSUpstream(t, authority, func(w http.ResponseWriter, r *http.Request) {
		_, _ = w.Write([]byte("tls via chain"))
	})
	cp := newChainProxy(t)

	st, _ := store.Open(filepath.Join(t.TempDir(), "chainm.pf.sqlite"))
	t.Cleanup(func() { st.Close() })
	eng := &Engine{
		Pipeline:      pipeline.New(st, flows.NewBus(), slog.Default()),
		CA:            authority,
		UpstreamProxy: mustURL(t, cp.URL()),
		UpstreamRoots: authority.Pool(),
	}
	proxySrv := httptest.NewServer(eng)
	t.Cleanup(proxySrv.Close)

	client := &http.Client{
		Transport: &http.Transport{
			Proxy:           http.ProxyURL(mustURL(t, proxySrv.URL)),
			TLSClientConfig: &tls.Config{RootCAs: authority.Pool(), MinVersion: tls.VersionTLS12},
		},
		Timeout: 10 * time.Second,
	}
	resp, err := client.Get(up.srv.URL + "/secret")
	if err != nil {
		t.Fatalf("https via chain: %v", err)
	}
	body, _ := io.ReadAll(resp.Body)
	resp.Body.Close()
	if string(body) != "tls via chain" {
		t.Fatalf("body = %q", body)
	}
	if cp.connects.Load() != 1 {
		t.Errorf("chain CONNECT count = %d, want 1", cp.connects.Load())
	}
	f := singleFlow(t, st)
	if !f.MITM || f.Response == nil || string(f.Response.Body) != "tls via chain" {
		t.Fatalf("MITM flow not captured through chain: %+v", f)
	}
}

// --- SOCKS5 upstream ---

type socks5Server struct {
	ln    net.Listener
	dials atomic.Int64
}

func newSocks5Server(t *testing.T) *socks5Server {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	s := &socks5Server{ln: ln}
	go func() {
		for {
			conn, err := ln.Accept()
			if err != nil {
				return
			}
			go s.handle(conn)
		}
	}()
	t.Cleanup(func() { ln.Close() })
	return s
}

func (s *socks5Server) handle(conn net.Conn) {
	defer conn.Close()
	head := make([]byte, 2)
	if _, err := io.ReadFull(conn, head); err != nil {
		return
	}
	methods := make([]byte, int(head[1]))
	if _, err := io.ReadFull(conn, methods); err != nil {
		return
	}
	if _, err := conn.Write([]byte{5, 0}); err != nil { // no auth
		return
	}
	req := make([]byte, 4)
	if _, err := io.ReadFull(conn, req); err != nil || req[1] != 1 { // CONNECT
		return
	}
	var host string
	switch req[3] {
	case 1:
		b := make([]byte, 4)
		io.ReadFull(conn, b)
		host = net.IP(b).String()
	case 3:
		l := make([]byte, 1)
		io.ReadFull(conn, l)
		b := make([]byte, int(l[0]))
		io.ReadFull(conn, b)
		host = string(b)
	case 4:
		b := make([]byte, 16)
		io.ReadFull(conn, b)
		host = net.IP(b).String()
	}
	pb := make([]byte, 2)
	io.ReadFull(conn, pb)
	port := int(pb[0])<<8 | int(pb[1])
	s.dials.Add(1)
	target, err := net.DialTimeout("tcp", net.JoinHostPort(host, strconv.Itoa(port)), 5*time.Second)
	if err != nil {
		conn.Write([]byte{5, 1, 0, 1, 0, 0, 0, 0, 0, 0})
		return
	}
	defer target.Close()
	if _, err := conn.Write([]byte{5, 0, 0, 1, 0, 0, 0, 0, 0, 0}); err != nil {
		return
	}
	done := make(chan struct{})
	go func() { io.Copy(target, conn); close(done) }()
	io.Copy(conn, target)
	<-done
}

func TestSOCKS5UpstreamPlain(t *testing.T) {
	var reached atomic.Bool
	up := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		reached.Store(true)
		_, _ = w.Write([]byte("via socks"))
	}))
	t.Cleanup(up.Close)

	socks := newSocks5Server(t)
	st, _ := store.Open(filepath.Join(t.TempDir(), "socks.pf.sqlite"))
	t.Cleanup(func() { st.Close() })
	eng := &Engine{
		Pipeline:      pipeline.New(st, flows.NewBus(), slog.Default()),
		UpstreamProxy: mustURL(t, "socks5://"+socks.ln.Addr().String()),
	}
	proxySrv := httptest.NewServer(eng)
	t.Cleanup(proxySrv.Close)

	client := &http.Client{
		Transport: &http.Transport{Proxy: http.ProxyURL(mustURL(t, proxySrv.URL))},
		Timeout:   10 * time.Second,
	}
	resp, err := client.Get(up.URL + "/s")
	if err != nil {
		t.Fatalf("get via socks: %v", err)
	}
	body, _ := io.ReadAll(resp.Body)
	resp.Body.Close()
	if string(body) != "via socks" || !reached.Load() {
		t.Fatalf("socks chain broken: %q %v", body, reached.Load())
	}
	if socks.dials.Load() == 0 {
		t.Errorf("socks server never dialed")
	}
	if singleFlow(t, st).Request.Host != stripPort(up.URL) {
		t.Errorf("flow host wrong")
	}
}

// --- upstream client certificates (mTLS) ---

// genClientCertPair creates a CA and a client leaf with ClientAuth EKU.
func genClientCertPair(t *testing.T, cn string) (*x509.CertPool, tls.Certificate) {
	t.Helper()
	caKey, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	caTpl := &x509.Certificate{
		SerialNumber:          big.NewInt(1),
		Subject:               pkix.Name{CommonName: "test client CA"},
		NotBefore:             time.Now().Add(-time.Hour),
		NotAfter:              time.Now().Add(24 * time.Hour),
		IsCA:                  true,
		KeyUsage:              x509.KeyUsageCertSign,
		BasicConstraintsValid: true,
	}
	caDER, err := x509.CreateCertificate(rand.Reader, caTpl, caTpl, caKey.Public(), caKey)
	if err != nil {
		t.Fatal(err)
	}
	caCert, _ := x509.ParseCertificate(caDER)
	pool := x509.NewCertPool()
	pool.AddCert(caCert)

	leafKey, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	leafTpl := &x509.Certificate{
		SerialNumber: big.NewInt(2),
		Subject:      pkix.Name{CommonName: cn},
		NotBefore:    time.Now().Add(-time.Hour),
		NotAfter:     time.Now().Add(24 * time.Hour),
		KeyUsage:     x509.KeyUsageDigitalSignature,
		ExtKeyUsage:  []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth},
	}
	leafDER, err := x509.CreateCertificate(rand.Reader, leafTpl, caCert, leafKey.Public(), caKey)
	if err != nil {
		t.Fatal(err)
	}
	return pool, tls.Certificate{
		Certificate: [][]byte{leafDER},
		PrivateKey:  leafKey,
	}
}

func TestUpstreamClientCert(t *testing.T) {
	authority := newAuthority(t)
	pool, clientLeaf := genClientCertPair(t, "proxyforge-client")

	var peerCN atomic.Value
	up := httptest.NewUnstartedServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.TLS != nil && len(r.TLS.PeerCertificates) > 0 {
			peerCN.Store(r.TLS.PeerCertificates[0].Subject.CommonName)
		}
		_, _ = w.Write([]byte("mtls ok"))
	}))
	serverLeaf, _ := authority.Mint("127.0.0.1")
	up.TLS = &tls.Config{
		Certificates: []tls.Certificate{serverLeaf},
		ClientCAs:    pool,
		ClientAuth:   tls.RequireAndVerifyClientCert,
		MinVersion:   tls.VersionTLS12,
	}
	up.StartTLS()
	t.Cleanup(up.Close)

	st, _ := store.Open(filepath.Join(t.TempDir(), "mtls.pf.sqlite"))
	t.Cleanup(func() { st.Close() })
	eng := &Engine{
		Pipeline:      pipeline.New(st, flows.NewBus(), slog.Default()),
		CA:            authority,
		UpstreamRoots: authority.Pool(),
		ClientCerts:   []ClientCert{{Pattern: "127.0.0.1", Cert: clientLeaf}},
	}
	proxySrv := httptest.NewServer(eng)
	t.Cleanup(proxySrv.Close)
	client := &http.Client{
		Transport: &http.Transport{
			Proxy:           http.ProxyURL(mustURL(t, proxySrv.URL)),
			TLSClientConfig: &tls.Config{RootCAs: authority.Pool(), MinVersion: tls.VersionTLS12},
		},
		Timeout: 10 * time.Second,
	}
	resp, err := client.Get(up.URL + "/mtls")
	if err != nil {
		t.Fatalf("mtls request: %v", err)
	}
	io.Copy(io.Discard, resp.Body)
	resp.Body.Close()
	if got, _ := peerCN.Load().(string); got != "proxyforge-client" {
		t.Fatalf("origin saw client cert CN = %q", got)
	}
	f := singleFlow(t, st)
	if f.Response == nil || f.Response.Status != 200 {
		t.Fatalf("flow missing 200: %+v", f.Response)
	}
}

func TestHostMatches(t *testing.T) {
	cases := []struct {
		pattern, host string
		want          bool
	}{
		{"*.example.com", "api.example.com", true},
		{"*.example.com", "example.com", false},
		{"*.example.com", "a.b.example.com", true},
		{"*.example.com", "api.example.org", false},
		{"api.example.com", "api.example.com", true},
		{"API.Example.COM", "api.example.com", true},
		{"api.example.com", "other.com", false},
		{"127.0.0.1", "127.0.0.1", true},
	}
	for _, c := range cases {
		if got := HostMatches(c.pattern, c.host); got != c.want {
			t.Errorf("HostMatches(%q,%q) = %v, want %v", c.pattern, c.host, got, c.want)
		}
	}
}

// helpers

func mustURL(t *testing.T, raw string) *url.URL {
	t.Helper()
	u, err := url.Parse(raw)
	if err != nil {
		t.Fatal(err)
	}
	return u
}

func stripPort(raw string) string {
	u, _ := url.Parse(raw)
	return u.Hostname()
}
