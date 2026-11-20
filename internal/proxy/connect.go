package proxy

import (
	"bufio"
	"context"
	"crypto/tls"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/url"
	"strconv"
	"sync"
	"time"

	"golang.org/x/net/http2"
	"golang.org/x/net/proxy"

	"github.com/NitinGavhane/proxyforge/internal/flows"
)

// mitmCtxKey marks requests served inside an intercepted TLS session and
// carries the CONNECT host/port (the inner Host header may differ).
type mitmCtxKey struct{}

type mitmInfo struct {
	Host string
	Port int
	// Scheme is the effective inner scheme: "https" for intercepted TLS,
	// "http" for a plaintext CONNECT tunnel (e.g. ws:// dialed via proxy).
	Scheme string
	// TLSVersion is the negotiated downstream (client ↔ proxy) version.
	TLSVersion string
}

func mitmFromContext(ctx context.Context) (mitmInfo, bool) {
	info, ok := ctx.Value(mitmCtxKey{}).(mitmInfo)
	return info, ok
}

// brConn layers a bufio.Reader under a net.Conn so bytes the outer
// http.Server buffered before hijack are not lost (an eager client may send
// the TLS ClientHello immediately after CONNECT).
type brConn struct {
	net.Conn
	br *bufio.Reader
}

func (c brConn) Read(p []byte) (int, error) { return c.br.Read(p) }

// mitmListener hands exactly one connection to an http.Server and derives
// the request base context from it.
type mitmListener struct {
	conn   net.Conn
	ctx    context.Context
	served bool
	closed bool
}

func (l *mitmListener) Accept() (net.Conn, error) {
	if l.served {
		return nil, io.EOF
	}
	l.served = true
	return l.conn, nil
}

// Close must NOT close the connection: http.Server.Serve defers Close after
// the one-shot Accept ends, while the spawned serve goroutine is still using
// the conn. The conn's lifecycle is owned by handleConnect.
func (l *mitmListener) Close() error {
	l.closed = true
	return nil
}

func (l *mitmListener) Addr() net.Addr { return l.conn.LocalAddr() }

// handleConnect serves a client CONNECT request: MITM (default) or an
// opaque pass-through tunnel for pinned hosts.
func (e *Engine) handleConnect(w http.ResponseWriter, r *http.Request) {
	host, portStr, err := net.SplitHostPort(r.Host)
	if err != nil {
		http.Error(w, "ProxyForge: malformed CONNECT target "+r.Host, http.StatusBadRequest)
		return
	}
	port, _ := strconv.Atoi(portStr)
	if port == 0 {
		port = 443
	}

	hj, ok := w.(http.Hijacker)
	if !ok {
		http.Error(w, "ProxyForge: connection cannot be hijacked", http.StatusInternalServerError)
		return
	}
	conn, brw, err := hj.Hijack()
	if err != nil {
		return
	}
	defer conn.Close()
	_ = conn.SetDeadline(time.Time{})
	_ = brw.Writer.Flush()

	for _, pattern := range e.PassThrough {
		if HostMatches(pattern, host) {
			e.passThrough(conn, brw, r, host, port)
			return
		}
	}

	if _, err := io.WriteString(conn, "HTTP/1.1 200 Connection Established\r\n\r\n"); err != nil {
		return
	}
	e.mitm(conn, brw.Reader, r.RemoteAddr, host, port)
}

// trackedConn signals when the http.Server's serve goroutine has finished
// with the connection (it always closes c.rwc via defer). mitm() blocks on
// that signal so the caller's conn cleanup happens at the right time.
type trackedConn struct {
	net.Conn
	once sync.Once
	done chan struct{}
}

func (c *trackedConn) Close() error {
	err := c.Conn.Close()
	c.once.Do(func() { close(c.done) })
	return err
}

// mitm serves intercepted traffic inside an established CONNECT tunnel
// (the 200 was already sent). The first byte decides the shape:
// 0x16 (TLS ClientHello) → terminate TLS with a minted leaf (HTTP/2 or 1.1
// by ALPN); anything else → plaintext HTTP/1.1 on the raw tunnel (gorilla
// and other ws clients dial ws:// through proxies with CONNECT, speaking
// plaintext WebSocket inside). Without a CA the tunnel is spliced opaquely
// so traffic keeps flowing, just without decryption.
func (e *Engine) mitm(conn net.Conn, br *bufio.Reader, remoteAddr, host string, port int) {
	first, err := br.Peek(1)
	if err != nil {
		return // client closed the tunnel immediately
	}
	if first[0] != 0x16 { // not a TLS ClientHello → plaintext HTTP tunnel
		if e.CA == nil {
			e.tunnelSplice(conn, br, remoteAddr, host, port)
			return
		}
		info := mitmInfo{Host: host, Port: port, Scheme: "http"}
		ctx := context.WithValue(context.Background(), mitmCtxKey{}, info)
		tc := &trackedConn{Conn: brConn{Conn: conn, br: br}, done: make(chan struct{})}
		ln := &mitmListener{conn: tc, ctx: ctx}
		srv := &http.Server{Handler: e, BaseContext: func(net.Listener) context.Context { return ln.ctx }}
		_ = srv.Serve(ln)
		<-tc.done
		return
	}

	if e.CA == nil { // TLS we cannot decrypt: fall back to an opaque tunnel
		e.tunnelSplice(conn, br, remoteAddr, host, port)
		return
	}

	tlsConn, err := e.serverTLS(brConn{Conn: conn, br: br}, host, e.h2Allowed(host))
	if err != nil {
		return // handshake failure: nothing to record beyond a closed tunnel
	}
	info := mitmInfo{
		Host:       host,
		Port:       port,
		Scheme:     "https",
		TLSVersion: tls.VersionName(tlsConn.ConnectionState().Version),
	}
	ctx := context.WithValue(context.Background(), mitmCtxKey{}, info)

	if tlsConn.ConnectionState().NegotiatedProtocol == "h2" {
		// ServeConn blocks until the connection is done and manages its own
		// goroutines — no lifecycle juggling needed on this path.
		e.h2Server().ServeConn(tlsConn, &http2.ServeConnOpts{
			Handler: e,
			Context: ctx,
		})
		return
	}

	tc := &trackedConn{Conn: tlsConn, done: make(chan struct{})}
	ln := &mitmListener{conn: tc, ctx: ctx}
	srv := &http.Server{
		Handler:     e,
		BaseContext: func(net.Listener) context.Context { return ln.ctx },
	}
	_ = srv.Serve(ln) // returns after the one-shot Accept; conn may still be live
	<-tc.done         // wait until the inner serve goroutine closed the conn
}

// h2Allowed reports whether the downstream leg may negotiate HTTP/2 for host
// (per-host downgrade list for misbehaving clients).
func (e *Engine) h2Allowed(host string) bool {
	for _, pattern := range e.H2DisableHosts {
		if HostMatches(pattern, host) {
			return false
		}
	}
	return true
}

// h2Server lazily builds the shared downstream HTTP/2 server.
func (e *Engine) h2Server() *http2.Server {
	e.h2Once.Do(func() {
		e.h2srv = &http2.Server{
			MaxConcurrentStreams: 250,
			IdleTimeout:          0,
		}
	})
	return e.h2srv
}

// serverTLS handshakes as the MITM server, minting a leaf for the SNI
// (falling back to the CONNECT host when the client sends none). HTTP/2 is
// offered via ALPN unless the host is on the downgrade list.
func (e *Engine) serverTLS(conn net.Conn, fallbackHost string, allowH2 bool) (*tls.Conn, error) {
	protos := []string{"http/1.1"}
	if allowH2 {
		protos = []string{"h2", "http/1.1"}
	}
	cfg := &tls.Config{
		MinVersion: tls.VersionTLS12,
		NextProtos: protos,
		GetCertificate: func(chi *tls.ClientHelloInfo) (*tls.Certificate, error) {
			host := chi.ServerName
			if host == "" {
				host = fallbackHost
			}
			leaf, err := e.CA.Mint(host)
			if err != nil {
				return nil, err
			}
			return &leaf, nil
		},
	}
	tc := tls.Server(conn, cfg)
	_ = tc.SetDeadline(time.Now().Add(15 * time.Second))
	if err := tc.Handshake(); err != nil {
		return nil, err
	}
	_ = tc.SetDeadline(time.Time{})
	return tc, nil
}

// passThrough splices the CONNECT tunnel opaquely (no decryption) and logs
// tunnel metadata with byte counts. Dials before confirming so failures can
// still be surfaced to the client.
func (e *Engine) passThrough(client net.Conn, brw *bufio.ReadWriter, r *http.Request, host string, port int) {
	f, targetConn, ok := e.tunnelDial(remoteIP(r.RemoteAddr), host, port, r.Proto, flows.FromHTTP(r.Header))
	if !ok {
		fmt.Fprintf(client, "HTTP/1.1 502 Bad Gateway\r\nContent-Length: 0\r\n\r\n")
		return
	}
	if _, err := io.WriteString(client, "HTTP/1.1 200 Connection Established\r\n\r\n"); err != nil {
		targetConn.Close()
		return
	}
	e.spliceTunnel(client, brw.Reader, targetConn, f)
}

// tunnelSplice is the already-confirmed variant: the client got its 200, so
// dial failures just close the connection.
func (e *Engine) tunnelSplice(client net.Conn, br *bufio.Reader, remoteAddr, host string, port int) {
	f, targetConn, ok := e.tunnelDial(remoteIP(remoteAddr), host, port, "HTTP/1.1", nil)
	if !ok {
		return
	}
	e.spliceTunnel(client, br, targetConn, f)
}

// tunnelDial builds the tunnel flow record and dials the target.
func (e *Engine) tunnelDial(clientAddr, host string, port int, proto string, hdrs flows.Headers) (*flows.Flow, net.Conn, bool) {
	started := time.Now()
	target := net.JoinHostPort(host, strconv.Itoa(port))
	f := &flows.Flow{
		Started:    started,
		ClientAddr: clientAddr,
		ServerAddr: target,
		Origin:     flows.OriginProxy,
		InScope:    true,
		Tunnel:     true,
		Request: &flows.Request{
			Method:      http.MethodConnect,
			Scheme:      "https",
			Host:        host,
			Port:        port,
			HTTPVersion: proto,
			Headers:     hdrs,
		},
	}
	f.InScope = e.inScope(f.Request)
	targetConn, err := e.dialUpstream(target)
	if err != nil {
		f.Err = "tunnel dial: " + err.Error()
		f.Finished = time.Now()
		e.saveIfInScope(f)
		return nil, nil, false
	}
	return f, targetConn, true
}

// spliceTunnel splices both directions, counts bytes, and records the flow.
func (e *Engine) spliceTunnel(client net.Conn, br *bufio.Reader, targetConn net.Conn, f *flows.Flow) {
	defer targetConn.Close()
	started := f.Started

	cConn := brConn{Conn: client, br: br}
	upBytes := make(chan int64, 1)
	go func() {
		n, _ := io.Copy(targetConn, cConn)
		if tc, ok := targetConn.(*net.TCPConn); ok {
			_ = tc.CloseWrite() // propagate client half-close
		}
		upBytes <- n
	}()
	down, _ := io.Copy(cConn, targetConn)
	up := <-upBytes
	_ = client.Close()

	f.ReqBytes = up
	f.RespBytes = down
	f.Response = &flows.Response{
		Status:      http.StatusOK,
		StatusText:  "Connection Established",
		HTTPVersion: "HTTP/1.1",
	}
	f.DurationMS = time.Since(started).Milliseconds()
	f.Finished = time.Now()
	e.saveIfInScope(f)
}

// dialUpstream opens a TCP connection to addr, through the configured
// upstream proxy (CONNECT) or SOCKS5 dialer when chaining.
func (e *Engine) dialUpstream(addr string) (net.Conn, error) {
	up := e.UpstreamProxy
	if up == nil {
		return net.DialTimeout("tcp", addr, 15*time.Second)
	}
	switch up.Scheme {
	case "socks5", "socks5h":
		d, err := proxy.FromURL(up, proxy.Direct)
		if err != nil {
			return nil, err
		}
		return d.Dial("tcp", addr)
	case "http", "https":
		proxyAddr := up.Host
		if up.Port() == "" {
			if up.Scheme == "https" {
				proxyAddr = net.JoinHostPort(up.Host, "443")
			} else {
				proxyAddr = net.JoinHostPort(up.Host, "80")
			}
		}
		raw, err := net.DialTimeout("tcp", proxyAddr, 15*time.Second)
		if err != nil {
			return nil, err
		}
		var conn net.Conn = raw
		if up.Scheme == "https" {
			conn = tls.Client(raw, &tls.Config{
				ServerName: up.Hostname(),
				MinVersion: tls.VersionTLS12,
			})
		}
		req := &http.Request{
			Method: http.MethodConnect,
			URL:    &url.URL{Opaque: addr},
			Host:   addr,
			Header: make(http.Header),
		}
		if err := req.Write(conn); err != nil {
			conn.Close()
			return nil, err
		}
		br := bufio.NewReader(conn)
		resp, err := http.ReadResponse(br, req)
		if err != nil {
			conn.Close()
			return nil, err
		}
		resp.Body.Close()
		if resp.StatusCode != http.StatusOK {
			conn.Close()
			return nil, fmt.Errorf("upstream proxy CONNECT failed: %s", resp.Status)
		}
		return brConn{Conn: conn, br: br}, nil
	default:
		return nil, fmt.Errorf("unsupported upstream proxy scheme %q", up.Scheme)
	}
}
