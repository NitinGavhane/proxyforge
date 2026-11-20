// Package proxy implements the ProxyForge engine: listeners that terminate
// client traffic and forward it upstream while capturing every exchange as a
// Flow through the pipeline.
//
// M2 scope: plain HTTP/1.1 proxying plus HTTPS CONNECT with MITM (leaf certs
// from the local CA), TLS pass-through tunnels, upstream proxy/SOCKS
// chaining, and upstream client certificates. HTTP/2 downstream arrives M3.
package proxy

import (
	"bytes"
	"context"
	"crypto/tls"
	"crypto/x509"
	"net"
	"net/http"
	"net/url"
	"strconv"
	"strings"
	"sync"
	"time"

	"golang.org/x/net/http2"
	"golang.org/x/net/proxy"

	"github.com/NitinGavhane/proxyforge/internal/ca"
	"github.com/NitinGavhane/proxyforge/internal/extjs"
	"github.com/NitinGavhane/proxyforge/internal/flows"
	"github.com/NitinGavhane/proxyforge/internal/intercept"
	"github.com/NitinGavhane/proxyforge/internal/matchreplace"
	"github.com/NitinGavhane/proxyforge/internal/pipeline"
	"github.com/NitinGavhane/proxyforge/internal/scope"
	"github.com/NitinGavhane/proxyforge/internal/tags"
)

// hop-by-hop headers are never forwarded upstream (RFC 7230 §6.1); the
// captured Flow still records what the client actually sent.
var hopByHop = map[string]bool{
	"Connection":          true,
	"Proxy-Connection":    true,
	"Keep-Alive":          true,
	"Proxy-Authenticate":  true,
	"Proxy-Authorization": true,
	"Te":                  true,
	"Trailer":             true,
	"Transfer-Encoding":   true,
	"Upgrade":             true,
}

// ClientCert pairs a host pattern with a client certificate for upstream mTLS.
type ClientCert struct {
	Pattern string
	Cert    tls.Certificate
}

// Engine is the proxy listener + forwarding logic.
type Engine struct {
	Pipeline *pipeline.Pipeline
	// Transport for upstream requests. nil → engine-built transport
	// (honors UpstreamProxy and ClientCerts). Tests may override.
	Transport http.RoundTripper

	// CA enables HTTPS MITM when non-nil.
	CA *ca.CA
	// PassThrough lists hosts (exact or *.wildcard) whose CONNECT tunnels
	// are spliced opaquely instead of being intercepted.
	PassThrough []string
	// UpstreamProxy chains egress through http(s):// or socks5://.
	UpstreamProxy *url.URL
	// ClientCerts are offered for upstream mTLS by host pattern.
	ClientCerts []ClientCert
	// UpstreamRoots overrides the system root pool for upstream TLS
	// verification (e.g. corporate intercepting proxies, lab CAs).
	UpstreamRoots *x509.CertPool
	// H2DisableHosts force-negotiates HTTP/1.1 downstream for these hosts
	// (exact or *.wildcard) — per-host downgrade for misbehaving clients.
	H2DisableHosts []string
	// Intercept parks matching flows for manual edit/forward/drop when set.
	Intercept *intercept.Manager
	// MatchReplace applies automatic modifications before interception.
	MatchReplace *matchreplace.Manager
	// Scope decides which targets are logged/intercepted and gates
	// tool-originated outbound traffic. nil = everything in scope.
	Scope *scope.Manager
	// Tags marks flows from extension-tagged origins (highlight + comment).
	Tags *tags.Manager
	// Scripts runs JS extensions (Phase 3 P9) before M&R; nil = none.
	Scripts *extjs.Manager

	srv       *http.Server
	trOnce    sync.Once
	defaultTr http.RoundTripper
	h2Once    sync.Once
	h2srv     *http2.Server
}

// buildTransport creates the upstream transport honoring chaining and
// client certificates.
func (e *Engine) buildTransport() *http.Transport {
	tr := &http.Transport{
		Proxy:                 nil,
		ForceAttemptHTTP2:     true,
		MaxIdleConns:          100,
		IdleConnTimeout:       90 * time.Second,
		TLSHandshakeTimeout:   10 * time.Second,
		ExpectContinueTimeout: time.Second,
	}
	if up := e.UpstreamProxy; up != nil {
		switch up.Scheme {
		case "http", "https":
			tr.Proxy = http.ProxyURL(up)
		case "socks5", "socks5h":
			if d, err := proxy.FromURL(up, proxy.Direct); err == nil {
				if cd, ok := d.(proxy.ContextDialer); ok {
					tr.DialContext = cd.DialContext
				}
			}
		}
	}
	if len(e.ClientCerts) > 0 || e.UpstreamRoots != nil {
		cfg := &tls.Config{MinVersion: tls.VersionTLS12}
		if e.UpstreamRoots != nil {
			cfg.RootCAs = e.UpstreamRoots
		}
		if len(e.ClientCerts) > 0 {
			cfg.GetClientCertificate = e.clientCertFor
		}
		tr.TLSClientConfig = cfg
	}
	return tr
}

// upstreamHostKey carries the target host into the TLS handshake so
// GetClientCertificate can select a per-host client cert.
type upstreamHostKey struct{}

// clientCertFor returns the first matching client certificate for the
// upstream host (nil cert = none offered). The host travels on the request
// context because CertificateRequestInfo does not expose it directly.
func (e *Engine) clientCertFor(cri *tls.CertificateRequestInfo) (*tls.Certificate, error) {
	host, _ := cri.Context().Value(upstreamHostKey{}).(string)
	for i := range e.ClientCerts {
		if HostMatches(e.ClientCerts[i].Pattern, host) {
			return &e.ClientCerts[i].Cert, nil
		}
	}
	return nil, nil
}

// HostMatches reports whether host matches an exact name or *.wildcard
// pattern (case-insensitive; IPv6 literals compare exactly).
func HostMatches(pattern, host string) bool {
	pattern = strings.ToLower(strings.TrimSpace(pattern))
	host = strings.ToLower(strings.TrimSpace(host))
	if strings.HasPrefix(pattern, "*.") {
		suffix := pattern[1:] // ".example.com"
		return strings.HasSuffix(host, suffix) && len(host) > len(suffix)
	}
	return host == pattern
}

// transport returns the upstream transport, created lazily.
func (e *Engine) transport() http.RoundTripper {
	if e.Transport != nil {
		return e.Transport
	}
	e.trOnce.Do(func() { e.defaultTr = e.buildTransport() })
	return e.defaultTr
}

// Listen starts the proxy listener on addr (blocking until Close).
func (e *Engine) Listen(addr string) error {
	ln, err := net.Listen("tcp", addr)
	if err != nil {
		return err
	}
	e.srv = &http.Server{
		Handler:           e,
		ReadHeaderTimeout: 30 * time.Second,
		// no WriteTimeout: intercepted/slow exchanges are legitimate
	}
	return e.srv.Serve(ln)
}

// Close shuts the listener down.
func (e *Engine) Close() error {
	if e.srv == nil {
		return nil
	}
	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()
	return e.srv.Shutdown(ctx)
}

// ServeHTTP implements the proxy protocol.
func (e *Engine) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	if r.Method == http.MethodConnect {
		e.handleConnect(w, r)
		return
	}
	e.forwardHTTP(w, r)
}

// forwardHTTP captures and forwards one HTTP exchange (plain proxying or a
// request inside an MITM'd TLS session).
func (e *Engine) forwardHTTP(w http.ResponseWriter, r *http.Request) {
	started := time.Now()

	// MITM context: requests served inside an intercepted CONNECT tunnel.
	mitmTarget, isMITM := mitmFromContext(r.Context())

	// Resolve absolute target URL: proxy requests carry absolute-form;
	// origin-form requests use the Host header (MITM inner requests are
	// origin-form over our TLS session).
	target := *r.URL
	if !target.IsAbs() {
		scheme := "http"
		switch {
		case isMITM:
			scheme = mitmTarget.Scheme // https inside TLS tunnels, http in plaintext ones
		case r.TLS != nil:
			scheme = "https"
		}
		target = url.URL{Scheme: scheme, Host: r.Host, Path: r.URL.Path, RawPath: r.URL.RawPath, RawQuery: r.URL.RawQuery}
	}
	switch target.Scheme {
	case "http", "https", "ws", "wss":
		// ok (ws/wss arrive as absolute-form upgrades on the plain leg)
	default:
		http.Error(w, "ProxyForge: unsupported scheme "+target.Scheme, http.StatusBadGateway)
		return
	}
	host := target.Hostname()
	port := 0
	if p := target.Port(); p != "" {
		if n, err := strconv.Atoi(p); err == nil {
			port = n
		}
	}
	if port == 0 && isMITM {
		port = mitmTarget.Port
	}

	// Virtual host: the engine serves its own CA page for proxied clients.
	// Never forwarded, logged, intercepted, or modified.
	if isProxyLocal(host) {
		e.serveProxyLocal(w, r)
		return
	}

	// WebSocket upgrade (h1 only — h2 extended CONNECT is out of Phase 1
	// scope) is spliced with frame capture instead of being forwarded.
	if isWebSocketUpgrade(r) {
		e.handleWebSocket(w, r, target, host, port, mitmTarget, isMITM)
		return
	}

	f := &flows.Flow{
		Started:    started,
		ClientAddr: remoteIP(r.RemoteAddr),
		Origin:     flows.OriginProxy,
		MITM:       isMITM,
		InScope:    true,
		Request: &flows.Request{
			Method:      r.Method,
			Scheme:      target.Scheme,
			Host:        host,
			Port:        port,
			Path:        target.RequestURI(),
			HTTPVersion: r.Proto,
			Headers:     flows.FromHTTP(r.Header),
		},
	}
	if r.TLS != nil {
		f.TLSClient = tls.VersionName(r.TLS.Version)
	} else if isMITM {
		f.TLSClient = mitmTarget.TLSVersion // inner server doesn't set r.TLS
	}
	f.ServerAddr = hostPort(host, port, target.Scheme)
	f.InScope = e.inScope(f.Request)
	if e.Tags != nil && (e.Tags.Match(host) || (port != 0 && e.Tags.Match(net.JoinHostPort(host, strconv.Itoa(port))))) {
		f.Highlight = "magenta"
		if f.Comment == "" {
			f.Comment = "tagged via extension"
		}
	}

	// Read (capped) request body before forwarding.
	var err error
	if r.Body != nil {
		f.Request.Body, f.Request.BodyTrunc, err = flows.ReadBody(r.Body, flows.MaxBodyBytes)
		if err != nil {
			f.Err = "read request body: " + err.Error()
		}
	}
	f.Request.Trailer = flows.FromHTTP(r.Trailer) // populated after body read

	// JS extensions run first, then match & replace (so rule predicates see
	// scripted rewrites); out-of-scope traffic is never modified or parked.
	if e.Scripts != nil && f.InScope {
		e.Scripts.RunRequest(f)
	}
	if e.MatchReplace != nil && f.InScope {
		e.MatchReplace.Apply(f, false)
		if host, ok := f.Request.Headers.Get("Host"); ok && host != "" && host != target.Host {
			target = rebuildTarget(target, f.Request)
		}
	}

	// Intercept gate (request phase): park for edit/forward/drop. Edits may
	// change method, host (via Host header), path, headers, and body, so the
	// upstream target is rebuilt afterwards.
	if e.Intercept != nil && f.InScope && e.Intercept.Match(f, false) {
		if !e.Intercept.Park(f, false) {
			e.dropFlow(w, f, started, "intercept: dropped")
			return
		}
		target = rebuildTarget(target, f.Request)
	}

	// Build the upstream request: normalized headers minus hop-by-hop.
	upURL := target
	upReq, err := http.NewRequestWithContext(r.Context(), f.Request.Method, upURL.String(),
		bytes.NewReader(f.Request.Body))
	if err != nil {
		e.failFlow(w, f, started, "build upstream request: "+err.Error())
		return
	}
	if len(e.ClientCerts) > 0 {
		upReq = upReq.WithContext(context.WithValue(upReq.Context(), upstreamHostKey{}, upURL.Hostname()))
	}
	for _, hd := range f.Request.Headers {
		if hopByHop[http.CanonicalHeaderKey(hd.Key)] {
			continue
		}
		if http.CanonicalHeaderKey(hd.Key) == "Host" {
			upReq.Host = hd.Value // the Host header travels via req.Host
			continue
		}
		upReq.Header.Add(hd.Key, hd.Value)
	}
	if f.Request.BodyTrunc {
		// cannot faithfully forward a truncated body; mark undeliverable
		e.failFlow(w, f, started, "request body exceeds capture cap; not forwarded (raise MaxBodyBytes)")
		return
	}
	if upReq.Header.Get("Content-Length") == "" && len(f.Request.Body) > 0 {
		upReq.ContentLength = int64(len(f.Request.Body))
	}
	// declared request trailers are forwarded and captured after the body
	for _, hd := range f.Request.Headers {
		if strings.EqualFold(hd.Key, "Trailer") {
			upReq.Header.Set("Trailer", hd.Value)
		}
	}
	if len(r.Trailer) > 0 {
		upReq.Trailer = make(http.Header)
		for key, vs := range r.Trailer {
			for _, v := range vs {
				upReq.Trailer.Add(key, v)
			}
		}
	}

	// Forward, capture response.
	resp, err := e.transport().RoundTrip(upReq)
	if err != nil {
		e.failFlow(w, f, started, "upstream: "+err.Error())
		return
	}
	defer resp.Body.Close()
	if resp.TLS != nil {
		f.TLSServer = tls.VersionName(resp.TLS.Version)
	}

	respBody, respTrunc, err := flows.ReadBody(resp.Body, flows.MaxBodyBytes)
	f.Response = &flows.Response{
		Status:      resp.StatusCode,
		StatusText:  strings.TrimPrefix(resp.Status, strconv.Itoa(resp.StatusCode)+" "),
		HTTPVersion: resp.Proto,
		Headers:     flows.FromHTTP(resp.Header),
		Body:        respBody,
		BodyTrunc:   respTrunc,
	}
	// trailers are only visible after the body has been read
	f.Response.Trailer = flows.FromHTTP(resp.Trailer)
	if err != nil {
		f.Err = "read response body: " + err.Error()
	}
	f.Truncated = f.Request.BodyTrunc || respTrunc

	// JS extensions + match & replace (response direction) before delivery.
	if e.Scripts != nil && f.InScope {
		e.Scripts.RunResponse(f)
	}
	if e.MatchReplace != nil && f.InScope {
		e.MatchReplace.Apply(f, true)
	}
	if e.MatchReplace != nil && f.InScope || e.Scripts != nil && f.InScope {
		respBody = f.Response.Body
	}

	// Intercept gate (response phase): park the exchange before delivery;
	// edits may change status, headers, or body.
	if e.Intercept != nil && f.InScope && e.Intercept.Match(f, true) {
		if !e.Intercept.Park(f, true) {
			e.dropFlow(w, f, started, "intercept: response dropped")
			return
		}
		respBody = f.Response.Body
	}

	// Reply to the client (hop-by-hop stripped, body replayed; a truncated
	// body is delivered as captured — the flow record carries the flag).
	h := w.Header()
	for _, hd := range f.Response.Headers {
		if hopByHop[http.CanonicalHeaderKey(hd.Key)] {
			continue
		}
		h.Add(hd.Key, hd.Value)
	}
	// declare + emit captured trailers back to the client
	if len(f.Response.Trailer) > 0 {
		declared := h.Get("Trailer")
		for _, hd := range f.Response.Trailer {
			declared += ", " + hd.Key
		}
		h.Set("Trailer", strings.TrimPrefix(declared, ", "))
	}
	w.WriteHeader(f.Response.Status)
	_, _ = w.Write(respBody)
	for _, hd := range f.Response.Trailer {
		w.Header().Set(hd.Key, hd.Value) // Go writes these as trailers post-body
	}

	f.DurationMS = time.Since(started).Milliseconds()
	f.Finished = time.Now()
	e.saveIfInScope(f)
}

func (e *Engine) failFlow(w http.ResponseWriter, f *flows.Flow, started time.Time, msg string) {
	f.Err = msg
	f.DurationMS = time.Since(started).Milliseconds()
	f.Finished = time.Now()
	e.saveIfInScope(f)
	http.Error(w, "ProxyForge: "+msg, http.StatusBadGateway)
}

// dropFlow records a dropped exchange and aborts the client connection
// without writing a response (Burp-style drop).
func (e *Engine) dropFlow(w http.ResponseWriter, f *flows.Flow, started time.Time, msg string) {
	_ = w
	f.Err = msg
	f.DurationMS = time.Since(started).Milliseconds()
	f.Finished = time.Now()
	e.saveIfInScope(f)
	panic(http.ErrAbortHandler)
}

// saveIfInScope persists in-scope flows; out-of-scope exchanges pass through
// unlogged (counter only).
func (e *Engine) saveIfInScope(f *flows.Flow) {
	if f.InScope {
		_ = e.Pipeline.Save(context.Background(), f)
		return
	}
	if e.Scope != nil {
		e.Scope.CountOutOfScope()
	}
}

// inScope evaluates the scope manager (nil manager = everything in scope).
func (e *Engine) inScope(req *flows.Request) bool {
	return e.Scope == nil || e.Scope.MatchRequest(req)
}

// rebuildTarget applies request edits (Host header, path) to the upstream
// target URL after an intercept forward.
func rebuildTarget(target url.URL, req *flows.Request) url.URL {
	t := target
	if host, ok := req.Headers.Get("Host"); ok && host != "" {
		t.Host = host
	}
	path := req.Path
	if i := strings.IndexByte(path, '?'); i >= 0 {
		t.Path, t.RawQuery = path[:i], path[i+1:]
	} else {
		t.Path, t.RawQuery = path, ""
	}
	return t
}

func remoteIP(addr string) string {
	if host, _, err := net.SplitHostPort(addr); err == nil {
		return host
	}
	return addr
}

func hostPort(host string, port int, scheme string) string {
	if port == 0 {
		if scheme == "https" {
			port = 443
		} else {
			port = 80
		}
	}
	return net.JoinHostPort(host, strconv.Itoa(port))
}
