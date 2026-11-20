// Outbound gate + tool send path (M7).
//
// Every outbound exchange flows through the same gate: proxy-origin traffic
// may leave for any host (the proxy is a pass-through; scope only filters
// logging/interception), while tool-origin traffic (repeater, intruder,
// scanner, mcp — and test senders) must target in-scope hosts. Refusals are
// logged to the audit trail and the flow is recorded with an error.
package proxy

import (
	"bytes"
	"context"
	"crypto/tls"
	"fmt"
	"net/http"
	"strconv"
	"strings"
	"time"

	"github.com/NitinGavhane/proxyforge/internal/flows"
)

// OutOfScopeError marks gate refusals.
type OutOfScopeError struct{ Target string }

func (e *OutOfScopeError) Error() string {
	return "outbound gate: target out of scope: " + e.Target
}

// outboundAllowed enforces scope by origin. Proxy-origin traffic always
// passes; tool origins must be in scope.
func (e *Engine) outboundAllowed(f *flows.Flow) error {
	if e.Scope == nil || f.Origin == flows.OriginProxy {
		return nil
	}
	if !e.Scope.MatchRequest(f.Request) {
		return &OutOfScopeError{Target: f.Request.URL()}
	}
	return nil
}

// SendToolFlow sends one tool-originated flow through the outbound gate and
// capture pipeline. This is the foundation for Phase 3 tools (Repeater,
// Intruder, Scanner) and is exercised in M7 with synthetic tool origins.
// The response is attached to the flow, which is persisted either way.
func (e *Engine) SendToolFlow(f *flows.Flow) error {
	if f == nil || f.Request == nil {
		return fmt.Errorf("tool flow: missing request")
	}
	if f.Origin == "" || f.Origin == flows.OriginProxy {
		f.Origin = flows.OriginRepeater // default tool origin for direct sends
	}
	started := time.Now()
	if f.Started.IsZero() {
		f.Started = started
	}
	f.InScope = e.Scope == nil || e.Scope.MatchRequest(f.Request)

	if err := e.outboundAllowed(f); err != nil {
		f.Err = err.Error()
		f.Finished = time.Now()
		f.DurationMS = time.Since(started).Milliseconds()
		_ = e.Pipeline.Save(context.Background(), f)
		e.auditRefusal(f)
		return err
	}

	upReq, err := buildUpstreamRequest(f.Request)
	if err != nil {
		f.Err = err.Error()
		f.Finished = time.Now()
		_ = e.Pipeline.Save(context.Background(), f)
		return err
	}
	resp, err := e.transport().RoundTrip(upReq)
	if err != nil {
		f.Err = "upstream: " + err.Error()
		f.Finished = time.Now()
		f.DurationMS = time.Since(started).Milliseconds()
		_ = e.Pipeline.Save(context.Background(), f)
		return err
	}
	defer resp.Body.Close()
	if resp.TLS != nil {
		f.TLSServer = tls.VersionName(resp.TLS.Version)
	}
	body, trunc, rerr := flows.ReadBody(resp.Body, flows.MaxBodyBytes)
	f.Response = &flows.Response{
		Status:      resp.StatusCode,
		StatusText:  strings.TrimPrefix(resp.Status, strconv.Itoa(resp.StatusCode)+" "),
		HTTPVersion: resp.Proto,
		Headers:     flows.FromHTTP(resp.Header),
		Body:        body,
		BodyTrunc:   trunc,
		Trailer:     flows.FromHTTP(resp.Trailer),
	}
	if rerr != nil {
		f.Err = "read response body: " + rerr.Error()
	}
	f.Truncated = f.Request.BodyTrunc || trunc
	f.DurationMS = time.Since(started).Milliseconds()
	f.Finished = time.Now()
	return e.Pipeline.Save(context.Background(), f)
}

// buildUpstreamRequest constructs the outbound request from the flow model:
// non-hop-by-hop headers, host from the Host header when present.
func buildUpstreamRequest(req *flows.Request) (*http.Request, error) {
	scheme := req.Scheme
	if scheme == "" {
		scheme = "http"
	}
	if scheme == "ws" {
		scheme = "http"
	} else if scheme == "wss" {
		scheme = "https"
	}
	port := ""
	if req.Port != 0 && !((scheme == "http" && req.Port == 80) || (scheme == "https" && req.Port == 443)) {
		port = ":" + strconv.Itoa(req.Port)
	}
	rawURL := scheme + "://" + req.Host + port + req.Path
	upReq, err := http.NewRequest(req.Method, rawURL, bytes.NewReader(req.Body))
	if err != nil {
		return nil, err
	}
	for _, hd := range req.Headers {
		key := http.CanonicalHeaderKey(hd.Key)
		if hopByHop[key] {
			continue
		}
		if key == "Host" {
			upReq.Host = hd.Value
			continue
		}
		upReq.Header.Add(hd.Key, hd.Value)
	}
	if upReq.Header.Get("Content-Length") == "" && len(req.Body) > 0 {
		upReq.ContentLength = int64(len(req.Body))
	}
	return upReq, nil
}

// auditRefusal records a gate refusal in the audit log.
func (e *Engine) auditRefusal(f *flows.Flow) {
	if e.Pipeline == nil {
		return
	}
	_ = e.Pipeline.Store.AppendAudit(context.Background(),
		"engine", "outbound_gate.refuse", f.Request.Host,
		fmt.Sprintf("origin=%s url=%s", f.Origin, f.Request.URL()))
}
