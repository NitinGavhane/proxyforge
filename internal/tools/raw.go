// Package tools hosts ProxyForge's active tools (Repeater, discovery,
// later Intruder/Scanner). Every outbound send goes through
// proxy.Engine.SendToolFlow — scope-gated and audited by construction.
package tools

import (
	"fmt"
	"net/url"
	"strconv"
	"strings"

	"github.com/NitinGavhane/proxyforge/internal/flows"
)

// ParseRawRequest parses a Burp-style raw request:
//
//	METHOD /path HTTP/1.1
//	Host: example.com
//	Header: value
//
//	body bytes (everything after the first blank line)
//
// The request target may be origin-form (Host header required) or
// absolute-form (scheme/host taken from the URL). Body length is derived
// from the remaining bytes and Content-Length is normalized.
func ParseRawRequest(raw string) (*flows.Request, error) {
	raw = strings.ReplaceAll(raw, "\r\n", "\n")
	head, body, hasBody := strings.Cut(raw, "\n\n")
	lines := strings.Split(head, "\n")
	if len(lines) == 0 || strings.TrimSpace(lines[0]) == "" {
		return nil, fmt.Errorf("raw: empty request")
	}
	parts := strings.Fields(lines[0])
	if len(parts) != 3 {
		return nil, fmt.Errorf("raw: request line must be 'METHOD path HTTP/x.y', got %q", lines[0])
	}
	method, target, version := parts[0], parts[1], parts[2]
	if !strings.HasPrefix(version, "HTTP/") {
		return nil, fmt.Errorf("raw: bad protocol %q", version)
	}

	req := &flows.Request{Method: method, HTTPVersion: version}
	path := target
	scheme := "http"
	if u, err := url.Parse(target); err == nil && u.IsAbs() && u.Host != "" {
		scheme = u.Scheme
		req.Host = u.Hostname()
		if p := u.Port(); p != "" {
			req.Port, _ = strconv.Atoi(p)
		}
		path = u.RequestURI()
	}

	for _, line := range lines[1:] {
		if strings.TrimSpace(line) == "" {
			continue
		}
		k, v, ok := strings.Cut(line, ":")
		if !ok {
			return nil, fmt.Errorf("raw: malformed header %q", line)
		}
		k, v = strings.TrimSpace(k), strings.TrimSpace(v)
		req.Headers.Add(k, v)
		if strings.EqualFold(k, "Host") {
			h := v
			if host, p, err := splitPort(h); err == nil {
				req.Host = host
				if p != "" {
					req.Port, _ = strconv.Atoi(p)
				}
			} else {
				req.Host = h
			}
		}
	}
	if req.Host == "" {
		return nil, fmt.Errorf("raw: no Host header or absolute URL — cannot route")
	}
	if req.Port == 0 {
		if scheme == "https" || scheme == "wss" {
			req.Port = 443
		} else {
			req.Port = 80
		}
	}
	if scheme == "https" && strings.Contains(strings.ToLower(head), "host:") {
		// default http unless the absolute-form said https — callers can
		// override by using an absolute URL or a scheme hint header below
	}
	req.Scheme = schemeHint(head, scheme)
	req.Path = path
	if hasBody {
		req.Body = []byte(strings.TrimPrefix(body, "\n"))
	}
	// normalize framing headers
	req.Headers.Del("Content-Length")
	req.Headers.Del("Transfer-Encoding")
	if len(req.Body) > 0 {
		req.Headers.Add("Content-Length", strconv.Itoa(len(req.Body)))
	}
	return req, nil
}

// schemeHint honors an explicit X-Scheme hint (used by the UI for https raw
// requests without an absolute URL), defaulting to the parsed scheme.
func schemeHint(head, def string) string {
	for _, line := range strings.Split(head, "\n") {
		if strings.HasPrefix(strings.ToLower(line), "x-scheme:") {
			v := strings.ToLower(strings.TrimSpace(strings.TrimPrefix(line[9:], " ")))
			if v == "https" || v == "http" {
				return v
			}
		}
	}
	return def
}

func splitPort(hostport string) (string, string, error) {
	i := strings.LastIndexByte(hostport, ':')
	if i < 0 {
		return hostport, "", fmt.Errorf("no port")
	}
	return hostport[:i], hostport[i+1:], nil
}

// RenderRaw is the inverse of ParseRawRequest for round-tripping (reuses
// the flows renderer with the Host header first).
func RenderRaw(req *flows.Request) string {
	return string(flows.RenderRequest(req))
}

// ParseRawResponse parses an HTTP/1.1 response wire form (status line,
// headers, body) — the import counterpart of flows.RenderResponse.
func ParseRawResponse(raw string) (*flows.Response, error) {
	raw = strings.ReplaceAll(raw, "\r\n", "\n")
	head, body, hasBody := strings.Cut(raw, "\n\n")
	lines := strings.Split(head, "\n")
	if len(lines) == 0 {
		return nil, fmt.Errorf("raw response: empty")
	}
	parts := strings.Fields(lines[0])
	if len(parts) < 2 || !strings.HasPrefix(parts[0], "HTTP/") {
		return nil, fmt.Errorf("raw response: bad status line %q", lines[0])
	}
	status := 0
	if _, err := fmt.Sscanf(parts[1], "%d", &status); err != nil {
		return nil, fmt.Errorf("raw response: bad status %q", parts[1])
	}
	text := strings.Join(parts[2:], " ")
	resp := &flows.Response{Status: status, StatusText: text, HTTPVersion: parts[0]}
	for _, line := range lines[1:] {
		if strings.TrimSpace(line) == "" {
			continue
		}
		k, v, ok := strings.Cut(line, ":")
		if !ok {
			continue
		}
		resp.Headers.Add(strings.TrimSpace(k), strings.TrimSpace(v))
	}
	if hasBody {
		resp.Body = []byte(strings.TrimPrefix(body, "\n"))
	}
	return resp, nil
}
