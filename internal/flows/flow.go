// Package flows defines ProxyForge's central message model (Flow) and the
// processing pipeline that every exchange — proxied or tool-originated —
// passes through.
package flows

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"io"
	"net"
	"net/http"
	"slices"
	"strconv"
	"strings"
	"time"
)

// Origin tags identify where a Flow came from. Tool origins are subject to
// scope enforcement at the outbound gate; proxy-origin traffic may traverse
// any host (it is only pass-through) but is not logged when out of scope.
const (
	OriginProxy    = "proxy"
	OriginRepeater = "repeater"
	OriginIntruder = "intruder"
	OriginScanner  = "scanner"
	OriginMCP      = "mcp"
	OriginImport   = "import"
)

// MaxBodyBytes is the per-body capture cap. Bodies larger than this are
// stored truncated and the flow is flagged.
var MaxBodyBytes = 8 << 20 // 8 MiB

// Header is a single header field preserving insertion order.
type Header struct {
	Key   string `json:"k"`
	Value string `json:"v"`
}

// Headers is an ordered header list.
type Headers []Header

// Get returns the first value for key (case-insensitive) and whether it
// exists.
func (h Headers) Get(key string) (string, bool) {
	for _, hd := range h {
		if strings.EqualFold(hd.Key, key) {
			return hd.Value, true
		}
	}
	return "", false
}

// Set removes all fields with key (case-insensitive) then appends key/value.
func (h *Headers) Set(key, value string) {
	h.Del(key)
	*h = append(*h, Header{Key: key, Value: value})
}

// Del removes all fields with key (case-insensitive).
func (h *Headers) Del(key string) {
	out := (*h)[:0]
	for _, hd := range *h {
		if !strings.EqualFold(hd.Key, key) {
			out = append(out, hd)
		}
	}
	*h = out
}

// Add appends key/value without removing existing fields.
func (h *Headers) Add(key, value string) {
	*h = append(*h, Header{Key: key, Value: value})
}

// FromHTTP converts an http.Header (map, unordered) into Headers in sorted
// key order for deterministic output. ProxyForge stores a normalized view of
// headers; exact wire ordering is not captured by the stdlib server and is a
// documented non-goal (see ARCHITECTURE.md §4.2).
func FromHTTP(h http.Header) Headers {
	keys := make([]string, 0, len(h))
	for k := range h {
		keys = append(keys, k)
	}
	slices.Sort(keys)
	out := make(Headers, 0, len(h))
	for _, k := range keys {
		for _, v := range h[k] {
			out = append(out, Header{Key: k, Value: v})
		}
	}
	return out
}

// Request is a captured outbound request.
type Request struct {
	Method      string  `json:"method"`
	Scheme      string  `json:"scheme"` // http | https | ws | wss
	Host        string  `json:"host"`
	Port        int     `json:"port"`
	Path        string  `json:"path"` // path + query, origin-form
	HTTPVersion string  `json:"version"`
	Headers     Headers `json:"headers"`
	Body        []byte  `json:"-"`
	Trailer     Headers `json:"trailer"`
	BodyTrunc   bool    `json:"body_truncated"`
}

// URL renders the absolute URL.
func (r *Request) URL() string {
	port := ""
	if (r.Scheme == "http" && r.Port != 80) || (r.Scheme == "https" && r.Port != 443) {
		port = ":" + strconv.Itoa(r.Port)
	}
	return r.Scheme + "://" + r.Host + port + r.Path
}

// HostPort renders host:port for the outbound dial.
func (r *Request) HostPort() string {
	port := r.Port
	if port == 0 {
		if r.Scheme == "https" {
			port = 443
		} else {
			port = 80
		}
	}
	return net.JoinHostPort(r.Host, strconv.Itoa(port))
}

// Response is a captured upstream response.
type Response struct {
	Status      int     `json:"status"`
	StatusText  string  `json:"status_text"`
	HTTPVersion string  `json:"version"`
	Headers     Headers `json:"headers"`
	Body        []byte  `json:"-"`
	Trailer     Headers `json:"trailer"`
	BodyTrunc   bool    `json:"body_truncated"`
}

// Flow is one request/response exchange.
type Flow struct {
	ID         int64     `json:"id"`
	Started    time.Time `json:"started"`
	Finished   time.Time `json:"finished"`
	DurationMS int64     `json:"duration_ms"`
	ClientAddr string    `json:"client_addr"`
	ServerAddr string    `json:"server_addr"`
	Origin     string    `json:"origin"`
	MITM       bool      `json:"mitm"`
	Tunnel     bool      `json:"tunnel"`               // CONNECT pass-through, opaque bytes
	TLSClient  string    `json:"tls_client,omitempty"` // e.g. "TLS 1.3" (browser ↔ proxy)
	TLSServer  string    `json:"tls_server,omitempty"` // e.g. "TLS 1.3" (proxy ↔ origin)
	InScope    bool      `json:"in_scope"`
	Truncated  bool      `json:"truncated"`
	Err        string    `json:"err,omitempty"`
	Comment    string    `json:"comment"`
	Highlight  string    `json:"highlight"`
	Request    *Request  `json:"request"`
	Response   *Response `json:"response"`
	// WSCount is the number of captured WebSocket frames on this flow.
	WSCount int64 `json:"ws_count"`
	// ToolRef links tool-originated flows to their tool object (e.g. the
	// repeater tab that sent them).
	ToolRef int64 `json:"tool_ref,omitempty"`
	// ReqBytes/RespBytes override body-length sizes when set (tunnels).
	ReqBytes  int64 `json:"req_bytes,omitempty"`
	RespBytes int64 `json:"resp_bytes,omitempty"`
}

// WebSocket message directions.
const (
	DirC2S = "c2s" // client → server
	DirS2C = "s2c" // server → client
)

// WSMessage is one captured WebSocket frame (RFC 6455).
type WSMessage struct {
	ID         int64  `json:"id"`
	FlowID     int64  `json:"flow_id"`
	TS         int64  `json:"ts"`        // unix millis
	Direction  string `json:"direction"` // c2s | s2c
	Opcode     int    `json:"opcode"`
	FIN        bool   `json:"fin"`
	Compressed bool   `json:"compressed"`
	Size       int    `json:"size"`
	Payload    []byte `json:"-"`
}

// Opcode names for display.
func OpcodeName(op int) string {
	switch op {
	case 0:
		return "continuation"
	case 1:
		return "text"
	case 2:
		return "binary"
	case 8:
		return "close"
	case 9:
		return "ping"
	case 10:
		return "pong"
	default:
		return "control"
	}
}

// ReadBody reads up to MaxBodyBytes from r into dst, setting truncated flags
// when the body was cut short.
func ReadBody(r io.Reader, max int) (body []byte, truncated bool, err error) {
	if max <= 0 {
		max = MaxBodyBytes
	}
	lr := io.LimitReader(r, int64(max)+1)
	body, err = io.ReadAll(lr)
	if err != nil {
		return body, true, err
	}
	if len(body) > max {
		return body[:max], true, nil
	}
	return body, false, nil
}

// SHA256 hex digest of b.
func SHA256(b []byte) string {
	sum := sha256.Sum256(b)
	return hex.EncodeToString(sum[:])
}

// RenderRequest serializes the request in HTTP/1.1 wire form (normalized
// header order, no chunked encoding — body written as-is). Used for golden
// tests, Repeater raw mode, and MCP output.
func RenderRequest(r *Request) []byte {
	var buf bytes.Buffer
	p := r.Path
	if p == "" {
		p = "/"
	}
	fmt.Fprintf(&buf, "%s %s %s\r\n", r.Method, p, orDefault(r.HTTPVersion, "HTTP/1.1"))
	if _, ok := r.Headers.Get("Host"); !ok {
		// host lives on the request struct, not in captured headers
		port := ""
		if (r.Scheme == "http" && r.Port != 0 && r.Port != 80) ||
			(r.Scheme == "https" && r.Port != 0 && r.Port != 443) {
			port = ":" + strconv.Itoa(r.Port)
		}
		buf.WriteString("Host: " + r.Host + port + "\r\n")
	}
	writeHeaders(&buf, r.Headers)
	buf.WriteString("\r\n")
	buf.Write(r.Body)
	return buf.Bytes()
}

// RenderResponse serializes the response in HTTP/1.1 wire form.
func RenderResponse(r *Response) []byte {
	var buf bytes.Buffer
	fmt.Fprintf(&buf, "%s %d %s\r\n", orDefault(r.HTTPVersion, "HTTP/1.1"), r.Status, orDefault(r.StatusText, http.StatusText(r.Status)))
	writeHeaders(&buf, r.Headers)
	buf.WriteString("\r\n")
	buf.Write(r.Body)
	return buf.Bytes()
}

func writeHeaders(buf *bytes.Buffer, h Headers) {
	for _, hd := range h {
		buf.WriteString(hd.Key)
		buf.WriteString(": ")
		buf.WriteString(hd.Value)
		buf.WriteString("\r\n")
	}
}

func orDefault(s, def string) string {
	if s == "" {
		return def
	}
	return s
}
