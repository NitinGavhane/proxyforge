// Package har exports captured flows in HAR 1.2 format (the interchange
// format for the REA reference tool and standard tooling).
package har

import (
	"encoding/base64"
	"encoding/json"
	"fmt"
	"net/url"
	"strconv"
	"strings"
	"time"
	"unicode/utf8"

	"github.com/NitinGavhane/proxyforge/internal/flows"
)

// Header is a HAR name/value pair.
type Header struct {
	Name  string `json:"name"`
	Value string `json:"value"`
}

// Cookie is a HAR cookie.
type Cookie struct {
	Name  string `json:"name"`
	Value string `json:"value"`
}

// Content is a HAR response body descriptor.
type Content struct {
	Size     int    `json:"size"`
	MimeType string `json:"mimeType"`
	Text     string `json:"text"`
	Encoding string `json:"encoding,omitempty"` // "base64" for non-UTF-8 bodies
}

// PostData is a HAR request body descriptor.
type PostData struct {
	MimeType string `json:"mimeType"`
	Text     string `json:"text"`
}

// Request is a HAR request.
type Request struct {
	Method      string    `json:"method"`
	URL         string    `json:"url"`
	HTTPVersion string    `json:"httpVersion"`
	Cookies     []Cookie  `json:"cookies"`
	Headers     []Header  `json:"headers"`
	QueryString []Header  `json:"queryString"`
	HeadersSize int       `json:"headersSize"`
	BodySize    int       `json:"bodySize"`
	PostData    *PostData `json:"postData,omitempty"`
}

// Response is a HAR response.
type Response struct {
	Status      int      `json:"status"`
	StatusText  string   `json:"statusText"`
	HTTPVersion string   `json:"httpVersion"`
	Cookies     []Cookie `json:"cookies"`
	Headers     []Header `json:"headers"`
	Content     Content  `json:"content"`
	RedirectURL string   `json:"redirectURL"`
	HeadersSize int      `json:"headersSize"`
	BodySize    int      `json:"bodySize"`
}

// Timings is a HAR timing block (ProxyForge records only the total).
type Timings struct {
	Send    int `json:"send"`
	Wait    int `json:"wait"`
	Receive int `json:"receive"`
}

// Entry is one exchange.
type Entry struct {
	StartedDateTime string   `json:"startedDateTime"`
	Time            int      `json:"time"`
	Request         Request  `json:"request"`
	Response        Response `json:"response"`
	Cache           struct{} `json:"cache"`
	Timings         Timings  `json:"timings"`
	ServerIPAddress string   `json:"serverIPAddress,omitempty"`
	Connection      string   `json:"connection,omitempty"`
	Comment         string   `json:"comment,omitempty"`
}

// Creator identifies the producing tool.
type Creator struct {
	Name    string `json:"name"`
	Version string `json:"version"`
}

// Log is the HAR root.
type Log struct {
	Version string  `json:"version"`
	Creator Creator `json:"creator"`
	Entries []Entry `json:"entries"`
}

type harFile struct {
	Log Log `json:"log"`
}

// Version reported in exports.
const Version = "0.1.0"

// Export builds a HAR document from flows. Tunnel entries (opaque CONNECT
// splices with no decoded exchange) are skipped.
func Export(fs []*flows.Flow) ([]byte, error) {
	out := harFile{Log: Log{
		Version: "1.2",
		Creator: Creator{Name: "ProxyForge", Version: Version},
		Entries: []Entry{},
	}}
	for _, f := range fs {
		if f == nil || f.Request == nil || f.Tunnel {
			continue
		}
		out.Log.Entries = append(out.Log.Entries, buildEntry(f))
	}
	b, err := json.MarshalIndent(out, "", "  ")
	if err != nil {
		return nil, err
	}
	return append(b, '\n'), nil
}

func buildEntry(f *flows.Flow) Entry {
	req := f.Request
	e := Entry{
		StartedDateTime: f.Started.UTC().Format("2006-01-02T15:04:05.000Z"),
		Time:            int(f.DurationMS),
		Connection:      strconv.FormatInt(f.ID, 10),
	}
	e.Request = Request{
		Method:      req.Method,
		URL:         req.URL(),
		HTTPVersion: orDef(req.HTTPVersion, "HTTP/1.1"),
		Cookies:     parseCookieHeader(req.Headers, "Cookie"),
		Headers:     toHARHeaders(req.Headers),
		QueryString: parseQuery(req.Path),
		HeadersSize: -1,
		BodySize:    len(req.Body),
	}
	if len(req.Body) > 0 {
		e.Request.PostData = &PostData{
			MimeType: headerValue(req.Headers, "Content-Type"),
			Text:     bodyText(req.Body),
		}
	}
	if f.Response != nil {
		resp := f.Response
		e.Response = Response{
			Status:      resp.Status,
			StatusText:  orDef(resp.StatusText, httpStatusText(resp.Status)),
			HTTPVersion: orDef(resp.HTTPVersion, "HTTP/1.1"),
			Cookies:     parseCookieHeader(resp.Headers, "Set-Cookie"),
			Headers:     toHARHeaders(resp.Headers),
			Content: Content{
				Size:     len(resp.Body),
				MimeType: headerValue(resp.Headers, "Content-Type"),
				Text:     bodyText(resp.Body),
			},
			RedirectURL: headerValue(resp.Headers, "Location"),
			HeadersSize: -1,
			BodySize:    len(resp.Body),
		}
		if !utf8.Valid(resp.Body) {
			e.Response.Content.Encoding = "base64"
		}
	}
	e.ServerIPAddress = serverIP(f.ServerAddr)
	if f.DurationMS >= 0 {
		e.Timings.Receive = int(f.DurationMS)
	}
	return e
}

func toHARHeaders(h flows.Headers) []Header {
	out := make([]Header, 0, len(h))
	for _, hd := range h {
		out = append(out, Header{Name: hd.Key, Value: hd.Value})
	}
	return out
}

func headerValue(h flows.Headers, key string) string {
	v, _ := h.Get(key)
	return v
}

// bodyText renders a body: raw text for UTF-8, base64 otherwise.
func bodyText(b []byte) string {
	if utf8.Valid(b) {
		return string(b)
	}
	return base64.StdEncoding.EncodeToString(b)
}

// parseQuery extracts name/value pairs from the URL query.
func parseQuery(path string) []Header {
	i := strings.IndexByte(path, '?')
	if i < 0 {
		return []Header{}
	}
	out := []Header{}
	for _, pair := range strings.Split(path[i+1:], "&") {
		if pair == "" {
			continue
		}
		k, v, _ := strings.Cut(pair, "=")
		dk, err1 := url.QueryUnescape(k)
		dv, err2 := url.QueryUnescape(v)
		if err1 != nil {
			dk = k
		}
		if err2 != nil {
			dv = v
		}
		out = append(out, Header{Name: dk, Value: dv})
	}
	return out
}

// parseCookieHeader extracts cookies from Cookie / Set-Cookie headers. A
// Cookie header carries one cookie per "; " pair; a Set-Cookie header carries
// exactly one cookie, with attributes (Path, HttpOnly, …) after it.
func parseCookieHeader(h flows.Headers, name string) []Cookie {
	out := []Cookie{}
	for _, hd := range h {
		if !strings.EqualFold(hd.Key, name) {
			continue
		}
		parts := strings.Split(hd.Value, ";")
		limit := len(parts)
		if strings.EqualFold(name, "Set-Cookie") {
			limit = 1
		}
		for _, part := range parts[:limit] {
			k, v, ok := strings.Cut(strings.TrimSpace(part), "=")
			if ok && k != "" {
				out = append(out, Cookie{Name: k, Value: v})
			}
		}
	}
	return out
}

func serverIP(serverAddr string) string {
	host, _, err := splitHostPort(serverAddr)
	if err != nil {
		return ""
	}
	return host
}

func orDef(s, def string) string {
	if s == "" {
		return def
	}
	return s
}

func httpStatusText(code int) string {
	return fmt.Sprintf("Status %d", code)
}

// splitHostPort avoids importing net in this package for one call.
func splitHostPort(hostport string) (string, string, error) {
	i := strings.LastIndexByte(hostport, ':')
	if i < 0 {
		return hostport, "", nil
	}
	return hostport[:i], hostport[i+1:], nil
}

// StartedNow is a helper for tests.
func StartedNow() time.Time { return time.Now() }
