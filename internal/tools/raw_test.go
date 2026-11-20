package tools

import (
	"strings"
	"testing"
)

func TestParseRawOriginForm(t *testing.T) {
	raw := "POST /api/login?next=/ HTTP/1.1\r\nHost: api.example.test:8443\r\nContent-Type: application/json\r\nX-Scheme: https\r\n\r\n{\"u\":\"a\"}"
	req, err := ParseRawRequest(raw)
	if err != nil {
		t.Fatal(err)
	}
	if req.Method != "POST" || req.Path != "/api/login?next=/" || req.HTTPVersion != "HTTP/1.1" {
		t.Errorf("line: %+v", req)
	}
	if req.Host != "api.example.test" || req.Port != 8443 {
		t.Errorf("host: %+v", req)
	}
	if req.Scheme != "https" {
		t.Errorf("scheme hint ignored: %q", req.Scheme)
	}
	if string(req.Body) != `{"u":"a"}` {
		t.Errorf("body: %q", req.Body)
	}
	if v, _ := req.Headers.Get("Content-Length"); v != "9" {
		t.Errorf("content-length normalized to %q", v)
	}
}

func TestParseRawAbsoluteForm(t *testing.T) {
	raw := "GET https://other.example/x HTTP/1.1\nAccept: */*\n"
	req, err := ParseRawRequest(raw)
	if err != nil {
		t.Fatal(err)
	}
	if req.Host != "other.example" || req.Scheme != "https" || req.Path != "/x" || req.Port != 443 {
		t.Fatalf("absolute form: %+v", req)
	}
}

func TestParseRawErrors(t *testing.T) {
	for _, raw := range []string{
		"",
		"GARBAGE\nHost: x\n",
		"GET / HTTP/1.1\n", // no host
	} {
		if _, err := ParseRawRequest(raw); err == nil {
			t.Errorf("expected error for %q", raw)
		}
	}
	if _, err := ParseRawRequest("GET /x HTTP/1.1\nHost: a\nHost: b\n\n"); err != nil {
		t.Errorf("duplicate host should not error: %v", err)
	}
	// unknown HTTP/x version parses (forwarded verbatim); only non-HTTP/
	// prefixes are rejected
	if _, err := ParseRawRequest("GET / FTP/1.0\nHost: a\n"); err == nil {
		t.Error("non-HTTP protocol accepted")
	}
}

func TestRawRoundTrip(t *testing.T) {
	raw := "PUT /thing HTTP/1.1\nHost: roundtrip.example\nX-Multi: a\nX-Multi: b\n\nline1\nline2"
	req, err := ParseRawRequest(raw)
	if err != nil {
		t.Fatal(err)
	}
	out := RenderRaw(req)
	// reparse the render: semantics must survive
	req2, err := ParseRawRequest(out)
	if err != nil {
		t.Fatalf("reparse: %v\n%s", err, out)
	}
	if req2.Method != req.Method || req2.Host != req.Host || req2.Path != req.Path {
		t.Errorf("semantics lost:\n%+v\n%+v", req, req2)
	}
	if string(req2.Body) != string(req.Body) {
		t.Errorf("body lost: %q vs %q", req2.Body, req.Body)
	}
	a, _ := req.Headers.Get("X-Multi")
	if a != "a" {
		t.Errorf("multi header lost")
	}
	if !strings.Contains(out, "line1") {
		t.Errorf("render dropped body: %s", out)
	}
}

func TestParseRawEmptyBody(t *testing.T) {
	req, err := ParseRawRequest("GET / HTTP/1.1\nHost: x.example\n")
	if err != nil {
		t.Fatal(err)
	}
	if len(req.Body) != 0 {
		t.Errorf("body = %q", req.Body)
	}
	if _, ok := req.Headers.Get("Content-Length"); ok {
		t.Error("no Content-Length without a body")
	}
}
