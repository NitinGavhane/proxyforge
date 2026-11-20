package flows

import (
	"bytes"
	"net/http"
	"strings"
	"testing"
)

func TestHeadersGetSetDel(t *testing.T) {
	h := Headers{}
	h.Add("Set-Cookie", "a=1")
	h.Add("Set-Cookie", "b=2")
	h.Set("Host", "example.test")

	if v, ok := h.Get("set-cookie"); !ok || v != "a=1" {
		t.Fatalf("Get case-insensitive = %q,%v", v, ok)
	}
	if v, _ := h.Get("host"); v != "example.test" {
		t.Fatalf("Get host = %q", v)
	}
	h.Del("SET-COOKIE")
	if _, ok := h.Get("set-cookie"); ok {
		t.Fatal("Del did not remove all case variants")
	}
	if len(h) != 1 {
		t.Fatalf("after del len = %d, want 1", len(h))
	}
}

func TestRequestURLAndHostPort(t *testing.T) {
	r := &Request{Scheme: "http", Host: "example.test", Port: 80, Path: "/a?b=1"}
	if got := r.URL(); got != "http://example.test/a?b=1" {
		t.Fatalf("URL = %q", got)
	}
	if got := r.HostPort(); got != "example.test:80" {
		t.Fatalf("HostPort = %q", got)
	}
	r2 := &Request{Scheme: "https", Host: "example.test", Port: 8443, Path: "/"}
	if got := r2.URL(); got != "https://example.test:8443/" {
		t.Fatalf("URL = %q", got)
	}
	r3 := &Request{Scheme: "https", Host: "example.test"} // implicit port
	if got := r3.HostPort(); got != "example.test:443" {
		t.Fatalf("HostPort default = %q", got)
	}
}

func TestReadBodyTruncation(t *testing.T) {
	big := bytes.Repeat([]byte("x"), MaxBodyBytes+10)
	got, trunc, err := ReadBody(bytes.NewReader(big), MaxBodyBytes)
	if err != nil || !trunc {
		t.Fatalf("trunc=%v err=%v", trunc, err)
	}
	if len(got) != MaxBodyBytes {
		t.Fatalf("len=%d want %d", len(got), MaxBodyBytes)
	}
	small, trunc, err := ReadBody(strings.NewReader("hello"), MaxBodyBytes)
	if err != nil || trunc || string(small) != "hello" {
		t.Fatalf("small body: %q trunc=%v err=%v", small, trunc, err)
	}
}

func TestFromHTTPOrdered(t *testing.T) {
	h := http.Header{}
	h.Add("Z-Last", "1")
	h.Add("A-First", "2")
	h.Add("A-First", "3")
	got := FromHTTP(h)
	if len(got) != 3 {
		t.Fatalf("len=%d", len(got))
	}
	if got[0].Key != "A-First" || got[0].Value != "2" || got[1].Value != "3" {
		t.Fatalf("A-First not first with both values: %+v", got[:2])
	}
	if got[2].Key != "Z-Last" {
		t.Fatalf("Z-Last not last: %+v", got)
	}
}

func TestRenderRequestGolden(t *testing.T) {
	r := &Request{
		Method:      "POST",
		Scheme:      "https",
		Host:        "example.test",
		Port:        443,
		Path:        "/api/login?next=/",
		HTTPVersion: "HTTP/1.1",
		Headers: Headers{
			{"Host", "example.test"},
			{"Content-Type", "application/json"},
			{"X-Multi", "a"},
			{"X-Multi", "b"},
		},
		Body: []byte(`{"user":"admin"}`),
	}
	want := "POST /api/login?next=/ HTTP/1.1\r\n" +
		"Host: example.test\r\n" +
		"Content-Type: application/json\r\n" +
		"X-Multi: a\r\n" +
		"X-Multi: b\r\n" +
		"\r\n" +
		`{"user":"admin"}`
	if got := string(RenderRequest(r)); got != want {
		t.Fatalf("RenderRequest mismatch:\n got: %q\nwant: %q", got, want)
	}
}

func TestRenderResponseGolden(t *testing.T) {
	r := &Response{
		Status:      200,
		StatusText:  "OK",
		HTTPVersion: "HTTP/1.1",
		Headers:     Headers{{"Content-Type", "text/html"}},
		Body:        []byte("<h1>hi</h1>"),
	}
	want := "HTTP/1.1 200 OK\r\nContent-Type: text/html\r\n\r\n<h1>hi</h1>"
	if got := string(RenderResponse(r)); got != want {
		t.Fatalf("RenderResponse mismatch:\n got: %q\nwant: %q", got, want)
	}
}

func TestRenderDefaults(t *testing.T) {
	r := &Request{Method: "GET", Path: "/"}
	got := string(RenderRequest(r))
	if !strings.HasPrefix(got, "GET / HTTP/1.1\r\n") {
		t.Fatalf("version default missing: %q", got)
	}
	resp := &Response{Status: 404}
	if !strings.Contains(string(RenderResponse(resp)), "404 Not Found") {
		t.Fatalf("status text default missing: %q", RenderResponse(resp))
	}
}
