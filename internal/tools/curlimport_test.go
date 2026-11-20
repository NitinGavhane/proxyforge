package tools

import (
	"strings"
	"testing"
)

func TestParseCURLSimple(t *testing.T) {
	raw, err := ParseCURL(`curl https://api.example.com/v1/users?x=1`)
	if err != nil {
		t.Fatal(err)
	}
	req, err := ParseRawRequest(raw)
	if err != nil {
		t.Fatalf("reparse: %v\n%s", err, raw)
	}
	if req.Method != "GET" || req.Host != "api.example.com" || req.Path != "/v1/users?x=1" || req.Scheme != "https" {
		t.Fatalf("req: %+v (raw %q)", req, raw)
	}
}

func TestParseCURLFull(t *testing.T) {
	raw, err := ParseCURL(`curl -X POST 'https://api.example.com/login' ` +
		`-H 'Content-Type: application/json' ` +
		`-H 'Authorization: Bearer tok' ` +
		`-d '{"user":"a","pass":"b"}' -k --compressed`)
	if err != nil {
		t.Fatal(err)
	}
	req, err := ParseRawRequest(raw)
	if err != nil {
		t.Fatalf("reparse: %v\n%s", err, raw)
	}
	if req.Method != "POST" || req.Path != "/login" {
		t.Fatalf("req: %+v", req)
	}
	if v, _ := req.Headers.Get("Authorization"); v != "Bearer tok" {
		t.Errorf("auth header: %q", v)
	}
	if v, _ := req.Headers.Get("Content-Type"); v != "application/json" {
		t.Errorf("content-type: %q", v)
	}
	if string(req.Body) != `{"user":"a","pass":"b"}` {
		t.Errorf("body: %q", req.Body)
	}
}

func TestParseCURLUserAndFormData(t *testing.T) {
	raw, err := ParseCURL(`curl http://example.com/x -u admin:secret -d a=1 -d b=2`)
	if err != nil {
		t.Fatal(err)
	}
	req, _ := ParseRawRequest(raw)
	if req.Method != "POST" {
		t.Fatalf("method = %s", req.Method)
	}
	auth, _ := req.Headers.Get("Authorization")
	if !strings.HasPrefix(auth, "Basic ") {
		t.Fatalf("auth = %q", auth)
	}
	if v, _ := req.Headers.Get("Content-Type"); v != "application/x-www-form-urlencoded" {
		t.Errorf("implicit content-type missing: %q", v)
	}
	if string(req.Body) != "a=1&b=2" {
		t.Errorf("body: %q", req.Body)
	}
}

func TestParseCURLQuoteVariants(t *testing.T) {
	// double quotes and $'...' with newline
	raw, err := ParseCURL(`curl "http://h.example/a b" -H $'X-Note: line1\nline2'`)
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(raw, "/a%20b") && !strings.Contains(raw, "/a b") {
		t.Logf("url handling: %q", raw)
	}
	if !strings.Contains(raw, "X-Note: line1\nline2") && !strings.Contains(raw, "line1\\nline2") {
		t.Errorf("$'…' newline not handled: %q", raw)
	}
}

func TestParseCURRErrors(t *testing.T) {
	if _, err := ParseCURL("curl"); err == nil {
		t.Error("empty accepted")
	}
	if _, err := ParseCURL("curl -X"); err == nil {
		t.Error("missing value accepted")
	}
	if _, err := ParseCURL("curl notaurl"); err == nil {
		t.Error("bad url accepted")
	}
}

const openAPIDoc = `openapi: 3.0.0
servers:
  - url: https://api.example.com/v2
paths:
  /users:
    get:
      summary: list
    post:
      summary: create
  /users/{id}:
    delete: {}
    parameters: []
`

func TestParseOpenAPI(t *testing.T) {
	eps, err := ParseOpenAPI(openAPIDoc)
	if err != nil {
		t.Fatal(err)
	}
	byMP := map[string]bool{}
	for _, e := range eps {
		if e.Host != "api.example.com" || e.Scheme != "https" || e.Port != 443 {
			t.Fatalf("endpoint: %+v", e)
		}
		byMP[e.Method+" "+e.Path] = true
	}
	for _, want := range []string{"GET /users", "POST /users", "DELETE /users/{id}"} {
		if !byMP[want] {
			t.Errorf("missing %s (have %v)", want, byMP)
		}
	}
	if len(eps) != 3 {
		t.Fatalf("count = %d", len(eps))
	}

	// JSON variant with relative server
	jsonDoc := `{"openapi":"3.0.0","servers":[{"url":"/api"}],"paths":{"/health":{"get":{}}}}`
	eps, err = ParseOpenAPI(jsonDoc)
	if err != nil {
		t.Fatal(err)
	}
	if eps[0].Host != "spec-host" || eps[0].Path != "/health" {
		t.Fatalf("json: %+v", eps[0])
	}

	if _, err := ParseOpenAPI(`{"no":"paths"}`); err == nil {
		t.Error("pathless doc accepted")
	}
	if _, err := ParseOpenAPI(`not [valid`); err == nil {
		t.Error("garbage accepted")
	}
}

const postmanDoc = `{
  "info": {"name": "demo"},
  "variable": [{"key": "base", "value": "https://api.example.com"}],
  "item": [
    {"name": "login", "request": {"method": "POST", "url": {"raw": "{{base}}/login?x=1"}}},
    {"name": "folder", "item": [
      {"name": "list", "request": {"method": "GET", "url": {"raw": "{{base}}/items"}}},
      {"name": "plain", "request": {"method": "GET", "url": "http://other.example/p"}}
    ]}
  ]
}`

func TestParsePostman(t *testing.T) {
	eps, err := ParsePostman(postmanDoc)
	if err != nil {
		t.Fatal(err)
	}
	if len(eps) != 3 {
		t.Fatalf("count = %d: %+v", len(eps), eps)
	}
	found := map[string]bool{}
	for _, e := range eps {
		found[e.Method+" "+e.Host+e.Path] = true
	}
	if !found["POST api.example.com/login?x=1"] {
		t.Errorf("login missing: %+v", eps)
	}
	if !found["GET api.example.com/items"] {
		t.Errorf("nested item missing: %+v", eps)
	}
	if !found["GET other.example/p"] {
		t.Errorf("plain url missing: %+v", eps)
	}
	if _, err := ParsePostman(`{"info":{}}`); err == nil {
		t.Error("empty collection accepted")
	}
}
