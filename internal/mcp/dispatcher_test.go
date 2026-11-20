package mcp

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/NitinGavhane/proxyforge/internal/flows"
	"github.com/NitinGavhane/proxyforge/internal/intercept"
	"github.com/NitinGavhane/proxyforge/internal/matchreplace"
	"github.com/NitinGavhane/proxyforge/internal/pipeline"
	"github.com/NitinGavhane/proxyforge/internal/proxy"
	"github.com/NitinGavhane/proxyforge/internal/scope"
	"github.com/NitinGavhane/proxyforge/internal/store"
	"github.com/NitinGavhane/proxyforge/internal/tools"
)

func newBackend(t *testing.T) (*Backend, *store.Store) {
	t.Helper()
	st, err := store.Open(filepath.Join(t.TempDir(), "mcp.pf.sqlite"))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { st.Close() })
	bus := flows.NewBus()
	sc, _ := scope.New(st, bus)
	icept, err := intercept.New(st, bus)
	if err != nil {
		t.Fatal(err)
	}
	mr, _ := matchreplace.New(st, bus)
	eng := &proxy.Engine{Pipeline: pipeline.New(st, bus, nil), Scope: sc}
	up := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Write([]byte(`{"ok":true,"note":"db-prod-01"}`))
	}))
	t.Cleanup(up.Close)
	b := &Backend{
		Store: st, Intercept: icept, Scope: sc, MatchRep: mr,
		Repeater: tools.NewRepeater(st, eng),
		Intruder: tools.NewIntruder(eng),
		Scanner:  tools.NewScanner(st, eng),
		Version:  "test",
	}
	// seed two captured flows + scope
	f1 := &flows.Flow{
		Started: time.Now(), Origin: flows.OriginProxy,
		Request:  &flows.Request{Method: "POST", Scheme: "http", Host: "api.example.test", Port: 80, Path: "/login?x=1", Body: []byte(`{"user":"admin"}`)},
		Response: &flows.Response{Status: 200, Body: []byte(`{"token":"abc"}`)},
	}
	f2 := &flows.Flow{
		Started: time.Now(), Origin: flows.OriginProxy,
		Request:  &flows.Request{Method: "GET", Scheme: "http", Host: "api.example.test", Port: 80, Path: "/users/42"},
		Response: &flows.Response{Status: 200, Body: []byte(`{"id":42,"email":"user@example.test"}`)},
	}
	for _, f := range []*flows.Flow{f1, f2} {
		if err := st.InsertFlow(context.Background(), f); err != nil {
			t.Fatal(err)
		}
	}
	b.Scope.Add(scope.KindInclude, `^http://127[.]0[.]0[.]1`, true)
	b.upstreamURL = up.URL
	return b, st
}

func call(t *testing.T, b *Backend, method string, params any) Response {
	t.Helper()
	raw, _ := json.Marshal(params)
	req := Request{JSONRPC: "2.0", ID: json.RawMessage("1"), Method: method, Params: raw}
	return b.Dispatch(context.Background(), req)
}

func resultJSON(t *testing.T, resp Response) map[string]any {
	t.Helper()
	if resp.Error != nil {
		t.Fatalf("rpc error: %s", resp.Error.Message)
	}
	var m map[string]any
	if err := json.Unmarshal(resp.Result, &m); err != nil {
		t.Fatalf("result not object: %v", err)
	}
	return m
}

func TestInitializeHandshake(t *testing.T) {
	b, _ := newBackend(t)
	resp := call(t, b, "initialize", map[string]any{
		"params": map[string]any{"protocolVersion": "2025-06-18", "capabilities": map[string]any{}},
	})
	res := resultJSON(t, resp)
	if res["serverInfo"].(map[string]any)["name"] != "proxyforge" {
		t.Fatalf("serverInfo: %+v", res)
	}
	if res["capabilities"].(map[string]any)["tools"] == nil {
		t.Fatal("tools capability missing")
	}
	// ping
	resp = call(t, b, "ping", map[string]any{})
	resultJSON(t, resp)
	// unknown method
	req := Request{JSONRPC: "2.0", ID: json.RawMessage("9"), Method: "bogus"}
	r := b.Dispatch(context.Background(), req)
	if r.Error == nil || r.Error.Code != CodeMethodNotFound {
		t.Fatal("unknown method not rejected")
	}
}

func TestToolsListCatalog(t *testing.T) {
	b, _ := newBackend(t)
	resp := call(t, b, "tools/list", map[string]any{})
	res := resultJSON(t, resp)
	toolsList := res["tools"].([]any)
	names := map[string]bool{}
	for _, tl := range toolsList {
		names[tl.(map[string]any)["name"].(string)] = true
	}
	for _, want := range []string{
		"proxy_status", "list_history", "get_request", "search_traffic",
		"intercept_enable", "list_intercepted", "intercept_forward", "intercept_drop",
		"repeater_send", "repeater_history", "intruder_start", "intruder_stop", "intruder_results",
		"scanner_start", "list_issues", "get_issue", "scope_get", "scope_set",
		"match_replace_add", "match_replace_list", "match_replace_remove",
		"decode", "compare", "jwt_inspect", "sitemap_get", "export_report",
	} {
		if !names[want] {
			t.Errorf("tool missing: %s", want)
		}
	}
}

func TestHistoryAndSearchWithProvenance(t *testing.T) {
	b, _ := newBackend(t)
	resp := call(t, b, "tools/call", map[string]any{
		"name": "search_traffic", "arguments": map[string]any{"query": "login"},
	})
	res := resultJSON(t, resp)
	content := res["content"].([]any)[0].(map[string]any)
	text := content["text"].(string)
	if !strings.Contains(text, "/login") {
		t.Fatalf("search missed the login flow: %.200s", text)
	}
	var payload struct {
		Meta struct {
			UntrustedContent bool   `json:"untrusted_content"`
			Source           string `json:"source"`
		} `json:"_meta"`
		Data struct {
			Matches []map[string]any `json:"matches"`
		} `json:"data"`
	}
	if err := json.Unmarshal([]byte(text), &payload); err != nil {
		t.Fatalf("content not an envelope: %v", err)
	}
	if !payload.Meta.UntrustedContent {
		t.Fatal("captured content must carry untrusted_content provenance")
	}
	if payload.Meta.Source != "captured_traffic" {
		t.Fatalf("source = %q", payload.Meta.Source)
	}
	if len(payload.Data.Matches) == 0 {
		t.Fatal("no matches in data")
	}
}

func TestGetRequestReturnsBodies(t *testing.T) {
	b, _ := newBackend(t)
	resp := call(t, b, "tools/call", map[string]any{
		"name": "get_request", "arguments": map[string]any{"id": 1},
	})
	res := resultJSON(t, resp)
	text := res["content"].([]any)[0].(map[string]any)["text"].(string)
	var payload struct {
		Data struct {
			RequestBodyB64 string `json:"request_body_b64"`
			Response       struct {
				BodyB64 string `json:"body_b64"`
			} `json:"response"`
		} `json:"data"`
	}
	json.Unmarshal([]byte(text), &payload)
	if payload.Data.RequestBodyB64 == "" || payload.Data.Response.BodyB64 == "" {
		t.Fatalf("bodies missing: %s", text[:200])
	}
	if !strings.Contains(string(decodeB64(payload.Data.Response.BodyB64)), "token") {
		t.Error("response body not decodable")
	}
}

func decodeB64(s string) []byte {
	b, _ := base64.StdEncoding.DecodeString(s)
	return b
}

func TestInterceptFlowViaMCP(t *testing.T) {
	b, st := newBackend(t)
	// enable
	resp := call(t, b, "tools/call", map[string]any{
		"name": "intercept_enable", "arguments": map[string]any{"enabled": true},
	})
	resultJSON(t, resp)
	if !b.Intercept.Enabled() {
		t.Fatal("intercept not enabled")
	}
	// park a flow through the manager directly (engine path covered elsewhere)
	parked := &flows.Flow{Request: &flows.Request{Method: "GET", Scheme: "http", Host: "x", Port: 80, Path: "/p"}}
	done := make(chan bool, 1)
	go func() { done <- b.Intercept.Park(parked, false) }()
	deadline := time.Now().Add(2 * time.Second)
	for b.Intercept.PendingLen() == 0 && time.Now().Before(deadline) {
		time.Sleep(10 * time.Millisecond)
	}
	// list + forward with edit
	resp = call(t, b, "tools/call", map[string]any{
		"name": "list_intercepted", "arguments": map[string]any{},
	})
	res := resultJSON(t, resp)
	text := res["content"].([]any)[0].(map[string]any)["text"].(string)
	var lv struct {
		Data struct {
			Pending []struct {
				ID int64 `json:"id"`
			} `json:"pending"`
		} `json:"data"`
	}
	json.Unmarshal([]byte(text), &lv)
	if len(lv.Data.Pending) != 1 {
		t.Fatal("pending not listed")
	}
	id := lv.Data.Pending[0].ID
	resp = call(t, b, "tools/call", map[string]any{
		"name": "intercept_forward", "arguments": map[string]any{"id": id, "path": "/edited"},
	})
	resultJSON(t, resp)
	if !<-done {
		t.Fatal("park returned drop")
	}
	if parked.Request.Path != "/edited" {
		t.Fatalf("edit not applied: %q", parked.Request.Path)
	}
	// audited as mcp actor
	audit, _ := st.AuditJSONL(context.Background())
	if !strings.Contains(audit, `"actor":"mcp"`) {
		t.Fatal("mcp actions not audited")
	}
}

func TestRepeaterSendViaMCP(t *testing.T) {
	b, _ := newBackend(t)
	resp := call(t, b, "tools/call", map[string]any{
		"name": "repeater_send",
		"arguments": map[string]any{
			"raw": "GET /probe HTTP/1.1\nHost: " + strings.TrimPrefix(b.upstreamURL, "http://") + "\n",
		},
	})
	res := resultJSON(t, resp)
	if res["isError"] == true {
		t.Fatalf("send failed: %+v", res)
	}
	text := res["content"].([]any)[0].(map[string]any)["text"].(string)
	var payload struct {
		Data struct {
			Status int `json:"status"`
		} `json:"data"`
	}
	json.Unmarshal([]byte(text), &payload)
	if payload.Data.Status != 200 {
		t.Fatalf("status = %d (text %.200s)", payload.Data.Status, text)
	}
}

func TestIntruderRequiresAuthorization(t *testing.T) {
	b, _ := newBackend(t)
	resp := call(t, b, "tools/call", map[string]any{
		"name": "intruder_start",
		"arguments": map[string]any{
			"attack_type": "sniper",
			"raw":         "GET /§n§ HTTP/1.1\nHost: 127.0.0.1\n",
		},
	})
	res := resultJSON(t, resp)
	if res["isError"] != true {
		t.Fatal("unauthorized intruder start accepted")
	}
	text := res["content"].([]any)[0].(map[string]any)["text"].(string)
	if !strings.Contains(text, "authorized=true") {
		t.Fatalf("wrong error: %s", text)
	}
}

func TestScopeAndMatchReplaceViaMCP(t *testing.T) {
	b, _ := newBackend(t)
	resp := call(t, b, "tools/call", map[string]any{
		"name": "scope_set", "arguments": map[string]any{
			"action": "add", "kind": "include", "pattern": `^https://api\.example\.com`,
		},
	})
	resultJSON(t, resp)
	resp = call(t, b, "tools/call", map[string]any{"name": "scope_get", "arguments": map[string]any{}})
	res := resultJSON(t, resp)
	text := res["content"].([]any)[0].(map[string]any)["text"].(string)
	// the pattern's dots are regex-escaped in the JSON text
	if !strings.Contains(text, "api") || !strings.Contains(text, "example") || !strings.Contains(text, "include") {
		t.Fatalf("scope_get: %s", text)
	}
	// match_replace add + list
	call(t, b, "tools/call", map[string]any{
		"name": "match_replace_add", "arguments": map[string]any{
			"name": "tag", "direction": "request",
			"action": map[string]any{"type": "header_add", "header_key": "X-MCP", "header_value": "1"},
		},
	})
	resp = call(t, b, "tools/call", map[string]any{"name": "match_replace_list", "arguments": map[string]any{}})
	res = resultJSON(t, resp)
	text = res["content"].([]any)[0].(map[string]any)["text"].(string)
	if !strings.Contains(text, "tag") {
		t.Fatalf("match_replace_list: %s", text)
	}
}

func TestDecodeCompareJWT(t *testing.T) {
	b, _ := newBackend(t)
	resp := call(t, b, "tools/call", map[string]any{
		"name": "decode", "arguments": map[string]any{"input": "Zm9vYmFy", "format": "base64"},
	})
	res := resultJSON(t, resp)
	if !strings.Contains(res["content"].([]any)[0].(map[string]any)["text"].(string), "foobar") {
		t.Fatal("decode broken")
	}
	resp = call(t, b, "tools/call", map[string]any{
		"name": "compare", "arguments": map[string]any{"a": "x y", "b": "x z"},
	})
	resultJSON(t, resp)
	resp = call(t, b, "tools/call", map[string]any{
		"name":      "jwt_inspect",
		"arguments": map[string]any{"token": "eyJhbGciOiJub25lIn0.eyJzdWIiOiJhZG1pbiJ9."},
	})
	res = resultJSON(t, resp)
	if !strings.Contains(res["content"].([]any)[0].(map[string]any)["text"].(string), "admin") {
		t.Fatal("jwt_inspect broken")
	}
}

func TestResourcesAndPrompts(t *testing.T) {
	b, _ := newBackend(t)
	resp := call(t, b, "resources/list", map[string]any{})
	res := resultJSON(t, resp)
	if len(res["resources"].([]any)) != 3 {
		t.Fatalf("resources: %+v", res)
	}
	resp = call(t, b, "resources/read", map[string]any{"uri": "proxyforge://history"})
	res = resultJSON(t, resp)
	text := res["contents"].([]any)[0].(map[string]any)["text"].(string)
	if !strings.Contains(text, "untrusted_content") {
		t.Fatal("history resource lacks provenance marker")
	}
	resp = call(t, b, "prompts/list", map[string]any{})
	res = resultJSON(t, resp)
	if len(res["prompts"].([]any)) != 3 {
		t.Fatalf("prompts: %+v", res)
	}
	for _, p := range []string{"analyze-auth-flow", "find-idor-candidates", "summarize-attack-surface"} {
		resp = call(t, b, "prompts/get", map[string]any{"name": p})
		res = resultJSON(t, resp)
		msgs := res["messages"].([]any)
		if len(msgs) == 0 {
			t.Fatalf("prompt %s empty", p)
		}
	}
	// unknown
	resp = call(t, b, "prompts/get", map[string]any{"name": "nope"})
	if resp.Error == nil {
		t.Fatal("unknown prompt accepted")
	}
}
