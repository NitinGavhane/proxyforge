package api

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/coder/websocket"

	"github.com/NitinGavhane/proxyforge/internal/flows"
	"github.com/NitinGavhane/proxyforge/internal/intercept"
	"github.com/NitinGavhane/proxyforge/internal/matchreplace"
	"github.com/NitinGavhane/proxyforge/internal/scope"
	"github.com/NitinGavhane/proxyforge/internal/store"
)

func newTestServer(t *testing.T) (*httptest.Server, *store.Store, *flows.Bus) {
	t.Helper()
	st, err := store.Open(filepath.Join(t.TempDir(), "api.pf.sqlite"))
	if err != nil {
		t.Fatalf("store: %v", err)
	}
	t.Cleanup(func() { st.Close() })
	bus := flows.NewBus()
	s := &Server{Store: st, Bus: bus, Token: "testtoken123", Started: time.Now()}
	srv := httptest.NewServer(s.Handler())
	t.Cleanup(srv.Close)
	return srv, st, bus
}

func bearer(req *http.Request, token string) *http.Request {
	req.Header.Set("Authorization", "Bearer "+token)
	return req
}

func insertSampleFlow(t *testing.T, st *store.Store) *flows.Flow {
	t.Helper()
	f := &flows.Flow{
		Started:  time.Now(),
		Finished: time.Now(),
		Origin:   flows.OriginProxy,
		InScope:  true,
		Request: &flows.Request{
			Method: "GET", Scheme: "http", Host: "example.test", Port: 80,
			Path: "/a?b=1", HTTPVersion: "HTTP/1.1",
			Headers: flows.Headers{{Key: "Host", Value: "example.test"}},
			Body:    []byte("reqbody"),
		},
		Response: &flows.Response{
			Status: 200, StatusText: "OK", HTTPVersion: "HTTP/1.1",
			Headers: flows.Headers{{Key: "Content-Type", Value: "text/plain"}},
			Body:    []byte("respbody"),
		},
	}
	if err := st.InsertFlow(context.Background(), f); err != nil {
		t.Fatalf("insert: %v", err)
	}
	return f
}

func TestAuthRequired(t *testing.T) {
	srv, _, _ := newTestServer(t)
	for _, path := range []string{"/api/v1/status", "/api/v1/flows", "/api/v1/audit.jsonl"} {
		resp, err := http.Get(srv.URL + path)
		if err != nil {
			t.Fatalf("get %s: %v", path, err)
		}
		resp.Body.Close()
		if resp.StatusCode != http.StatusUnauthorized {
			t.Errorf("%s: status = %d, want 401", path, resp.StatusCode)
		}
	}
	// The UI shell loads without a token (it renders the token gate); every
	// /api route above stays protected.
	resp, _ := http.Get(srv.URL + "/")
	resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		t.Errorf("/ status = %d, want 200 (shell must load for the token gate)", resp.StatusCode)
	}
}

func TestWrongTokenRejected(t *testing.T) {
	srv, _, _ := newTestServer(t)
	req, _ := http.NewRequest("GET", srv.URL+"/api/v1/status", nil)
	bearer(req, "wrong")
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	resp.Body.Close()
	if resp.StatusCode != http.StatusUnauthorized {
		t.Fatalf("status = %d", resp.StatusCode)
	}
}

func TestStatusWithBearer(t *testing.T) {
	srv, st, _ := newTestServer(t)
	insertSampleFlow(t, st)
	req, _ := http.NewRequest("GET", srv.URL+"/api/v1/status", nil)
	resp, err := http.DefaultClient.Do(bearer(req, "testtoken123"))
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	var out map[string]any
	if err := json.NewDecoder(resp.Body).Decode(&out); err != nil {
		t.Fatal(err)
	}
	if out["flows"].(float64) != 1 {
		t.Errorf("flows = %v", out["flows"])
	}
}

func TestAuthEndpointSetsCookie(t *testing.T) {
	srv, _, _ := newTestServer(t)
	resp, err := http.Post(srv.URL+"/api/v1/auth", "application/json",
		strings.NewReader(`{"token":"testtoken123"}`))
	if err != nil {
		t.Fatal(err)
	}
	resp.Body.Close()
	if resp.StatusCode != 200 {
		t.Fatalf("status = %d", resp.StatusCode)
	}
	found := false
	for _, c := range resp.Cookies() {
		if c.Name == SessionCookie && c.Value == "testtoken123" && c.SameSite == http.SameSiteStrictMode {
			found = true
		}
	}
	if !found {
		t.Fatal("session cookie not set correctly")
	}
	// wrong token
	resp2, _ := http.Post(srv.URL+"/api/v1/auth", "application/json",
		strings.NewReader(`{"token":"nope"}`))
	resp2.Body.Close()
	if resp2.StatusCode != http.StatusUnauthorized {
		t.Fatalf("wrong token status = %d", resp2.StatusCode)
	}
}

func TestListAndGetFlows(t *testing.T) {
	srv, st, _ := newTestServer(t)
	f := insertSampleFlow(t, st)

	req, _ := http.NewRequest("GET", srv.URL+"/api/v1/flows?q=example", nil)
	resp, err := http.DefaultClient.Do(bearer(req, "testtoken123"))
	if err != nil {
		t.Fatal(err)
	}
	var list struct{ Flows []store.FlowRow }
	json.NewDecoder(resp.Body).Decode(&list)
	resp.Body.Close()
	if len(list.Flows) != 1 || list.Flows[0].ID != f.ID {
		t.Fatalf("list = %+v", list)
	}

	req2, _ := http.NewRequest("GET", fmt.Sprintf("%s/api/v1/flows/%d", srv.URL, f.ID), nil)
	resp2, err := http.DefaultClient.Do(bearer(req2, "testtoken123"))
	if err != nil {
		t.Fatal(err)
	}
	defer resp2.Body.Close()
	var got map[string]any
	json.NewDecoder(resp2.Body).Decode(&got)
	if got["req_body_b64"] != "cmVxYm9keQ==" {
		t.Errorf("req_body_b64 = %v", got["req_body_b64"])
	}
	req3, _ := http.NewRequest("GET", srv.URL+"/api/v1/flows/999", nil)
	resp3, _ := http.DefaultClient.Do(bearer(req3, "testtoken123"))
	resp3.Body.Close()
	if resp3.StatusCode != http.StatusNotFound {
		t.Errorf("missing flow status = %d", resp3.StatusCode)
	}
}

func TestListWSMessagesEndpoint(t *testing.T) {
	srv, st, _ := newTestServer(t)
	// build a ws flow with two frames
	f := &flows.Flow{
		Started: time.Now(), Origin: flows.OriginProxy, InScope: true,
		Request: &flows.Request{
			Method: "GET", Scheme: "ws", Host: "ws.example", Port: 80,
			Path: "/chat", HTTPVersion: "HTTP/1.1",
		},
		Response: &flows.Response{Status: 101, HTTPVersion: "HTTP/1.1"},
	}
	if err := st.InsertFlow(context.Background(), f); err != nil {
		t.Fatal(err)
	}
	for _, m := range []*flows.WSMessage{
		{FlowID: f.ID, TS: time.Now().UnixMilli(), Direction: "c2s", Opcode: 1, FIN: true, Size: 5, Payload: []byte("hello")},
		{FlowID: f.ID, TS: time.Now().UnixMilli(), Direction: "s2c", Opcode: 1, FIN: true, Size: 5, Payload: []byte("world")},
	} {
		if err := st.InsertWSMessage(context.Background(), m); err != nil {
			t.Fatal(err)
		}
	}
	if err := st.UpdateFlowWSClose(context.Background(), f.ID, time.Now().UnixMilli(), 42, 2); err != nil {
		t.Fatal(err)
	}

	req, _ := http.NewRequest("GET", fmt.Sprintf("%s/api/v1/flows/%d/ws", srv.URL, f.ID), nil)
	resp, err := http.DefaultClient.Do(bearer(req, "testtoken123"))
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	if resp.Header.Get("X-Untrusted-Content") != "captured" {
		t.Errorf("missing untrusted-content marker")
	}
	var out struct {
		Messages []store.WSMessageRow `json:"messages"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&out); err != nil {
		t.Fatal(err)
	}
	if len(out.Messages) != 2 {
		t.Fatalf("messages = %d", len(out.Messages))
	}
	if out.Messages[0].Direction != "c2s" || out.Messages[0].OpcodeName != "text" {
		t.Errorf("msg0 = %+v", out.Messages[0])
	}
	if out.Messages[1].Opcode != 1 || out.Messages[1].Size != 5 {
		t.Errorf("msg1 = %+v", out.Messages[1])
	}

	// flow json now carries ws_count
	req2, _ := http.NewRequest("GET", fmt.Sprintf("%s/api/v1/flows/%d", srv.URL, f.ID), nil)
	resp2, err := http.DefaultClient.Do(bearer(req2, "testtoken123"))
	if err != nil {
		t.Fatal(err)
	}
	defer resp2.Body.Close()
	var fjson map[string]any
	json.NewDecoder(resp2.Body).Decode(&fjson)
	if fjson["ws_count"].(float64) != 2 {
		t.Errorf("ws_count = %v", fjson["ws_count"])
	}
}

func TestInterceptEndpoints(t *testing.T) {
	st, err := store.Open(filepath.Join(t.TempDir(), "icept.pf.sqlite"))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { st.Close() })
	bus := flows.NewBus()
	mgr, err := intercept.New(st, bus)
	if err != nil {
		t.Fatal(err)
	}
	s := &Server{Store: st, Bus: bus, Token: "testtoken123", Started: time.Now(), Intercept: mgr}
	srv := httptest.NewServer(s.Handler())
	t.Cleanup(srv.Close)

	// overview: disabled by default
	req, _ := http.NewRequest("GET", srv.URL+"/api/v1/intercept", nil)
	resp, err := http.DefaultClient.Do(bearer(req, "testtoken123"))
	if err != nil {
		t.Fatal(err)
	}
	var ov struct {
		Enabled bool            `json:"enabled"`
		Rules   json.RawMessage `json:"rules"`
		Pending json.RawMessage `json:"pending"`
	}
	json.NewDecoder(resp.Body).Decode(&ov)
	resp.Body.Close()
	if ov.Enabled {
		t.Fatal("should start disabled")
	}

	// enable via toggle
	req, _ = http.NewRequest("POST", srv.URL+"/api/v1/intercept/toggle",
		strings.NewReader(`{"enabled":true,"intercept_responses":true}`))
	req.Header.Set("Content-Type", "application/json")
	resp, err = http.DefaultClient.Do(bearer(req, "testtoken123"))
	if err != nil {
		t.Fatal(err)
	}
	resp.Body.Close()
	if !mgr.Enabled() || !mgr.InterceptResponses() {
		t.Fatal("toggle did not apply")
	}

	// add a rule
	req, _ = http.NewRequest("POST", srv.URL+"/api/v1/intercept/rules",
		strings.NewReader(`{"name":"logins","enabled":true,"spec":{"method":"POST","url_regex":"/login"}}`))
	req.Header.Set("Content-Type", "application/json")
	resp, err = http.DefaultClient.Do(bearer(req, "testtoken123"))
	if err != nil {
		t.Fatal(err)
	}
	var addOut struct {
		ID    int64                `json:"id"`
		Rules []intercept.RuleView `json:"rules"`
	}
	json.NewDecoder(resp.Body).Decode(&addOut)
	resp.Body.Close()
	if addOut.ID == 0 || len(addOut.Rules) != 1 || addOut.Rules[0].Spec.Method != "POST" {
		t.Fatalf("rule add: %+v", addOut)
	}

	// invalid regex rejected
	req, _ = http.NewRequest("POST", srv.URL+"/api/v1/intercept/rules",
		strings.NewReader(`{"name":"bad","enabled":true,"spec":{"url_regex":"("}}`))
	resp, _ = http.DefaultClient.Do(bearer(req, "testtoken123"))
	resp.Body.Close()
	if resp.StatusCode != http.StatusBadRequest {
		t.Fatalf("bad regex status = %d", resp.StatusCode)
	}

	// forward on unknown id → 404
	req, _ = http.NewRequest("POST", srv.URL+"/api/v1/intercept/999/forward", nil)
	resp, _ = http.DefaultClient.Do(bearer(req, "testtoken123"))
	resp.Body.Close()
	if resp.StatusCode != http.StatusNotFound {
		t.Fatalf("unknown forward status = %d", resp.StatusCode)
	}

	// park a flow via the manager and drive it through the HTTP endpoints
	parked := &flows.Flow{
		Request: &flows.Request{Method: "POST", Scheme: "https", Host: "x.test", Path: "/login"},
	}
	done := make(chan bool, 1)
	go func() { done <- mgr.Park(parked, false) }()
	deadline := time.Now().Add(2 * time.Second)
	for mgr.PendingLen() == 0 && time.Now().Before(deadline) {
		time.Sleep(5 * time.Millisecond)
	}
	if mgr.PendingLen() != 1 {
		t.Fatal("flow did not park")
	}
	pendingID := mgr.Pending()[0].ID
	req, _ = http.NewRequest("POST", fmt.Sprintf("%s/api/v1/intercept/%d/forward", srv.URL, pendingID),
		strings.NewReader(`{"path":"/tampered"}`))
	req.Header.Set("Content-Type", "application/json")
	resp, err = http.DefaultClient.Do(bearer(req, "testtoken123"))
	if err != nil {
		t.Fatal(err)
	}
	resp.Body.Close()
	if resp.StatusCode != 200 {
		t.Fatalf("forward status = %d", resp.StatusCode)
	}
	if !<-done {
		t.Fatal("park returned drop")
	}
	if parked.Request.Path != "/tampered" {
		t.Fatalf("edit not applied: %q", parked.Request.Path)
	}

	// audit captured the actions
	req, _ = http.NewRequest("GET", srv.URL+"/api/v1/audit.jsonl", nil)
	resp, err = http.DefaultClient.Do(bearer(req, "testtoken123"))
	if err != nil {
		t.Fatal(err)
	}
	body, _ := io.ReadAll(resp.Body)
	resp.Body.Close()
	for _, action := range []string{"intercept.toggle", "intercept.rule.add", "intercept.forward"} {
		if !strings.Contains(string(body), action) {
			t.Errorf("audit missing %q", action)
		}
	}

	// delete the rule
	req, _ = http.NewRequest("DELETE", fmt.Sprintf("%s/api/v1/intercept/rules/%d", srv.URL, addOut.ID), nil)
	resp, err = http.DefaultClient.Do(bearer(req, "testtoken123"))
	if err != nil {
		t.Fatal(err)
	}
	resp.Body.Close()
	if len(mgr.RuleList()) != 0 {
		t.Fatal("rule not deleted")
	}
}

func TestMatchReplaceEndpoints(t *testing.T) {
	st, err := store.Open(filepath.Join(t.TempDir(), "mr.pf.sqlite"))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { st.Close() })
	bus := flows.NewBus()
	mgr, err := matchreplace.New(st, bus)
	if err != nil {
		t.Fatal(err)
	}
	s := &Server{Store: st, Bus: bus, Token: "testtoken123", Started: time.Now(), MatchReplace: mgr}
	srv := httptest.NewServer(s.Handler())
	t.Cleanup(srv.Close)

	// empty list
	req, _ := http.NewRequest("GET", srv.URL+"/api/v1/match-replace", nil)
	resp, err := http.DefaultClient.Do(bearer(req, "testtoken123"))
	if err != nil {
		t.Fatal(err)
	}
	var list struct{ Rules []matchreplace.RuleView }
	json.NewDecoder(resp.Body).Decode(&list)
	resp.Body.Close()
	if len(list.Rules) != 0 {
		t.Fatalf("expected empty list, got %+v", list.Rules)
	}

	// add a rule
	req, _ = http.NewRequest("POST", srv.URL+"/api/v1/match-replace",
		strings.NewReader(`{"name":"tag","enabled":true,"direction":"request","spec":{},"action":{"type":"header_add","header_key":"X-Tag","header_value":"pf"}}`))
	req.Header.Set("Content-Type", "application/json")
	resp, err = http.DefaultClient.Do(bearer(req, "testtoken123"))
	if err != nil {
		t.Fatal(err)
	}
	var addOut struct {
		ID    int64                   `json:"id"`
		Rules []matchreplace.RuleView `json:"rules"`
	}
	json.NewDecoder(resp.Body).Decode(&addOut)
	resp.Body.Close()
	if addOut.ID == 0 || len(addOut.Rules) != 1 {
		t.Fatalf("add: %+v", addOut)
	}

	// invalid action rejected
	req, _ = http.NewRequest("POST", srv.URL+"/api/v1/match-replace",
		strings.NewReader(`{"name":"bad","enabled":true,"direction":"request","spec":{},"action":{"type":"nope"}}`))
	resp, _ = http.DefaultClient.Do(bearer(req, "testtoken123"))
	resp.Body.Close()
	if resp.StatusCode != http.StatusBadRequest {
		t.Fatalf("bad action status = %d", resp.StatusCode)
	}

	// apply once, then check hits + recent surfaced via API
	f := &flows.Flow{Request: &flows.Request{
		Method: "GET", Scheme: "http", Host: "h.test", Path: "/p",
		Headers: flows.Headers{},
	}}
	mgr.Apply(f, false)
	if v, _ := f.Request.Headers.Get("X-Tag"); v != "pf" {
		t.Fatalf("rule not applied: %+v", f.Request.Headers)
	}
	req, _ = http.NewRequest("GET", srv.URL+"/api/v1/match-replace", nil)
	resp, _ = http.DefaultClient.Do(bearer(req, "testtoken123"))
	json.NewDecoder(resp.Body).Decode(&list)
	resp.Body.Close()
	if list.Rules[0].Hits != 1 {
		t.Fatalf("hits = %d", list.Rules[0].Hits)
	}
	if len(list.Rules[0].Recent) != 1 || !strings.Contains(list.Rules[0].Recent[0].Where, "h.test") {
		t.Fatalf("recent = %+v", list.Rules[0].Recent)
	}

	// toggle off, delete
	req, _ = http.NewRequest("PATCH", fmt.Sprintf("%s/api/v1/match-replace/%d", srv.URL, addOut.ID),
		strings.NewReader(`{"enabled":false}`))
	req.Header.Set("Content-Type", "application/json")
	resp, _ = http.DefaultClient.Do(bearer(req, "testtoken123"))
	resp.Body.Close()
	req, _ = http.NewRequest("DELETE", fmt.Sprintf("%s/api/v1/match-replace/%d", srv.URL, addOut.ID), nil)
	resp, _ = http.DefaultClient.Do(bearer(req, "testtoken123"))
	resp.Body.Close()
	if len(mgr.List()) != 0 {
		t.Fatal("rule not deleted")
	}

	// audited
	req, _ = http.NewRequest("GET", srv.URL+"/api/v1/audit.jsonl", nil)
	resp, _ = http.DefaultClient.Do(bearer(req, "testtoken123"))
	body, _ := io.ReadAll(resp.Body)
	resp.Body.Close()
	for _, action := range []string{"matchreplace.rule.add", "matchreplace.rule.patch", "matchreplace.rule.delete"} {
		if !strings.Contains(string(body), action) {
			t.Errorf("audit missing %q", action)
		}
	}
}

func TestScopeEndpoints(t *testing.T) {
	st, err := store.Open(filepath.Join(t.TempDir(), "sc.pf.sqlite"))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { st.Close() })
	bus := flows.NewBus()
	sc, err := scope.New(st, bus)
	if err != nil {
		t.Fatal(err)
	}
	s := &Server{Store: st, Bus: bus, Token: "testtoken123", Started: time.Now(), Scope: sc}
	srv := httptest.NewServer(s.Handler())
	t.Cleanup(srv.Close)

	// empty overview
	req, _ := http.NewRequest("GET", srv.URL+"/api/v1/scope", nil)
	resp, err := http.DefaultClient.Do(bearer(req, "testtoken123"))
	if err != nil {
		t.Fatal(err)
	}
	var ov struct {
		Rules           []scope.RuleView `json:"rules"`
		OutOfScopeCount int64            `json:"out_of_scope_count"`
	}
	json.NewDecoder(resp.Body).Decode(&ov)
	resp.Body.Close()
	if len(ov.Rules) != 0 || ov.OutOfScopeCount != 0 {
		t.Fatalf("empty overview: %+v", ov)
	}

	// seed two flows, then add an include rule and preview
	for _, p := range []string{"/in", "/out"} {
		f := &flows.Flow{
			Started: time.Now(), Origin: flows.OriginProxy,
			Request: &flows.Request{Method: "GET", Scheme: "http", Host: "h.example", Path: p},
		}
		if err := st.InsertFlow(context.Background(), f); err != nil {
			t.Fatal(err)
		}
	}
	req, _ = http.NewRequest("POST", srv.URL+"/api/v1/scope",
		strings.NewReader(`{"kind":"include","pattern":"^http://h\\.example/in","enabled":true}`))
	req.Header.Set("Content-Type", "application/json")
	resp, err = http.DefaultClient.Do(bearer(req, "testtoken123"))
	if err != nil {
		t.Fatal(err)
	}
	var addOut struct {
		ID    int64            `json:"id"`
		Rules []scope.RuleView `json:"rules"`
	}
	json.NewDecoder(resp.Body).Decode(&addOut)
	resp.Body.Close()
	if addOut.ID == 0 || len(addOut.Rules) != 1 {
		t.Fatalf("add: %+v", addOut)
	}

	req, _ = http.NewRequest("GET", srv.URL+"/api/v1/scope/preview", nil)
	resp, err = http.DefaultClient.Do(bearer(req, "testtoken123"))
	if err != nil {
		t.Fatal(err)
	}
	var pv struct {
		Preview []scope.PreviewRow `json:"preview"`
	}
	json.NewDecoder(resp.Body).Decode(&pv)
	resp.Body.Close()
	if len(pv.Preview) != 2 {
		t.Fatalf("preview rows = %d", len(pv.Preview))
	}
	// /in in scope, /out not (newest first: /out then /in)
	if pv.Preview[1].InScope != true || pv.Preview[0].InScope != false {
		t.Fatalf("preview verdicts wrong: %+v", pv.Preview)
	}

	// invalid regex rejected
	req, _ = http.NewRequest("POST", srv.URL+"/api/v1/scope",
		strings.NewReader(`{"kind":"include","pattern":"(","enabled":true}`))
	resp, _ = http.DefaultClient.Do(bearer(req, "testtoken123"))
	resp.Body.Close()
	if resp.StatusCode != http.StatusBadRequest {
		t.Fatalf("bad pattern status = %d", resp.StatusCode)
	}

	// toggle + delete audited
	req, _ = http.NewRequest("PATCH", fmt.Sprintf("%s/api/v1/scope/%d", srv.URL, addOut.ID),
		strings.NewReader(`{"enabled":false}`))
	req.Header.Set("Content-Type", "application/json")
	resp, _ = http.DefaultClient.Do(bearer(req, "testtoken123"))
	resp.Body.Close()
	req, _ = http.NewRequest("DELETE", fmt.Sprintf("%s/api/v1/scope/%d", srv.URL, addOut.ID), nil)
	resp, _ = http.DefaultClient.Do(bearer(req, "testtoken123"))
	resp.Body.Close()

	req, _ = http.NewRequest("GET", srv.URL+"/api/v1/audit.jsonl", nil)
	resp, _ = http.DefaultClient.Do(bearer(req, "testtoken123"))
	body, _ := io.ReadAll(resp.Body)
	resp.Body.Close()
	for _, action := range []string{"scope.rule.add", "scope.rule.patch", "scope.rule.delete"} {
		if !strings.Contains(string(body), action) {
			t.Errorf("audit missing %q", action)
		}
	}
}

func TestExportAndDiffEndpoints(t *testing.T) {
	srv, st, _ := newTestServer(t)
	mk := func(id int, path, body string) *flows.Flow {
		return &flows.Flow{
			Started: time.Now(), Origin: flows.OriginProxy,
			Request: &flows.Request{
				Method: "POST", Scheme: "http", Host: "example.test", Port: 80,
				Path: path, HTTPVersion: "HTTP/1.1",
				Headers: flows.Headers{{Key: "Host", Value: "example.test"}},
				Body:    []byte(body),
			},
			Response: &flows.Response{
				Status: 200, StatusText: "OK", HTTPVersion: "HTTP/1.1",
				Headers: flows.Headers{{Key: "Content-Type", Value: "text/plain"}},
				Body:    []byte("resp " + body),
			},
		}
	}
	f1 := mk(1, "/a", `{"role":"user"}`)
	f2 := mk(2, "/b", `{"role":"admin"}`)
	for _, f := range []*flows.Flow{f1, f2} {
		if err := st.InsertFlow(context.Background(), f); err != nil {
			t.Fatal(err)
		}
	}

	// single-flow HAR
	req, _ := http.NewRequest("GET", fmt.Sprintf("%s/api/v1/flows/%d/har", srv.URL, f1.ID), nil)
	resp, err := http.DefaultClient.Do(bearer(req, "testtoken123"))
	if err != nil {
		t.Fatal(err)
	}
	body, _ := io.ReadAll(resp.Body)
	resp.Body.Close()
	if resp.Header.Get("X-Untrusted-Content") != "captured" {
		t.Error("missing untrusted-content marker on export")
	}
	if !strings.Contains(string(body), `"log"`) || !strings.Contains(string(body), `"version": "1.2"`) {
		t.Fatalf("HAR export malformed: %s", body[:200])
	}

	// filtered-set HAR via ids
	req, _ = http.NewRequest("GET", fmt.Sprintf("%s/api/v1/export/har?ids=%d,%d", srv.URL, f1.ID, f2.ID), nil)
	resp, err = http.DefaultClient.Do(bearer(req, "testtoken123"))
	if err != nil {
		t.Fatal(err)
	}
	body, _ = io.ReadAll(resp.Body)
	resp.Body.Close()
	if strings.Count(string(body), `"startedDateTime"`) != 2 {
		t.Fatalf("expected 2 entries, got: %.200s", body)
	}

	// diff between the two bodies
	req, _ = http.NewRequest("GET",
		fmt.Sprintf("%s/api/v1/flows/%d/diff/%d?part=req_body&mode=word", srv.URL, f1.ID, f2.ID), nil)
	resp, err = http.DefaultClient.Do(bearer(req, "testtoken123"))
	if err != nil {
		t.Fatal(err)
	}
	var d struct {
		Mode     string `json:"mode"`
		Segments []struct {
			Type string `json:"type"`
			Text string `json:"text"`
		} `json:"segments"`
	}
	json.NewDecoder(resp.Body).Decode(&d)
	resp.Body.Close()
	foundDel, foundIns := false, false
	for _, seg := range d.Segments {
		if seg.Type == "delete" && strings.Contains(seg.Text, "user") {
			foundDel = true
		}
		if seg.Type == "insert" && strings.Contains(seg.Text, "admin") {
			foundIns = true
		}
	}
	if !foundDel || !foundIns {
		t.Fatalf("diff segments wrong: %+v", d.Segments)
	}

	// bad part rejected
	req, _ = http.NewRequest("GET",
		fmt.Sprintf("%s/api/v1/flows/%d/diff/%d?part=nonsense", srv.URL, f1.ID, f2.ID), nil)
	resp, _ = http.DefaultClient.Do(bearer(req, "testtoken123"))
	resp.Body.Close()
	if resp.StatusCode != http.StatusBadRequest {
		t.Fatalf("bad part status = %d", resp.StatusCode)
	}
}

func TestAnnotateWritesAudit(t *testing.T) {
	srv, st, _ := newTestServer(t)
	f := insertSampleFlow(t, st)

	req, _ := http.NewRequest("PATCH", fmt.Sprintf("%s/api/v1/flows/%d", srv.URL, f.ID),
		strings.NewReader(`{"comment":"check auth","highlight":"red"}`))
	req.Header.Set("Content-Type", "application/json")
	resp, err := http.DefaultClient.Do(bearer(req, "testtoken123"))
	if err != nil {
		t.Fatal(err)
	}
	resp.Body.Close()
	if resp.StatusCode != 200 {
		t.Fatalf("status = %d", resp.StatusCode)
	}

	// audit export contains the action
	req2, _ := http.NewRequest("GET", srv.URL+"/api/v1/audit.jsonl", nil)
	resp2, err := http.DefaultClient.Do(bearer(req2, "testtoken123"))
	if err != nil {
		t.Fatal(err)
	}
	defer resp2.Body.Close()
	body := make([]byte, 4096)
	n, _ := resp2.Body.Read(body)
	if !strings.Contains(string(body[:n]), "flow.annotate") {
		t.Errorf("audit missing annotate entry: %q", string(body[:n]))
	}
}

func TestEventsWebSocket(t *testing.T) {
	srv, st, bus := newTestServer(t)
	insertSampleFlow(t, st)

	wsURL := "ws" + strings.TrimPrefix(srv.URL, "http") + "/api/v1/events"
	hdr := http.Header{}
	hdr.Set("Authorization", "Bearer testtoken123")
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	c, _, err := websocket.Dial(ctx, wsURL, &websocket.DialOptions{HTTPHeader: hdr})
	if err != nil {
		t.Fatalf("dial: %v", err)
	}
	defer c.CloseNow()

	// publish an event; expect to receive it
	bus.PublishJSON(flows.EventNotice, map[string]string{"msg": "hello"})
	rctx, rcancel := context.WithTimeout(ctx, 3*time.Second)
	defer rcancel()
	_, data, err := c.Read(rctx)
	if err != nil {
		t.Fatalf("read: %v", err)
	}
	if !strings.Contains(string(data), `"hello"`) {
		t.Errorf("unexpected event: %s", data)
	}

	// unauthorized dial must fail
	c2ctx, c2cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer c2cancel()
	badHdr := http.Header{}
	badHdr.Set("Authorization", "Bearer wrong")
	if _, _, err := websocket.Dial(c2ctx, wsURL, &websocket.DialOptions{HTTPHeader: badHdr}); err == nil {
		t.Error("unauthorized WS dial should fail")
	}
}
