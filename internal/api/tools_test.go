package api

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"net/url"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/NitinGavhane/proxyforge/internal/extjs"
	"github.com/NitinGavhane/proxyforge/internal/flows"
	"github.com/NitinGavhane/proxyforge/internal/intercept"
	"github.com/NitinGavhane/proxyforge/internal/matchreplace"
	"github.com/NitinGavhane/proxyforge/internal/mcp"
	"github.com/NitinGavhane/proxyforge/internal/pipeline"
	"github.com/NitinGavhane/proxyforge/internal/proxy"
	"github.com/NitinGavhane/proxyforge/internal/scope"
	"github.com/NitinGavhane/proxyforge/internal/store"
	"github.com/NitinGavhane/proxyforge/internal/tools"
)

func iceptForMCP(t *testing.T, st *store.Store, bus *flows.Bus) *intercept.Manager {
	t.Helper()
	m, err := intercept.New(st, bus)
	if err != nil {
		t.Fatal(err)
	}
	return m
}

func newToolsServer(t *testing.T) (*httptest.Server, *store.Store) {
	t.Helper()
	st, err := store.Open(filepath.Join(t.TempDir(), "tools.pf.sqlite"))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { st.Close() })
	bus := flows.NewBus()
	sc, _ := scope.New(st, bus)
	if _, err := sc.Add(scope.KindInclude, `^http://127[.]0[.]0[.]1`, true); err != nil {
		t.Fatal(err)
	}
	eng := &proxy.Engine{Pipeline: pipeline.New(st, bus, nil), Scope: sc}
	mr, _ := matchreplace.New(st, bus)
	mcpBackend := &mcp.Backend{
		Store: st, Intercept: iceptForMCP(t, st, bus),
		Repeater: tools.NewRepeater(st, eng), Intruder: tools.NewIntruder(eng),
		Scanner: tools.NewScanner(st, eng), Scope: sc,
		MatchRep: mr, Scripts: mustScripts(t, st), Version: "test",
	}
	s := &Server{
		Store: st, Bus: bus, Token: "testtoken123", Started: time.Now(),
		Repeater:  tools.NewRepeater(st, eng),
		Discovery: tools.NewDiscovery(st, eng),
		Intruder:  tools.NewIntruder(eng),
		Scanner:   tools.NewScanner(st, eng),
		Scripts:   mustScripts(t, st),
		MCP:       mcpBackend,
	}
	srv := httptest.NewServer(s.Handler())
	t.Cleanup(srv.Close)
	return srv, st
}

func TestSitemapTreeAndShadows(t *testing.T) {
	srv, st := newToolsServer(t)
	ctx := context.Background()

	// two captured endpoints on one host
	for _, p := range []string{"/a", "/b"} {
		f := &flows.Flow{
			Started: time.Now(), Origin: flows.OriginProxy,
			Request:  &flows.Request{Method: "GET", Scheme: "http", Host: "live.example", Port: 80, Path: p},
			Response: &flows.Response{Status: 200},
		}
		if err := st.InsertFlow(ctx, f); err != nil {
			t.Fatal(err)
		}
		if err := st.UpsertEndpointFromFlow(ctx, f); err != nil {
			t.Fatal(err)
		}
	}
	// import endpoints: one already observed live, one never observed
	req, _ := http.NewRequest("POST", srv.URL+"/api/v1/sitemap/import",
		strings.NewReader(`{"endpoints":[
			{"host":"live.example","scheme":"http","port":80,"path":"/a","method":"GET"},
			{"host":"live.example","scheme":"http","port":80,"path":"/hidden-api","method":"POST"},
			{"host":"recovered.example","scheme":"https","path":"/v2/secret"}
		]}`))
	req.Header.Set("Content-Type", "application/json")
	resp, err := http.DefaultClient.Do(bearer(req, "testtoken123"))
	if err != nil {
		t.Fatal(err)
	}
	var imp struct{ Imported int }
	json.NewDecoder(resp.Body).Decode(&imp)
	resp.Body.Close()
	if imp.Imported != 3 {
		t.Fatalf("imported = %d", imp.Imported)
	}

	req, _ = http.NewRequest("GET", srv.URL+"/api/v1/sitemap", nil)
	resp, err = http.DefaultClient.Do(bearer(req, "testtoken123"))
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	var sm struct {
		Hosts []struct {
			Host      string `json:"host"`
			Endpoints int    `json:"endpoints"`
			Paths     []struct {
				Path     string   `json:"path"`
				Methods  []string `json:"methods"`
				Observed bool     `json:"observed"`
				Shadow   bool     `json:"shadow"`
				Source   string   `json:"source"`
			} `json:"paths"`
		} `json:"hosts"`
	}
	json.NewDecoder(resp.Body).Decode(&sm)

	byHost := map[string][]string{}
	shadows := map[string]bool{}
	for _, h := range sm.Hosts {
		for _, p := range h.Paths {
			byHost[h.Host] = append(byHost[h.Host], p.Path)
			shadows[h.Host+p.Path] = p.Shadow
		}
	}
	if len(byHost["live.example"]) != 3 {
		t.Fatalf("live.example paths = %v", byHost["live.example"])
	}
	if !shadows["live.example/hidden-api"] {
		t.Error("imported-but-unobserved endpoint must be shadow")
	}
	if !shadows["recovered.example/v2/secret"] {
		t.Error("recovered host endpoint must be shadow")
	}
	if shadows["live.example/a"] {
		t.Error("observed endpoint must not be shadow")
	}
	if shadows["live.example/b"] {
		t.Error("captured endpoint must not be shadow")
	}
}

func TestRepeaterAPIFlow(t *testing.T) {
	srv, _ := newToolsServer(t)
	up := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, _ = io.WriteString(w, "api-echo")
	}))
	t.Cleanup(up.Close)

	// create tab
	req, _ := http.NewRequest("POST", srv.URL+"/api/v1/repeater",
		strings.NewReader(fmt.Sprintf(`{"name":"t","raw":"GET /x HTTP/1.1\nHost: %s\n"}`, strings.TrimPrefix(up.URL, "http://"))))
	req.Header.Set("Content-Type", "application/json")
	resp, _ := http.DefaultClient.Do(bearer(req, "testtoken123"))
	var tab struct{ ID int64 }
	json.NewDecoder(resp.Body).Decode(&tab)
	resp.Body.Close()
	if tab.ID == 0 {
		t.Fatal("tab not created")
	}

	// send
	req, _ = http.NewRequest("POST", fmt.Sprintf("%s/api/v1/repeater/%d/send", srv.URL, tab.ID),
		strings.NewReader(`{"follow_redirects":false}`))
	req.Header.Set("Content-Type", "application/json")
	resp, err := http.DefaultClient.Do(bearer(req, "testtoken123"))
	if err != nil {
		t.Fatal(err)
	}
	var out struct {
		Result struct {
			Final struct {
				Response struct {
					Status int    `json:"status"`
					Body   []byte `json:"Body"`
				} `json:"response"`
			} `json:"final"`
		} `json:"result"`
	}
	json.NewDecoder(resp.Body).Decode(&out)
	resp.Body.Close()
	if out.Result.Final.Response.Status != 200 {
		t.Fatalf("send status = %d", out.Result.Final.Response.Status)
	}

	// history
	req, _ = http.NewRequest("GET", fmt.Sprintf("%s/api/v1/repeater/%d/history", srv.URL, tab.ID), nil)
	resp, _ = http.DefaultClient.Do(bearer(req, "testtoken123"))
	var hist struct {
		History []store.FlowRow `json:"history"`
	}
	json.NewDecoder(resp.Body).Decode(&hist)
	resp.Body.Close()
	if len(hist.History) != 1 {
		t.Fatalf("history = %d", len(hist.History))
	}

	// audited
	req, _ = http.NewRequest("GET", srv.URL+"/api/v1/audit.jsonl", nil)
	resp, _ = http.DefaultClient.Do(bearer(req, "testtoken123"))
	body, _ := io.ReadAll(resp.Body)
	resp.Body.Close()
	for _, action := range []string{"repeater.tab.new", "repeater.send"} {
		if !strings.Contains(string(body), action) {
			t.Errorf("audit missing %q", action)
		}
	}
}

func TestDiscoveryAPISmoke(t *testing.T) {
	srv, _ := newToolsServer(t)
	up := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/admin" {
			w.Write([]byte("a longer body than the plain 404 padding body"))
			return
		}
		w.WriteHeader(404)
		w.Write([]byte("nope"))
	}))
	t.Cleanup(up.Close)

	req, _ := http.NewRequest("POST", srv.URL+"/api/v1/discovery/start",
		strings.NewReader(fmt.Sprintf(`{"base_url":%q,"wordlist":["admin","zz"],"rate_per_sec":20}`, up.URL+"/")))
	req.Header.Set("Content-Type", "application/json")
	resp, err := http.DefaultClient.Do(bearer(req, "testtoken123"))
	if err != nil {
		t.Fatal(err)
	}
	var start struct {
		Job struct{ ID int64 } `json:"job"`
	}
	json.NewDecoder(resp.Body).Decode(&start)
	resp.Body.Close()
	if start.Job.ID == 0 {
		t.Fatal("job not started")
	}

	// wait for completion
	deadline := time.Now().Add(10 * time.Second)
	var job struct {
		Job struct {
			State   string `json:"state"`
			Results []struct {
				Path        string `json:"path"`
				Interesting bool   `json:"interesting"`
			} `json:"results"`
		} `json:"job"`
	}
	for time.Now().Before(deadline) {
		req, _ = http.NewRequest("GET", fmt.Sprintf("%s/api/v1/discovery/%d", srv.URL, start.Job.ID), nil)
		resp, _ = http.DefaultClient.Do(bearer(req, "testtoken123"))
		json.NewDecoder(resp.Body).Decode(&job)
		resp.Body.Close()
		if job.Job.State != "running" {
			break
		}
		time.Sleep(100 * time.Millisecond)
	}
	if job.Job.State != "done" {
		t.Fatalf("job state = %s", job.Job.State)
	}
	found := false
	for _, r := range job.Job.Results {
		if r.Path == "admin" && r.Interesting {
			found = true
		}
	}
	if !found {
		t.Fatalf("/admin not found interesting: %+v", job.Job.Results)
	}
}

func TestIntruderAPI(t *testing.T) {
	srv, _ := newToolsServer(t)
	up := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Write([]byte(`{"role":"user","token":"abc-999"}`))
	}))
	t.Cleanup(up.Close)

	req, _ := http.NewRequest("POST", srv.URL+"/api/v1/intruder/start",
		strings.NewReader(fmt.Sprintf(`{
			"attack_type":"cluster_bomb",
			"raw":"POST /§u§?p=§p§ HTTP/1.1\nHost: %s\n",
			"payload_sets":[{"type":"list","items":["alice","bob"]},{"type":"numbers","from":1,"to":2}],
			"extract":[{"name":"token","regex":"\"token\":\"([^\"]+)\""}],
			"rate_per_sec":20
		}`, strings.TrimPrefix(up.URL, "http://"))))
	req.Header.Set("Content-Type", "application/json")
	resp, err := http.DefaultClient.Do(bearer(req, "testtoken123"))
	if err != nil {
		t.Fatal(err)
	}
	var start struct {
		Job struct{ ID int64 } `json:"job"`
	}
	json.NewDecoder(resp.Body).Decode(&start)
	resp.Body.Close()
	if start.Job.ID == 0 {
		t.Fatal("attack not started")
	}

	var job struct {
		Job struct {
			State   string `json:"state"`
			Sent    int    `json:"sent"`
			Results []struct {
				Status   int               `json:"status"`
				Extracts map[string]string `json:"extracts"`
			} `json:"results"`
		} `json:"job"`
	}
	deadline := time.Now().Add(15 * time.Second)
	for time.Now().Before(deadline) {
		req, _ = http.NewRequest("GET", fmt.Sprintf("%s/api/v1/intruder/%d", srv.URL, start.Job.ID), nil)
		resp, _ = http.DefaultClient.Do(bearer(req, "testtoken123"))
		json.NewDecoder(resp.Body).Decode(&job)
		resp.Body.Close()
		if job.Job.State != "running" {
			break
		}
		time.Sleep(100 * time.Millisecond)
	}
	if job.Job.State != "done" || job.Job.Sent != 4 {
		t.Fatalf("state=%s sent=%d", job.Job.State, job.Job.Sent)
	}
	for _, r := range job.Job.Results {
		if r.Status != 200 || r.Extracts["token"] != "abc-999" {
			t.Fatalf("row: %+v", r)
		}
	}

	// audited
	req, _ = http.NewRequest("GET", srv.URL+"/api/v1/audit.jsonl", nil)
	resp, _ = http.DefaultClient.Do(bearer(req, "testtoken123"))
	body, _ := io.ReadAll(resp.Body)
	resp.Body.Close()
	if !strings.Contains(string(body), "intruder.start") {
		t.Error("attack start not audited")
	}
}

func TestScannerAPI(t *testing.T) {
	srv, st := newToolsServer(t)
	// deliberately misconfigured origin + reflecting endpoint
	up := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Server", "Leak/1.0")
		w.Header().Set("Access-Control-Allow-Origin", "*")
		w.Header().Set("Access-Control-Allow-Credentials", "true")
		if v := r.URL.Query().Get("q"); v != "" {
			w.Write([]byte("echo: " + v))
			return
		}
		w.Write([]byte(`{"key":"AKIAIOSFODNN7EXAMPLE"}`))
	}))
	t.Cleanup(up.Close)

	// passive scan via API
	req, _ := http.NewRequest("POST", srv.URL+"/api/v1/scanner/scan",
		strings.NewReader(fmt.Sprintf(`{"base_url":%q}`, up.URL+"/")))
	req.Header.Set("Content-Type", "application/json")
	resp, err := http.DefaultClient.Do(bearer(req, "testtoken123"))
	if err != nil {
		t.Fatal(err)
	}
	var start struct {
		Job struct{ ID int64 } `json:"job"`
	}
	json.NewDecoder(resp.Body).Decode(&start)
	resp.Body.Close()
	if start.Job.ID == 0 {
		t.Fatal("scan not started")
	}

	var job struct {
		Job struct {
			State  string `json:"state"`
			Issues int    `json:"issues"`
			Err    string `json:"err"`
		} `json:"job"`
	}
	deadline := time.Now().Add(15 * time.Second)
	for time.Now().Before(deadline) {
		req, _ = http.NewRequest("GET", fmt.Sprintf("%s/api/v1/scanner/%d", srv.URL, start.Job.ID), nil)
		resp, _ = http.DefaultClient.Do(bearer(req, "testtoken123"))
		json.NewDecoder(resp.Body).Decode(&job)
		resp.Body.Close()
		if job.Job.State != "running" {
			break
		}
		time.Sleep(100 * time.Millisecond)
	}
	if job.Job.State != "done" || job.Job.Issues == 0 {
		t.Fatalf("state=%s issues=%d err=%s", job.Job.State, job.Job.Issues, job.Job.Err)
	}

	// active scan without confirm → 400
	req, _ = http.NewRequest("POST", srv.URL+"/api/v1/scanner/scan",
		strings.NewReader(fmt.Sprintf(`{"base_url":%q,"passive":false,"active":true}`, up.URL+"/")))
	req.Header.Set("Content-Type", "application/json")
	resp, _ = http.DefaultClient.Do(bearer(req, "testtoken123"))
	resp.Body.Close()
	if resp.StatusCode != http.StatusBadRequest {
		t.Fatalf("unconfirmed active scan status = %d", resp.StatusCode)
	}

	// issues list + detail
	req, _ = http.NewRequest("GET", srv.URL+"/api/v1/issues", nil)
	resp, _ = http.DefaultClient.Do(bearer(req, "testtoken123"))
	var list struct {
		Issues []store.Issue `json:"issues"`
	}
	json.NewDecoder(resp.Body).Decode(&list)
	resp.Body.Close()
	if len(list.Issues) == 0 {
		t.Fatal("no issues listed")
	}
	req, _ = http.NewRequest("GET", fmt.Sprintf("%s/api/v1/issues/%d", srv.URL, list.Issues[0].ID), nil)
	resp, _ = http.DefaultClient.Do(bearer(req, "testtoken123"))
	var iss store.Issue
	json.NewDecoder(resp.Body).Decode(&iss)
	resp.Body.Close()
	if iss.ID != list.Issues[0].ID || iss.Title == "" {
		t.Fatalf("issue detail: %+v", iss)
	}

	// audited
	req, _ = http.NewRequest("GET", srv.URL+"/api/v1/audit.jsonl", nil)
	resp, _ = http.DefaultClient.Do(bearer(req, "testtoken123"))
	body, _ := io.ReadAll(resp.Body)
	resp.Body.Close()
	if !strings.Contains(string(body), "scanner.start") {
		t.Error("scan not audited")
	}
	_ = st.ListIssues
}

func TestCollabRequiresConfiguration(t *testing.T) {
	// no collaborator on the test server → endpoints 503
	srv, _ := newToolsServer(t)
	req, _ := http.NewRequest("POST", srv.URL+"/api/v1/collab/new", nil)
	resp, _ := http.DefaultClient.Do(bearer(req, "testtoken123"))
	resp.Body.Close()
	if resp.StatusCode != http.StatusServiceUnavailable {
		t.Fatalf("collab/new without config = %d", resp.StatusCode)
	}
}

func TestOrganizerJarAndExports(t *testing.T) {
	srv, st := newToolsServer(t)
	// seed flows with cookies via a proxied login
	up := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/login" {
			w.Header().Set("Set-Cookie", "sid=xyz; Path=/; Secure; HttpOnly")
			w.Write([]byte(`{"ok":true}`))
			return
		}
		w.Write([]byte("ok"))
	}))
	t.Cleanup(up.Close)
	u, _ := url.Parse(up.URL)
	_ = u
	f := &flows.Flow{
		Started: time.Now(), Origin: flows.OriginProxy,
		Request: &flows.Request{Method: "POST", Scheme: "http", Host: "sess.example", Port: 80, Path: "/login"},
		Response: &flows.Response{Status: 200, Headers: flows.Headers{
			{Key: "Set-Cookie", Value: "sid=xyz; Path=/; Secure; HttpOnly"},
		}, Body: []byte(`{"ok":true}`)},
	}
	if err := st.InsertFlow(context.Background(), f); err != nil {
		t.Fatal(err)
	}
	if err := st.CaptureCookies(context.Background(), f); err != nil {
		t.Fatal(err)
	}

	// jar
	req, _ := http.NewRequest("GET", srv.URL+"/api/v1/jar?host=sess.example&port=80", nil)
	resp, _ := http.DefaultClient.Do(bearer(req, "testtoken123"))
	var jar struct {
		Cookies []store.Cookie `json:"cookies"`
	}
	json.NewDecoder(resp.Body).Decode(&jar)
	resp.Body.Close()
	if len(jar.Cookies) != 1 || jar.Cookies[0].Name != "sid" || !jar.Cookies[0].Secure {
		t.Fatalf("jar: %+v", jar.Cookies)
	}

	// organizer save/list/delete
	req, _ = http.NewRequest("POST", srv.URL+"/api/v1/organizer",
		strings.NewReader(`{"flow_id":1,"note":"interesting auth flow","tags":"auth,jwt"}`))
	req.Header.Set("Content-Type", "application/json")
	resp, _ = http.DefaultClient.Do(bearer(req, "testtoken123"))
	var saved struct{ ID int64 }
	json.NewDecoder(resp.Body).Decode(&saved)
	resp.Body.Close()
	if saved.ID == 0 {
		t.Fatal("organizer save failed")
	}
	req, _ = http.NewRequest("GET", srv.URL+"/api/v1/organizer", nil)
	resp, _ = http.DefaultClient.Do(bearer(req, "testtoken123"))
	var list struct {
		Items []store.OrganizerItem `json:"items"`
	}
	json.NewDecoder(resp.Body).Decode(&list)
	resp.Body.Close()
	if len(list.Items) != 1 || list.Items[0].Tags != "auth,jwt" {
		t.Fatalf("organizer list: %+v", list.Items)
	}
	req, _ = http.NewRequest("DELETE", fmt.Sprintf("%s/api/v1/organizer/%d", srv.URL, saved.ID), nil)
	resp, _ = http.DefaultClient.Do(bearer(req, "testtoken123"))
	resp.Body.Close()
	list2, _ := st.ListOrganizer(context.Background())
	if len(list2) != 0 {
		t.Fatal("organizer delete failed")
	}

	// macros
	req, _ = http.NewRequest("POST", srv.URL+"/api/v1/macros",
		strings.NewReader(`{"name":"login","flow_id":1}`))
	req.Header.Set("Content-Type", "application/json")
	resp, _ = http.DefaultClient.Do(bearer(req, "testtoken123"))
	var mac struct{ ID int64 }
	json.NewDecoder(resp.Body).Decode(&mac)
	resp.Body.Close()
	if mac.ID == 0 {
		t.Fatal("macro save failed")
	}

	// exports
	req, _ = http.NewRequest("GET", srv.URL+"/api/v1/export/flows.csv", nil)
	resp, _ = http.DefaultClient.Do(bearer(req, "testtoken123"))
	csvBody, _ := io.ReadAll(resp.Body)
	resp.Body.Close()
	if !strings.Contains(string(csvBody), "sess.example") || !strings.HasPrefix(string(csvBody), "id,") {
		t.Fatalf("csv: %.100s", csvBody)
	}
	req, _ = http.NewRequest("GET", srv.URL+"/api/v1/export/burp.xml", nil)
	resp, _ = http.DefaultClient.Do(bearer(req, "testtoken123"))
	xmlBody, _ := io.ReadAll(resp.Body)
	resp.Body.Close()
	if !strings.Contains(string(xmlBody), "<items>") || !strings.Contains(string(xmlBody), "sess.example") {
		t.Fatalf("burp xml: %.100s", xmlBody)
	}

	// burp xml import round trip
	req, _ = http.NewRequest("POST", srv.URL+"/api/v1/import/burp.xml", bytes.NewReader(xmlBody))
	resp, err := http.DefaultClient.Do(bearer(req, "testtoken123"))
	if err != nil {
		t.Fatal(err)
	}
	var imp struct{ Imported int }
	json.NewDecoder(resp.Body).Decode(&imp)
	resp.Body.Close()
	if imp.Imported != 1 {
		t.Fatalf("imported = %d", imp.Imported)
	}
}

func TestImportsAndReport(t *testing.T) {
	srv, st := newToolsServer(t)

	// cURL import → repeater tab
	req, _ := http.NewRequest("POST", srv.URL+"/api/v1/import/curl",
		strings.NewReader(`{"command":"curl -X POST https://api.example.com/login -H 'Content-Type: application/json' -d '{\"u\":1}'","as_tab":true}`))
	req.Header.Set("Content-Type", "application/json")
	resp, err := http.DefaultClient.Do(bearer(req, "testtoken123"))
	if err != nil {
		t.Fatal(err)
	}
	var cr struct {
		Raw   string `json:"raw"`
		TabID int64  `json:"tab_id"`
	}
	json.NewDecoder(resp.Body).Decode(&cr)
	resp.Body.Close()
	if cr.TabID == 0 || !strings.Contains(cr.Raw, "POST /login HTTP/1.1") {
		t.Fatalf("curl import: %+v raw=%q", cr, cr.Raw)
	}
	// bad curl rejected
	req, _ = http.NewRequest("POST", srv.URL+"/api/v1/import/curl",
		strings.NewReader(`{"command":"curl"}`))
	resp, _ = http.DefaultClient.Do(bearer(req, "testtoken123"))
	resp.Body.Close()
	if resp.StatusCode != http.StatusBadRequest {
		t.Fatalf("bad curl status = %d", resp.StatusCode)
	}

	// OpenAPI import
	req, _ = http.NewRequest("POST", srv.URL+"/api/v1/import/openapi",
		strings.NewReader(`{"openapi":"3.0.0","servers":[{"url":"https://api.example.com/v2"}],"paths":{"/users":{"get":{},"post":{}}}}`))
	resp, _ = http.DefaultClient.Do(bearer(req, "testtoken123"))
	var oa struct{ Imported int }
	json.NewDecoder(resp.Body).Decode(&oa)
	resp.Body.Close()
	if oa.Imported != 2 {
		t.Fatalf("openapi imported = %d", oa.Imported)
	}
	// endpoints present and shadow (never observed)
	eps, _ := st.ListEndpoints(context.Background())
	n := 0
	for _, e := range eps {
		if e.Source == "import" && e.Host == "api.example.com" {
			n++
		}
	}
	if n != 2 {
		t.Fatalf("imported endpoints = %d", n)
	}

	// report contains them (empty issues → placeholder)
	req, _ = http.NewRequest("GET", srv.URL+"/api/v1/report.md", nil)
	resp, _ = http.DefaultClient.Do(bearer(req, "testtoken123"))
	body, _ := io.ReadAll(resp.Body)
	resp.Body.Close()
	if !strings.Contains(string(body), "ProxyForge Security Report") {
		t.Fatalf("report.md: %.100s", body)
	}
	req, _ = http.NewRequest("GET", srv.URL+"/api/v1/report.html", nil)
	resp, _ = http.DefaultClient.Do(bearer(req, "testtoken123"))
	body, _ = io.ReadAll(resp.Body)
	resp.Body.Close()
	if !strings.Contains(string(body), "<h1>") {
		t.Fatalf("report.html: %.100s", body)
	}
}

func TestExtensionAPI(t *testing.T) {
	srv, st := newToolsServer(t)
	// seed a captured flow to test against
	f := &flows.Flow{
		Started: time.Now(), Origin: flows.OriginProxy,
		Request:  &flows.Request{Method: "GET", Scheme: "http", Host: "x.example", Port: 80, Path: "/p"},
		Response: &flows.Response{Status: 200, Body: []byte("internal box db-prod-01")},
	}
	if err := st.InsertFlow(context.Background(), f); err != nil {
		t.Fatal(err)
	}

	// add (compile-checked)
	req, _ := http.NewRequest("POST", srv.URL+"/api/v1/extensions",
		strings.NewReader(`{"name":"redact","enabled":true,"code":"function onResponse(flow) { flow.response.body = flow.response.body.split('db-prod-01').join('[internal]'); }"}`))
	req.Header.Set("Content-Type", "application/json")
	resp, _ := http.DefaultClient.Do(bearer(req, "testtoken123"))
	var add struct{ ID int64 }
	json.NewDecoder(resp.Body).Decode(&add)
	resp.Body.Close()
	if add.ID == 0 {
		t.Fatal("extension not added")
	}
	// bad syntax → 400
	req, _ = http.NewRequest("POST", srv.URL+"/api/v1/extensions",
		strings.NewReader(`{"name":"bad","code":"function ("}`))
	resp, _ = http.DefaultClient.Do(bearer(req, "testtoken123"))
	resp.Body.Close()
	if resp.StatusCode != http.StatusBadRequest {
		t.Fatalf("bad code status = %d", resp.StatusCode)
	}

	// dry-run test against the captured flow
	req, _ = http.NewRequest("POST", fmt.Sprintf("%s/api/v1/extensions/%d/test", srv.URL, add.ID),
		strings.NewReader(fmt.Sprintf(`{"flow_id":%d}`, f.ID)))
	req.Header.Set("Content-Type", "application/json")
	resp, _ = http.DefaultClient.Do(bearer(req, "testtoken123"))
	var view struct {
		Before struct {
			Response struct {
				Body string `json:"body"`
			} `json:"response"`
		} `json:"before"`
		After struct {
			Response struct {
				Body string `json:"body"`
			} `json:"response"`
		} `json:"after"`
	}
	json.NewDecoder(resp.Body).Decode(&view)
	resp.Body.Close()
	if !strings.Contains(view.Before.Response.Body, "db-prod-01") {
		t.Fatalf("before: %+v", view.Before)
	}
	if !strings.Contains(view.After.Response.Body, "[internal]") ||
		strings.Contains(view.After.Response.Body, "db-prod-01") {
		t.Fatalf("after: %+v", view.After)
	}
	// the stored flow is untouched (dry run)
	stored, _ := st.GetFlow(context.Background(), f.ID)
	if !strings.Contains(string(stored.Response.Body), "db-prod-01") {
		t.Fatal("dry run mutated stored flow")
	}

	// list + delete
	req, _ = http.NewRequest("GET", srv.URL+"/api/v1/extensions", nil)
	resp, _ = http.DefaultClient.Do(bearer(req, "testtoken123"))
	var list struct {
		Extensions []store.Extension `json:"extensions"`
	}
	json.NewDecoder(resp.Body).Decode(&list)
	resp.Body.Close()
	if len(list.Extensions) != 1 {
		t.Fatalf("list = %+v", list)
	}
	req, _ = http.NewRequest("DELETE", fmt.Sprintf("%s/api/v1/extensions/%d", srv.URL, add.ID), nil)
	resp, _ = http.DefaultClient.Do(bearer(req, "testtoken123"))
	resp.Body.Close()
	list2, _ := st.ListExtensions(context.Background())
	if len(list2) != 0 {
		t.Fatal("delete failed")
	}
}

func mustScripts(t *testing.T, st *store.Store) *extjs.Manager {
	t.Helper()
	m, err := extjs.NewManager(st, nil)
	if err != nil {
		t.Fatal(err)
	}
	return m
}

func TestMCPStreamableHTTP(t *testing.T) {
	srv, st := newToolsServer(t)
	// seed a flow
	f := &flows.Flow{
		Started: time.Now(), Origin: flows.OriginProxy,
		Request: &flows.Request{Method: "GET", Scheme: "http", Host: "mcp.example", Port: 80, Path: "/probe"},
	}
	if err := st.InsertFlow(context.Background(), f); err != nil {
		t.Fatal(err)
	}

	rpc := func(method string, params any) map[string]any {
		body, _ := json.Marshal(map[string]any{
			"jsonrpc": "2.0", "id": 1, "method": method, "params": params,
		})
		req, _ := http.NewRequest("POST", srv.URL+"/api/v1/mcp", bytes.NewReader(body))
		req.Header.Set("Content-Type", "application/json")
		resp, err := http.DefaultClient.Do(bearer(req, "testtoken123"))
		if err != nil {
			t.Fatal(err)
		}
		defer resp.Body.Close()
		if resp.Header.Get("Content-Type") != "application/json" {
			t.Fatalf("content-type = %s", resp.Header.Get("Content-Type"))
		}
		var out map[string]any
		json.NewDecoder(resp.Body).Decode(&out)
		return out
	}

	// initialize (JSON-RPC envelope: payload sits under "result")
	out := rpc("initialize", map[string]any{"protocolVersion": "2025-06-18"})
	res := out["result"].(map[string]any)
	if res["serverInfo"].(map[string]any)["name"] != "proxyforge" {
		t.Fatalf("init: %+v", out)
	}
	// tools/list
	out = rpc("tools/list", map[string]any{})
	res = out["result"].(map[string]any)
	if len(res["tools"].([]any)) < 25 {
		t.Fatalf("tools = %d", len(res["tools"].([]any)))
	}
	// tools/call with captured content → provenance marker present
	out = rpc("tools/call", map[string]any{
		"name": "list_history", "arguments": map[string]any{"host": "mcp.example"},
	})
	text := out["result"].(map[string]any)["content"].([]any)[0].(map[string]any)["text"].(string)
	if !strings.Contains(text, "untrusted_content") {
		t.Fatalf("no provenance: %.200s", text)
	}
	if !strings.Contains(text, "mcp.example") {
		t.Fatalf("no flow: %.200s", text)
	}
	// unknown tool → in-result error
	out = rpc("tools/call", map[string]any{"name": "nope"})
	if out["result"].(map[string]any)["isError"] != true {
		t.Fatal("unknown tool not flagged")
	}
	// unauthenticated
	body, _ := json.Marshal(map[string]any{"jsonrpc": "2.0", "id": 1, "method": "ping"})
	req, _ := http.NewRequest("POST", srv.URL+"/api/v1/mcp", bytes.NewReader(body))
	resp, _ := http.DefaultClient.Do(req)
	resp.Body.Close()
	if resp.StatusCode != http.StatusUnauthorized {
		t.Fatalf("unauth mcp = %d", resp.StatusCode)
	}
	// audited
	rows, _ := st.ListFlows(context.Background(), store.Filter{})
	_ = rows
	audit, _ := st.AuditJSONL(context.Background())
	if !strings.Contains(audit, "mcp.request") {
		t.Fatal("mcp requests not audited")
	}
}
