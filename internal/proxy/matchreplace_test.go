package proxy

import (
	"context"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"strings"
	"sync"
	"testing"

	"github.com/NitinGavhane/proxyforge/internal/flows"
	"github.com/NitinGavhane/proxyforge/internal/intercept"
	"github.com/NitinGavhane/proxyforge/internal/matchreplace"
	"github.com/NitinGavhane/proxyforge/internal/pipeline"
	"github.com/NitinGavhane/proxyforge/internal/store"
)

func newMREngine(t *testing.T) (*matchreplace.Manager, *httptest.Server, *store.Store) {
	t.Helper()
	st, err := store.Open(filepath.Join(t.TempDir(), "mr.pf.sqlite"))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { st.Close() })
	mgr, err := matchreplace.New(st, flows.NewBus())
	if err != nil {
		t.Fatal(err)
	}
	eng := &Engine{
		Pipeline:     pipeline.New(st, flows.NewBus(), nil),
		MatchReplace: mgr,
	}
	proxySrv := httptest.NewServer(eng)
	t.Cleanup(proxySrv.Close)
	return mgr, proxySrv, st
}

func TestMRHeaderRewriteSeenUpstream(t *testing.T) {
	mgr, proxySrv, _ := newMREngine(t)
	var gotUA, gotExtra, gotMissing string
	up := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		gotUA = r.Header.Get("User-Agent")
		gotExtra = r.Header.Get("X-Injected")
		gotMissing = r.Header.Get("X-Strip-Me")
	}))
	t.Cleanup(up.Close)

	if _, err := mgr.Add("rewrite ua", true, matchreplace.DirRequest,
		intercept.Spec{},
		matchreplace.Action{Type: matchreplace.ActHeaderSet, HeaderKey: "User-Agent", HeaderValue: "ProxyForge/1.0"}); err != nil {
		t.Fatal(err)
	}
	if _, err := mgr.Add("inject", true, matchreplace.DirRequest,
		intercept.Spec{},
		matchreplace.Action{Type: matchreplace.ActHeaderAdd, HeaderKey: "X-Injected", HeaderValue: "yes"}); err != nil {
		t.Fatal(err)
	}
	if _, err := mgr.Add("strip", true, matchreplace.DirRequest,
		intercept.Spec{},
		matchreplace.Action{Type: matchreplace.ActHeaderRemove, HeaderKey: "X-Strip-Me"}); err != nil {
		t.Fatal(err)
	}

	req, _ := http.NewRequest("GET", up.URL+"/x", nil)
	req.Header.Set("User-Agent", "curl/8.0")
	req.Header.Set("X-Strip-Me", "secret")
	client := &http.Client{Transport: &http.Transport{Proxy: http.ProxyURL(mustURL(t, proxySrv.URL))}}
	resp, err := client.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	resp.Body.Close()

	if gotUA != "ProxyForge/1.0" {
		t.Errorf("upstream UA = %q", gotUA)
	}
	if gotExtra != "yes" {
		t.Errorf("X-Injected = %q", gotExtra)
	}
	if gotMissing != "" {
		t.Errorf("X-Strip-Me not removed: %q", gotMissing)
	}
}

func TestMRBodyRegexCaptureGroups(t *testing.T) {
	mgr, proxySrv, st := newMREngine(t)
	var upBody []byte
	up := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		upBody, _ = io.ReadAll(r.Body)
		w.WriteHeader(200)
	}))
	t.Cleanup(up.Close)

	if _, err := mgr.Add("privatize", true, matchreplace.DirRequest,
		intercept.Spec{ContentType: "application/json"},
		matchreplace.Action{
			Type:        matchreplace.ActBodyRegex,
			Regex:       `"password":"[^"]*"`,
			Replacement: `"password":"REDACTED-$1"`,
		}); err != nil {
		t.Fatal(err)
	}
	// note: $1 doesn't exist in this pattern → literal "$1"? Go expands
	// unmatched groups to empty; check actual behavior below.
	client := &http.Client{Transport: &http.Transport{Proxy: http.ProxyURL(mustURL(t, proxySrv.URL))}}
	resp, err := client.Post(up.URL+"/login", "application/json",
		strings.NewReader(`{"user":"admin","password":"hunter2"}`))
	if err != nil {
		t.Fatal(err)
	}
	resp.Body.Close()

	got := string(upBody)
	if !strings.Contains(got, `"password":"REDACTED-`) || strings.Contains(got, "hunter2") {
		t.Errorf("upstream body = %q", got)
	}

	// capture-group rewrite: swap user value using $1
	if _, err := mgr.Add("userswap", true, matchreplace.DirRequest,
		intercept.Spec{},
		matchreplace.Action{
			Type:        matchreplace.ActBodyRegex,
			Regex:       `"user":"(\w+)"`,
			Replacement: `"user":"$1-impersonated"`,
		}); err != nil {
		t.Fatal(err)
	}
	resp2, err := client.Post(up.URL+"/login2", "application/json",
		strings.NewReader(`{"user":"bob"}`))
	if err != nil {
		t.Fatal(err)
	}
	resp2.Body.Close()
	if !strings.Contains(string(upBody), `"user":"bob-impersonated"`) {
		t.Errorf("capture group not applied: %q", upBody)
	}

	// captured flow shows the rewritten body + counters bumped
	rows, _ := st.ListFlows(context.Background(), store.Filter{})
	if len(rows) < 2 {
		t.Fatalf("flows = %d", len(rows))
	}
	var mrFlow *flows.Flow
	for _, r := range rows {
		f, _ := st.GetFlow(context.Background(), r.ID)
		if f.Request.Path == "/login" && strings.Contains(string(f.Request.Body), "REDACTED") {
			mrFlow = f
		}
	}
	if mrFlow == nil {
		t.Fatal("rewritten request not captured in history")
	}
	for _, rv := range mgr.List() {
		if rv.Name == "privatize" && rv.Hits != 1 {
			t.Errorf("privatize hits = %d, want 1", rv.Hits)
		}
	}
}

func TestMRResponseBodyReachesClient(t *testing.T) {
	mgr, proxySrv, _ := newMREngine(t)
	up := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "text/html")
		fmt.Fprint(w, `<html><a href="http://internal.example/admin">admin</a></html>`)
	}))
	t.Cleanup(up.Close)

	if _, err := mgr.Add("absolutize", true, matchreplace.DirResponse,
		intercept.Spec{ContentType: "text/html"},
		matchreplace.Action{
			Type:    matchreplace.ActBodyRaw,
			Find:    "http://internal.example",
			Replace: "https://proxyforge.test",
		}); err != nil {
		t.Fatal(err)
	}

	client := &http.Client{Transport: &http.Transport{Proxy: http.ProxyURL(mustURL(t, proxySrv.URL))}}
	resp, err := client.Get(up.URL + "/page")
	if err != nil {
		t.Fatal(err)
	}
	body, _ := io.ReadAll(resp.Body)
	resp.Body.Close()
	got := string(body)
	if !strings.Contains(got, "https://proxyforge.test/admin") || strings.Contains(got, "internal.example") {
		t.Fatalf("client body = %q", got)
	}
}

func TestMRResponseContentLengthFixedAfterEdit(t *testing.T) {
	mgr, proxySrv, _ := newMREngine(t)
	up := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		fmt.Fprint(w, "short body!") // 11 bytes; Go derives Content-Length
	}))
	t.Cleanup(up.Close)

	// replace with something LONGER than the original content-length
	if _, err := mgr.Add("grow", true, matchreplace.DirResponse,
		intercept.Spec{},
		matchreplace.Action{
			Type:    matchreplace.ActBodyRaw,
			Find:    "short",
			Replace: "considerably longer",
		}); err != nil {
		t.Fatal(err)
	}
	client := &http.Client{Transport: &http.Transport{Proxy: http.ProxyURL(mustURL(t, proxySrv.URL))}}
	resp, err := client.Get(up.URL + "/grow")
	if err != nil {
		t.Fatal(err)
	}
	body, err := io.ReadAll(resp.Body)
	resp.Body.Close()
	if err != nil {
		t.Fatalf("client read failed (bad content-length?): %v", err)
	}
	if !strings.Contains(string(body), "considerably longer") {
		t.Fatalf("body = %q", body)
	}
}

func TestMRDisabledRuleInert(t *testing.T) {
	mgr, proxySrv, _ := newMREngine(t)
	var gotHeader string
	up := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		gotHeader = r.Header.Get("X-Injected")
	}))
	t.Cleanup(up.Close)

	id, err := mgr.Add("off", false, matchreplace.DirRequest, intercept.Spec{},
		matchreplace.Action{Type: matchreplace.ActHeaderAdd, HeaderKey: "X-Injected", HeaderValue: "x"})
	if err != nil {
		t.Fatal(err)
	}
	client := &http.Client{Transport: &http.Transport{Proxy: http.ProxyURL(mustURL(t, proxySrv.URL))}}
	resp, _ := client.Get(up.URL + "/")
	resp.Body.Close()
	if gotHeader != "" {
		t.Fatalf("disabled rule applied: %q", gotHeader)
	}
	// enable → now applies
	if err := mgr.SetEnabled(id, true); err != nil {
		t.Fatal(err)
	}
	resp2, _ := client.Get(up.URL + "/on")
	resp2.Body.Close()
	if gotHeader != "x" {
		t.Fatalf("enabled rule not applied: %q", gotHeader)
	}
}

func TestMROrderingStable(t *testing.T) {
	mgr, proxySrv, _ := newMREngine(t)
	var mu sync.Mutex
	var seen []string
	up := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		mu.Lock()
		seen = r.Header.Values("X-Order")
		mu.Unlock()
	}))
	t.Cleanup(up.Close)

	for i := 1; i <= 3; i++ {
		if _, err := mgr.Add(fmt.Sprintf("order-%d", i), true, matchreplace.DirRequest,
			intercept.Spec{},
			matchreplace.Action{Type: matchreplace.ActHeaderAdd, HeaderKey: "X-Order", HeaderValue: fmt.Sprintf("v%d", i)}); err != nil {
			t.Fatal(err)
		}
	}
	client := &http.Client{Transport: &http.Transport{Proxy: http.ProxyURL(mustURL(t, proxySrv.URL))}}
	resp, _ := client.Get(up.URL + "/order")
	resp.Body.Close()

	mu.Lock()
	defer mu.Unlock()
	if len(seen) != 3 || seen[0] != "v1" || seen[1] != "v2" || seen[2] != "v3" {
		t.Fatalf("header order = %v", seen)
	}
}

func TestMRRulesPersistAcrossRestart(t *testing.T) {
	dir := filepath.Join(t.TempDir(), "mrp.pf.sqlite")
	st, _ := store.Open(dir)
	m1, err := matchreplace.New(st, nil)
	if err != nil {
		t.Fatal(err)
	}
	id, err := m1.Add("persist", true, matchreplace.DirRequest,
		intercept.Spec{Method: "POST"},
		matchreplace.Action{Type: matchreplace.ActHeaderAdd, HeaderKey: "X-P", HeaderValue: "1"})
	if err != nil {
		t.Fatal(err)
	}
	st.Close()

	st2, _ := store.Open(dir)
	defer st2.Close()
	m2, err := matchreplace.New(st2, nil)
	if err != nil {
		t.Fatal(err)
	}
	rules := m2.List()
	if len(rules) != 1 || rules[0].ID != id || rules[0].Spec.Method != "POST" || !rules[0].Enabled {
		t.Fatalf("rules not persisted: %+v", rules)
	}
}

func TestMRInvalidRuleRejected(t *testing.T) {
	mgr, _, _ := newMREngine(t)
	cases := []struct {
		name string
		dir  string
		act  matchreplace.Action
	}{
		{"bad direction", "both", matchreplace.Action{Type: matchreplace.ActHeaderAdd, HeaderKey: "X"}},
		{"missing key", matchreplace.DirRequest, matchreplace.Action{Type: matchreplace.ActHeaderAdd}},
		{"unknown type", matchreplace.DirRequest, matchreplace.Action{Type: "magic"}},
		{"missing find", matchreplace.DirRequest, matchreplace.Action{Type: matchreplace.ActBodyRaw, Replace: "x"}},
		{"bad regex", matchreplace.DirRequest, matchreplace.Action{Type: matchreplace.ActBodyRegex, Regex: "("}},
	}
	for _, tc := range cases {
		if _, err := mgr.Add(tc.name, true, tc.dir, intercept.Spec{}, tc.act); err == nil {
			t.Errorf("%s: expected rejection", tc.name)
		}
	}
}
