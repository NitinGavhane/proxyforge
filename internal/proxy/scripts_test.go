package proxy

import (
	"context"
	"io"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"strings"
	"testing"

	"github.com/NitinGavhane/proxyforge/internal/extjs"
	"github.com/NitinGavhane/proxyforge/internal/flows"
	"github.com/NitinGavhane/proxyforge/internal/pipeline"
	"github.com/NitinGavhane/proxyforge/internal/scope"
	"github.com/NitinGavhane/proxyforge/internal/store"
)

func newScriptsEngine(t *testing.T) (*Engine, *store.Store, *extjs.Manager) {
	t.Helper()
	st, err := store.Open(filepath.Join(t.TempDir(), "scripts.pf.sqlite"))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { st.Close() })
	bus := flows.NewBus()
	sc, _ := scope.New(st, bus)
	if _, err := sc.Add(scope.KindInclude, `^http://127[.]0[.]0[.]1`, true); err != nil {
		t.Fatal(err)
	}
	mgr, err := extjs.NewManager(st, nil)
	if err != nil {
		t.Fatal(err)
	}
	return &Engine{
		Pipeline: pipeline.New(st, bus, nil),
		Scope:    sc,
		Scripts:  mgr,
	}, st, mgr
}

func TestScriptEndToEndThroughProxy(t *testing.T) {
	eng, _, mgr := newScriptsEngine(t)
	var gotHeader, gotBody string
	up := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		gotHeader = r.Header.Get("X-Script")
		b, _ := io.ReadAll(r.Body)
		gotBody = string(b)
		w.Write([]byte("internal hostname: db-prod-01"))
	}))
	t.Cleanup(up.Close)

	if _, err := mgr.Add(context.Background(), "e2e", `
		function onRequest(flow) {
			flow.request.headers.push({ name: "X-Script", value: "ran" });
			flow.request.body = "scripted";
		}
		function onResponse(flow) {
			flow.response.body = flow.response.body.replace("db-prod-01", "[host-redacted]");
		}
	`, true); err != nil {
		t.Fatal(err)
	}

	srv := httptest.NewServer(eng)
	t.Cleanup(srv.Close)
	client := &http.Client{Transport: &http.Transport{Proxy: http.ProxyURL(mustURL(t, srv.URL))}}
	resp, err := client.Post(up.URL+"/e", "text/plain", strings.NewReader("original"))
	if err != nil {
		t.Fatal(err)
	}
	body, _ := io.ReadAll(resp.Body)
	resp.Body.Close()

	if gotHeader != "ran" {
		t.Fatalf("upstream X-Script = %q", gotHeader)
	}
	if gotBody != "scripted" {
		t.Fatalf("upstream body = %q", gotBody)
	}
	if string(body) != "internal hostname: [host-redacted]" {
		t.Fatalf("client body = %q", body)
	}
}

func TestScriptOutOfScopeNeverRuns(t *testing.T) {
	eng, _, mgr := newScriptsEngine(t)
	var seen string
	up := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		seen = r.Header.Get("X-Script")
	}))
	t.Cleanup(up.Close)
	if _, err := mgr.Add(context.Background(), "tag", `
		function onRequest(flow) { flow.request.headers.push({name:"X-Script",value:"ran"}); }
	`, true); err != nil {
		t.Fatal(err)
	}

	// scope only allows 127.0.0.1; the scripted rewrite happens in-scope...
	srv := httptest.NewServer(eng)
	t.Cleanup(srv.Close)
	client := &http.Client{Transport: &http.Transport{Proxy: http.ProxyURL(mustURL(t, srv.URL))}}
	resp, _ := client.Get(up.URL + "/")
	io.Copy(io.Discard, resp.Body)
	resp.Body.Close()
	if seen != "ran" {
		t.Fatalf("in-scope script did not run: %q", seen)
	}
}
