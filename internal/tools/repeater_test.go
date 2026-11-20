package tools

import (
	"context"
	"io"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"strings"
	"sync/atomic"
	"testing"

	"github.com/NitinGavhane/proxyforge/internal/flows"
	"github.com/NitinGavhane/proxyforge/internal/pipeline"
	"github.com/NitinGavhane/proxyforge/internal/proxy"
	"github.com/NitinGavhane/proxyforge/internal/scope"
	"github.com/NitinGavhane/proxyforge/internal/store"
)

func newEngine(t *testing.T) (*proxy.Engine, *store.Store) {
	t.Helper()
	st, err := store.Open(filepath.Join(t.TempDir(), "rep.pf.sqlite"))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { st.Close() })
	bus := flows.NewBus()
	sc, err := scope.New(st, bus)
	if err != nil {
		t.Fatal(err)
	}
	// permissive scope for the test origins (loopback)
	if _, err := sc.Add(scope.KindInclude, `^http://127[.]0[.]0[.]1`, true); err != nil {
		t.Fatal(err)
	}
	eng := &proxy.Engine{
		Pipeline: pipeline.New(st, bus, nil),
		Scope:    sc,
	}
	return eng, st
}

func TestRepeaterSendAndCapture(t *testing.T) {
	eng, st := newEngine(t)
	var seenPath, seenHdr, seenBody atomic.Value
	up := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		b, _ := io.ReadAll(r.Body)
		seenPath.Store(r.URL.RequestURI())
		seenHdr.Store(r.Header.Get("X-Repeater"))
		seenBody.Store(string(b))
		w.WriteHeader(200)
		_, _ = w.Write([]byte("repeater-ok"))
	}))
	t.Cleanup(up.Close)

	rep := NewRepeater(st, eng)
	tab, err := rep.NewTab(context.Background(), "t1", "")
	if err != nil {
		t.Fatal(err)
	}
	raw := "POST /probe?x=1 HTTP/1.1\nHost: " + strings.TrimPrefix(up.URL, "http://") + "\nX-Repeater: yes\nContent-Type: text/plain\n\nhello-body"
	res, err := rep.Send(context.Background(), tab, raw, false, 0)
	if err != nil {
		t.Fatal(err)
	}
	if res.Final.Response == nil || res.Final.Response.Status != 200 {
		t.Fatalf("final: %+v", res.Final.Response)
	}
	if string(res.Final.Response.Body) != "repeater-ok" {
		t.Errorf("body = %q", res.Final.Response.Body)
	}
	if seenPath.Load() != "/probe?x=1" {
		t.Errorf("origin saw path %v", seenPath.Load())
	}
	if seenHdr.Load() != "yes" || seenBody.Load() != "hello-body" {
		t.Errorf("origin saw hdr=%v body=%v", seenHdr.Load(), seenBody.Load())
	}
	// flow persisted with origin=repeater + tool_ref
	f, _ := st.GetFlow(context.Background(), res.Final.ID)
	if f.Origin != flows.OriginRepeater || f.ToolRef != tab {
		t.Fatalf("flow meta: origin=%s tool_ref=%d", f.Origin, f.ToolRef)
	}
	// endpoint aggregated into the site map
	eps, _ := st.ListEndpoints(context.Background())
	found := false
	for _, e := range eps {
		if e.Path == "/probe" && e.Source == "capture" {
			found = true
		}
	}
	if !found {
		t.Error("repeater send not aggregated into site map")
	}
	// tab history
	hist, err := rep.History(context.Background(), tab, 10)
	if err != nil || len(hist) != 1 {
		t.Fatalf("history: %v %+v", err, hist)
	}
}

func TestRepeaterFollowRedirects(t *testing.T) {
	eng, st := newEngine(t)
	up := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/start":
			http.Redirect(w, r, "/middle", 302)
		case "/middle":
			http.Redirect(w, r, "/final-landing", 302)
		case "/final-landing":
			_, _ = w.Write([]byte("landed"))
		default:
			http.NotFound(w, r)
		}
	}))
	t.Cleanup(up.Close)

	rep := NewRepeater(st, eng)
	tab, _ := rep.NewTab(context.Background(), "redir", "")
	raw := "POST /start HTTP/1.1\nHost: " + strings.TrimPrefix(up.URL, "http://") + "\nAuthorization: Bearer secret\n\norig-body"
	res, err := rep.Send(context.Background(), tab, raw, true, 10)
	if err != nil {
		t.Fatal(err)
	}
	if len(res.Hops) != 3 {
		t.Fatalf("hops = %d: %+v", len(res.Hops), res.Hops)
	}
	if res.Final.Request.Path != "/final-landing" {
		t.Fatalf("final path = %q", res.Final.Request.Path)
	}
	if string(res.Final.Response.Body) != "landed" {
		t.Fatalf("final body = %q", res.Final.Response.Body)
	}
	// 302 converts POST → GET and drops the body
	if res.Hops[1].Request.Method != "GET" || len(res.Hops[1].Request.Body) != 0 {
		t.Errorf("hop2: method=%s body=%q", res.Hops[1].Request.Method, res.Hops[1].Request.Body)
	}
	// each hop recorded in history
	hist, _ := rep.History(context.Background(), tab, 10)
	if len(hist) != 3 {
		t.Fatalf("history = %d", len(hist))
	}
}

func TestRepeaterRedirectDropsAuthCrossHost(t *testing.T) {
	eng, st := newEngine(t)
	var gotAuth atomic.Value
	target := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		gotAuth.Store(r.Header.Get("Authorization"))
		_, _ = w.Write([]byte("t"))
	}))
	t.Cleanup(target.Close)
	up := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		http.Redirect(w, r, target.URL+"/x", 302)
	}))
	t.Cleanup(up.Close)

	rep := NewRepeater(st, eng)
	tab, _ := rep.NewTab(context.Background(), "xhost", "")
	raw := "GET / HTTP/1.1\nHost: " + strings.TrimPrefix(up.URL, "http://") + "\nAuthorization: Bearer secret\n"
	if _, err := rep.Send(context.Background(), tab, raw, true, 5); err != nil {
		t.Fatal(err)
	}
	if gotAuth.Load() != "" {
		t.Fatal("Authorization leaked to a cross-host redirect target")
	}
}

func TestRepeaterOutOfScopeRefused(t *testing.T) {
	eng, st := newEngine(t)
	rep := NewRepeater(st, eng)
	tab, _ := rep.NewTab(context.Background(), "scope", "")
	raw := "GET / HTTP/1.1\nHost: blocked.example\n"
	res, err := rep.Send(context.Background(), tab, raw, false, 5)
	if err == nil || !strings.Contains(err.Error(), "out of scope") {
		t.Fatalf("expected gate refusal, got %v", err)
	}
	if res.Final == nil || !strings.Contains(res.Final.Err, "out of scope") {
		t.Fatal("refusal not recorded on the flow")
	}
	// audit row
	audit, _ := st.AuditJSONL(context.Background())
	if !strings.Contains(audit, "outbound_gate.refuse") {
		t.Fatal("refusal not audited")
	}
}

func TestRepeaterBadRawRejected(t *testing.T) {
	eng, st := newEngine(t)
	rep := NewRepeater(st, eng)
	tab, _ := rep.NewTab(context.Background(), "bad", "")
	if _, err := rep.Send(context.Background(), tab, "NOT A REQUEST", false, 5); err == nil {
		t.Fatal("bad raw accepted")
	}
}
