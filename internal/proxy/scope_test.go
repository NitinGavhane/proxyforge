package proxy

import (
	"context"
	"io"
	"net/http"
	"net/http/httptest"
	"net/url"
	"path/filepath"
	"strconv"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/NitinGavhane/proxyforge/internal/flows"
	"github.com/NitinGavhane/proxyforge/internal/intercept"
	"github.com/NitinGavhane/proxyforge/internal/matchreplace"
	"github.com/NitinGavhane/proxyforge/internal/pipeline"
	"github.com/NitinGavhane/proxyforge/internal/scope"
	"github.com/NitinGavhane/proxyforge/internal/store"
)

func newScopeEngine(t *testing.T) (*scope.Manager, *httptest.Server, *store.Store) {
	t.Helper()
	st, err := store.Open(filepath.Join(t.TempDir(), "sc.pf.sqlite"))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { st.Close() })
	sc, err := scope.New(st, flows.NewBus())
	if err != nil {
		t.Fatal(err)
	}
	eng := &Engine{
		Pipeline: pipeline.New(st, flows.NewBus(), nil),
		Scope:    sc,
	}
	proxySrv := httptest.NewServer(eng)
	t.Cleanup(proxySrv.Close)
	return sc, proxySrv, st
}

func scopeClient(t *testing.T, proxySrv *httptest.Server) *http.Client {
	t.Helper()
	return &http.Client{
		Transport: &http.Transport{Proxy: http.ProxyURL(mustURL(t, proxySrv.URL))},
		Timeout:   10 * time.Second,
	}
}

func TestOutOfScopePassesButNotLogged(t *testing.T) {
	sc, proxySrv, st := newScopeEngine(t)
	var upstream atomic.Bool
	up := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		upstream.Store(true)
		_, _ = w.Write([]byte("public"))
	}))
	t.Cleanup(up.Close)

	// scope: only the target's host:port; the test upstream is on another port
	if _, err := sc.Add(scope.KindInclude, `^http://in-scope\.example`, true); err != nil {
		t.Fatal(err)
	}

	client := scopeClient(t, proxySrv)
	resp, err := client.Get(up.URL + "/outside")
	if err != nil {
		t.Fatalf("out-of-scope traffic must still pass through: %v", err)
	}
	body, _ := io.ReadAll(resp.Body)
	resp.Body.Close()
	if string(body) != "public" || !upstream.Load() {
		t.Fatalf("pass-through broken: %q %v", body, upstream.Load())
	}

	time.Sleep(100 * time.Millisecond) // any async save would land by now
	n, _ := st.CountFlows(context.Background())
	if n != 0 {
		t.Fatalf("out-of-scope flow was logged: %d rows", n)
	}
	if got := sc.OutOfScopeCount(); got != 1 {
		t.Fatalf("counter = %d, want 1", got)
	}
}

func TestInScopeLogged(t *testing.T) {
	sc, proxySrv, st := newScopeEngine(t)
	up := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, _ = w.Write([]byte("ok"))
	}))
	t.Cleanup(up.Close)
	if _, err := sc.Add(scope.KindInclude, `^http://127\.0\.0\.1`, true); err != nil {
		t.Fatal(err)
	}
	client := scopeClient(t, proxySrv)
	resp, err := client.Get(up.URL + "/inside")
	if err != nil {
		t.Fatal(err)
	}
	resp.Body.Close()
	deadline := time.Now().Add(2 * time.Second)
	for time.Now().Before(deadline) {
		if n, _ := st.CountFlows(context.Background()); n == 1 {
			return
		}
		time.Sleep(10 * time.Millisecond)
	}
	t.Fatal("in-scope flow not logged")
}

func TestOutOfScopeNotInterceptedOrModified(t *testing.T) {
	st, err := store.Open(filepath.Join(t.TempDir(), "sci.pf.sqlite"))
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
	mr, err := matchreplace.New(st, bus)
	if err != nil {
		t.Fatal(err)
	}
	if err := icept.SetEnabled(true); err != nil {
		t.Fatal(err)
	}
	if _, err := mr.Add("tag", true, matchreplace.DirRequest, intercept.Spec{},
		matchreplace.Action{Type: matchreplace.ActHeaderAdd, HeaderKey: "X-MR", HeaderValue: "applied"}); err != nil {
		t.Fatal(err)
	}
	var sawHeader atomic.Bool
	up := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		sawHeader.Store(r.Header.Get("X-MR") == "applied")
	}))
	t.Cleanup(up.Close)

	eng := &Engine{
		Pipeline:     pipeline.New(st, bus, nil),
		Scope:        sc,
		Intercept:    icept,
		MatchReplace: mr,
	}
	proxySrv := httptest.NewServer(eng)
	t.Cleanup(proxySrv.Close)

	if _, err := sc.Add(scope.KindInclude, `^http://in-scope\.only`, true); err != nil {
		t.Fatal(err)
	}
	client := scopeClient(t, proxySrv)

	// out-of-scope: no parking, no modification
	resp, err := client.Get(up.URL + "/outside")
	if err != nil {
		t.Fatalf("request failed: %v", err)
	}
	resp.Body.Close()
	if icept.PendingLen() != 0 {
		t.Fatal("out-of-scope request was intercepted")
	}
	if sawHeader.Load() {
		t.Fatal("out-of-scope request was modified by match & replace")
	}
	if n, _ := st.CountFlows(context.Background()); n != 0 {
		t.Fatalf("out-of-scope logged: %d rows", n)
	}
}

func TestScopeChangesNotRetroactive(t *testing.T) {
	sc, proxySrv, st := newScopeEngine(t)
	up := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {}))
	t.Cleanup(up.Close)
	client := scopeClient(t, proxySrv)

	resp, _ := client.Get(up.URL + "/first")
	resp.Body.Close()
	deadline := time.Now().Add(2 * time.Second)
	for time.Now().Before(deadline) {
		if n, _ := st.CountFlows(context.Background()); n == 1 {
			break
		}
		time.Sleep(10 * time.Millisecond)
	}
	if n, _ := st.CountFlows(context.Background()); n != 1 {
		t.Fatal("first flow not captured")
	}

	// now restrict scope — the stored flow must remain visible
	if _, err := sc.Add(scope.KindInclude, `^https://elsewhere\.example`, true); err != nil {
		t.Fatal(err)
	}
	rows, _ := st.ListFlows(context.Background(), store.Filter{})
	if len(rows) != 1 {
		t.Fatalf("stored flow vanished after scope change: %d rows", len(rows))
	}
	f, _ := st.GetFlow(context.Background(), rows[0].ID)
	if !f.InScope {
		t.Fatal("stored verdict must keep the capture-time value")
	}
}

func TestOutboundGateRefusesToolOrigins(t *testing.T) {
	sc, _, st := newScopeEngine(t)
	up := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, _ = w.Write([]byte("ok"))
	}))
	t.Cleanup(up.Close)

	if _, err := sc.Add(scope.KindInclude, `^http://allowed\.example`, true); err != nil {
		t.Fatal(err)
	}
	// the in-scope probe target (loopback test upstream)
	if _, err := sc.Add(scope.KindInclude, `^http://127\.0\.0\.1`, true); err != nil {
		t.Fatal(err)
	}

	eng := &Engine{
		Pipeline: pipeline.New(st, flows.NewBus(), nil),
		Scope:    sc,
	}

	// synthetic tool origin, out of scope → refused before any bytes leave
	blocked := &flows.Flow{
		Origin: flows.OriginRepeater,
		Request: &flows.Request{
			Method: "GET", Scheme: "http", Host: "blocked.example", Port: 80, Path: "/x",
		},
	}
	err := eng.SendToolFlow(blocked)
	if err == nil {
		t.Fatal("out-of-scope tool flow must be refused")
	}
	if !strings.Contains(err.Error(), "out of scope") {
		t.Fatalf("unexpected error: %v", err)
	}
	var gateErr *OutOfScopeError
	if !errorsAs(err, &gateErr) {
		t.Fatalf("must be OutOfScopeError: %T", err)
	}
	// refusal recorded on the flow + audit row
	rows, _ := st.ListFlows(context.Background(), store.Filter{})
	if len(rows) != 1 || rows[0].Err == "" || rows[0].Origin != flows.OriginRepeater {
		t.Fatalf("refusal flow wrong: %+v", rows)
	}
	audit, _ := st.AuditJSONL(context.Background())
	if !strings.Contains(audit, "outbound_gate.refuse") {
		t.Fatal("gate refusal not audited")
	}

	// in-scope tool origin → allowed, response captured
	allowed := &flows.Flow{
		Origin: flows.OriginScanner,
		Request: &flows.Request{
			Method: "GET", Scheme: "http", Host: hostOf(up.URL), Port: portOf(up.URL), Path: "/probe",
			Headers: flows.Headers{{Key: "Host", Value: hostOf(up.URL)}},
		},
	}
	if err := eng.SendToolFlow(allowed); err != nil {
		t.Fatalf("in-scope tool flow failed: %v", err)
	}
	if allowed.Response == nil || allowed.Response.Status != 200 {
		t.Fatalf("tool response missing: %+v", allowed.Response)
	}
	f, _ := st.GetFlow(context.Background(), 2)
	if f == nil || f.Origin != flows.OriginScanner || !f.InScope {
		t.Fatalf("tool flow not persisted correctly: %+v", f)
	}
}

func errorsAs(err error, target *(*OutOfScopeError)) bool {
	if o, ok := err.(*OutOfScopeError); ok {
		*target = o
		return true
	}
	return false
}

func hostOf(raw string) string {
	u, err := url.Parse(raw)
	if err != nil {
		return ""
	}
	return u.Hostname()
}

func portOf(raw string) int {
	u, err := url.Parse(raw)
	if err != nil {
		return 0
	}
	if p := u.Port(); p != "" {
		if n, err := strconv.Atoi(p); err == nil {
			return n
		}
	}
	return 0
}
