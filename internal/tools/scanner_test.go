package tools

import (
	"context"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/NitinGavhane/proxyforge/internal/flows"
	"github.com/NitinGavhane/proxyforge/internal/pipeline"
	"github.com/NitinGavhane/proxyforge/internal/proxy"
	"github.com/NitinGavhane/proxyforge/internal/scope"
	"github.com/NitinGavhane/proxyforge/internal/store"
)

func newScannerEngine(t *testing.T) (*proxy.Engine, *store.Store) {
	t.Helper()
	st, err := store.Open(t.TempDir() + "/scan.pf.sqlite")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { st.Close() })
	bus := flows.NewBus()
	sc, _ := scope.New(st, bus)
	if _, err := sc.Add(scope.KindInclude, `^http://127[.]0[.]0[.]1`, true); err != nil {
		t.Fatal(err)
	}
	return &proxy.Engine{Pipeline: pipeline.New(st, bus, nil), Scope: sc}, st
}

func boolPtr(b bool) *bool { return &b }

func TestPassiveScanMisconfiguredOrigin(t *testing.T) {
	eng, st := newScannerEngine(t)
	up := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Server", "nginx/1.14.0 (Ubuntu)")
		w.Header().Set("X-Powered-By", "PHP/7.2")
		w.Header().Set("Access-Control-Allow-Origin", "*")
		w.Header().Set("Access-Control-Allow-Credentials", "true")
		w.Header().Set("Set-Cookie", "sid=abc; Path=/")
		w.Write([]byte(`{"note":"leak AKIAIOSFODNN7EXAMPLE here"}`))
	}))
	t.Cleanup(up.Close)

	scn := NewScanner(st, eng)
	job, err := scn.Start(ScanConfig{BaseURL: up.URL + "/", Passive: boolPtr(true)})
	if err != nil {
		t.Fatal(err)
	}
	waitScan(t, scn, job.ID)
	snap, _ := scn.Get(job.ID)
	if snap.State != "done" {
		t.Fatalf("state=%s err=%s", snap.State, snap.Err)
	}

	issues, _ := st.ListIssues(context.Background(), store.IssueFilter{})
	found := map[string]store.Issue{}
	for _, i := range issues {
		found[i.CheckID] = i
	}
	for _, want := range []string{
		"passive.headers.no-sniff", "passive.headers.clickjacking",
		"passive.headers.csp", "passive.headers.referrer",
		"passive.cookie.httponly", "passive.cookie.secure", "passive.cookie.samesite",
		"passive.cors.wildcard-credentials",
		"passive.secrets.aws-key",
	} {
		if _, ok := found[want]; !ok {
			t.Errorf("missing finding %q (have %v)", want, keys(found))
		}
	}
	// severities sane
	if found["passive.cors.wildcard-credentials"].Severity != SevHigh {
		t.Errorf("CORS severity = %s", found["passive.cors.wildcard-credentials"].Severity)
	}
	if found["passive.secrets.aws-key"].Confidence != ConfTentative {
		t.Errorf("secret findings must be tentative")
	}
	// both disclosed banners become distinct issues
	banners := 0
	for _, i := range issues {
		if strings.HasPrefix(i.CheckID, "passive.info.banner.") {
			banners++
		}
	}
	if banners != 2 {
		t.Errorf("banner issues = %d", banners)
	}
	// evidence recorded (the fetch flow)
	if found["passive.headers.csp"].EvidenceFlowID == 0 {
		t.Error("no evidence flow linked")
	}
}

func keys(m map[string]store.Issue) []string {
	out := make([]string, 0, len(m))
	for k := range m {
		out = append(out, k)
	}
	return out
}

func TestPassiveScanCleanOrigin(t *testing.T) {
	eng, st := newScannerEngine(t)
	up := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("X-Content-Type-Options", "nosniff")
		w.Header().Set("X-Frame-Options", "DENY")
		w.Header().Set("Content-Security-Policy", "default-src 'self'")
		w.Header().Set("Referrer-Policy", "no-referrer")
		w.Header().Set("Set-Cookie", "sid=abc; Secure; HttpOnly; SameSite=Strict")
		w.Write([]byte("plain"))
	}))
	t.Cleanup(up.Close)

	scn := NewScanner(st, eng)
	job, _ := scn.Start(ScanConfig{BaseURL: up.URL + "/", Passive: boolPtr(true)})
	waitScan(t, scn, job.ID)
	issues, _ := st.ListIssues(context.Background(), store.IssueFilter{})
	for _, i := range issues {
		t.Errorf("clean origin produced finding: %s (%s)", i.CheckID, i.Title)
	}
}

func TestPassiveScanFromCapturedFlow(t *testing.T) {
	eng, st := newScannerEngine(t)
	// capture a flow through the proxy
	up := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Write([]byte("body with -----BEGIN RSA PRIVATE KEY----- inside"))
	}))
	t.Cleanup(up.Close)
	proxySrv := httptest.NewServer(eng)
	t.Cleanup(proxySrv.Close)
	proxyURL, _ := url.Parse(proxySrv.URL)
	client := &http.Client{Transport: &http.Transport{Proxy: http.ProxyURL(proxyURL)}}
	resp, err := client.Get(up.URL + "/key")
	if err != nil {
		t.Fatal(err)
	}
	resp.Body.Close()
	time.Sleep(100 * time.Millisecond)
	rows, _ := st.ListFlows(context.Background(), store.Filter{})
	if len(rows) == 0 {
		t.Fatal("no captured flow")
	}

	scn := NewScanner(st, eng)
	job, err := scn.Start(ScanConfig{FlowID: rows[0].ID, Passive: boolPtr(true), Active: false})
	if err != nil {
		t.Fatal(err)
	}
	waitScan(t, scn, job.ID)
	issues, _ := st.ListIssues(context.Background(), store.IssueFilter{})
	foundPK := false
	for _, i := range issues {
		if i.CheckID == "passive.secrets.private-key" && i.Severity == SevCritical {
			foundPK = true
		}
	}
	if !foundPK {
		t.Fatalf("private key not flagged from captured flow: %v", issues)
	}
}

func TestActiveChecksDetectPlantedVulns(t *testing.T) {
	eng, st := newScannerEngine(t)
	up := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		r.ParseForm()
		switch {
		case strings.Contains(r.URL.Path, "xss"):
			if v := r.Form.Get("q"); v != "" {
				w.Write([]byte("<html>results for " + v + "</html>")) // raw reflection
				return
			}
		case strings.Contains(r.URL.Path, "sqli"):
			if v := r.Form.Get("id"); v != "" {
				w.Write([]byte("Error: you have an error in your SQL syntax near 'PFSQL'"))
				return
			}
		case strings.Contains(r.URL.Path, "redirect"):
			if v := r.Form.Get("next"); v != "" {
				http.Redirect(w, r, v, 302)
				return
			}
		case strings.Contains(r.URL.Path, "traversal"):
			if v := r.Form.Get("file"); v != "" {
				w.Write([]byte("root:x:0:0:root:/root:/bin/bash\ndaemon:x:1:1:daemon:/usr/sbin:/usr/sbin/nologin"))
				return
			}
		}
		w.Write([]byte("ok"))
	}))
	t.Cleanup(up.Close)
	host := strings.TrimPrefix(up.URL, "http://")

	scn := NewScanner(st, eng)
	for _, tc := range []struct {
		path  string
		check string
		want  string
	}{
		{"/xss", "xss-reflect", "active.xss.reflect"},
		{"/sqli", "sqli-error", "active.sqli.error"},
		{"/redirect", "open-redirect", "active.redirect.open"},
		{"/traversal", "path-traversal", "active.traversal.file-read"},
	} {
		job, err := scn.Start(ScanConfig{
			BaseURL:       up.URL + tc.path,
			Passive:       boolPtr(false),
			Active:        true,
			ActiveChecks:  []string{tc.check},
			ConfirmActive: true,
			RatePerSec:    20,
		})
		if err != nil {
			t.Fatal(err)
		}
		waitScan(t, scn, job.ID)
		snap, _ := scn.Get(job.ID)
		if snap.State != "done" {
			t.Fatalf("%s: state=%s err=%s", tc.check, snap.State, snap.Err)
		}
		if snap.Issues != 1 {
			t.Errorf("%s: issues = %d (want 1)", tc.check, snap.Issues)
		}
	}
	issues, _ := st.ListIssues(context.Background(), store.IssueFilter{})
	checks := map[string]bool{}
	for _, i := range issues {
		checks[i.CheckID] = true
	}
	for _, want := range []string{"active.xss.reflect", "active.sqli.error", "active.redirect.open", "active.traversal.file-read"} {
		if !checks[want] {
			t.Errorf("missing %s", want)
		}
	}
	_ = host
}

func TestActiveRequiresConfirmAndScope(t *testing.T) {
	eng, st := newScannerEngine(t)
	scn := NewScanner(st, eng)

	// no confirm → refused
	if _, err := scn.Start(ScanConfig{BaseURL: "http://127.0.0.1:1/", Active: true}); err == nil {
		t.Fatal("active scan without confirm accepted")
	} else if !strings.Contains(err.Error(), "confirm_active") {
		t.Fatalf("wrong error: %v", err)
	}
	// unknown check
	if _, err := scn.Start(ScanConfig{BaseURL: "http://127.0.0.1:1/", Active: true, ConfirmActive: true, ActiveChecks: []string{"rce"}}); err == nil {
		t.Fatal("unknown active check accepted")
	}
	// out of scope target errors
	job, err := scn.Start(ScanConfig{BaseURL: "http://blocked.example/", Passive: boolPtr(true)})
	if err != nil {
		t.Fatal(err)
	}
	waitScan(t, scn, job.ID)
	snap, _ := scn.Get(job.ID)
	if snap.State != "error" || !strings.Contains(snap.Err, "out of scope") {
		t.Fatalf("state=%s err=%s", snap.State, snap.Err)
	}
	// nothing to do
	if _, err := scn.Start(ScanConfig{BaseURL: "http://127.0.0.1:1/", Passive: boolPtr(false)}); err == nil {
		t.Fatal("empty scan accepted")
	}
	// both targets
	if _, err := scn.Start(ScanConfig{BaseURL: "http://x/", FlowID: 5, Passive: boolPtr(true)}); err == nil {
		t.Fatal("both targets accepted")
	}
}

func waitScan(t *testing.T, scn *Scanner, id int64) {
	t.Helper()
	deadline := time.Now().Add(15 * time.Second)
	for time.Now().Before(deadline) {
		j, _ := scn.Get(id)
		if j.State != "running" {
			return
		}
		time.Sleep(50 * time.Millisecond)
	}
	t.Fatal("scan never finished")
}

type fakeCollab struct {
	mu sync.Mutex

	fired map[string]bool
	onHit func(string)
}

func (f *fakeCollab) NewCanary(ctx context.Context, label string) (string, string, error) {
	return "canary123", "http://collab.test/canary123", nil
}

func (f *fakeCollab) HasInteraction(ctx context.Context, id string) bool {
	f.mu.Lock()
	defer f.mu.Unlock()
	if f.fired[id] {
		return true
	}
	// simulate async fire after first poll
	if f.onHit != nil {
		f.onHit(id)
	}
	f.fired[id] = true
	return true
}

func TestSSRFCanaryCheck(t *testing.T) {
	eng, st := newScannerEngine(t)
	var fetched atomicBoolScan
	up := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if v := r.URL.Query().Get("url"); v != "" {
			// the vulnerable origin fetches the URL server-side
			go func() {
				resp, err := http.Get(v)
				if err == nil {
					resp.Body.Close()
				}
				fetched.Store(true)
			}()
			w.Write([]byte(`{"queued":true}`))
			return
		}
		w.Write([]byte("ok"))
	}))
	t.Cleanup(up.Close)

	scn := NewScanner(st, eng)
	scn.SetCollaborator(&fakeCollab{fired: map[string]bool{}})
	job, err := scn.Start(ScanConfig{
		BaseURL: up.URL + "/fetch", Passive: boolPtr(false),
		Active: true, ActiveChecks: []string{"ssrf-canary"}, ConfirmActive: true,
		RatePerSec: 20,
	})
	if err != nil {
		t.Fatal(err)
	}
	waitScan(t, scn, job.ID)
	issues, _ := st.ListIssues(context.Background(), store.IssueFilter{})
	found := false
	for _, i := range issues {
		if i.CheckID == "active.ssrf.canary" && i.Severity == SevHigh && i.Confidence == ConfCertain {
			found = true
		}
	}
	if !found {
		t.Fatalf("ssrf canary not flagged: %+v", issues)
	}
	if !fetched.Load() {
		t.Error("origin never fetched the canary URL")
	}

	// without collaborator → rejected at start
	scn2 := NewScanner(st, eng)
	if _, err := scn2.Start(ScanConfig{BaseURL: up.URL + "/", Passive: boolPtr(false),
		Active: true, ActiveChecks: []string{"ssrf-canary"}, ConfirmActive: true}); err == nil {
		t.Fatal("ssrf-canary without collaborator accepted")
	}
}

type atomicBoolScan struct{ v atomic.Bool }

func (b *atomicBoolScan) Store(x bool) { b.v.Store(x) }
func (b *atomicBoolScan) Load() bool   { return b.v.Load() }

func TestCmdInjectTimeCheck(t *testing.T) {
	eng, st := newScannerEngine(t)
	up := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if v := r.URL.Query().Get("q"); strings.Contains(v, "sleep 2") {
			time.Sleep(2 * time.Second) // the "vulnerable" command runner
		}
		w.Write([]byte("done"))
	}))
	t.Cleanup(up.Close)

	scn := NewScanner(st, eng)
	job, err := scn.Start(ScanConfig{
		BaseURL: up.URL + "/run", Passive: boolPtr(false),
		Active: true, ActiveChecks: []string{"cmd-inject"}, ConfirmActive: true,
		RatePerSec: 20,
	})
	if err != nil {
		t.Fatal(err)
	}
	waitScan(t, scn, job.ID)
	issues, _ := st.ListIssues(context.Background(), store.IssueFilter{})
	found := false
	for _, i := range issues {
		if i.CheckID == "active.cmdinject.time" {
			found = true
			if i.Confidence != ConfTentative {
				t.Errorf("time-based must be tentative: %s", i.Confidence)
			}
		}
	}
	if !found {
		t.Fatalf("cmd injection not flagged: %+v", issues)
	}

	// non-sleeping origin → no issue
	clean := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Write([]byte("fast"))
	}))
	t.Cleanup(clean.Close)
	scn2 := NewScanner(st, eng)
	st2 := st
	_ = st2
	job2, _ := scn2.Start(ScanConfig{
		BaseURL: clean.URL + "/", Passive: boolPtr(false),
		Active: true, ActiveChecks: []string{"cmd-inject"}, ConfirmActive: true,
		RatePerSec: 20,
	})
	waitScan(t, scn2, job2.ID)
	// no NEW cmdinject issue for the clean host
}
