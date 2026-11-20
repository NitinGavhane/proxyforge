package tools

import (
	"context"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/NitinGavhane/proxyforge/internal/proxy"
)

// compile-time: the concrete engine satisfies Sender
var _ Sender = (*proxy.Engine)(nil)

func TestDiscoveryFindsPlantedPaths(t *testing.T) {
	eng, st := newEngine(t)
	mux := http.NewServeMux()
	// planted interesting endpoints
	mux.HandleFunc("/admin", func(w http.ResponseWriter, r *http.Request) {
		w.Write([]byte("admin console here, much longer than the boring notfound body"))
	})
	mux.HandleFunc("/api/", func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(401)
		w.Write([]byte(`{"error":"unauthorized"}`))
	})
	// everything else: soft-404 with a fixed body
	notFound := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(404)
		w.Write([]byte("not found"))
	})
	mux.Handle("/", notFound)
	up := httptest.NewServer(mux)
	t.Cleanup(up.Close)

	d := NewDiscovery(st, eng)

	// short custom list keeps the test fast at the default rate
	job, err := d.Start(up.URL+"/", []string{"admin", "api/", "nope-nothing", "robots.txt"}, 20)
	if err != nil {
		t.Fatal(err)
	}
	deadline := time.Now().Add(15 * time.Second)
	for time.Now().Before(deadline) {
		snap, _ := d.Get(job.ID)
		if snap.State != "running" {
			break
		}
		time.Sleep(100 * time.Millisecond)
	}
	snap, err := d.Get(job.ID)
	if err != nil {
		t.Fatal(err)
	}
	if snap.State != "done" {
		t.Fatalf("job state = %s err=%s", snap.State, snap.Err)
	}
	if snap.Probed != 4 {
		t.Fatalf("probed = %d", snap.Probed)
	}
	verdicts := map[string]bool{}
	for _, r := range snap.Results {
		verdicts[r.Path] = r.Interesting
	}
	if !verdicts["admin"] {
		t.Errorf("/admin not flagged: %+v", snap.Results)
	}
	if !verdicts["api/"] {
		t.Errorf("/api/ (401) not flagged")
	}
	if verdicts["nope-nothing"] {
		t.Errorf("soft-404 flagged as interesting")
	}
	// probed endpoints land in the site map (aggregated from the probe
	// flows themselves)
	eps, _ := st.ListEndpoints(context.Background())
	paths := map[string]int{}
	for _, e := range eps {
		paths[e.Path]++
	}
	if paths["/admin"] == 0 || paths["/api/"] == 0 {
		t.Errorf("discovered paths missing from site map: %+v", eps)
	}
}

func TestDiscoveryStop(t *testing.T) {
	eng, st := newEngine(t)
	up := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(404)
	}))
	t.Cleanup(up.Close)

	d := NewDiscovery(st, eng)
	job, err := d.Start(up.URL+"/", DiscoveryWordlist, 1) // slow rate
	if err != nil {
		t.Fatal(err)
	}
	time.Sleep(700 * time.Millisecond) // a couple of probes at 1 rps
	if err := d.Stop(job.ID); err != nil {
		t.Fatal(err)
	}
	snap, _ := d.Get(job.ID)
	if snap.State != "stopped" {
		t.Fatalf("state = %s", snap.State)
	}
	if snap.Probed == snap.Total {
		t.Fatalf("stop came too late (all %d probed)", snap.Total)
	}
}

func TestDiscoveryOutOfScopeBaseErrors(t *testing.T) {
	eng, st := newEngine(t)
	d := NewDiscovery(st, eng)
	job, err := d.Start("http://blocked.example/", []string{"a", "b"}, 20)
	if err != nil {
		t.Fatal(err)
	}
	deadline := time.Now().Add(5 * time.Second)
	for time.Now().Before(deadline) {
		snap, _ := d.Get(job.ID)
		if snap.State != "running" {
			break
		}
		time.Sleep(50 * time.Millisecond)
	}
	snap, _ := d.Get(job.ID)
	if snap.State != "error" || !strings.Contains(snap.Err, "out of scope") {
		t.Fatalf("expected scope error, got state=%s err=%s", snap.State, snap.Err)
	}
}

func TestDiscoveryRejectsBadBase(t *testing.T) {
	eng, st := newEngine(t)
	d := NewDiscovery(st, eng)
	if _, err := d.Start("not a url", nil, 5); err == nil {
		t.Fatal("bad base accepted")
	}
	if _, err := d.Start("ftp://x/", nil, 5); err == nil {
		t.Fatal("non-http scheme accepted")
	}
}
