package tools

import (
	"context"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/NitinGavhane/proxyforge/internal/flows"
	"github.com/NitinGavhane/proxyforge/internal/pipeline"
	"github.com/NitinGavhane/proxyforge/internal/proxy"
	"github.com/NitinGavhane/proxyforge/internal/scope"
	"github.com/NitinGavhane/proxyforge/internal/store"
)

func TestParsePositions(t *testing.T) {
	raw := "GET /§id§/x HTTP/1.1\nHost: h\nX-§name§: v§\n"
	pos := ParsePositions(raw)
	if len(pos) != 2 {
		t.Fatalf("positions = %+v", pos)
	}
	if pos[0].Name != "id" || pos[1].Name != "name" {
		t.Errorf("names: %+v", pos)
	}
	// markers slice out cleanly
	out := Render(raw, pos, []string{"1", "Y"})
	if !strings.Contains(out, "GET /1/x HTTP/1.1") || !strings.Contains(out, "X-Y: v§") {
		t.Errorf("render: %q", out)
	}
	// no markers → no positions; render is identity
	if p := ParsePositions("plain"); len(p) != 0 {
		t.Errorf("plain: %+v", p)
	}
	// unbalanced marker ignored
	if p := ParsePositions("a § b"); len(p) != 0 {
		t.Errorf("unbalanced: %+v", p)
	}
}

func TestPayloadGenerators(t *testing.T) {
	list, err := (PayloadSet{Type: "list", Items: []string{"a", "b"}}).Generate()
	if err != nil || len(list) != 2 {
		t.Fatalf("list: %v %v", list, err)
	}
	nulls, _ := (PayloadSet{Type: "null"}).Generate()
	if len(nulls) != 1 || nulls[0] != "" {
		t.Fatalf("null: %v", nulls)
	}
	nums, err := (PayloadSet{Type: "numbers", From: 1, To: 5, Step: 2}).Generate()
	if err != nil || strings.Join(nums, ",") != "1,3,5" {
		t.Fatalf("numbers: %v %v", nums, err)
	}
	if _, err := (PayloadSet{Type: "numbers", From: 5, To: 1}).Generate(); err == nil {
		t.Error("reversed range accepted")
	}
	brute, err := (PayloadSet{Type: "bruteforcer", Charset: "ab", MinLen: 1, MaxLen: 2}).Generate()
	if err != nil || len(brute) != 6 { // a b aa ab ba bb
		t.Fatalf("brute: %v (%d) err=%v", brute, len(brute), err)
	}
	if _, err := (PayloadSet{Type: "bruteforcer", MinLen: 1, MaxLen: 5}).Generate(); err == nil {
		t.Error("oversized brute accepted")
	}
	if _, err := (PayloadSet{Type: "warp"}).Generate(); err == nil {
		t.Error("unknown type accepted")
	}
	if _, err := (PayloadSet{Type: "list"}).Generate(); err == nil {
		t.Error("empty list accepted")
	}
}

// exact request sets per attack mode — the P3 exit criteria
func TestAttackMatrices(t *testing.T) {
	raw := "GET /§a§/§b§ HTTP/1.1\nHost: h\n"
	pos := ParsePositions(raw)
	A := PayloadSet{Type: "list", Items: []string{"1", "2"}}
	B := PayloadSet{Type: "list", Items: []string{"x", "y", "z"}}

	m, err := buildPayloadMatrix("sniper", raw, pos, []PayloadSet{A})
	if err != nil {
		t.Fatal(err)
	}
	if len(m) != 4 { // 2 positions × 2 payloads
		t.Fatalf("sniper rows = %d", len(m))
	}
	// sniper fills one position at a time; the other stays marked
	if Render(raw, pos, m[0]) != "GET /1/§b§ HTTP/1.1\nHost: h\n" {
		t.Errorf("sniper[0]: %q", Render(raw, pos, m[0]))
	}
	if Render(raw, pos, m[2]) != "GET /§a§/1 HTTP/1.1\nHost: h\n" {
		t.Errorf("sniper[2]: %q", Render(raw, pos, m[2]))
	}

	m, err = buildPayloadMatrix("battering_ram", raw, pos, []PayloadSet{A})
	if err != nil || len(m) != 2 {
		t.Fatalf("ram: %v %v", m, err)
	}
	if Render(raw, pos, m[1]) != "GET /2/2 HTTP/1.1\nHost: h\n" {
		t.Errorf("ram[1]: %q", Render(raw, pos, m[1]))
	}

	m, err = buildPayloadMatrix("pitchfork", raw, pos, []PayloadSet{A, B})
	if err != nil || len(m) != 2 {
		t.Fatalf("pitchfork: %d %v", len(m), err)
	}
	if Render(raw, pos, m[0]) != "GET /1/x HTTP/1.1\nHost: h\n" ||
		Render(raw, pos, m[1]) != "GET /2/y HTTP/1.1\nHost: h\n" {
		t.Errorf("pitchfork rows wrong")
	}

	m, err = buildPayloadMatrix("cluster_bomb", raw, pos, []PayloadSet{A, B})
	if err != nil || len(m) != 6 {
		t.Fatalf("cluster: %d %v", len(m), err)
	}
	first := Render(raw, pos, m[0])
	last := Render(raw, pos, m[5])
	if first != "GET /1/x HTTP/1.1\nHost: h\n" || last != "GET /2/z HTTP/1.1\nHost: h\n" {
		t.Errorf("cluster bounds: %q … %q", first, last)
	}

	if _, err := buildPayloadMatrix("pitchfork", raw, pos, []PayloadSet{A}); err == nil {
		t.Error("set-count mismatch accepted")
	}
	if _, err := buildPayloadMatrix("bogus", raw, pos, []PayloadSet{A}); err == nil {
		t.Error("unknown attack type accepted")
	}
}

func newIntruderEngine(t *testing.T) (*proxy.Engine, *store.Store) {
	t.Helper()
	st, err := store.Open(t.TempDir() + "/int.pf.sqlite")
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

func TestIntruderClusterBombEndToEnd(t *testing.T) {
	eng, st := newIntruderEngine(t)
	var seen []string
	var mu = make(chan struct{}, 1)
	mu <- struct{}{}
	up := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		body, _ := io.ReadAll(r.Body)
		<-mu
		seen = append(seen, r.URL.Path+"|"+string(body))
		mu <- struct{}{}
		if strings.Contains(r.URL.Path, "admin") {
			w.Write([]byte(`{"user":"admin","token":"tok-12345"}`))
			return
		}
		w.Write([]byte(`{"user":"nobody"}`))
	}))
	t.Cleanup(up.Close)

	in := NewIntruder(eng)
	raw := "POST /§user§ HTTP/1.1\nHost: " + strings.TrimPrefix(up.URL, "http://") + "\nContent-Type: application/json\n\n{\"pw\":\"§pw§\"}"
	job, err := in.Start(AttackConfig{
		AttackType:  "cluster_bomb",
		Raw:         raw,
		PayloadSets: []PayloadSet{{Type: "list", Items: []string{"admin", "user"}}, {Type: "list", Items: []string{"f", "g"}}},
		Match:       []GrepSpec{{Name: "admin-hit", Regex: `"user":"admin"`}},
		Extract:     []GrepSpec{{Name: "token", Regex: `"token":"([^"]+)"`}},
		RatePerSec:  20,
	})
	if err != nil {
		t.Fatal(err)
	}
	waitJob(t, in, job.ID)
	snap, _ := in.Get(job.ID)
	if snap.State != "done" || snap.Sent != 4 {
		t.Fatalf("state=%s sent=%d err=%s", snap.State, snap.Sent, snap.Err)
	}
	// flows captured with origin=intruder
	rows, _ := st.ListFlows(context.Background(), store.Filter{Limit: 500})
	intruderCount := 0
	for _, r := range rows {
		if r.Origin == flows.OriginIntruder {
			intruderCount++
		}
	}
	if intruderCount != 4 {
		t.Fatalf("intruder flows = %d", intruderCount)
	}
	// grep: admin row matched and token extracted
	var adminRes *IntruderResult
	for i := range snap.Results {
		if snap.Results[i].Payloads[0] == "admin" {
			adminRes = &snap.Results[i]
		}
	}
	if adminRes == nil || adminRes.Matches["admin-hit"] == "" {
		t.Fatalf("grep match missing: %+v", snap.Results)
	}
	if adminRes.Extracts["token"] != "tok-12345" {
		t.Fatalf("extract wrong: %+v", adminRes.Extracts)
	}
	// upstream saw exact substitutions
	<-mu
	if len(seen) != 4 {
		t.Fatalf("upstream saw %d: %v", len(seen), seen)
	}
	want := map[string]bool{
		"/admin|{\"pw\":\"f\"}": true, "/admin|{\"pw\":\"g\"}": true,
		"/user|{\"pw\":\"f\"}": true, "/user|{\"pw\":\"g\"}": true,
	}
	for _, s := range seen {
		if !want[s] {
			t.Errorf("unexpected upstream request %q", s)
		}
	}
	mu <- struct{}{}
}

func waitJob(t *testing.T, in *Intruder, id int64) {
	t.Helper()
	deadline := time.Now().Add(20 * time.Second)
	for time.Now().Before(deadline) {
		j, _ := in.Get(id)
		if j.State != "running" {
			return
		}
		time.Sleep(50 * time.Millisecond)
	}
	t.Fatal("intruder job never finished")
}

func TestIntruderRateLimitHonored(t *testing.T) {
	eng, _ := newIntruderEngine(t)
	up := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {}))
	t.Cleanup(up.Close)

	in := NewIntruder(eng)
	raw := "GET /§n§ HTTP/1.1\nHost: " + strings.TrimPrefix(up.URL, "http://") + "\n"
	started := time.Now()
	job, err := in.Start(AttackConfig{
		AttackType:  "sniper",
		Raw:         raw,
		PayloadSets: []PayloadSet{{Type: "numbers", From: 1, To: 5}},
		RatePerSec:  10, // 5 requests at 10 rps → ≥ 0.4s
	})
	if err != nil {
		t.Fatal(err)
	}
	waitJob(t, in, job.ID)
	elapsed := time.Since(started)
	if elapsed < 350*time.Millisecond {
		t.Fatalf("rate not honored: %d requests in %v", job.Sent, elapsed)
	}
}

func TestIntruderStopAndScope(t *testing.T) {
	eng, _ := newIntruderEngine(t)
	up := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {}))
	t.Cleanup(up.Close)
	in := NewIntruder(eng)

	// stop mid-attack (numbers 1..50 at 5 rps ≈ 10s)
	job, err := in.Start(AttackConfig{
		AttackType:  "sniper",
		Raw:         "GET /§n§ HTTP/1.1\nHost: " + strings.TrimPrefix(up.URL, "http://") + "\n",
		PayloadSets: []PayloadSet{{Type: "numbers", From: 1, To: 50}},
		RatePerSec:  5,
	})
	if err != nil {
		t.Fatal(err)
	}
	time.Sleep(800 * time.Millisecond)
	if err := in.Stop(job.ID); err != nil {
		t.Fatal(err)
	}
	snap, _ := in.Get(job.ID)
	if snap.State != "stopped" || snap.Sent >= snap.Total {
		t.Fatalf("state=%s sent=%d/%d", snap.State, snap.Sent, snap.Total)
	}

	// out of scope target errors immediately
	job2, err := in.Start(AttackConfig{
		AttackType:  "sniper",
		Raw:         "GET /§n§ HTTP/1.1\nHost: blocked.example\n",
		PayloadSets: []PayloadSet{{Type: "list", Items: []string{"a"}}},
	})
	if err != nil {
		t.Fatal(err)
	}
	waitJob(t, in, job2.ID)
	snap2, _ := in.Get(job2.ID)
	if snap2.State != "error" || !strings.Contains(snap2.Err, "out of scope") {
		t.Fatalf("state=%s err=%s", snap2.State, snap2.Err)
	}

	// no positions rejected
	if _, err := in.Start(AttackConfig{AttackType: "sniper", Raw: "GET / HTTP/1.1\nHost: h\n", PayloadSets: []PayloadSet{{Type: "null"}}}); err == nil {
		t.Fatal("positionless template accepted")
	}
}
