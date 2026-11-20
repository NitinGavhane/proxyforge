package intercept

import (
	"context"
	"encoding/json"
	"path/filepath"
	"testing"
	"time"

	"github.com/NitinGavhane/proxyforge/internal/flows"
	"github.com/NitinGavhane/proxyforge/internal/store"
)

func newManager(t *testing.T) (*Manager, *store.Store) {
	t.Helper()
	st, err := store.Open(filepath.Join(t.TempDir(), "m.pf.sqlite"))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { st.Close() })
	m, err := New(st, nil)
	if err != nil {
		t.Fatal(err)
	}
	return m, st
}

func sampleFlow() *flows.Flow {
	return &flows.Flow{
		Request: &flows.Request{
			Method: "POST",
			Scheme: "https",
			Host:   "api.example.test",
			Port:   443,
			Path:   "/v1/login?next=/",
			Headers: flows.Headers{
				{Key: "Host", Value: "api.example.test"},
				{Key: "Content-Type", Value: "application/json"},
				{Key: "X-Token", Value: "abc123"},
			},
			Body: []byte(`{"user":"admin"}`),
		},
		Response: &flows.Response{
			Status:  302,
			Headers: flows.Headers{{Key: "Set-Cookie", Value: "sid=x"}},
			Body:    []byte("found"),
		},
	}
}

func TestMatchDisabled(t *testing.T) {
	m, _ := newManager(t)
	f := sampleFlow()
	if m.Match(f, false) {
		t.Fatal("disabled manager must not park")
	}
	_ = m.SetEnabled(true)
	if !m.Match(f, false) {
		t.Fatal("enabled manager with no rules parks everything (Burp semantics)")
	}
}

func TestMatchNoResponse(t *testing.T) {
	m, _ := newManager(t)
	_ = m.SetEnabled(true)
	_ = m.SetInterceptResponses(true)
	f := sampleFlow()
	f.Response = nil
	if m.Match(f, true) {
		t.Fatal("response phase must not park when no response present")
	}
}

func TestMatchRulePredicates(t *testing.T) {
	cases := []struct {
		name string
		spec Spec
		req  bool // park request?
		resp bool // park response?
	}{
		{"method match", Spec{Method: "POST"}, true, false},
		{"method mismatch", Spec{Method: "GET"}, false, false},
		{"host substring", Spec{Host: "api.example"}, true, false},
		{"host case-insensitive", Spec{Host: "API.EXAMPLE"}, true, false},
		// URL is conversation-level: a URL rule parks BOTH phases of matching
		// exchanges (header/body regexes apply per-phase message content).
		{"url regex", Spec{URLRegex: `^https://api\.example\.test/v1/`}, true, true},
		{"url regex miss", Spec{URLRegex: `/v2/`}, false, false},
		{"content type", Spec{ContentType: "application/json"}, true, false},
		{"header regex", Spec{HeaderRegex: `x-token: abc`}, true, false},
		{"header regex miss", Spec{HeaderRegex: `authorization:`}, false, false},
		{"body regex", Spec{BodyRegex: `admin`}, true, false},
		{"body regex miss", Spec{BodyRegex: `root`}, false, false},
		{"status regex response", Spec{StatusRegex: `^3\d\d$`}, false, true},
		{"status regex miss", Spec{StatusRegex: `^5\d\d$`}, false, false},
		{"combined", Spec{Method: "POST", URLRegex: "/login", BodyRegex: "admin"}, true, false},
		{"combined miss one", Spec{Method: "POST", URLRegex: "/login", BodyRegex: "nope"}, false, false},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			m, _ := newManager(t)
			_ = m.SetEnabled(true)
			_ = m.SetInterceptResponses(true)
			if _, err := m.AddRule("r", true, tc.spec); err != nil {
				t.Fatal(err)
			}
			f := sampleFlow()
			if got := m.Match(f, false); got != tc.req {
				t.Errorf("request phase: got %v want %v", got, tc.req)
			}
			if got := m.Match(f, true); got != tc.resp {
				t.Errorf("response phase: got %v want %v", got, tc.resp)
			}
		})
	}
}

func TestBadRegexRejected(t *testing.T) {
	m, _ := newManager(t)
	if _, err := m.AddRule("bad", true, Spec{URLRegex: "("}); err == nil {
		t.Fatal("invalid regex must be rejected")
	}
}

func TestDisabledRuleIgnored(t *testing.T) {
	m, _ := newManager(t)
	_ = m.SetEnabled(true)
	if _, err := m.AddRule("off", false, Spec{Method: "POST"}); err != nil {
		t.Fatal(err)
	}
	if m.Match(sampleFlow(), false) {
		t.Fatal("disabled rule must not park")
	}
}

func TestSettingsPersist(t *testing.T) {
	dir := filepath.Join(t.TempDir(), "s.pf.sqlite")
	st, err := store.Open(dir)
	if err != nil {
		t.Fatal(err)
	}
	bus := flows.NewBus()
	m1, err := New(st, bus)
	if err != nil {
		t.Fatal(err)
	}
	_ = m1.SetEnabled(true)
	_ = m1.SetInterceptResponses(true)
	st.Close()

	st2, _ := store.Open(dir)
	defer st2.Close()
	m2, err := New(st2, nil)
	if err != nil {
		t.Fatal(err)
	}
	if !m2.Enabled() || !m2.InterceptResponses() {
		t.Fatal("toggles not persisted")
	}
}

func TestRulesPersistAndDelete(t *testing.T) {
	dir := filepath.Join(t.TempDir(), "r.pf.sqlite")
	st, _ := store.Open(dir)
	m1, _ := New(st, nil)
	id, err := m1.AddRule("persisted", true, Spec{Method: "POST"})
	if err != nil {
		t.Fatal(err)
	}
	st.Close()

	st2, _ := store.Open(dir)
	defer st2.Close()
	m2, _ := New(st2, nil)
	rules := m2.RuleList()
	if len(rules) != 1 || rules[0].ID != id || rules[0].Spec.Method != "POST" {
		t.Fatalf("rule not persisted: %+v", rules)
	}
	if err := m2.DeleteRule(id); err != nil {
		t.Fatal(err)
	}
	if len(m2.RuleList()) != 0 {
		t.Fatal("rule not deleted")
	}
}

func TestRecoverMarksPendingRestarted(t *testing.T) {
	m, st := newManager(t)
	// simulate a daemon dying with an item parked: insert directly
	snap, err := json.Marshal(sampleFlow())
	if err != nil {
		t.Fatal(err)
	}
	id, err := st.InsertQueueItem(context.Background(), false, string(snap))
	if err != nil {
		t.Fatal(err)
	}
	n, err := m.Recover(context.Background())
	if err != nil || n != 1 {
		t.Fatalf("recover: n=%d err=%v", n, err)
	}
	pending, _ := st.PendingQueue(context.Background())
	if len(pending) != 0 {
		t.Fatalf("pending after recover: %+v", pending)
	}
	all, _ := st.ListQueue(context.Background(), nil)
	if len(all) != 1 || all[0].State != store.QueueRestarted {
		t.Fatalf("queue after recover: %+v", all)
	}
	_ = id
	_ = time.Now
}
