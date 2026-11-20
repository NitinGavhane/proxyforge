package scope

import (
	"context"
	"path/filepath"
	"testing"

	"github.com/NitinGavhane/proxyforge/internal/flows"
	"github.com/NitinGavhane/proxyforge/internal/store"
)

func newManager(t *testing.T) (*Manager, *store.Store) {
	t.Helper()
	st, err := store.Open(filepath.Join(t.TempDir(), "sc.pf.sqlite"))
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

func TestNoRulesEverythingInScope(t *testing.T) {
	m, _ := newManager(t)
	for _, u := range []string{
		"https://anything.example/", "http://10.0.0.1:8080/x", "ws://ws.example/chat",
	} {
		if !m.Match(u) {
			t.Errorf("%q should be in scope with no rules", u)
		}
	}
}

func TestIncludeExcludeSemantics(t *testing.T) {
	m, _ := newManager(t)
	// host-boundary anchored (a bare `^https://host` prefix would also match
	// host.evil.io — the UI preview surfaces this before saving)
	if _, err := m.Add(KindInclude, `^https://app\.example\.com(/|$)`, true); err != nil {
		t.Fatal(err)
	}
	if _, err := m.Add(KindInclude, `^http://api\.example\.com/`, true); err != nil {
		t.Fatal(err)
	}
	cases := map[string]bool{
		"https://app.example.com/login":    true,
		"http://api.example.com/v1/x":      true,
		"https://app.example.com.evil.io/": false, // anchored include
		"https://other.example.com/":       false,
		"http://api.example.com:8080/x":    false, // port differs from pattern
	}
	for u, want := range cases {
		if got := m.Match(u); got != want {
			t.Errorf("Match(%q) = %v, want %v", u, got, want)
		}
	}

	// excludes win over includes
	if _, err := m.Add(KindExclude, `/admin`, true); err != nil {
		t.Fatal(err)
	}
	if m.Match("https://app.example.com/admin") {
		t.Error("exclude must win over include")
	}
	if !m.Match("https://app.example.com/user") {
		t.Error("exclude over-matched")
	}
}

func TestDisabledRulesIgnored(t *testing.T) {
	m, _ := newManager(t)
	id, err := m.Add(KindInclude, `^https://only\.example`, true)
	if err != nil {
		t.Fatal(err)
	}
	if m.Match("http://other.example/") {
		t.Fatal("include should restrict")
	}
	if err := m.SetEnabled(id, false); err != nil {
		t.Fatal(err)
	}
	if !m.Match("http://other.example/") {
		t.Fatal("disabled include must not restrict")
	}
}

func TestInvalidPatternRejected(t *testing.T) {
	m, _ := newManager(t)
	if _, err := m.Add(KindInclude, "(", true); err == nil {
		t.Fatal("bad regex accepted")
	}
	if _, err := m.Add("sideways", "x", true); err == nil {
		t.Fatal("bad kind accepted")
	}
}

func TestPersistenceAndCounter(t *testing.T) {
	dir := filepath.Join(t.TempDir(), "p.pf.sqlite")
	st, _ := store.Open(dir)
	m1, _ := New(st, nil)
	id, err := m1.Add(KindExclude, `^https://ads\.example`, true)
	if err != nil {
		t.Fatal(err)
	}
	st.Close()

	st2, _ := store.Open(dir)
	defer st2.Close()
	m2, err := New(st2, nil)
	if err != nil {
		t.Fatal(err)
	}
	rules := m2.List()
	if len(rules) != 1 || rules[0].ID != id || rules[0].Kind != KindExclude {
		t.Fatalf("rules not persisted: %+v", rules)
	}
	if m2.Match("https://ads.example/x") {
		t.Fatal("persisted exclude not applied")
	}
	// counter
	if m2.OutOfScopeCount() != 0 {
		t.Fatal("counter should start at zero")
	}
	m2.CountOutOfScope()
	m2.CountOutOfScope()
	if m2.OutOfScopeCount() != 2 {
		t.Fatal("counter broken")
	}
}

func TestPreviewHistoryMatchesEngineTruth(t *testing.T) {
	m, _ := newManager(t)
	if _, err := m.Add(KindInclude, `^https://in\.example`, true); err != nil {
		t.Fatal(err)
	}
	rows := []store.FlowRow{
		{Scheme: "https", Host: "in.example", Path: "/a"},
		{Scheme: "http", Host: "out.example", Path: "/b"},
		{Scheme: "http", Host: "porty.example", Port: 8080, Path: "/c"},
	}
	prev := m.PreviewHistory(rows)
	if len(prev) != 3 {
		t.Fatalf("preview rows = %d", len(prev))
	}
	// non-default ports must be included so verdicts match the engine
	if prev[2].RawURL != "http://porty.example:8080/c" {
		t.Errorf("port dropped from preview URL: %q", prev[2].RawURL)
	}
	// preview verdicts must equal engine verdicts on the same URLs
	for i, p := range prev {
		if p.InScope != m.Match(p.RawURL) {
			t.Errorf("preview[%d] disagrees with Match", i)
		}
		if p.InScope != m.MatchRequest(&flows.Request{
			Scheme: rows[i].Scheme, Host: rows[i].Host, Port: rows[i].Port, Path: rows[i].Path,
		}) {
			t.Errorf("preview[%d] disagrees with the engine URL builder", i)
		}
	}
	if !prev[0].InScope || prev[1].InScope {
		t.Errorf("preview verdicts wrong: %+v", prev)
	}
}

func TestMatchRequestHelper(t *testing.T) {
	m, _ := newManager(t)
	req := &flows.Request{Method: "GET", Scheme: "https", Host: "h.example", Port: 443, Path: "/x"}
	if !m.MatchRequest(req) {
		t.Fatal("nil-manager semantics broken")
	}
	if m.MatchRequest(nil) {
		t.Fatal("nil request must be out of scope")
	}
	_ = context.Background
}
