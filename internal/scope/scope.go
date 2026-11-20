// Package scope decides which targets belong to the engagement. Scope is the
// single source of truth for the pipeline (logging/interception filtering),
// the outbound gate (tool-origin enforcement), and the UI.
//
// Semantics: a target is in scope when it matches at least one enabled
// include rule (or no include rules exist — an unset scope logs everything)
// and no enabled exclude rule. Excludes always win.
package scope

import (
	"context"
	"fmt"
	"regexp"
	"strings"
	"sync"
	"sync/atomic"

	"github.com/NitinGavhane/proxyforge/internal/flows"
	"github.com/NitinGavhane/proxyforge/internal/store"
)

// Rule kinds.
const (
	KindInclude = "include"
	KindExclude = "exclude"
)

// Rule is a compiled scope rule.
type Rule struct {
	ID      int64
	Kind    string
	Pattern string
	Enabled bool
	re      *regexp.Regexp
}

// Manager owns the rule set and the out-of-scope counter.
type Manager struct {
	store *store.Store
	bus   *flows.Bus

	mu       sync.Mutex
	rules    []*Rule
	outCount atomic.Int64
}

// New builds a manager and loads persisted rules.
func New(st *store.Store, bus *flows.Bus) (*Manager, error) {
	m := &Manager{store: st, bus: bus}
	if err := m.Load(context.Background()); err != nil {
		return nil, err
	}
	return m, nil
}

// Load (re)reads rules from the store.
func (m *Manager) Load(ctx context.Context) error {
	rows, err := m.store.ListScopeRules(ctx)
	if err != nil {
		return err
	}
	m.mu.Lock()
	defer m.mu.Unlock()
	m.rules = nil
	for _, row := range rows {
		r, err := compileRule(row.Kind, row.Pattern)
		if err != nil {
			return fmt.Errorf("scope rule %d: %w", row.ID, err)
		}
		r.ID, r.Enabled = row.ID, row.Enabled
		m.rules = append(m.rules, r)
	}
	return nil
}

func compileRule(kind, pattern string) (*Rule, error) {
	if kind != KindInclude && kind != KindExclude {
		return nil, fmt.Errorf("kind must be %q or %q", KindInclude, KindExclude)
	}
	re, err := regexp.Compile(pattern)
	if err != nil {
		return nil, fmt.Errorf("pattern: %w", err)
	}
	return &Rule{Kind: kind, Pattern: pattern, Enabled: true, re: re}, nil
}

// Match reports whether rawURL (scheme://host[:port]/path) is in scope.
// Excludes always win; with no include rules everything not excluded is in
// scope. Stored flows keep the verdict they were captured with — scope
// changes are never applied retroactively.
func (m *Manager) Match(rawURL string) bool {
	m.mu.Lock()
	rules := m.rules
	m.mu.Unlock()

	for _, r := range rules {
		if r.Enabled && r.Kind == KindExclude && r.re.MatchString(rawURL) {
			return false
		}
	}
	hasInclude, matched := false, false
	for _, r := range rules {
		if r.Enabled && r.Kind == KindInclude {
			hasInclude = true
			if r.re.MatchString(rawURL) {
				matched = true
				break
			}
		}
	}
	return !hasInclude || matched
}

// MatchRequest is a convenience wrapper for flows.
func (m *Manager) MatchRequest(req *flows.Request) bool {
	if req == nil {
		return false
	}
	return m.Match(req.URL())
}

// CountOutOfScope registers one filtered exchange and returns the total.
func (m *Manager) CountOutOfScope() int64 { return m.outCount.Add(1) }

// OutOfScopeCount returns the filtered-exchange total.
func (m *Manager) OutOfScopeCount() int64 { return m.outCount.Load() }

// RuleView is the API projection.
type RuleView struct {
	ID      int64  `json:"id"`
	Kind    string `json:"kind"`
	Pattern string `json:"pattern"`
	Enabled bool   `json:"enabled"`
}

// List returns the rules.
func (m *Manager) List() []RuleView {
	m.mu.Lock()
	defer m.mu.Unlock()
	out := []RuleView{}
	for _, r := range m.rules {
		out = append(out, RuleView{ID: r.ID, Kind: r.Kind, Pattern: r.Pattern, Enabled: r.Enabled})
	}
	return out
}

// Add validates, persists, and reloads a rule.
func (m *Manager) Add(kind, pattern string, enabled bool) (int64, error) {
	if _, err := compileRule(kind, pattern); err != nil {
		return 0, err
	}
	id, err := m.store.InsertScopeRule(context.Background(), kind, pattern, enabled)
	if err != nil {
		return 0, err
	}
	return id, m.Load(context.Background())
}

// SetEnabled toggles a rule.
func (m *Manager) SetEnabled(id int64, enabled bool) error {
	if err := m.store.SetScopeEnabled(context.Background(), id, enabled); err != nil {
		return err
	}
	return m.Load(context.Background())
}

// Delete removes a rule.
func (m *Manager) Delete(id int64) error {
	if err := m.store.DeleteScopeRule(context.Background(), id); err != nil {
		return err
	}
	return m.Load(context.Background())
}

// PreviewRow is one sampled-history verdict for the UI.
type PreviewRow struct {
	Host    string `json:"host"`
	Path    string `json:"path"`
	RawURL  string `json:"url"`
	InScope bool   `json:"in_scope"`
}

// PreviewHistory evaluates the CURRENT rules against recent stored flows so
// the scope editor can show what a change would do before saving. URLs are
// rebuilt exactly like flows.Request.URL() (port included when non-default)
// so preview verdicts always match engine verdicts.
func (m *Manager) PreviewHistory(rows []store.FlowRow) []PreviewRow {
	out := make([]PreviewRow, 0, len(rows))
	for _, r := range rows {
		port := ""
		if r.Port != 0 && !((r.Scheme == "http" && r.Port == 80) || (r.Scheme == "https" && r.Port == 443)) {
			port = fmt.Sprintf(":%d", r.Port)
		}
		raw := fmt.Sprintf("%s://%s%s%s", r.Scheme, r.Host, port, r.Path)
		out = append(out, PreviewRow{
			Host: r.Host, Path: r.Path, RawURL: raw, InScope: m.Match(raw),
		})
	}
	return out
}

// TrimURLPrefix is a helper for display.
func TrimURLPrefix(raw string) string {
	return strings.TrimPrefix(strings.TrimPrefix(raw, "https://"), "http://")
}
