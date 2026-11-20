// Package matchreplace applies automatic request/response modifications
// (header ops, regex body rewrites with capture groups, raw byte replaces)
// in the pipeline before interception. Rules share the intercept predicate
// model and run in stable id order.
package matchreplace

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"regexp"
	"sync"
	"time"

	"github.com/NitinGavhane/proxyforge/internal/flows"
	"github.com/NitinGavhane/proxyforge/internal/intercept"
	"github.com/NitinGavhane/proxyforge/internal/store"
)

// Directions.
const (
	DirRequest  = "request"
	DirResponse = "response"
)

// Action types.
const (
	ActHeaderSet    = "header_set"    // HeaderKey = HeaderValue (replaces all)
	ActHeaderAdd    = "header_add"    // HeaderKey: HeaderValue appended
	ActHeaderRemove = "header_remove" // HeaderKey deleted
	ActBodyRegex    = "body_regex"    // Regex → Replacement ($1 capture groups)
	ActBodyRaw      = "body_raw"      // literal Find → Replace
)

// Action is what a rule does when its predicate matches.
type Action struct {
	Type        string `json:"type"`
	HeaderKey   string `json:"header_key,omitempty"`
	HeaderValue string `json:"header_value,omitempty"`
	Regex       string `json:"regex,omitempty"`
	Replacement string `json:"replacement,omitempty"`
	Find        string `json:"find,omitempty"`
	Replace     string `json:"replace,omitempty"`
}

// Rule is a compiled match & replace rule.
type Rule struct {
	ID        int64
	Name      string
	Enabled   bool
	Direction string
	Action    Action
	Hits      int64

	matcher  *intercept.Rule
	matchAll bool // zero predicate: applies to every flow in its direction
	bodyRe   *regexp.Regexp
}

// specEmpty reports whether no predicate field is set.
func specEmpty(s intercept.Spec) bool {
	return s.Method == "" && s.Host == "" && s.URLRegex == "" &&
		s.ContentType == "" && s.HeaderRegex == "" && s.BodyRegex == "" &&
		s.StatusRegex == ""
}

// MatchPreview is a recent-hit record for the UI.
type MatchPreview struct {
	TS    int64  `json:"ts"`
	Where string `json:"where"` // host + path
	Note  string `json:"note"`  // short description of the applied action
}

// Manager owns the rule set, hit counters, and recent-match previews.
type Manager struct {
	store *store.Store
	bus   *flows.Bus

	mu     sync.Mutex
	rules  []*Rule
	recent map[int64][]MatchPreview
}

const recentCap = 5

// New builds a manager and loads persisted rules.
func New(st *store.Store, bus *flows.Bus) (*Manager, error) {
	m := &Manager{store: st, bus: bus, recent: map[int64][]MatchPreview{}}
	if err := m.load(context.Background()); err != nil {
		return nil, err
	}
	return m, nil
}

func (m *Manager) load(ctx context.Context) error {
	rows, err := m.store.ListMRRules(ctx)
	if err != nil {
		return err
	}
	m.mu.Lock()
	defer m.mu.Unlock()
	m.rules = nil
	for _, row := range rows {
		r, err := compileRule(row.Name, row.Direction, row.Spec, row.Action)
		if err != nil {
			return fmt.Errorf("match & replace rule %d (%s): %w", row.ID, row.Name, err)
		}
		r.ID, r.Enabled, r.Hits = row.ID, row.Enabled, row.Hits
		m.rules = append(m.rules, r)
	}
	return nil
}

func compileRule(name, direction, specJSON, actionJSON string) (*Rule, error) {
	var spec intercept.Spec
	if err := json.Unmarshal([]byte(specJSON), &spec); err != nil {
		return nil, fmt.Errorf("bad spec: %w", err)
	}
	matcher, err := intercept.CompileRule(spec)
	if err != nil {
		return nil, err
	}
	var act Action
	if err := json.Unmarshal([]byte(actionJSON), &act); err != nil {
		return nil, fmt.Errorf("bad action: %w", err)
	}
	r := &Rule{Name: name, Direction: direction, Action: act, matcher: matcher, Enabled: true}
	if err := validate(r); err != nil {
		return nil, err
	}
	r.matchAll = specEmpty(spec)
	if act.Type == ActBodyRegex {
		r.bodyRe, err = regexp.Compile(act.Regex)
		if err != nil {
			return nil, fmt.Errorf("regex: %w", err)
		}
	}
	return r, nil
}

func validate(r *Rule) error {
	switch r.Direction {
	case DirRequest, DirResponse:
	default:
		return fmt.Errorf("direction must be %q or %q", DirRequest, DirResponse)
	}
	switch r.Action.Type {
	case ActHeaderSet, ActHeaderAdd:
		if r.Action.HeaderKey == "" {
			return fmt.Errorf("%s requires header_key", r.Action.Type)
		}
	case ActHeaderRemove:
		if r.Action.HeaderKey == "" {
			return fmt.Errorf("header_remove requires header_key")
		}
	case ActBodyRegex:
		if r.Action.Regex == "" {
			return fmt.Errorf("body_regex requires regex")
		}
	case ActBodyRaw:
		if r.Action.Find == "" {
			return fmt.Errorf("body_raw requires find")
		}
	default:
		return fmt.Errorf("unknown action type %q", r.Action.Type)
	}
	return nil
}

// RuleView is the API projection.
type RuleView struct {
	ID        int64          `json:"id"`
	Name      string         `json:"name"`
	Enabled   bool           `json:"enabled"`
	Direction string         `json:"direction"`
	Spec      intercept.Spec `json:"spec"`
	Action    Action         `json:"action"`
	Hits      int64          `json:"hits"`
	Recent    []MatchPreview `json:"recent,omitempty"`
}

// List returns rules with hit counts and recent previews.
func (m *Manager) List() []RuleView {
	m.mu.Lock()
	defer m.mu.Unlock()
	out := []RuleView{}
	for _, r := range m.rules {
		v := RuleView{
			ID: r.ID, Name: r.Name, Enabled: r.Enabled, Direction: r.Direction,
			Spec: r.matcher.Spec, Action: r.Action, Hits: r.Hits,
		}
		v.Recent = m.recent[r.ID]
		out = append(out, v)
	}
	return out
}

// Add validates, persists, and reloads a rule.
func (m *Manager) Add(name string, enabled bool, direction string, spec intercept.Spec, action Action) (int64, error) {
	specJSON, _ := json.Marshal(spec)
	actionJSON, _ := json.Marshal(action)
	if name == "" {
		return 0, fmt.Errorf("name required")
	}
	if _, err := compileRule(name, direction, string(specJSON), string(actionJSON)); err != nil {
		return 0, err
	}
	id, err := m.store.InsertMRRule(context.Background(), name, enabled, direction, string(specJSON), string(actionJSON))
	if err != nil {
		return 0, err
	}
	return id, m.load(context.Background())
}

// SetEnabled toggles a rule.
func (m *Manager) SetEnabled(id int64, enabled bool) error {
	if err := m.store.SetMREnabled(context.Background(), id, enabled); err != nil {
		return err
	}
	return m.load(context.Background())
}

// Delete removes a rule.
func (m *Manager) Delete(id int64) error {
	if err := m.store.DeleteMRRule(context.Background(), id); err != nil {
		return err
	}
	m.mu.Lock()
	delete(m.recent, id)
	m.mu.Unlock()
	return m.load(context.Background())
}

// Apply runs enabled rules for this direction against the flow, mutating it
// in place. Body actions are skipped on truncated captures (rewriting a
// partial body could corrupt it). Content-Length is fixed up whenever a body
// changes so forwarding stays consistent.
func (m *Manager) Apply(f *flows.Flow, isResponse bool) {
	if f == nil {
		return
	}
	m.mu.Lock()
	rules := make([]*Rule, len(m.rules))
	copy(rules, m.rules)
	m.mu.Unlock()

	direction := DirRequest
	if isResponse {
		direction = DirResponse
		if f.Response == nil {
			return
		}
	}

	for _, r := range rules {
		if !r.Enabled || r.Direction != direction {
			continue
		}
		if !r.matchAll && !r.matcher.Matches(f, isResponse) {
			continue
		}
		note, hit := applyAction(r, f, isResponse)
		if !hit {
			continue
		}
		m.store.BumpMRHits(context.Background(), r.ID)
		m.mu.Lock()
		r.Hits++
		m.recent[r.ID] = append([]MatchPreview{{
			TS:    nowMillis(),
			Where: fmt.Sprintf("%s%s", f.Request.Host, f.Request.Path),
			Note:  note,
		}}, m.recent[r.ID]...)
		if len(m.recent[r.ID]) > recentCap {
			m.recent[r.ID] = m.recent[r.ID][:recentCap]
		}
		m.mu.Unlock()
	}
	if m.bus != nil {
		m.bus.PublishJSON("matchreplace.hit", nil)
	}
}

func applyAction(r *Rule, f *flows.Flow, isResponse bool) (note string, hit bool) {
	hdrs := &f.Request.Headers
	body := &f.Request.Body
	truncated := f.Request.BodyTrunc
	if isResponse {
		hdrs = &f.Response.Headers
		body = &f.Response.Body
		truncated = f.Response.BodyTrunc
	}
	switch r.Action.Type {
	case ActHeaderSet:
		hdrs.Set(r.Action.HeaderKey, r.Action.HeaderValue)
		if !isResponse && (r.Action.HeaderKey == "Host" || r.Action.HeaderKey == "host") {
			f.Request.Host = r.Action.HeaderValue // keep capture/display consistent
		}
		return fmt.Sprintf("set %s", r.Action.HeaderKey), true
	case ActHeaderAdd:
		hdrs.Add(r.Action.HeaderKey, r.Action.HeaderValue)
		return fmt.Sprintf("add %s", r.Action.HeaderKey), true
	case ActHeaderRemove:
		hdrs.Del(r.Action.HeaderKey)
		return fmt.Sprintf("remove %s", r.Action.HeaderKey), true
	case ActBodyRegex:
		if truncated {
			return "", false
		}
		out := r.bodyRe.ReplaceAll(*body, []byte(r.Action.Replacement))
		if bytes.Equal(out, *body) {
			return "", false // no occurrence → no hit
		}
		note := fmt.Sprintf("body %q → %q", snippet(*body), snippet(out))
		*body = out
		fixContentLength(hdrs, len(out))
		return note, true
	case ActBodyRaw:
		if truncated {
			return "", false
		}
		if !bytes.Contains(*body, []byte(r.Action.Find)) {
			return "", false
		}
		out := bytes.ReplaceAll(*body, []byte(r.Action.Find), []byte(r.Action.Replace))
		note := fmt.Sprintf("body %q → %q", snippet(*body), snippet(out))
		*body = out
		fixContentLength(hdrs, len(out))
		return note, true
	}
	return "", false
}

// fixContentLength keeps forwarded metadata consistent after body edits:
// set the header when present, else leave it absent (the engine derives
// length from the body).
func fixContentLength(hdrs *flows.Headers, n int) {
	if _, ok := hdrs.Get("Content-Length"); ok {
		hdrs.Set("Content-Length", fmt.Sprintf("%d", n))
	}
}

func snippet(b []byte) string {
	const max = 60
	if len(b) > max {
		return string(b[:max]) + "…"
	}
	return string(b)
}

func nowMillis() int64 { return time.Now().UnixMilli() }
