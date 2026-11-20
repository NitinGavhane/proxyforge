// Package intercept implements the pause/edit/forward/drop gate: parked
// requests and responses block in the engine until a control-plane action
// (UI, REST, or later MCP) releases them.
package intercept

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"regexp"
	"strings"
	"sync"
	"sync/atomic"

	"github.com/NitinGavhane/proxyforge/internal/flows"
	"github.com/NitinGavhane/proxyforge/internal/store"
)

// Spec is a rule predicate. Empty fields match anything; all set fields must
// match (AND). Regexes are RE2, applied case-insensitively.
type Spec struct {
	Method      string `json:"method,omitempty"`       // exact, e.g. POST
	Host        string `json:"host,omitempty"`         // substring, e.g. api.example
	URLRegex    string `json:"url_regex,omitempty"`    // scheme://host/path?query
	ContentType string `json:"content_type,omitempty"` // substring of Content-Type
	HeaderRegex string `json:"header_regex,omitempty"` // matched against "Key: value" lines
	BodyRegex   string `json:"body_regex,omitempty"`   // matched against captured body
	StatusRegex string `json:"status_regex,omitempty"` // responses: e.g. ^3\d\d$
}

// Rule is a named, persisted Spec.
type Rule struct {
	ID      int64
	Name    string
	Enabled bool
	Spec    Spec

	compiled struct {
		url, header, body, status *regexp.Regexp
	}
}

// CompileRule builds a compiled matcher from a bare Spec (shared with the
// match & replace engine).
func CompileRule(spec Spec) (*Rule, error) {
	r := &Rule{Spec: spec, Enabled: true}
	if err := r.compile(); err != nil {
		return nil, err
	}
	return r, nil
}

// Matches reports whether the compiled rule parks/applies to this flow in
// this phase (see ruleMatches for phase semantics).
func (r *Rule) Matches(f *flows.Flow, isResponse bool) bool {
	return ruleMatches(r, f, isResponse)
}

func (r *Rule) compile() error {
	var err error
	c := &r.compiled
	if c.url, err = compile(r.Spec.URLRegex); err != nil {
		return fmt.Errorf("url_regex: %w", err)
	}
	if c.header, err = compile(r.Spec.HeaderRegex); err != nil {
		return fmt.Errorf("header_regex: %w", err)
	}
	if c.body, err = compile(r.Spec.BodyRegex); err != nil {
		return fmt.Errorf("body_regex: %w", err)
	}
	if c.status, err = compile(r.Spec.StatusRegex); err != nil {
		return fmt.Errorf("status_regex: %w", err)
	}
	return nil
}

func compile(expr string) (*regexp.Regexp, error) {
	if expr == "" {
		return nil, nil
	}
	return regexp.Compile(`(?i)` + expr)
}

// Edit carries optional modifications applied before forwarding. Zero values
// keep the original.
type Edit struct {
	Method  *string        `json:"method,omitempty"`
	Path    *string        `json:"path,omitempty"`
	Headers []flows.Header `json:"headers,omitempty"`  // replaces all headers when set
	BodyB64 *string        `json:"body_b64,omitempty"` // replaces body when set
	Status  *int           `json:"status,omitempty"`   // response edits
}

type action int

const (
	actionForward action = iota
	actionDrop
)

// Item is one parked exchange.
type Item struct {
	ID         int64
	IsResponse bool
	Flow       *flows.Flow
	ch         chan action
	edit       Edit
	hasEdit    bool
}

// Manager owns the queue, rules, and toggles.
type Manager struct {
	store *store.Store
	bus   *flows.Bus

	mu      sync.Mutex
	items   map[int64]*Item
	rules   []*Rule
	enabled atomic.Bool
	respOn  atomic.Bool
}

// New builds a manager and loads persisted state.
func New(st *store.Store, bus *flows.Bus) (*Manager, error) {
	m := &Manager{store: st, bus: bus, items: map[int64]*Item{}}
	if err := m.Load(context.Background()); err != nil {
		return nil, err
	}
	return m, nil
}

// Load reads toggles and rules from the store.
func (m *Manager) Load(ctx context.Context) error {
	en, resp, err := m.store.InterceptSettings(ctx)
	if err != nil {
		return err
	}
	m.enabled.Store(en)
	m.respOn.Store(resp)
	rows, err := m.store.ListInterceptRules(ctx)
	if err != nil {
		return err
	}
	m.mu.Lock()
	defer m.mu.Unlock()
	m.rules = nil
	for _, row := range rows {
		r := &Rule{ID: row.ID, Name: row.Name, Enabled: row.Enabled}
		if err := json.Unmarshal([]byte(row.Spec), &r.Spec); err != nil {
			return fmt.Errorf("rule %d (%s): bad spec: %w", row.ID, row.Name, err)
		}
		if err := r.compile(); err != nil {
			return fmt.Errorf("rule %d (%s): %w", row.ID, row.Name, err)
		}
		m.rules = append(m.rules, r)
	}
	return nil
}

// Enabled reports the master toggle.
func (m *Manager) Enabled() bool { return m.enabled.Load() }

// InterceptResponses reports the response-phase toggle.
func (m *Manager) InterceptResponses() bool { return m.respOn.Load() }

// SetEnabled flips the master toggle (persisted, audited by caller).
func (m *Manager) SetEnabled(on bool) error {
	m.enabled.Store(on)
	m.notify()
	return m.store.SaveInterceptSettings(context.Background(), on, m.respOn.Load())
}

// SetInterceptResponses flips the response-phase toggle.
func (m *Manager) SetInterceptResponses(on bool) error {
	m.respOn.Store(on)
	m.notify()
	return m.store.SaveInterceptSettings(context.Background(), m.enabled.Load(), on)
}

// Match reports whether f should be parked in this phase (isResponse selects
// the phase). With interception on and no enabled rules, everything parks
// (Burp semantics); with rules, any match parks.
func (m *Manager) Match(f *flows.Flow, isResponse bool) bool {
	if !m.enabled.Load() {
		return false
	}
	if isResponse && !m.respOn.Load() {
		return false
	}
	if isResponse && f.Response == nil {
		return false
	}
	m.mu.Lock()
	rules := m.rules
	m.mu.Unlock()
	if len(rules) == 0 {
		return true
	}
	for _, r := range rules {
		if r.Enabled && ruleMatches(r, f, isResponse) {
			return true
		}
	}
	return false
}

// ruleMatches reports whether the rule parks this flow in this phase. A
// rule applies to a phase only when it has at least one predicate for it:
// request predicates are Method/Host/ContentType (plus shared URL, header,
// and body regexes against the request message); response predicates are
// StatusRegex (plus shared regexes against the response message).
func ruleMatches(r *Rule, f *flows.Flow, isResponse bool) bool {
	req := f.Request
	if req == nil {
		return false
	}
	applicable := false
	if !isResponse {
		if r.Spec.Method != "" {
			applicable = true
			if req.Method != r.Spec.Method {
				return false
			}
		}
		if r.Spec.Host != "" {
			applicable = true
			if !strings.Contains(strings.ToLower(req.Host), strings.ToLower(r.Spec.Host)) {
				return false
			}
		}
	}
	if r.Spec.ContentType != "" {
		// phase-aware: request rules match the request's Content-Type,
		// response rules the response's
		applicable = true
		hdrs := req.Headers
		if isResponse {
			hdrs = f.Response.Headers
		}
		ct, ok := hdrs.Get("Content-Type")
		if !ok || !strings.Contains(strings.ToLower(ct), strings.ToLower(r.Spec.ContentType)) {
			return false
		}
	}
	if isResponse && f.Response == nil {
		return false
	}
	if r.compiled.url != nil {
		applicable = true
		if !r.compiled.url.MatchString(req.URL()) {
			return false
		}
	}
	if r.compiled.header != nil {
		applicable = true
		hdrs := req.Headers
		if isResponse {
			hdrs = f.Response.Headers
		}
		if !matchHeaders(r.compiled.header, hdrs) {
			return false
		}
	}
	if r.compiled.body != nil {
		applicable = true
		body := req.Body
		if isResponse {
			body = f.Response.Body
		}
		if !r.compiled.body.Match(body) {
			return false
		}
	}
	if isResponse && r.compiled.status != nil {
		applicable = true
		if !r.compiled.status.MatchString(fmt.Sprintf("%d", f.Response.Status)) {
			return false
		}
	}
	return applicable
}

func matchHeaders(re *regexp.Regexp, hdrs flows.Headers) bool {
	for _, h := range hdrs {
		if re.MatchString(h.Key + ": " + h.Value) {
			return true
		}
	}
	return false
}

// snapshotJSON serializes a parked flow (bodies base64).
type snapshot struct {
	*flows.Flow
	ReqBodyB64  string `json:"req_body_b64,omitempty"`
	RespBodyB64 string `json:"resp_body_b64,omitempty"`
}

func buildSnapshot(f *flows.Flow) (string, error) {
	s := snapshot{Flow: f, ReqBodyB64: base64.StdEncoding.EncodeToString(f.Request.Body)}
	if f.Response != nil {
		s.RespBodyB64 = base64.StdEncoding.EncodeToString(f.Response.Body)
	}
	b, err := json.Marshal(s)
	if err != nil {
		return "", err
	}
	return string(b), nil
}

// Park registers f, persists a queue row, publishes an event, and BLOCKS
// until Forward/Drop. It returns (forwarded bool); on forward the flow may
// carry edits.
func (m *Manager) Park(f *flows.Flow, isResponse bool) bool {
	snap, err := buildSnapshot(f)
	if err == nil {
		var id int64
		id, err = m.store.InsertQueueItem(context.Background(), isResponse, snap)
		if err == nil {
			it := &Item{ID: id, IsResponse: isResponse, Flow: f, ch: make(chan action, 1)}
			m.mu.Lock()
			m.items[id] = it
			m.mu.Unlock()
			m.notify()
			act := <-it.ch
			m.mu.Lock()
			delete(m.items, id)
			m.mu.Unlock()
			m.notify()
			if act == actionForward {
				m.applyEdit(it, f)
				_ = m.store.UpdateQueueState(context.Background(), id, store.QueueForwarded)
				return true
			}
			_ = m.store.UpdateQueueState(context.Background(), id, store.QueueDropped)
			return false
		}
	}
	// persistence failed: never block traffic on intercept bookkeeping
	return true
}

func (m *Manager) applyEdit(it *Item, f *flows.Flow) {
	m.mu.Lock()
	edit, has := it.edit, it.hasEdit
	m.mu.Unlock()
	if !has {
		return
	}
	if !it.IsResponse {
		if edit.Method != nil && *edit.Method != "" {
			f.Request.Method = *edit.Method
		}
		if edit.Path != nil && *edit.Path != "" {
			f.Request.Path = *edit.Path
		}
		if edit.Headers != nil {
			f.Request.Headers = edit.Headers
		}
		if edit.BodyB64 != nil {
			if b, err := base64.StdEncoding.DecodeString(*edit.BodyB64); err == nil {
				f.Request.Body = b
				f.Request.BodyTrunc = false
			}
		}
		return
	}
	// response-phase edits
	if f.Response == nil {
		return
	}
	if edit.Headers != nil {
		f.Response.Headers = edit.Headers
	}
	if edit.BodyB64 != nil {
		if b, err := base64.StdEncoding.DecodeString(*edit.BodyB64); err == nil {
			f.Response.Body = b
			f.Response.BodyTrunc = false
		}
	}
	if edit.Status != nil {
		f.Response.Status = *edit.Status
	}
}

// Forward releases a parked item, optionally applying edits.
func (m *Manager) Forward(id int64, edit *Edit) error {
	it, err := m.lookup(id)
	if err != nil {
		return err
	}
	if edit != nil {
		m.mu.Lock()
		it.edit, it.hasEdit = *edit, true
		m.mu.Unlock()
	}
	select {
	case it.ch <- actionForward:
		return nil
	default:
		return fmt.Errorf("intercept %d: not parked", id)
	}
}

// Drop aborts a parked item.
func (m *Manager) Drop(id int64) error {
	it, err := m.lookup(id)
	if err != nil {
		return err
	}
	select {
	case it.ch <- actionDrop:
		return nil
	default:
		return fmt.Errorf("intercept %d: not parked", id)
	}
}

// ForwardAll releases every parked item without edits; returns the count.
func (m *Manager) ForwardAll() int {
	m.mu.Lock()
	ids := make([]int64, 0, len(m.items))
	for id := range m.items {
		ids = append(ids, id)
	}
	m.mu.Unlock()
	n := 0
	for _, id := range ids {
		if err := m.Forward(id, nil); err == nil {
			n++
		}
	}
	return n
}

func (m *Manager) lookup(id int64) (*Item, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	it, ok := m.items[id]
	if !ok {
		return nil, fmt.Errorf("intercept %d: not parked", id)
	}
	return it, nil
}

// ItemView is the API projection of a parked item.
type ItemView struct {
	ID         int64           `json:"id"`
	IsResponse bool            `json:"is_response"`
	Flow       json.RawMessage `json:"flow"`
}

// Pending returns the live parked items (flow snapshots with base64 bodies).
func (m *Manager) Pending() []ItemView {
	m.mu.Lock()
	defer m.mu.Unlock()
	out := make([]ItemView, 0, len(m.items))
	for _, it := range m.items {
		raw, err := buildSnapshot(it.Flow)
		if err != nil {
			continue
		}
		out = append(out, ItemView{ID: it.ID, IsResponse: it.IsResponse, Flow: json.RawMessage(raw)})
	}
	return out
}

// RulesView exposes rules for the API.
type RuleView struct {
	ID      int64  `json:"id"`
	Name    string `json:"name"`
	Enabled bool   `json:"enabled"`
	Spec    Spec   `json:"spec"`
}

// RuleList returns the rule set.
func (m *Manager) RuleList() []RuleView {
	m.mu.Lock()
	defer m.mu.Unlock()
	out := []RuleView{}
	for _, r := range m.rules {
		out = append(out, RuleView{ID: r.ID, Name: r.Name, Enabled: r.Enabled, Spec: r.Spec})
	}
	return out
}

// AddRule validates, persists, and reloads a rule.
func (m *Manager) AddRule(name string, enabled bool, spec Spec) (int64, error) {
	r := &Rule{Name: name, Enabled: enabled, Spec: spec}
	if err := r.compile(); err != nil {
		return 0, err
	}
	specJSON, err := json.Marshal(spec)
	if err != nil {
		return 0, err
	}
	id, err := m.store.InsertInterceptRule(context.Background(), name, enabled, string(specJSON))
	if err != nil {
		return 0, err
	}
	m.notify()
	return id, m.Load(context.Background())
}

// DeleteRule removes a rule and reloads.
func (m *Manager) DeleteRule(id int64) error {
	if err := m.store.DeleteInterceptRule(context.Background(), id); err != nil {
		return err
	}
	m.notify()
	return m.Load(context.Background())
}

// Recover handles items parked when the daemon died: their client
// connections are gone, so mark them restarted (snapshots stay inspectable).
func (m *Manager) Recover(ctx context.Context) (int, error) {
	pending, err := m.store.PendingQueue(ctx)
	if err != nil {
		return 0, err
	}
	n := 0
	for _, row := range pending {
		if err := m.store.UpdateQueueState(ctx, row.ID, store.QueueRestarted); err != nil {
			return n, err
		}
		n++
	}
	if n > 0 {
		m.notify()
	}
	return n, nil
}

// notify publishes a queue-change event.
func (m *Manager) notify() {
	if m.bus != nil {
		m.bus.PublishJSON(flows.EventIntercept, map[string]any{"pending": m.PendingLen()})
	}
}

// PendingLen is the live queue length.
func (m *Manager) PendingLen() int {
	m.mu.Lock()
	defer m.mu.Unlock()
	return len(m.items)
}
