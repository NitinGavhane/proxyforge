// Package extjs is ProxyForge's JS scripting host (Phase 3 P9). Scripts are
// pure ECMAScript running under goja — no I/O, no network, no filesystem by
// construction. Each invocation gets a fresh runtime with a time cap, so a
// runaway script cannot wedge the proxy.
//
// A script defines hooks and mutates the flow object in place:
//
//	function onRequest(flow) {
//	  flow.request.headers.push({ name: "X-Probe", value: "1" });
//	}
//	function onResponse(flow) {
//	  flow.response.body = flow.response.body.replace("internal", "[redacted]");
//	}
//
// Scripts run in id order, in-scope only, before match & replace. A script
// error is recorded on the script and NEVER blocks traffic.
package extjs

import (
	"context"
	"encoding/json"
	"fmt"
	"log/slog"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/dop251/goja"

	"github.com/NitinGavhane/proxyforge/internal/flows"
	"github.com/NitinGavhane/proxyforge/internal/store"
)

// MaxCodeSize caps a script's source.
const MaxCodeSize = 256 << 10

// RunTimeout caps each hook invocation.
const RunTimeout = 2 * time.Second

// script is a compiled extension.
type script struct {
	id      int64
	name    string
	enabled bool
	prog    *goja.Program
}

// Manager owns compiled scripts and execution.
type Manager struct {
	store *store.Store
	log   *slog.Logger

	mu      sync.Mutex
	scripts []*script
}

// NewManager builds and loads scripts.
func NewManager(st *store.Store, log *slog.Logger) (*Manager, error) {
	if log == nil {
		log = slog.Default()
	}
	m := &Manager{store: st, log: log}
	if err := m.Reload(context.Background()); err != nil {
		return nil, err
	}
	return m, nil
}

// Compile validates source (syntax + hook shape) without storing it.
func Compile(name, code string) error {
	if len(code) > MaxCodeSize {
		return fmt.Errorf("script %q: too large (> %d bytes)", name, MaxCodeSize)
	}
	prog, err := goja.Compile(name, code, false)
	if err != nil {
		return fmt.Errorf("compile: %w", err)
	}
	// hooks are optional at compile time; validate what exists
	rt := goja.New()
	if _, err := rt.RunProgram(prog); err != nil {
		// top-level throw is a valid script but surfaces now, which is the
		// friendlier moment to report it
		return fmt.Errorf("top-level: %w", err)
	}
	for _, hook := range []string{"onRequest", "onResponse"} {
		if v := rt.Get(hook); v != nil && !goja.IsUndefined(v) && !goja.IsNull(v) {
			if _, ok := goja.AssertFunction(v); !ok {
				return fmt.Errorf("%s must be a function", hook)
			}
		}
	}
	return nil
}

// Reload recompiles all stored scripts.
func (m *Manager) Reload(ctx context.Context) error {
	rows, err := m.store.ListExtensions(ctx)
	if err != nil {
		return err
	}
	m.mu.Lock()
	defer m.mu.Unlock()
	m.scripts = nil
	for _, row := range rows {
		prog, cerr := goja.Compile(row.Name, row.Code, false)
		if cerr != nil {
			m.log.Error("extension compile failed (disabled)", "name", row.Name, "err", cerr)
			continue
		}
		m.scripts = append(m.scripts, &script{id: row.ID, name: row.Name, enabled: row.Enabled, prog: prog})
	}
	return nil
}

// Add validates + stores + reloads.
func (m *Manager) Add(ctx context.Context, name, code string, enabled bool) (int64, error) {
	if name == "" {
		return 0, fmt.Errorf("name required")
	}
	if err := Compile(name, code); err != nil {
		return 0, err
	}
	id, err := m.store.InsertExtension(ctx, name, code, enabled)
	if err != nil {
		return 0, err
	}
	return id, m.Reload(ctx)
}

// Update patches a script (code changes recompile).
func (m *Manager) Update(ctx context.Context, id int64, name *string, code *string, enabled *bool) error {
	if code != nil {
		n := "(update)"
		if name != nil {
			n = *name
		} else if cur, err := m.get(ctx, id); err == nil {
			n = cur.Name
		}
		if err := Compile(n, *code); err != nil {
			return err
		}
	}
	if err := m.store.UpdateExtension(ctx, id, name, code, enabled); err != nil {
		return err
	}
	return m.Reload(ctx)
}

func (m *Manager) get(ctx context.Context, id int64) (*store.Extension, error) {
	rows, err := m.store.ListExtensions(ctx)
	if err != nil {
		return nil, err
	}
	for i := range rows {
		if rows[i].ID == id {
			return &rows[i], nil
		}
	}
	return nil, fmt.Errorf("extension %d: not found", id)
}

// Delete removes a script.
func (m *Manager) Delete(ctx context.Context, id int64) error {
	if err := m.store.DeleteExtension(ctx, id); err != nil {
		return err
	}
	return m.Reload(ctx)
}

// List returns stored scripts with stats.
func (m *Manager) List(ctx context.Context) ([]store.Extension, error) {
	return m.store.ListExtensions(ctx)
}

// The script-facing shape is nested maps keyed by lowercase names (goja
// exposes struct fields by Go name, so maps keep the JS surface stable).

type jsFlow = map[string]any

func toJS(f *flows.Flow) jsFlow {
	req := f.Request
	jf := jsFlow{
		"origin": f.Origin,
		"mitm":   f.MITM,
		"request": map[string]any{
			"method":  req.Method,
			"scheme":  req.Scheme,
			"host":    req.Host,
			"port":    req.Port,
			"path":    req.Path,
			"headers": hdrsToJS(req.Headers),
			"body":    string(req.Body),
		},
	}
	if f.Response != nil {
		jf["response"] = map[string]any{
			"status":  f.Response.Status,
			"headers": hdrsToJS(f.Response.Headers),
			"body":    string(f.Response.Body),
		}
	} else {
		jf["response"] = nil
	}
	return jf
}

func hdrsToJS(h flows.Headers) []map[string]any {
	out := make([]map[string]any, 0, len(h))
	for _, hd := range h {
		out = append(out, map[string]any{"name": hd.Key, "value": hd.Value})
	}
	return out
}

func hdrsFromJS(v any) flows.Headers {
	// untouched headers round-trip as []map[string]any (our own value);
	// JS-mutated ones come back as []any — accept both.
	items := []any{}
	switch list := v.(type) {
	case []any:
		items = list
	case []map[string]any:
		for _, m := range list {
			items = append(items, m)
		}
	default:
		return nil
	}
	out := make(flows.Headers, 0, len(items))
	for _, item := range items {
		m, ok := item.(map[string]any)
		if !ok {
			continue
		}
		name, _ := m["name"].(string)
		if name == "" {
			continue
		}
		value, _ := m["value"].(string)
		out = append(out, flows.Header{Key: name, Value: value})
	}
	return out
}

func str(v any) string { s, _ := v.(string); return s }

func num(v any) int {
	switch n := v.(type) {
	case int:
		return n
	case int64:
		return int(n)
	case float64:
		return int(n)
	}
	return 0
}

// applyFromJSON copies mutations back onto the flow. Body edits on
// truncated captures are refused (same policy as match & replace).
func applyFromJSON(f *flows.Flow, raw []byte) {
	var out jsFlow
	if err := json.Unmarshal(raw, &out); err != nil {
		return // malformed script output: keep the original
	}
	reqM, _ := out["request"].(map[string]any)
	if reqM == nil {
		return
	}
	req := f.Request
	req.Method = str(reqM["method"])
	req.Path = str(reqM["path"])
	req.Headers = hdrsFromJS(reqM["headers"])
	if host := str(reqM["host"]); host != "" {
		req.Host = host
	}
	if !req.BodyTrunc {
		if body := str(reqM["body"]); body != string(req.Body) {
			req.Body = []byte(body)
		}
	}
	if respM, ok := out["response"].(map[string]any); ok && f.Response != nil {
		f.Response.Status = num(respM["status"])
		f.Response.Headers = hdrsFromJS(respM["headers"])
		if !f.Response.BodyTrunc {
			if body := str(respM["body"]); body != string(f.Response.Body) {
				f.Response.Body = []byte(body)
				fixContentLength(f.Response.Headers, len(f.Response.Body))
			}
		}
	}
}

func fixContentLength(hdrs flows.Headers, n int) {
	if _, ok := hdrs.Get("Content-Length"); ok {
		hdrs.Set("Content-Length", strconv.Itoa(n))
	}
}

// RunRequest runs onRequest hooks (request phase).
func (m *Manager) RunRequest(f *flows.Flow) {
	m.run(f, "onRequest", false)
}

// RunResponse runs onResponse hooks (response phase).
func (m *Manager) RunResponse(f *flows.Flow) {
	m.run(f, "onResponse", true)
}

func (m *Manager) run(f *flows.Flow, hook string, isResponse bool) {
	m.mu.Lock()
	scripts := append([]*script(nil), m.scripts...)
	m.mu.Unlock()

	for _, sc := range scripts {
		if !sc.enabled {
			continue
		}
		if isResponse && f.Response == nil {
			continue
		}
		outJSON, runErr := m.invoke(sc, hook, f)
		if runErr == "" && outJSON != nil {
			applyFromJSON(f, outJSON)
		}
		m.store.RecordExtensionRun(context.Background(), sc.id, runErr)
		if runErr != "" {
			m.log.Warn("extension hook failed", "name", sc.name, "hook", hook, "err", runErr)
		}
	}
}

// invoke runs one hook with a fresh runtime and a hard timeout. The flow
// crosses the boundary as JSON: goja converts nested Go slices to fresh JS
// arrays (mutations would not write back), so round-tripping through
// JSON.parse/stringify is the only faithful bridge.
func (m *Manager) invoke(sc *script, hook string, f *flows.Flow) ([]byte, string) {
	rt := goja.New()
	if _, err := rt.RunProgram(sc.prog); err != nil {
		return nil, err.Error()
	}
	fn := rt.Get(hook)
	if goja.IsUndefined(fn) || goja.IsNull(fn) {
		return nil, "" // hook not defined: fine
	}
	callable, ok := goja.AssertFunction(fn)
	if !ok {
		return nil, hook + " is not a function"
	}

	in, err := json.Marshal(toJS(f))
	if err != nil {
		return nil, "marshal flow: " + err.Error()
	}
	flowVal, perr := rt.RunString("__pf_flow = JSON.parse(" + strconv.Quote(string(in)) + ")")
	if perr != nil {
		return nil, "parse flow: " + perr.Error()
	}

	// time cap: interrupt a runaway script
	timer := time.AfterFunc(RunTimeout, func() { rt.Interrupt("timeout") })
	defer timer.Stop()

	if _, err := callable(goja.Undefined(), flowVal); err != nil {
		if strings.Contains(err.Error(), "timeout") {
			return nil, "timeout after " + RunTimeout.String()
		}
		return nil, err.Error()
	}
	out, err := rt.RunString("JSON.stringify(__pf_flow)")
	if err != nil {
		return nil, "stringify: " + err.Error()
	}
	outStr, _ := out.Export().(string)
	if outStr == "" || outStr == "undefined" {
		return nil, "" // flow not returned/exposed — treat as read-only
	}
	return []byte(outStr), ""
}

// Test runs both hooks against a captured flow WITHOUT applying anything,
// returning the resulting view for the UI.
func (m *Manager) Test(ctx context.Context, flowID int64) (map[string]any, error) {
	f, err := m.store.GetFlow(ctx, flowID)
	if err != nil {
		return nil, err
	}
	// run on a private Manager copy so stats don't bump
	sandbox := &Manager{store: m.store, log: m.log}
	m.mu.Lock()
	sandbox.scripts = m.scripts
	m.mu.Unlock()
	view := map[string]any{"before": snapshot(f)}
	clone := cloneFlow(f)
	sandbox.RunRequest(clone)
	sandbox.RunResponse(clone)
	view["after"] = snapshot(clone)
	return view, nil
}

func snapshot(f *flows.Flow) map[string]any {
	jf := toJS(f)
	req, _ := jf["request"].(map[string]any)
	if f.Request.BodyTrunc {
		req["body"] = "(truncated)"
	}
	if resp, ok := jf["response"].(map[string]any); ok && f.Response != nil && f.Response.BodyTrunc {
		resp["body"] = "(truncated)"
	}
	return jf
}

func cloneFlow(f *flows.Flow) *flows.Flow {
	cp := *f
	if f.Request != nil {
		req := *f.Request
		req.Headers = append(flows.Headers(nil), f.Request.Headers...)
		req.Body = append([]byte(nil), f.Request.Body...)
		cp.Request = &req
	}
	if f.Response != nil {
		resp := *f.Response
		resp.Headers = append(flows.Headers(nil), f.Response.Headers...)
		resp.Body = append([]byte(nil), f.Response.Body...)
		cp.Response = &resp
	}
	return &cp
}

// TestWith dry-runs ONE script against a captured flow and returns the
// before/after view (nothing persisted, no stats bumped).
func (m *Manager) TestWith(ctx context.Context, id int64, flowID int64) (map[string]any, error) {
	m.mu.Lock()
	var sc *script
	for _, c := range m.scripts {
		if c.id == id {
			sc = c
		}
	}
	m.mu.Unlock()
	if sc == nil {
		return nil, fmt.Errorf("extension %d: not found", id)
	}
	f, err := m.store.GetFlow(ctx, flowID)
	if err != nil {
		return nil, fmt.Errorf("flow %d: %w", flowID, err)
	}
	view := map[string]any{"before": snapshot(f)}
	clone := cloneFlow(f)
	outJSON, runErr := m.invoke(sc, "onRequest", clone)
	if runErr == "" && outJSON != nil {
		applyFromJSON(clone, outJSON)
	}
	out2, runErr2 := m.invoke(sc, "onResponse", clone)
	if runErr2 == "" && out2 != nil {
		applyFromJSON(clone, out2)
	}
	view["after"] = snapshot(clone)
	if runErr != "" {
		view["error"] = runErr
	}
	if runErr2 != "" {
		view["error_response"] = runErr2
	}
	return view, nil
}
