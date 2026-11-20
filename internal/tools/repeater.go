package tools

import (
	"context"
	"fmt"
	"net/url"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/NitinGavhane/proxyforge/internal/flows"
	"github.com/NitinGavhane/proxyforge/internal/store"
)

// Sender is the engine capability Repeater uses (proxy.Engine satisfies it;
// kept narrow for tests).
type Sender interface {
	SendToolFlow(f *flows.Flow) error
}

// Repeater manages tabs and sends.
type Repeater struct {
	store  *store.Store
	sender Sender

	mu   sync.Mutex
	send map[int64]int64 // tabID → last send sequence (for ordering)
}

// NewRepeater builds the tool.
func NewRepeater(st *store.Store, sender Sender) *Repeater {
	return &Repeater{store: st, sender: sender, send: map[int64]int64{}}
}

// SendResult is the outcome of one send (possibly multiple redirect hops).
type SendResult struct {
	Final *flows.Flow   `json:"final"`
	Hops  []*flows.Flow `json:"hops"`
}

// Send parses raw (or uses the stored template), sends through the gate,
// and optionally follows redirects — each hop recorded as its own flow with
// the same tool_ref so the tab history shows the full chain.
func (r *Repeater) Send(ctx context.Context, tabID int64, raw string, followRedirects bool, maxHops int) (*SendResult, error) {
	return r.SendOpts(ctx, tabID, raw, followRedirects, maxHops, SendOptions{})
}

// SendOptions carries session behavior.
type SendOptions struct {
	// UseJar attaches the cookie jar's Cookie header for the target host.
	UseJar bool `json:"use_jar"`
	// MacroFlowID replays this captured flow once before the send when the
	// first attempt returns 401/403 (login-refresh).
	MacroFlowID int64 `json:"macro_flow_id"`

	macroDone bool // internal: one refresh per send
}

// SendSendOptions is the option-aware send used by the API.
func (r *Repeater) SendOpts(ctx context.Context, tabID int64, raw string, followRedirects bool, maxHops int, opts SendOptions) (*SendResult, error) {
	if raw == "" {
		tab, err := r.store.ListRepeaterTabs(ctx)
		if err != nil {
			return nil, err
		}
		for _, t := range tab {
			if t.ID == tabID {
				raw = t.Raw
			}
		}
	}
	req, err := ParseRawRequest(raw)
	if err != nil {
		return nil, err
	}
	if maxHops <= 0 {
		maxHops = 10
	}
	if opts.UseJar {
		r.attachJar(ctx, req)
	}
	res := &SendResult{}
	current := req
	for hop := 0; ; hop++ {
		f := &flows.Flow{
			Started: time.Now(),
			Origin:  flows.OriginRepeater,
			ToolRef: tabID,
			Request: cloneRequest(current),
		}
		if err := r.sender.SendToolFlow(f); err != nil {
			// gate refusals and upstream errors are recorded flows already;
			// surface the error with whatever hops we have
			if len(res.Hops) > 0 || f.ID != 0 {
				res.Hops = append(res.Hops, f)
			}
			res.Final = f
			return res, err
		}
		res.Hops = append(res.Hops, f)
		res.Final = f
		needsAuth := f.Response != nil && (f.Response.Status == 401 || f.Response.Status == 403)
		if needsAuth && opts.MacroFlowID != 0 && !opts.macroDone {
			// refresh the session once, then retry the original request
			opts.macroDone = true
			if mres, err := r.replayMacro(ctx, tabID, opts.MacroFlowID); err == nil {
				res.Hops = append(res.Hops, mres.Hops...) // macro flows recorded too
				if opts.UseJar {
					r.attachJar(ctx, current) // jar now holds fresh cookies
				}
				continue // retry this hop with refreshed credentials
			}
		}
		if !followRedirects || f.Response == nil || f.Response.Status < 300 || f.Response.Status > 399 || hop >= maxHops {
			return res, nil
		}
		loc, ok := f.Response.Headers.Get("Location")
		if !ok || loc == "" {
			return res, nil
		}
		next, err := redirectTarget(current, loc)
		if err != nil {
			return res, fmt.Errorf("redirect: %w", err)
		}
		current = next
	}
}

// redirectTarget resolves Location against the current request, keeping the
// method/headers/body and switching host when the redirect is absolute and
// cross-host (Authorization is dropped cross-host, matching common
// safe-redirect practice).
func redirectTarget(cur *flows.Request, location string) (*flows.Request, error) {
	base := &url.URL{Scheme: cur.Scheme, Host: hostPortOf(cur), Path: cur.Path}
	ref, err := url.Parse(location)
	if err != nil {
		return nil, err
	}
	target := base.ResolveReference(ref)

	next := cloneRequest(cur)
	next.Scheme = target.Scheme
	next.Host = target.Hostname()
	if p := target.Port(); p != "" {
		next.Port, _ = strconv.Atoi(p)
	} else if target.Scheme == "https" {
		next.Port = 443
	} else {
		next.Port = 80
	}
	next.Path = target.RequestURI()
	next.Headers.Del("Host")
	next.Headers.Add("Host", target.Host)
	if !sameOrigin(cur, next) {
		next.Headers.Del("Authorization")
		next.Headers.Del("Cookie")
	}
	// 303 (and 301/302 by common practice) become GET without a body
	if next.Method != "HEAD" {
		next.Method = "GET"
		next.Body = nil
		next.Headers.Del("Content-Length")
	}
	return next, nil
}

func hostPortOf(r *flows.Request) string {
	if r.Port == 0 {
		return r.Host
	}
	return r.Host + ":" + strconv.Itoa(r.Port)
}

// sameOrigin compares scheme+host+port — credentials survive only
// same-origin redirects.
func sameOrigin(a, b *flows.Request) bool {
	return strings.EqualFold(a.Scheme, b.Scheme) &&
		strings.EqualFold(a.Host, b.Host) && a.Port == b.Port
}

// History lists a tab's sends (flows with origin=repeater for this tab,
// newest first).
func (r *Repeater) History(ctx context.Context, tabID int64, limit int) ([]store.FlowRow, error) {
	if limit <= 0 {
		limit = 50
	}
	rows, err := r.store.ListFlows(ctx, store.Filter{Limit: 500})
	if err != nil {
		return nil, err
	}
	out := []store.FlowRow{}
	for _, row := range rows {
		if row.Origin == flows.OriginRepeater && row.ToolRef == tabID {
			out = append(out, row)
			if len(out) >= limit {
				break
			}
		}
	}
	return out, nil
}

// --- tab management (thin wrappers for the API) ---

func (r *Repeater) NewTab(ctx context.Context, name, raw string) (int64, error) {
	if name == "" {
		name = "Tab 1"
	}
	if raw == "" {
		raw = "GET / HTTP/1.1\nHost: example.com\n"
	}
	return r.store.InsertRepeaterTab(ctx, name, raw)
}

func (r *Repeater) SaveTab(ctx context.Context, id int64, name, raw string) error {
	return r.store.UpdateRepeaterTab(ctx, id, name, raw)
}

func (r *Repeater) DeleteTab(ctx context.Context, id int64) error {
	return r.store.DeleteRepeaterTab(ctx, id)
}

func (r *Repeater) Tabs(ctx context.Context) ([]store.RepeaterTab, error) {
	return r.store.ListRepeaterTabs(ctx)
}

// attachJar merges the stored Cookie header with the jar for the target
// host (explicit cookies win per name; jar fills the rest).
func (r *Repeater) attachJar(ctx context.Context, req *flows.Request) {
	cs, err := r.store.JarCookies(ctx, req.Host, req.Port)
	if err != nil || len(cs) == 0 {
		return
	}
	existing, _ := req.Headers.Get("Cookie")
	have := map[string]bool{}
	for _, pair := range strings.Split(existing, ";") {
		k, _, _ := strings.Cut(strings.TrimSpace(pair), "=")
		if k != "" {
			have[k] = true
		}
	}
	var add []string
	for _, c := range cs {
		if !have[c.Name] {
			add = append(add, c.Name+"="+c.Value)
		}
	}
	if len(add) == 0 {
		return
	}
	merged := existing
	if merged != "" {
		merged += "; "
	}
	merged += strings.Join(add, "; ")
	req.Headers.Set("Cookie", merged)
}

// replayMacro re-sends a captured flow to refresh the session.
func (r *Repeater) replayMacro(ctx context.Context, tabID int64, flowID int64) (*SendResult, error) {
	f, err := r.store.GetFlow(ctx, flowID)
	if err != nil {
		return nil, err
	}
	raw := RenderRaw(f.Request)
	return r.SendOpts(ctx, tabID, raw, false, 1, SendOptions{UseJar: true})
}

// cloneRequest deep-copies a request template for a send.
func cloneRequest(src *flows.Request) *flows.Request {
	dst := *src
	dst.Headers = append(flows.Headers(nil), src.Headers...)
	dst.Body = append([]byte(nil), src.Body...)
	dst.Trailer = append(flows.Headers(nil), src.Trailer...)
	return &dst
}
