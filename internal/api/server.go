// Package api serves the local control plane: REST + WebSocket on
// 127.0.0.1, token-authenticated, plus the embedded UI.
package api

import (
	"context"
	"crypto/subtle"
	"encoding/base64"
	"encoding/json"
	"log/slog"
	"net/http"
	"strconv"
	"strings"
	"time"

	"github.com/coder/websocket"

	"github.com/NitinGavhane/proxyforge/internal/collab"
	"github.com/NitinGavhane/proxyforge/internal/extjs"
	"github.com/NitinGavhane/proxyforge/internal/flows"
	"github.com/NitinGavhane/proxyforge/internal/intercept"
	"github.com/NitinGavhane/proxyforge/internal/matchreplace"
	"github.com/NitinGavhane/proxyforge/internal/mcp"
	"github.com/NitinGavhane/proxyforge/internal/scope"
	"github.com/NitinGavhane/proxyforge/internal/store"
	"github.com/NitinGavhane/proxyforge/internal/tags"
	"github.com/NitinGavhane/proxyforge/internal/tools"
	"github.com/NitinGavhane/proxyforge/ui"
)

// SessionCookie is the UI session cookie name.
const SessionCookie = "pf_session"

// Server is the control plane.
type Server struct {
	Store   *store.Store
	Bus     *flows.Bus
	Token   string
	Log     *slog.Logger
	Started time.Time
	// Intercept is the pause/forward/drop manager (nil disables those endpoints).
	Intercept *intercept.Manager
	// MatchReplace is the auto-modification manager (nil disables those endpoints).
	MatchReplace *matchreplace.Manager
	// Scope is the target-scope manager (nil disables those endpoints).
	Scope *scope.Manager
	// Tags receives browser-extension origin tags (nil disables the endpoint).
	Tags *tags.Manager
	// Repeater is the resend tool (nil disables its endpoints).
	Repeater *tools.Repeater
	// Discovery is the content-discovery tool (nil disables its endpoints).
	Discovery *tools.Discovery
	// Intruder is the attack tool (nil disables its endpoints).
	Intruder *tools.Intruder
	// Scanner is the vulnerability scanner (nil disables its endpoints).
	Scanner *tools.Scanner
	// Collab is the OOB interaction server (nil disables its endpoints).
	Collab *collab.Manager
	// Scripts is the JS extension host (nil disables its endpoints).
	Scripts *extjs.Manager
	// MCP is the Model Context Protocol dispatcher (nil disables /mcp).
	MCP *mcp.Backend

	srv *http.Server
}

// bodyInListCap: flows whose bodies are smaller than this are embedded in
// GET /flows/{id}; larger bodies must be fetched via ?part=.
const bodyInListCap = 1 << 20

// Handler builds the API + UI mux.
func (s *Server) Handler() http.Handler {
	mux := http.NewServeMux()
	mux.HandleFunc("POST /api/v1/auth", s.handleAuth)
	mux.Handle("GET /api/v1/status", s.auth(http.HandlerFunc(s.handleStatus)))
	mux.Handle("GET /api/v1/flows", s.auth(http.HandlerFunc(s.handleListFlows)))
	mux.Handle("GET /api/v1/flows/{id}", s.auth(http.HandlerFunc(s.handleGetFlow)))
	mux.Handle("GET /api/v1/flows/{id}/ws", s.auth(http.HandlerFunc(s.handleListWSMessages)))
	mux.Handle("PATCH /api/v1/flows/{id}", s.auth(s.audit("ui", "flow.annotate", http.HandlerFunc(s.handleAnnotate))))
	mux.Handle("GET /api/v1/audit.jsonl", s.auth(http.HandlerFunc(s.handleAuditExport)))
	mux.Handle("GET /api/v1/events", s.auth(http.HandlerFunc(s.handleEvents)))
	mux.Handle("POST /api/v1/mcp", s.auth(s.audit("mcp", "mcp.request", http.HandlerFunc(s.handleMCP))))

	// intercept endpoints: authenticated + every action audited
	interceptRoute := func(pattern, action string, h http.HandlerFunc) {
		mux.Handle(pattern, s.auth(s.audit("ui", action, h)))
	}
	mux.Handle("GET /api/v1/intercept", s.auth(http.HandlerFunc(s.handleInterceptOverview)))
	interceptRoute("POST /api/v1/intercept/toggle", "intercept.toggle", s.handleInterceptToggle)
	interceptRoute("POST /api/v1/intercept/rules", "intercept.rule.add", s.handleInterceptRuleAdd)
	interceptRoute("DELETE /api/v1/intercept/rules/{id}", "intercept.rule.delete", s.handleInterceptRuleDelete)
	interceptRoute("POST /api/v1/intercept/forward-all", "intercept.forward_all", s.handleInterceptForwardAll)
	interceptRoute("POST /api/v1/intercept/{id}/forward", "intercept.forward", s.handleInterceptForward)
	interceptRoute("POST /api/v1/intercept/{id}/drop", "intercept.drop", s.handleInterceptDrop)

	mrRoute := func(pattern, action string, h http.HandlerFunc) {
		mux.Handle(pattern, s.auth(s.audit("ui", action, h)))
	}
	mux.Handle("GET /api/v1/match-replace", s.auth(http.HandlerFunc(s.handleMRList)))
	mrRoute("POST /api/v1/match-replace", "matchreplace.rule.add", s.handleMRAdd)
	mrRoute("PATCH /api/v1/match-replace/{id}", "matchreplace.rule.patch", s.handleMRPatch)
	mrRoute("DELETE /api/v1/match-replace/{id}", "matchreplace.rule.delete", s.handleMRDelete)

	scopeRoute := func(pattern, action string, h http.HandlerFunc) {
		mux.Handle(pattern, s.auth(s.audit("ui", action, h)))
	}
	mux.Handle("GET /api/v1/scope", s.auth(http.HandlerFunc(s.handleScopeGet)))
	mux.Handle("GET /api/v1/scope/preview", s.auth(http.HandlerFunc(s.handleScopePreview)))
	scopeRoute("POST /api/v1/scope", "scope.rule.add", s.handleScopeAdd)
	scopeRoute("PATCH /api/v1/scope/{id}", "scope.rule.patch", s.handleScopePatch)
	scopeRoute("DELETE /api/v1/scope/{id}", "scope.rule.delete", s.handleScopeDelete)
	mux.Handle("POST /api/v1/annotate-tab", s.auth(s.audit("extension", "tab.tag", http.HandlerFunc(s.handleAnnotateTab))))

	mux.Handle("GET /api/v1/sitemap", s.auth(http.HandlerFunc(s.handleSitemapGet)))
	mux.Handle("POST /api/v1/sitemap/import", s.auth(s.audit("ui", "sitemap.import", http.HandlerFunc(s.handleSitemapImport))))

	mux.Handle("GET /api/v1/discovery", s.auth(http.HandlerFunc(s.handleDiscoveryList)))
	mux.Handle("POST /api/v1/discovery/start", s.auth(s.audit("ui", "discovery.start", http.HandlerFunc(s.handleDiscoveryStart))))
	mux.Handle("GET /api/v1/discovery/{id}", s.auth(http.HandlerFunc(s.handleDiscoveryGet)))
	mux.Handle("POST /api/v1/discovery/{id}/stop", s.auth(s.audit("ui", "discovery.stop", http.HandlerFunc(s.handleDiscoveryStop))))

	mux.Handle("GET /api/v1/repeater", s.auth(http.HandlerFunc(s.handleRepeaterTabs)))
	mux.Handle("POST /api/v1/repeater", s.auth(s.audit("ui", "repeater.tab.new", http.HandlerFunc(s.handleRepeaterTabs))))
	mux.Handle("PATCH /api/v1/repeater/{id}", s.auth(s.audit("ui", "repeater.tab.save", http.HandlerFunc(s.handleRepeaterTab))))
	mux.Handle("DELETE /api/v1/repeater/{id}", s.auth(s.audit("ui", "repeater.tab.delete", http.HandlerFunc(s.handleRepeaterTab))))
	mux.Handle("POST /api/v1/repeater/{id}/send", s.auth(s.audit("ui", "repeater.send", http.HandlerFunc(s.handleRepeaterSend))))
	mux.Handle("GET /api/v1/repeater/{id}/history", s.auth(http.HandlerFunc(s.handleRepeaterHistory)))

	mux.Handle("GET /api/v1/intruder", s.auth(http.HandlerFunc(s.handleIntruderList)))
	mux.Handle("POST /api/v1/intruder/start", s.auth(s.audit("ui", "intruder.start", http.HandlerFunc(s.handleIntruderStart))))
	mux.Handle("GET /api/v1/intruder/{id}", s.auth(http.HandlerFunc(s.handleIntruderGet)))
	mux.Handle("POST /api/v1/intruder/{id}/stop", s.auth(s.audit("ui", "intruder.stop", http.HandlerFunc(s.handleIntruderStop))))

	mux.Handle("POST /api/v1/scanner/scan", s.auth(s.audit("ui", "scanner.start", http.HandlerFunc(s.handleScanStart))))
	mux.Handle("GET /api/v1/scanner/{id}", s.auth(http.HandlerFunc(s.handleScanGet)))
	mux.Handle("GET /api/v1/issues", s.auth(http.HandlerFunc(s.handleIssuesList)))
	mux.Handle("GET /api/v1/issues/{id}", s.auth(http.HandlerFunc(s.handleIssueGet)))
	mux.Handle("POST /api/v1/collab/new", s.auth(s.audit("ui", "collab.new", http.HandlerFunc(s.handleCollabNew))))
	mux.Handle("GET /api/v1/collab/interactions", s.auth(http.HandlerFunc(s.handleCollabInteractions)))

	mux.Handle("GET /api/v1/export/flows.csv", s.auth(http.HandlerFunc(s.handleExportFlowsCSV)))
	mux.Handle("GET /api/v1/export/flows.json", s.auth(http.HandlerFunc(s.handleExportFlowsJSON)))
	mux.Handle("GET /api/v1/export/burp.xml", s.auth(http.HandlerFunc(s.handleExportBurpXML)))
	mux.Handle("POST /api/v1/import/burp.xml", s.auth(s.audit("ui", "import.burp_xml", http.HandlerFunc(s.handleImportBurpXML))))
	mux.Handle("POST /api/v1/import/curl", s.auth(s.audit("ui", "import.curl", http.HandlerFunc(s.handleImportCURL))))
	mux.Handle("POST /api/v1/import/openapi", s.auth(s.audit("ui", "import.openapi", http.HandlerFunc(s.handleImportOpenAPI))))
	mux.Handle("POST /api/v1/import/postman", s.auth(s.audit("ui", "import.postman", http.HandlerFunc(s.handleImportPostman))))

	mux.Handle("GET /api/v1/extensions", s.auth(http.HandlerFunc(s.handleExtList)))
	mux.Handle("POST /api/v1/extensions", s.auth(s.audit("ui", "extension.add", http.HandlerFunc(s.handleExtAdd))))
	mux.Handle("PATCH /api/v1/extensions/{id}", s.auth(s.audit("ui", "extension.patch", http.HandlerFunc(s.handleExtPatch))))
	mux.Handle("DELETE /api/v1/extensions/{id}", s.auth(s.audit("ui", "extension.delete", http.HandlerFunc(s.handleExtDelete))))
	mux.Handle("POST /api/v1/extensions/{id}/test", s.auth(http.HandlerFunc(s.handleExtTest)))

	mux.Handle("GET /api/v1/report.md", s.auth(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { s.handleReport(w, r, false) })))
	mux.Handle("GET /api/v1/report.html", s.auth(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { s.handleReport(w, r, true) })))

	mux.Handle("POST /api/v1/organizer", s.auth(s.audit("ui", "organizer.save", http.HandlerFunc(s.handleOrganizerSave))))
	mux.Handle("GET /api/v1/organizer", s.auth(http.HandlerFunc(s.handleOrganizerList)))
	mux.Handle("DELETE /api/v1/organizer/{id}", s.auth(s.audit("ui", "organizer.delete", http.HandlerFunc(s.handleOrganizerDelete))))

	mux.Handle("GET /api/v1/jar", s.auth(http.HandlerFunc(s.handleJarGet)))
	mux.Handle("POST /api/v1/macros", s.auth(s.audit("ui", "macro.new", http.HandlerFunc(s.handleMacroNew))))
	mux.Handle("GET /api/v1/macros", s.auth(http.HandlerFunc(s.handleMacroList)))
	mux.Handle("DELETE /api/v1/macros/{id}", s.auth(s.audit("ui", "macro.delete", http.HandlerFunc(s.handleMacroDelete))))

	mux.Handle("POST /api/v1/decode", s.auth(http.HandlerFunc(s.handleDecode)))
	mux.Handle("POST /api/v1/compare", s.auth(http.HandlerFunc(s.handleCompareRaw)))
	mux.Handle("POST /api/v1/sequencer/analyze", s.auth(http.HandlerFunc(s.handleSequencer)))

	mux.Handle("GET /api/v1/export/har", s.auth(http.HandlerFunc(s.handleExportHAR)))
	mux.Handle("GET /api/v1/flows/{id}/har", s.auth(http.HandlerFunc(s.handleFlowHAR)))
	mux.Handle("GET /api/v1/flows/{id}/diff/{other}", s.auth(http.HandlerFunc(s.handleFlowDiff)))

	// The UI shell serves no data and must load before the token gate can
	// appear — so it is public; every /api/v1/* route stays token-gated.
	mux.Handle("/", serveUI())
	return mux
}

// serveUI serves the embedded React app (placeholder page when unbuilt).
func serveUI() http.Handler {
	return ui.Handler()
}

// ListenAndServe starts the API server on addr (blocking).
func (s *Server) ListenAndServe(addr string) error {
	s.srv = &http.Server{
		Addr:              addr,
		Handler:           s.Handler(),
		ReadHeaderTimeout: 10 * time.Second,
	}
	return s.srv.ListenAndServe()
}

// Close shuts down the API server.
func (s *Server) Close() error {
	if s.srv == nil {
		return nil
	}
	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()
	return s.srv.Shutdown(ctx)
}

// auth wraps h with token authentication: bearer header or session cookie.
func (s *Server) auth(h http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		ok := false
		if c, err := r.Cookie(SessionCookie); err == nil && constantTimeEqual(c.Value, s.Token) {
			ok = true
		}
		if !ok {
			authz := r.Header.Get("Authorization")
			if strings.HasPrefix(authz, "Bearer ") && constantTimeEqual(strings.TrimPrefix(authz, "Bearer "), s.Token) {
				ok = true
			}
		}
		if !ok {
			w.Header().Set("WWW-Authenticate", `Bearer realm="proxyforge"`)
			http.Error(w, "unauthorized", http.StatusUnauthorized)
			return
		}
		h.ServeHTTP(w, r)
	})
}

func constantTimeEqual(a, b string) bool {
	return subtle.ConstantTimeCompare([]byte(a), []byte(b)) == 1
}

// audit records an action before invoking h.
func (s *Server) audit(actor, action string, h http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_ = s.Store.AppendAudit(r.Context(), actor, action, r.PathValue("id"), r.RemoteAddr)
		h.ServeHTTP(w, r)
	})
}

func writeJSON(w http.ResponseWriter, status int, v any) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(v)
}

func (s *Server) handleAuth(w http.ResponseWriter, r *http.Request) {
	var body struct {
		Token string `json:"token"`
	}
	if err := json.NewDecoder(r.Body).Decode(&body); err != nil || !constantTimeEqual(body.Token, s.Token) {
		http.Error(w, "invalid token", http.StatusUnauthorized)
		return
	}
	http.SetCookie(w, &http.Cookie{
		Name:     SessionCookie,
		Value:    s.Token,
		Path:     "/",
		SameSite: http.SameSiteStrictMode,
		HttpOnly: true,
	})
	writeJSON(w, http.StatusOK, map[string]bool{"ok": true})
}

func (s *Server) handleStatus(w http.ResponseWriter, r *http.Request) {
	n, _ := s.Store.CountFlows(r.Context())
	writeJSON(w, http.StatusOK, map[string]any{
		"version":  "0.1.0-m1",
		"uptime_s": int64(time.Since(s.Started).Seconds()),
		"flows":    n,
	})
}

func (s *Server) handleListFlows(w http.ResponseWriter, r *http.Request) {
	q := r.URL.Query()
	limit, _ := strconv.Atoi(q.Get("limit"))
	offset, _ := strconv.Atoi(q.Get("offset"))
	f := store.Filter{
		Query:  q.Get("q"),
		Host:   q.Get("host"),
		Method: q.Get("method"),
		Status: q.Get("status"),
		Search: q.Get("search"),
		Sort:   q.Get("sort"),
		Limit:  limit,
		Offset: offset,
	}
	rows, err := s.Store.ListFlows(r.Context(), f)
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	if rows == nil {
		rows = []store.FlowRow{}
	}
	writeJSON(w, http.StatusOK, map[string]any{"flows": rows})
}

// flowJSON is the wire form of a full flow; bodies are base64.
type flowJSON struct {
	*flows.Flow
	ReqBodyB64  string `json:"req_body_b64,omitempty"`
	RespBodyB64 string `json:"resp_body_b64,omitempty"`
}

func (s *Server) handleGetFlow(w http.ResponseWriter, r *http.Request) {
	id, err := strconv.ParseInt(r.PathValue("id"), 10, 64)
	if err != nil {
		http.Error(w, "bad id", http.StatusBadRequest)
		return
	}
	f, err := s.Store.GetFlow(r.Context(), id)
	if err != nil {
		http.Error(w, err.Error(), http.StatusNotFound)
		return
	}
	out := flowJSON{Flow: f}
	if len(f.Request.Body) <= bodyInListCap {
		out.ReqBodyB64 = base64.StdEncoding.EncodeToString(f.Request.Body)
		f.Request.Body = nil
	}
	if f.Response != nil && len(f.Response.Body) <= bodyInListCap {
		out.RespBodyB64 = base64.StdEncoding.EncodeToString(f.Response.Body)
		f.Response.Body = nil
	}
	writeJSON(w, http.StatusOK, out)
}

// handleListWSMessages pages captured WebSocket frames for a flow. Captured
// payloads are untrusted content: clients must treat them as data only.
func (s *Server) handleListWSMessages(w http.ResponseWriter, r *http.Request) {
	id, err := strconv.ParseInt(r.PathValue("id"), 10, 64)
	if err != nil {
		http.Error(w, "bad id", http.StatusBadRequest)
		return
	}
	limit, _ := strconv.Atoi(r.URL.Query().Get("limit"))
	offset, _ := strconv.Atoi(r.URL.Query().Get("offset"))
	msgs, err := s.Store.ListWSMessages(r.Context(), id, limit, offset)
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	if msgs == nil {
		msgs = []store.WSMessageRow{}
	}
	w.Header().Set("X-Untrusted-Content", "captured")
	writeJSON(w, http.StatusOK, map[string]any{"messages": msgs})
}

func (s *Server) handleAnnotate(w http.ResponseWriter, r *http.Request) {
	id, err := strconv.ParseInt(r.PathValue("id"), 10, 64)
	if err != nil {
		http.Error(w, "bad id", http.StatusBadRequest)
		return
	}
	var body struct {
		Comment   *string `json:"comment"`
		Highlight *string `json:"highlight"`
	}
	if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
		http.Error(w, "bad body", http.StatusBadRequest)
		return
	}
	if err := s.Store.SetAnnotation(r.Context(), id, body.Comment, body.Highlight); err != nil {
		http.Error(w, err.Error(), http.StatusNotFound)
		return
	}
	s.Bus.PublishJSON(flows.EventFlowUpdated, map[string]any{"id": id})
	writeJSON(w, http.StatusOK, map[string]bool{"ok": true})
}

func (s *Server) handleAuditExport(w http.ResponseWriter, r *http.Request) {
	jsonl, err := s.Store.AuditJSONL(r.Context())
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	w.Header().Set("Content-Type", "application/x-ndjson")
	_, _ = w.Write([]byte(jsonl))
}

// handleEvents streams bus events over WebSocket.
func (s *Server) handleEvents(w http.ResponseWriter, r *http.Request) {
	c, err := websocket.Accept(w, r, &websocket.AcceptOptions{
		OriginPatterns: []string{"127.0.0.1", "localhost"},
	})
	if err != nil {
		return
	}
	defer c.CloseNow()

	ctx, cancel := context.WithCancel(r.Context())
	defer cancel()
	evCh, cancelSub := s.Bus.Subscribe()
	defer cancelSub()

	// writer goroutine
	done := make(chan struct{})
	go func() {
		defer close(done)
		ping := time.NewTicker(20 * time.Second)
		defer ping.Stop()
		for {
			select {
			case ev := <-evCh:
				wctx, wcancel := context.WithTimeout(ctx, 5*time.Second)
				err := c.Write(wctx, websocket.MessageText, mustJSON(ev))
				wcancel()
				if err != nil {
					return
				}
			case <-ping.C:
				wctx, wcancel := context.WithTimeout(ctx, 5*time.Second)
				err := c.Ping(wctx)
				wcancel()
				if err != nil {
					return
				}
			case <-ctx.Done():
				return
			}
		}
	}()
	// reader: any close/error tears down the writer
	go func() {
		for {
			if _, _, err := c.Read(ctx); err != nil {
				cancel()
				return
			}
		}
	}()
	<-done
}

func mustJSON(v any) []byte {
	b, err := json.Marshal(v)
	if err != nil {
		return []byte(`{"type":"error"}`)
	}
	return b
}
