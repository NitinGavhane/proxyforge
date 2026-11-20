package api

import (
	"encoding/json"
	"net/http"
	"strconv"
	"time"

	"github.com/NitinGavhane/proxyforge/internal/scope"
	"github.com/NitinGavhane/proxyforge/internal/store"
	"github.com/NitinGavhane/proxyforge/internal/tags"
)

func (s *Server) requireScope(w http.ResponseWriter, r *http.Request) *scope.Manager {
	if s.Scope == nil {
		http.Error(w, "scope not configured", http.StatusServiceUnavailable)
		return nil
	}
	return s.Scope
}

func (s *Server) handleScopeGet(w http.ResponseWriter, r *http.Request) {
	m := s.requireScope(w, r)
	if m == nil {
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{
		"rules":              m.List(),
		"out_of_scope_count": m.OutOfScopeCount(),
	})
}

func (s *Server) handleScopeAdd(w http.ResponseWriter, r *http.Request) {
	m := s.requireScope(w, r)
	if m == nil {
		return
	}
	var body struct {
		Kind    string `json:"kind"`
		Pattern string `json:"pattern"`
		Enabled bool   `json:"enabled"`
	}
	if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
		http.Error(w, "bad body", http.StatusBadRequest)
		return
	}
	id, err := m.Add(body.Kind, body.Pattern, body.Enabled)
	if err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"id": id, "rules": m.List()})
}

func (s *Server) handleScopePatch(w http.ResponseWriter, r *http.Request) {
	m := s.requireScope(w, r)
	if m == nil {
		return
	}
	id, err := strconv.ParseInt(r.PathValue("id"), 10, 64)
	if err != nil {
		http.Error(w, "bad id", http.StatusBadRequest)
		return
	}
	var body struct {
		Enabled *bool `json:"enabled"`
	}
	if err := json.NewDecoder(r.Body).Decode(&body); err != nil || body.Enabled == nil {
		http.Error(w, "bad body", http.StatusBadRequest)
		return
	}
	if err := m.SetEnabled(id, *body.Enabled); err != nil {
		http.Error(w, err.Error(), http.StatusNotFound)
		return
	}
	writeJSON(w, http.StatusOK, map[string]bool{"ok": true})
}

func (s *Server) handleScopeDelete(w http.ResponseWriter, r *http.Request) {
	m := s.requireScope(w, r)
	if m == nil {
		return
	}
	id, err := strconv.ParseInt(r.PathValue("id"), 10, 64)
	if err != nil {
		http.Error(w, "bad id", http.StatusBadRequest)
		return
	}
	if err := m.Delete(id); err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	writeJSON(w, http.StatusOK, map[string]bool{"ok": true})
}

// handleScopePreview evaluates the CURRENT rules against recent history so
// the editor can show what a change would do before saving.
func (s *Server) handleScopePreview(w http.ResponseWriter, r *http.Request) {
	m := s.requireScope(w, r)
	if m == nil {
		return
	}
	rows, err := s.Store.ListFlows(r.Context(), store.Filter{Limit: 50})
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{
		"preview":            m.PreviewHistory(rows),
		"out_of_scope_count": m.OutOfScopeCount(),
	})
}

// handleAnnotateTab applies a browser-extension origin tag: matching flows
// are highlighted in history for the given duration.
func (s *Server) handleAnnotateTab(w http.ResponseWriter, r *http.Request) {
	if s.Tags == nil {
		http.Error(w, "tagging not configured", http.StatusServiceUnavailable)
		return
	}
	var body struct {
		Origin  string `json:"origin"`
		Minutes int    `json:"minutes"`
	}
	if err := json.NewDecoder(r.Body).Decode(&body); err != nil || body.Origin == "" {
		http.Error(w, "bad body: origin required", http.StatusBadRequest)
		return
	}
	mins := body.Minutes
	if mins <= 0 {
		mins = 10
	}
	s.Tags.Set(body.Origin, time.Duration(mins)*time.Minute)
	writeJSON(w, http.StatusOK, map[string]any{
		"origin":  tags.NormalizeHost(body.Origin),
		"minutes": mins,
		"active":  s.Tags.Active(),
	})
}
