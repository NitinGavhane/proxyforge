package api

import (
	"encoding/json"
	"net/http"
	"strconv"

	"github.com/NitinGavhane/proxyforge/internal/intercept"
)

// requireIntercept gates the intercept endpoints. Routes are registered with
// auth + audit in Handler(); these are manual-control-plane actions, so the
// audit log records each one.
func (s *Server) requireIntercept(w http.ResponseWriter, r *http.Request) *intercept.Manager {
	if s.Intercept == nil {
		http.Error(w, "intercept not configured", http.StatusServiceUnavailable)
		return nil
	}
	return s.Intercept
}

func (s *Server) handleInterceptOverview(w http.ResponseWriter, r *http.Request) {
	m := s.requireIntercept(w, r)
	if m == nil {
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{
		"enabled":             m.Enabled(),
		"intercept_responses": m.InterceptResponses(),
		"rules":               m.RuleList(),
		"pending":             m.Pending(),
	})
}

func (s *Server) handleInterceptToggle(w http.ResponseWriter, r *http.Request) {
	m := s.requireIntercept(w, r)
	if m == nil {
		return
	}
	var body struct {
		Enabled            *bool `json:"enabled"`
		InterceptResponses *bool `json:"intercept_responses"`
	}
	if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
		http.Error(w, "bad body", http.StatusBadRequest)
		return
	}
	if body.Enabled != nil {
		if err := m.SetEnabled(*body.Enabled); err != nil {
			http.Error(w, err.Error(), http.StatusInternalServerError)
			return
		}
	}
	if body.InterceptResponses != nil {
		if err := m.SetInterceptResponses(*body.InterceptResponses); err != nil {
			http.Error(w, err.Error(), http.StatusInternalServerError)
			return
		}
	}
	writeJSON(w, http.StatusOK, map[string]any{
		"enabled": m.Enabled(), "intercept_responses": m.InterceptResponses(),
	})
}

func (s *Server) handleInterceptRuleAdd(w http.ResponseWriter, r *http.Request) {
	m := s.requireIntercept(w, r)
	if m == nil {
		return
	}
	var body struct {
		Name    string         `json:"name"`
		Enabled bool           `json:"enabled"`
		Spec    intercept.Spec `json:"spec"`
	}
	if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
		http.Error(w, "bad body", http.StatusBadRequest)
		return
	}
	if body.Name == "" {
		http.Error(w, "name required", http.StatusBadRequest)
		return
	}
	id, err := m.AddRule(body.Name, body.Enabled, body.Spec)
	if err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"id": id, "rules": m.RuleList()})
}

func (s *Server) handleInterceptRuleDelete(w http.ResponseWriter, r *http.Request) {
	m := s.requireIntercept(w, r)
	if m == nil {
		return
	}
	id, err := strconv.ParseInt(r.PathValue("id"), 10, 64)
	if err != nil {
		http.Error(w, "bad id", http.StatusBadRequest)
		return
	}
	if err := m.DeleteRule(id); err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	writeJSON(w, http.StatusOK, map[string]bool{"ok": true})
}

func (s *Server) handleInterceptForward(w http.ResponseWriter, r *http.Request) {
	m := s.requireIntercept(w, r)
	if m == nil {
		return
	}
	id, err := strconv.ParseInt(r.PathValue("id"), 10, 64)
	if err != nil {
		http.Error(w, "bad id", http.StatusBadRequest)
		return
	}
	var edit intercept.Edit
	if r.ContentLength != 0 {
		if err := json.NewDecoder(r.Body).Decode(&edit); err != nil {
			http.Error(w, "bad edit", http.StatusBadRequest)
			return
		}
	}
	if err := m.Forward(id, &edit); err != nil {
		http.Error(w, err.Error(), http.StatusNotFound)
		return
	}
	writeJSON(w, http.StatusOK, map[string]bool{"ok": true})
}

func (s *Server) handleInterceptDrop(w http.ResponseWriter, r *http.Request) {
	m := s.requireIntercept(w, r)
	if m == nil {
		return
	}
	id, err := strconv.ParseInt(r.PathValue("id"), 10, 64)
	if err != nil {
		http.Error(w, "bad id", http.StatusBadRequest)
		return
	}
	if err := m.Drop(id); err != nil {
		http.Error(w, err.Error(), http.StatusNotFound)
		return
	}
	writeJSON(w, http.StatusOK, map[string]bool{"ok": true})
}

func (s *Server) handleInterceptForwardAll(w http.ResponseWriter, r *http.Request) {
	m := s.requireIntercept(w, r)
	if m == nil {
		return
	}
	n := m.ForwardAll()
	writeJSON(w, http.StatusOK, map[string]any{"forwarded": n})
}
