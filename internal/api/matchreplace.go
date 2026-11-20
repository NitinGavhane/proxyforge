package api

import (
	"encoding/json"
	"net/http"
	"strconv"

	"github.com/NitinGavhane/proxyforge/internal/intercept"
	"github.com/NitinGavhane/proxyforge/internal/matchreplace"
)

func (s *Server) requireMR(w http.ResponseWriter, r *http.Request) *matchreplace.Manager {
	if s.MatchReplace == nil {
		http.Error(w, "match & replace not configured", http.StatusServiceUnavailable)
		return nil
	}
	return s.MatchReplace
}

func (s *Server) handleMRList(w http.ResponseWriter, r *http.Request) {
	m := s.requireMR(w, r)
	if m == nil {
		return
	}
	rules := m.List()
	if rules == nil {
		rules = []matchreplace.RuleView{}
	}
	writeJSON(w, http.StatusOK, map[string]any{"rules": rules})
}

func (s *Server) handleMRAdd(w http.ResponseWriter, r *http.Request) {
	m := s.requireMR(w, r)
	if m == nil {
		return
	}
	var body struct {
		Name      string              `json:"name"`
		Enabled   bool                `json:"enabled"`
		Direction string              `json:"direction"`
		Spec      intercept.Spec      `json:"spec"`
		Action    matchreplace.Action `json:"action"`
	}
	if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
		http.Error(w, "bad body", http.StatusBadRequest)
		return
	}
	id, err := m.Add(body.Name, body.Enabled, body.Direction, body.Spec, body.Action)
	if err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"id": id, "rules": m.List()})
}

func (s *Server) handleMRPatch(w http.ResponseWriter, r *http.Request) {
	m := s.requireMR(w, r)
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

func (s *Server) handleMRDelete(w http.ResponseWriter, r *http.Request) {
	m := s.requireMR(w, r)
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
