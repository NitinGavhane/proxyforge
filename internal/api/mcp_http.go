package api

import (
	"encoding/json"
	"io"
	"net/http"

	"github.com/NitinGavhane/proxyforge/internal/mcp"
)

// handleMCP is the streamable HTTP transport: one JSON-RPC request per
// POST, one JSON response (stateless server mode). Auth + audit wrap it.
func (s *Server) handleMCP(w http.ResponseWriter, r *http.Request) {
	if s.MCP == nil {
		http.Error(w, "mcp not configured", http.StatusServiceUnavailable)
		return
	}
	body, err := io.ReadAll(io.LimitReader(r.Body, 4<<20))
	if err != nil {
		http.Error(w, "bad body", http.StatusBadRequest)
		return
	}
	var req mcp.Request
	if err := json.Unmarshal(body, &req); err != nil {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusOK)
		_ = json.NewEncoder(w).Encode(mcp.NewError(nil, mcp.CodeParseError, err.Error()))
		return
	}
	// MCP-Session-Id is ignored: the server is stateless.
	resp := s.MCP.Dispatch(r.Context(), req)
	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(resp)
}
