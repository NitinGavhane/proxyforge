package api

import (
	"fmt"
	"net/http"
	"strconv"
	"strings"

	"github.com/NitinGavhane/proxyforge/internal/diff"
	"github.com/NitinGavhane/proxyforge/internal/flows"
	"github.com/NitinGavhane/proxyforge/internal/har"
	"github.com/NitinGavhane/proxyforge/internal/store"
)

// handleExportHAR exports the filtered selection (or explicit ids) as HAR.
// Content is captured data: responses carry the untrusted-content marker.
func (s *Server) handleExportHAR(w http.ResponseWriter, r *http.Request) {
	q := r.URL.Query()
	var fs []*flows.Flow
	if ids := q.Get("ids"); ids != "" {
		for _, part := range strings.Split(ids, ",") {
			id, err := strconv.ParseInt(strings.TrimSpace(part), 10, 64)
			if err != nil {
				http.Error(w, "bad id in ids", http.StatusBadRequest)
				return
			}
			f, err := s.Store.GetFlow(r.Context(), id)
			if err != nil {
				http.Error(w, err.Error(), http.StatusNotFound)
				return
			}
			fs = append(fs, f)
		}
	} else {
		limit, _ := strconv.Atoi(q.Get("limit"))
		rows, err := s.Store.ListFlows(r.Context(), store.Filter{
			Query: q.Get("q"), Host: q.Get("host"), Method: q.Get("method"),
			Status: q.Get("status"), Search: q.Get("search"), Limit: limit,
		})
		if err != nil {
			http.Error(w, err.Error(), http.StatusInternalServerError)
			return
		}
		for _, row := range rows {
			f, err := s.Store.GetFlow(r.Context(), row.ID)
			if err != nil {
				continue
			}
			fs = append(fs, f)
		}
	}
	doc, err := har.Export(fs)
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	w.Header().Set("Content-Type", "application/json")
	w.Header().Set("Content-Disposition", `attachment; filename="proxyforge.har"`)
	w.Header().Set("X-Untrusted-Content", "captured")
	_, _ = w.Write(doc)
}

// handleFlowHAR exports one flow as HAR.
func (s *Server) handleFlowHAR(w http.ResponseWriter, r *http.Request) {
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
	doc, err := har.Export([]*flows.Flow{f})
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	w.Header().Set("Content-Type", "application/json")
	w.Header().Set("Content-Disposition", fmt.Sprintf(`attachment; filename="proxyforge-flow-%d.har"`, id))
	w.Header().Set("X-Untrusted-Content", "captured")
	_, _ = w.Write(doc)
}

// handleFlowDiff diffs one part of two flows.
func (s *Server) handleFlowDiff(w http.ResponseWriter, r *http.Request) {
	aID, err := strconv.ParseInt(r.PathValue("id"), 10, 64)
	if err != nil {
		http.Error(w, "bad id", http.StatusBadRequest)
		return
	}
	bID, err := strconv.ParseInt(r.PathValue("other"), 10, 64)
	if err != nil {
		http.Error(w, "bad other id", http.StatusBadRequest)
		return
	}
	a, err := s.Store.GetFlow(r.Context(), aID)
	if err != nil {
		http.Error(w, err.Error(), http.StatusNotFound)
		return
	}
	b, err := s.Store.GetFlow(r.Context(), bID)
	if err != nil {
		http.Error(w, err.Error(), http.StatusNotFound)
		return
	}

	mode := r.URL.Query().Get("mode")
	part := r.URL.Query().Get("part")
	if part == "" {
		part = "req_body"
	}
	var av, bv string
	switch part {
	case "req_body":
		av, bv = string(a.Request.Body), string(b.Request.Body)
	case "resp_body":
		av, bv = bodyOrEmpty(a.Response), bodyOrEmpty(b.Response)
	case "req_headers":
		av, bv = renderHeaders(a.Request.Headers), renderHeaders(b.Request.Headers)
	case "resp_headers":
		av, bv = headersOrEmpty(a.Response), headersOrEmpty(b.Response)
	default:
		http.Error(w, "part must be req_body|resp_body|req_headers|resp_headers", http.StatusBadRequest)
		return
	}
	res := diff.Compute(av, bv, mode)
	res.AMode = fmt.Sprintf("#%d", aID)
	res.BMode = fmt.Sprintf("#%d", bID)
	w.Header().Set("X-Untrusted-Content", "captured")
	writeJSON(w, http.StatusOK, res)
}

func bodyOrEmpty(resp *flows.Response) string {
	if resp == nil {
		return ""
	}
	return string(resp.Body)
}

func headersOrEmpty(resp *flows.Response) string {
	if resp == nil {
		return ""
	}
	return renderHeaders(resp.Headers)
}

func renderHeaders(h flows.Headers) string {
	var sb strings.Builder
	for _, hd := range h {
		sb.WriteString(hd.Key)
		sb.WriteString(": ")
		sb.WriteString(hd.Value)
		sb.WriteString("\n")
	}
	return sb.String()
}
