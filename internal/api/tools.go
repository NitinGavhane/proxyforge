package api

import (
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"strconv"
	"strings"
	"time"

	"github.com/NitinGavhane/proxyforge/internal/burpxml"
	"github.com/NitinGavhane/proxyforge/internal/collab"
	"github.com/NitinGavhane/proxyforge/internal/diff"
	"github.com/NitinGavhane/proxyforge/internal/extjs"
	"github.com/NitinGavhane/proxyforge/internal/flows"
	"github.com/NitinGavhane/proxyforge/internal/report"
	"github.com/NitinGavhane/proxyforge/internal/store"
	"github.com/NitinGavhane/proxyforge/internal/tools"
)

// --- site map ---

// SiteHost is one host node of the tree.
type SiteHost struct {
	Host      string     `json:"host"`
	Endpoints int        `json:"endpoints"`
	Paths     []SitePath `json:"paths"`
}

// SitePath aggregates the methods seen for one path.
type SitePath struct {
	Path     string   `json:"path"`
	Scheme   string   `json:"scheme"`
	Port     int      `json:"port"`
	Methods  []string `json:"methods"`
	Status   int      `json:"status,omitempty"`
	Count    int64    `json:"count"`
	Source   string   `json:"source"` // capture | import | discovery
	Observed bool     `json:"observed"`
	// Shadow marks imported-but-never-observed endpoints (e.g. recovered
	// from a client binary via REA) — candidate hidden API surface.
	Shadow   bool  `json:"shadow,omitempty"`
	LastSeen int64 `json:"last_seen"`
}

func (s *Server) handleSitemapGet(w http.ResponseWriter, r *http.Request) {
	eps, err := s.Store.ListEndpoints(r.Context())
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	// observed set: any captured endpoint (scheme,host,port,path)
	type key struct {
		scheme, host string
		port         int
		path         string
	}
	observed := map[key]bool{}
	for _, e := range eps {
		if e.Source == "capture" {
			observed[key{e.Scheme, e.Host, e.Port, e.Path}] = true
		}
	}
	hosts := map[string]*SiteHost{}
	order := []string{}
	addHost := func(h string) *SiteHost {
		hh, ok := hosts[h]
		if !ok {
			hh = &SiteHost{Host: h}
			hosts[h] = hh
			order = append(order, h)
		}
		return hh
	}
	// paths aggregate across methods; first source wins for display with
	// capture preferred
	pathIdx := map[string]*SitePath{}
	for _, e := range eps {
		hh := addHost(e.Host)
		hh.Endpoints++
		id := e.Scheme + "|" + strconv.Itoa(e.Port) + "|" + e.Path
		sp, ok := pathIdx[id]
		if !ok {
			sp = &SitePath{
				Path: e.Path, Scheme: e.Scheme, Port: e.Port,
				Status: e.Status, Count: e.Count, Source: e.Source,
				LastSeen: e.LastSeen,
			}
			pathIdx[id] = sp
			hh.Paths = append(hh.Paths, *sp)
			// replace the appended copy with the addressable one
			hh.Paths[len(hh.Paths)-1] = *sp
		}
		if !contains(sp.Methods, e.Method) {
			sp.Methods = append(sp.Methods, e.Method)
		}
		sp.Count += e.Count
		if e.Source == "capture" {
			sp.Source = "capture"
			sp.Status = e.Status
			sp.LastSeen = e.LastSeen
		}
	}
	// annotate shadows + fix method lists through the host copies
	out := make([]SiteHost, 0, len(order))
	for _, h := range order {
		hh := hosts[h]
		fixed := make([]SitePath, 0, len(hh.Paths))
		for i := range hh.Paths {
			sp := pathIdx[hh.Paths[i].Scheme+"|"+strconv.Itoa(hh.Paths[i].Port)+"|"+hh.Paths[i].Path]
			k := key{sp.Scheme, hh.Host, sp.Port, sp.Path}
			sp.Observed = observed[k]
			sp.Shadow = !sp.Observed && sp.Source == "import"
			fixed = append(fixed, *sp)
		}
		hh.Paths = fixed
		out = append(out, *hh)
	}
	writeJSON(w, http.StatusOK, map[string]any{"hosts": out})
}

func contains(list []string, s string) bool {
	for _, v := range list {
		if v == s {
			return true
		}
	}
	return false
}

// handleSitemapImport bulk-imports endpoints (the REA bridge: endpoints
// recovered from a client binary land here and are flagged as shadow
// surface until observed in live traffic).
func (s *Server) handleSitemapImport(w http.ResponseWriter, r *http.Request) {
	var body struct {
		Source    string `json:"source"` // default "import"
		Endpoints []struct {
			Scheme string `json:"scheme"`
			Host   string `json:"host"`
			Port   int    `json:"port"`
			Method string `json:"method"`
			Path   string `json:"path"`
		} `json:"endpoints"`
	}
	if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
		http.Error(w, "bad body", http.StatusBadRequest)
		return
	}
	if len(body.Endpoints) == 0 {
		http.Error(w, "endpoints required", http.StatusBadRequest)
		return
	}
	if body.Source == "" {
		body.Source = "import"
	}
	if body.Source != "import" {
		http.Error(w, "source must be 'import'", http.StatusBadRequest)
		return
	}
	n := 0
	for _, e := range body.Endpoints {
		if e.Host == "" || e.Path == "" {
			continue
		}
		if e.Scheme == "" {
			e.Scheme = "https"
		}
		if e.Port == 0 {
			if e.Scheme == "https" {
				e.Port = 443
			} else {
				e.Port = 80
			}
		}
		if e.Method == "" {
			e.Method = "GET"
		}
		ep := store.Endpoint{
			Source: body.Source, Scheme: e.Scheme, Host: e.Host, Port: e.Port,
			Method: e.Method, Path: e.Path,
		}
		if err := s.Store.InsertEndpoint(r.Context(), ep); err != nil {
			http.Error(w, err.Error(), http.StatusInternalServerError)
			return
		}
		n++
	}
	writeJSON(w, http.StatusOK, map[string]any{"imported": n})
}

// --- discovery ---

func (s *Server) requireDiscovery(w http.ResponseWriter, r *http.Request) *tools.Discovery {
	if s.Discovery == nil {
		http.Error(w, "discovery not configured", http.StatusServiceUnavailable)
		return nil
	}
	return s.Discovery
}

func (s *Server) handleDiscoveryStart(w http.ResponseWriter, r *http.Request) {
	d := s.requireDiscovery(w, r)
	if d == nil {
		return
	}
	var body struct {
		BaseURL    string   `json:"base_url"`
		Wordlist   []string `json:"wordlist"`
		RatePerSec int      `json:"rate_per_sec"`
	}
	if err := json.NewDecoder(r.Body).Decode(&body); err != nil || body.BaseURL == "" {
		http.Error(w, "bad body: base_url required", http.StatusBadRequest)
		return
	}
	job, err := d.Start(body.BaseURL, body.Wordlist, body.RatePerSec)
	if err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"job": job})
}

func (s *Server) handleDiscoveryList(w http.ResponseWriter, r *http.Request) {
	d := s.requireDiscovery(w, r)
	if d == nil {
		return
	}
	jobs := d.List()
	if jobs == nil {
		jobs = []tools.DiscoveryJob{}
	}
	writeJSON(w, http.StatusOK, map[string]any{"jobs": jobs})
}

func (s *Server) handleDiscoveryGet(w http.ResponseWriter, r *http.Request) {
	d := s.requireDiscovery(w, r)
	if d == nil {
		return
	}
	id, err := strconv.ParseInt(r.PathValue("id"), 10, 64)
	if err != nil {
		http.Error(w, "bad id", http.StatusBadRequest)
		return
	}
	job, err := d.Get(id)
	if err != nil {
		http.Error(w, err.Error(), http.StatusNotFound)
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"job": job})
}

func (s *Server) handleDiscoveryStop(w http.ResponseWriter, r *http.Request) {
	d := s.requireDiscovery(w, r)
	if d == nil {
		return
	}
	id, err := strconv.ParseInt(r.PathValue("id"), 10, 64)
	if err != nil {
		http.Error(w, "bad id", http.StatusBadRequest)
		return
	}
	if err := d.Stop(id); err != nil {
		http.Error(w, err.Error(), http.StatusNotFound)
		return
	}
	writeJSON(w, http.StatusOK, map[string]bool{"ok": true})
}

// --- repeater ---

func (s *Server) requireRepeater(w http.ResponseWriter, r *http.Request) *tools.Repeater {
	if s.Repeater == nil {
		http.Error(w, "repeater not configured", http.StatusServiceUnavailable)
		return nil
	}
	return s.Repeater
}

func (s *Server) handleRepeaterTabs(w http.ResponseWriter, r *http.Request) {
	rep := s.requireRepeater(w, r)
	if rep == nil {
		return
	}
	switch r.Method {
	case http.MethodGet:
		tabs, err := rep.Tabs(r.Context())
		if err != nil {
			http.Error(w, err.Error(), http.StatusInternalServerError)
			return
		}
		writeJSON(w, http.StatusOK, map[string]any{"tabs": tabs})
	case http.MethodPost:
		var body struct {
			Name string `json:"name"`
			Raw  string `json:"raw"`
		}
		if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
			http.Error(w, "bad body", http.StatusBadRequest)
			return
		}
		id, err := rep.NewTab(r.Context(), body.Name, body.Raw)
		if err != nil {
			http.Error(w, err.Error(), http.StatusInternalServerError)
			return
		}
		writeJSON(w, http.StatusOK, map[string]any{"id": id})
	}
}

func (s *Server) handleRepeaterTab(w http.ResponseWriter, r *http.Request) {
	rep := s.requireRepeater(w, r)
	if rep == nil {
		return
	}
	id, err := strconv.ParseInt(r.PathValue("id"), 10, 64)
	if err != nil {
		http.Error(w, "bad id", http.StatusBadRequest)
		return
	}
	switch r.Method {
	case http.MethodPatch:
		var body struct {
			Name string `json:"name"`
			Raw  string `json:"raw"`
		}
		if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
			http.Error(w, "bad body", http.StatusBadRequest)
			return
		}
		if err := rep.SaveTab(r.Context(), id, body.Name, body.Raw); err != nil {
			http.Error(w, err.Error(), http.StatusNotFound)
			return
		}
		writeJSON(w, http.StatusOK, map[string]bool{"ok": true})
	case http.MethodDelete:
		if err := rep.DeleteTab(r.Context(), id); err != nil {
			http.Error(w, err.Error(), http.StatusInternalServerError)
			return
		}
		writeJSON(w, http.StatusOK, map[string]bool{"ok": true})
	}
}

func (s *Server) handleRepeaterSend(w http.ResponseWriter, r *http.Request) {
	rep := s.requireRepeater(w, r)
	if rep == nil {
		return
	}
	id, err := strconv.ParseInt(r.PathValue("id"), 10, 64)
	if err != nil {
		http.Error(w, "bad id", http.StatusBadRequest)
		return
	}
	var body struct {
		Raw             string `json:"raw"`
		FollowRedirects bool   `json:"follow_redirects"`
		MaxHops         int    `json:"max_hops"`
		UseJar          bool   `json:"use_jar"`
		MacroFlowID     int64  `json:"macro_flow_id"`
	}
	_ = json.NewDecoder(r.Body).Decode(&body) // empty body = use stored raw
	opts := tools.SendOptions{UseJar: body.UseJar, MacroFlowID: body.MacroFlowID}
	res, err := rep.SendOpts(r.Context(), id, body.Raw, body.FollowRedirects, body.MaxHops, opts)
	if err != nil && res.Final == nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"result": res})
}

func (s *Server) handleRepeaterHistory(w http.ResponseWriter, r *http.Request) {
	rep := s.requireRepeater(w, r)
	if rep == nil {
		return
	}
	id, err := strconv.ParseInt(r.PathValue("id"), 10, 64)
	if err != nil {
		http.Error(w, "bad id", http.StatusBadRequest)
		return
	}
	rows, err := rep.History(r.Context(), id, 50)
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"history": rows})
}

// --- intruder ---

func (s *Server) requireIntruder(w http.ResponseWriter, r *http.Request) *tools.Intruder {
	if s.Intruder == nil {
		http.Error(w, "intruder not configured", http.StatusServiceUnavailable)
		return nil
	}
	return s.Intruder
}

func (s *Server) handleIntruderStart(w http.ResponseWriter, r *http.Request) {
	ins := s.requireIntruder(w, r)
	if ins == nil {
		return
	}
	var cfg tools.AttackConfig
	if err := json.NewDecoder(r.Body).Decode(&cfg); err != nil {
		http.Error(w, "bad body", http.StatusBadRequest)
		return
	}
	job, err := ins.Start(cfg)
	if err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"job": job})
}

func (s *Server) handleIntruderList(w http.ResponseWriter, r *http.Request) {
	ins := s.requireIntruder(w, r)
	if ins == nil {
		return
	}
	jobs := ins.List()
	if jobs == nil {
		jobs = []tools.IntruderJob{}
	}
	writeJSON(w, http.StatusOK, map[string]any{"jobs": jobs})
}

func (s *Server) handleIntruderGet(w http.ResponseWriter, r *http.Request) {
	ins := s.requireIntruder(w, r)
	if ins == nil {
		return
	}
	id, err := strconv.ParseInt(r.PathValue("id"), 10, 64)
	if err != nil {
		http.Error(w, "bad id", http.StatusBadRequest)
		return
	}
	job, err := ins.Get(id)
	if err != nil {
		http.Error(w, err.Error(), http.StatusNotFound)
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"job": job})
}

func (s *Server) handleIntruderStop(w http.ResponseWriter, r *http.Request) {
	ins := s.requireIntruder(w, r)
	if ins == nil {
		return
	}
	id, err := strconv.ParseInt(r.PathValue("id"), 10, 64)
	if err != nil {
		http.Error(w, "bad id", http.StatusBadRequest)
		return
	}
	if err := ins.Stop(id); err != nil {
		http.Error(w, err.Error(), http.StatusNotFound)
		return
	}
	writeJSON(w, http.StatusOK, map[string]bool{"ok": true})
}

// --- decoder / comparer / sequencer ---

func (s *Server) handleDecode(w http.ResponseWriter, r *http.Request) {
	var body struct {
		Input  string `json:"input"`
		Format string `json:"format"`
		Mode   string `json:"mode"`
	}
	if err := json.NewDecoder(r.Body).Decode(&body); err != nil || body.Input == "" {
		http.Error(w, "bad body: input required", http.StatusBadRequest)
		return
	}
	if body.Mode == "" {
		body.Mode = "decode"
	}
	writeJSON(w, http.StatusOK, map[string]any{
		"result": tools.Transform(body.Input, body.Format, body.Mode),
	})
}

func (s *Server) handleCompareRaw(w http.ResponseWriter, r *http.Request) {
	var body struct {
		A    string `json:"a"`
		B    string `json:"b"`
		Mode string `json:"mode"`
	}
	if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
		http.Error(w, "bad body", http.StatusBadRequest)
		return
	}
	if body.Mode == "" {
		body.Mode = "word"
	}
	writeJSON(w, http.StatusOK, diff.Compute(body.A, body.B, body.Mode))
}

func (s *Server) handleSequencer(w http.ResponseWriter, r *http.Request) {
	var body struct {
		Tokens string `json:"tokens"` // one per line
	}
	if err := json.NewDecoder(r.Body).Decode(&body); err != nil || strings.TrimSpace(body.Tokens) == "" {
		http.Error(w, "bad body: tokens required (one per line)", http.StatusBadRequest)
		return
	}
	res, err := tools.AnalyzeTokens(strings.Split(body.Tokens, "\n"))
	if err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"analysis": res})
}

// --- scanner ---

func (s *Server) requireScanner(w http.ResponseWriter, r *http.Request) *tools.Scanner {
	if s.Scanner == nil {
		http.Error(w, "scanner not configured", http.StatusServiceUnavailable)
		return nil
	}
	return s.Scanner
}

func (s *Server) handleScanStart(w http.ResponseWriter, r *http.Request) {
	scn := s.requireScanner(w, r)
	if scn == nil {
		return
	}
	var cfg tools.ScanConfig
	if err := json.NewDecoder(r.Body).Decode(&cfg); err != nil {
		http.Error(w, "bad body", http.StatusBadRequest)
		return
	}
	job, err := scn.Start(cfg)
	if err != nil {
		// the confirmation gate and validation errors are client errors
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"job": job})
}

func (s *Server) handleScanGet(w http.ResponseWriter, r *http.Request) {
	scn := s.requireScanner(w, r)
	if scn == nil {
		return
	}
	id, err := strconv.ParseInt(r.PathValue("id"), 10, 64)
	if err != nil {
		http.Error(w, "bad id", http.StatusBadRequest)
		return
	}
	job, err := scn.Get(id)
	if err != nil {
		http.Error(w, err.Error(), http.StatusNotFound)
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"job": job})
}

func (s *Server) handleIssuesList(w http.ResponseWriter, r *http.Request) {
	q := r.URL.Query()
	limit, _ := strconv.Atoi(q.Get("limit"))
	issues, err := s.Store.ListIssues(r.Context(), store.IssueFilter{
		Host:     q.Get("host"),
		Severity: q.Get("severity"),
		Limit:    limit,
	})
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	if issues == nil {
		issues = []store.Issue{}
	}
	writeJSON(w, http.StatusOK, map[string]any{"issues": issues})
}

func (s *Server) handleIssueGet(w http.ResponseWriter, r *http.Request) {
	id, err := strconv.ParseInt(r.PathValue("id"), 10, 64)
	if err != nil {
		http.Error(w, "bad id", http.StatusBadRequest)
		return
	}
	iss, err := s.Store.GetIssue(r.Context(), id)
	if err != nil {
		http.Error(w, err.Error(), http.StatusNotFound)
		return
	}
	writeJSON(w, http.StatusOK, iss)
}

// --- collaborator ---

func (s *Server) requireCollab(w http.ResponseWriter, r *http.Request) *collab.Manager {
	if s.Collab == nil {
		http.Error(w, "collaborator not configured (start daemon with -collab-addr)", http.StatusServiceUnavailable)
		return nil
	}
	return s.Collab
}

func (s *Server) handleCollabNew(w http.ResponseWriter, r *http.Request) {
	m := s.requireCollab(w, r)
	if m == nil {
		return
	}
	var body struct {
		Label string `json:"label"`
	}
	_ = json.NewDecoder(r.Body).Decode(&body) // label optional
	c, err := m.NewCanary(r.Context(), body.Label)
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"canary": c})
}

func (s *Server) handleCollabInteractions(w http.ResponseWriter, r *http.Request) {
	m := s.requireCollab(w, r)
	if m == nil {
		return
	}
	list, err := m.Interactions(r.Context(), r.URL.Query().Get("canary"))
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	if list == nil {
		list = []store.Interaction{}
	}
	writeJSON(w, http.StatusOK, map[string]any{"interactions": list})
}

// --- logger exports + organizer + session ---

func (s *Server) handleExportFlowsCSV(w http.ResponseWriter, r *http.Request) {
	rows, err := s.Store.ListFlows(r.Context(), store.Filter{Limit: 500})
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	var b strings.Builder
	b.WriteString("id,started,duration_ms,scheme,method,host,port,path,status,origin,comment\n")
	for _, f := range rows {
		fmt.Fprintf(&b, "%d,%d,%d,%s,%s,%s,%d,%s,%d,%s,%s\n",
			f.ID, f.Started, f.DurationMS, f.Scheme, csv(f.Method), csv(f.Host),
			f.Port, csv(f.Path), f.Status, f.Origin, csv(f.Comment))
	}
	w.Header().Set("Content-Type", "text/csv")
	w.Header().Set("Content-Disposition", `attachment; filename="proxyforge-flows.csv"`)
	_, _ = w.Write([]byte(b.String()))
}

func csv(v string) string {
	if strings.ContainsAny(v, ",\"\n") {
		return `"` + strings.ReplaceAll(v, `"`, `""`) + `"`
	}
	return v
}

func (s *Server) handleExportFlowsJSON(w http.ResponseWriter, r *http.Request) {
	rows, err := s.Store.ListFlows(r.Context(), store.Filter{Limit: 500})
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"flows": rows})
}

func (s *Server) handleExportBurpXML(w http.ResponseWriter, r *http.Request) {
	rows, err := s.Store.ListFlows(r.Context(), store.Filter{Limit: 500})
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	var fs []*flows.Flow
	for _, row := range rows {
		if f, err := s.Store.GetFlow(r.Context(), row.ID); err == nil {
			fs = append(fs, f)
		}
	}
	doc, err := burpxml.Export(fs)
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	w.Header().Set("Content-Type", "application/xml")
	w.Header().Set("Content-Disposition", `attachment; filename="proxyforge-burp.xml"`)
	_, _ = w.Write(doc)
}

// handleImportBurpXML reads a Burp XML export and records the entries as
// import-origin flows.
func (s *Server) handleImportBurpXML(w http.ResponseWriter, r *http.Request) {
	body, err := io.ReadAll(io.LimitReader(r.Body, 64<<20))
	if err != nil {
		http.Error(w, "bad body", http.StatusBadRequest)
		return
	}
	items, err := burpxml.Import(body)
	if err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}
	n := 0
	for _, it := range items {
		if it.Host == "" {
			continue
		}
		req, perr := tools.ParseRawRequest(string(it.Request))
		if perr != nil {
			continue
		}
		f := &flows.Flow{
			Started: time.Now(), Origin: flows.OriginImport,
			Comment: it.Comment,
			Request: req,
		}
		if len(it.Response) > 0 {
			if res, rerr := tools.ParseRawResponse(string(it.Response)); rerr == nil {
				f.Response = res
			}
		}
		if err := s.Store.InsertFlow(r.Context(), f); err == nil {
			_ = s.Store.UpsertEndpointFromFlow(r.Context(), f)
			n++
		}
	}
	writeJSON(w, http.StatusOK, map[string]any{"imported": n})
}

// --- organizer ---

func (s *Server) handleOrganizerSave(w http.ResponseWriter, r *http.Request) {
	var body struct {
		FlowID int64  `json:"flow_id"`
		Note   string `json:"note"`
		Tags   string `json:"tags"`
	}
	if err := json.NewDecoder(r.Body).Decode(&body); err != nil || body.FlowID == 0 {
		http.Error(w, "bad body: flow_id required", http.StatusBadRequest)
		return
	}
	if _, err := s.Store.GetFlow(r.Context(), body.FlowID); err != nil {
		http.Error(w, err.Error(), http.StatusNotFound)
		return
	}
	id, err := s.Store.SaveOrganizerItem(r.Context(), body.FlowID, body.Note, body.Tags)
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"id": id})
}

func (s *Server) handleOrganizerList(w http.ResponseWriter, r *http.Request) {
	items, err := s.Store.ListOrganizer(r.Context())
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	if items == nil {
		items = []store.OrganizerItem{}
	}
	writeJSON(w, http.StatusOK, map[string]any{"items": items})
}

func (s *Server) handleOrganizerDelete(w http.ResponseWriter, r *http.Request) {
	id, err := strconv.ParseInt(r.PathValue("id"), 10, 64)
	if err != nil {
		http.Error(w, "bad id", http.StatusBadRequest)
		return
	}
	if err := s.Store.DeleteOrganizerItem(r.Context(), id); err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	writeJSON(w, http.StatusOK, map[string]bool{"ok": true})
}

// --- session: jar + macros ---

func (s *Server) handleJarGet(w http.ResponseWriter, r *http.Request) {
	host := r.URL.Query().Get("host")
	port, _ := strconv.Atoi(r.URL.Query().Get("port"))
	cs, err := s.Store.JarCookies(r.Context(), host, port)
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	if cs == nil {
		cs = []store.Cookie{}
	}
	writeJSON(w, http.StatusOK, map[string]any{"cookies": cs})
}

func (s *Server) handleMacroNew(w http.ResponseWriter, r *http.Request) {
	var body struct {
		Name   string `json:"name"`
		FlowID int64  `json:"flow_id"`
	}
	if err := json.NewDecoder(r.Body).Decode(&body); err != nil || body.FlowID == 0 {
		http.Error(w, "bad body: flow_id required", http.StatusBadRequest)
		return
	}
	if _, err := s.Store.GetFlow(r.Context(), body.FlowID); err != nil {
		http.Error(w, err.Error(), http.StatusNotFound)
		return
	}
	id, err := s.Store.InsertMacro(r.Context(), body.Name, body.FlowID)
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"id": id})
}

func (s *Server) handleMacroList(w http.ResponseWriter, r *http.Request) {
	ms, err := s.Store.ListMacros(r.Context())
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	if ms == nil {
		ms = []store.Macro{}
	}
	writeJSON(w, http.StatusOK, map[string]any{"macros": ms})
}

func (s *Server) handleMacroDelete(w http.ResponseWriter, r *http.Request) {
	id, err := strconv.ParseInt(r.PathValue("id"), 10, 64)
	if err != nil {
		http.Error(w, "bad id", http.StatusBadRequest)
		return
	}
	if err := s.Store.DeleteMacro(r.Context(), id); err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	writeJSON(w, http.StatusOK, map[string]bool{"ok": true})
}

// --- P8: imports + reports ---

func (s *Server) handleImportCURL(w http.ResponseWriter, r *http.Request) {
	var body struct {
		Command string `json:"command"`
		AsTab   bool   `json:"as_tab"`
	}
	if err := json.NewDecoder(r.Body).Decode(&body); err != nil || strings.TrimSpace(body.Command) == "" {
		http.Error(w, "bad body: command required", http.StatusBadRequest)
		return
	}
	raw, err := tools.ParseCURL(body.Command)
	if err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}
	if body.AsTab && s.Repeater != nil {
		id, err := s.Repeater.NewTab(r.Context(), "curl import", raw)
		if err == nil {
			writeJSON(w, http.StatusOK, map[string]any{"raw": raw, "tab_id": id})
			return
		}
	}
	writeJSON(w, http.StatusOK, map[string]any{"raw": raw})
}

func (s *Server) handleImportEndpoints(w http.ResponseWriter, r *http.Request, kind string, parse func(string) ([]tools.ImportEndpoint, error)) {
	body, err := io.ReadAll(io.LimitReader(r.Body, 64<<20))
	if err != nil {
		http.Error(w, "bad body", http.StatusBadRequest)
		return
	}
	eps, err := parse(string(body))
	if err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}
	n := 0
	for _, e := range eps {
		if err := s.Store.InsertEndpoint(r.Context(), store.Endpoint{
			Source: "import", Scheme: e.Scheme, Host: e.Host, Port: e.Port,
			Method: e.Method, Path: e.Path,
		}); err == nil {
			n++
		}
	}
	writeJSON(w, http.StatusOK, map[string]any{"imported": n, "kind": kind})
}

func (s *Server) handleImportOpenAPI(w http.ResponseWriter, r *http.Request) {
	s.handleImportEndpoints(w, r, "openapi", tools.ParseOpenAPI)
}

func (s *Server) handleImportPostman(w http.ResponseWriter, r *http.Request) {
	s.handleImportEndpoints(w, r, "postman", tools.ParsePostman)
}

func (s *Server) handleReport(w http.ResponseWriter, r *http.Request, asHTML bool) {
	issues, err := s.Store.ListIssues(r.Context(), store.IssueFilter{})
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	meta := report.Meta{Target: r.URL.Query().Get("target"), When: time.Now()}
	if asHTML {
		w.Header().Set("Content-Type", "text/html; charset=utf-8")
		w.Header().Set("Content-Disposition", `attachment; filename="proxyforge-report.html"`)
		_, _ = w.Write([]byte(report.RenderHTML(r.Context(), s.Store, meta, issues)))
		return
	}
	w.Header().Set("Content-Type", "text/markdown; charset=utf-8")
	w.Header().Set("Content-Disposition", `attachment; filename="proxyforge-report.md"`)
	_, _ = w.Write([]byte(report.Render(r.Context(), s.Store, meta, issues)))
}

// --- extensions (P9) ---

func (s *Server) requireScripts(w http.ResponseWriter, r *http.Request) *extjs.Manager {
	if s.Scripts == nil {
		http.Error(w, "scripting not configured", http.StatusServiceUnavailable)
		return nil
	}
	return s.Scripts
}

func (s *Server) handleExtList(w http.ResponseWriter, r *http.Request) {
	m := s.requireScripts(w, r)
	if m == nil {
		return
	}
	list, err := m.List(r.Context())
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	if list == nil {
		list = []store.Extension{}
	}
	writeJSON(w, http.StatusOK, map[string]any{"extensions": list})
}

func (s *Server) handleExtAdd(w http.ResponseWriter, r *http.Request) {
	m := s.requireScripts(w, r)
	if m == nil {
		return
	}
	var body struct {
		Name    string `json:"name"`
		Code    string `json:"code"`
		Enabled bool   `json:"enabled"`
	}
	if err := json.NewDecoder(r.Body).Decode(&body); err != nil || body.Name == "" || body.Code == "" {
		http.Error(w, "bad body: name and code required", http.StatusBadRequest)
		return
	}
	id, err := m.Add(r.Context(), body.Name, body.Code, body.Enabled)
	if err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"id": id})
}

func (s *Server) handleExtPatch(w http.ResponseWriter, r *http.Request) {
	m := s.requireScripts(w, r)
	if m == nil {
		return
	}
	id, err := strconv.ParseInt(r.PathValue("id"), 10, 64)
	if err != nil {
		http.Error(w, "bad id", http.StatusBadRequest)
		return
	}
	var body struct {
		Name    *string `json:"name"`
		Code    *string `json:"code"`
		Enabled *bool   `json:"enabled"`
	}
	if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
		http.Error(w, "bad body", http.StatusBadRequest)
		return
	}
	if err := m.Update(r.Context(), id, body.Name, body.Code, body.Enabled); err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}
	writeJSON(w, http.StatusOK, map[string]bool{"ok": true})
}

func (s *Server) handleExtDelete(w http.ResponseWriter, r *http.Request) {
	m := s.requireScripts(w, r)
	if m == nil {
		return
	}
	id, err := strconv.ParseInt(r.PathValue("id"), 10, 64)
	if err != nil {
		http.Error(w, "bad id", http.StatusBadRequest)
		return
	}
	if err := m.Delete(r.Context(), id); err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	writeJSON(w, http.StatusOK, map[string]bool{"ok": true})
}

func (s *Server) handleExtTest(w http.ResponseWriter, r *http.Request) {
	m := s.requireScripts(w, r)
	if m == nil {
		return
	}
	id, err := strconv.ParseInt(r.PathValue("id"), 10, 64)
	if err != nil {
		http.Error(w, "bad id", http.StatusBadRequest)
		return
	}
	var body struct {
		FlowID int64 `json:"flow_id"`
	}
	_ = json.NewDecoder(r.Body).Decode(&body)
	view, err := m.TestWith(r.Context(), id, body.FlowID)
	if err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}
	writeJSON(w, http.StatusOK, view)
}
