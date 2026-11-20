// Scanner (Phase 3 P5): passive checks run against captured (or freshly
// fetched) responses; active checks are OPT-IN (explicit confirm flag) and
// send every probe through the outbound gate — scope-gated, audited,
// captured. Every issue carries the triggering flow as evidence.
package tools

import (
	"context"
	"fmt"
	"net/url"
	"regexp"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/NitinGavhane/proxyforge/internal/flows"
	"github.com/NitinGavhane/proxyforge/internal/store"
)

// Issue is one scanner finding (persisted shape).
type Issue = store.Issue

// Severity / confidence vocabularies.
const (
	SevInfo     = "info"
	SevLow      = "low"
	SevMedium   = "medium"
	SevHigh     = "high"
	SevCritical = "critical"

	ConfCertain   = "certain"
	ConfFirm      = "firm"
	ConfTentative = "tentative"
)

// ActiveChecks lists the opt-in active check ids.
var ActiveChecks = []string{"xss-reflect", "sqli-error", "open-redirect", "path-traversal", "ssrf-canary", "cmd-inject"}

// ScanConfig starts a scan.
type ScanConfig struct {
	// BaseURL fetches fresh pages (GET / and ?probe variants). Mutually
	// exclusive with FlowID.
	BaseURL string `json:"base_url"`
	// FlowID passively analyzes an existing captured flow.
	FlowID int64 `json:"flow_id"`
	// Passive enables passive checks (default true when neither active set).
	Passive *bool `json:"passive"`
	// Active enables active checks — requires ConfirmActive.
	Active        bool     `json:"active"`
	ActiveChecks  []string `json:"active_checks"` // subset of ActiveChecks; default all
	ConfirmActive bool     `json:"confirm_active"`
	RatePerSec    int      `json:"rate_per_sec"`
}

// ScanJob tracks a scan.
type ScanJob struct {
	ID       int64     `json:"id"`
	State    string    `json:"state"` // running | done | error
	Target   string    `json:"target"`
	Passive  bool      `json:"passive"`
	Active   bool      `json:"active"`
	Probed   int       `json:"probed"`
	Issues   int       `json:"issues"`
	Started  time.Time `json:"started"`
	Finished time.Time `json:"finished,omitempty"`
	Err      string    `json:"err,omitempty"`

	cancel context.CancelFunc
}

// Collaborator is the subset of the collab manager the scanner needs.
type Collaborator interface {
	NewCanary(ctx context.Context, label string) (canaryID string, canaryURL string, err error)
	HasInteraction(ctx context.Context, canaryID string) bool
}

// Scanner runs scans.
type Scanner struct {
	store  *store.Store
	sender Sender
	collab Collaborator

	mu   sync.Mutex
	next int64
	jobs map[int64]*ScanJob
}

// NewScanner builds the tool.
func NewScanner(st *store.Store, sender Sender) *Scanner {
	return &Scanner{store: st, sender: sender, jobs: map[int64]*ScanJob{}}
}

// SetCollaborator attaches the OOB server (enables ssrf-canary).
func (sc *Scanner) SetCollaborator(c Collaborator) { sc.collab = c }

// Start validates and launches a scan (active requires confirm).
func (sc *Scanner) Start(cfg ScanConfig) (*ScanJob, error) {
	passive := cfg.Passive == nil || *cfg.Passive
	if !passive && !cfg.Active {
		return nil, fmt.Errorf("scanner: nothing to do (passive and active both off)")
	}
	if cfg.Active && !cfg.ConfirmActive {
		return nil, fmt.Errorf("scanner: active checks send modified requests to the target — set confirm_active to acknowledge")
	}
	if cfg.BaseURL == "" && cfg.FlowID == 0 {
		return nil, fmt.Errorf("scanner: base_url or flow_id required")
	}
	if cfg.BaseURL != "" && cfg.FlowID != 0 {
		return nil, fmt.Errorf("scanner: base_url and flow_id are mutually exclusive")
	}
	checks := cfg.ActiveChecks
	if cfg.Active && len(checks) == 0 {
		checks = ActiveChecks
	}
	if !cfg.Active {
		checks = nil
	}
	for _, c := range checks {
		known := false
		for _, k := range ActiveChecks {
			if c == k {
				known = true
			}
		}
		if !known {
			return nil, fmt.Errorf("scanner: unknown active check %q (have %v)", c, ActiveChecks)
		}
		if c == "ssrf-canary" && sc.collab == nil {
			return nil, fmt.Errorf("scanner: ssrf-canary requires the collaborator (start the daemon with -collab-addr)")
		}
	}
	rate := cfg.RatePerSec
	if rate <= 0 {
		rate = 5
	}
	if rate > 20 {
		rate = 20
	}

	sc.mu.Lock()
	sc.next++
	job := &ScanJob{
		ID:      sc.next,
		State:   "running",
		Passive: passive,
		Active:  cfg.Active,
		Started: time.Now(),
	}
	job.cancel = func() {}
	sc.jobs[job.ID] = job
	sc.mu.Unlock()

	ctx, cancel := context.WithCancel(context.Background())
	job.cancel = cancel
	if cfg.FlowID != 0 {
		job.Target = fmt.Sprintf("flow:%d", cfg.FlowID)
	} else {
		job.Target = cfg.BaseURL
	}
	go sc.run(ctx, job, cfg, checks, rate)
	return job, nil
}

func (sc *Scanner) run(ctx context.Context, job *ScanJob, cfg ScanConfig, activeChecks []string, rate int) {
	finish := func(state, errStr string) {
		sc.mu.Lock()
		job.Finished = time.Now()
		if job.State == "running" {
			job.State = state
		}
		if errStr != "" {
			job.Err = errStr
		}
		sc.mu.Unlock()
	}
	defer finish("done", "")

	interval := time.Second / time.Duration(rate)
	tick := func() bool {
		select {
		case <-ctx.Done():
			finish("stopped", "")
			return false
		case <-time.After(interval):
			return true
		}
	}

	// acquire the seed flow: existing capture or fresh fetch
	var seed *flows.Flow
	if cfg.FlowID != 0 {
		f, err := sc.store.GetFlow(ctx, cfg.FlowID)
		if err != nil {
			finish("error", fmt.Sprintf("flow %d: %v", cfg.FlowID, err))
			return
		}
		seed = f
	} else {
		f, err := sc.fetch(cfg.BaseURL)
		if err != nil {
			if strings.Contains(err.Error(), "out of scope") {
				finish("error", "target out of scope: "+err.Error())
			} else {
				finish("error", err.Error())
			}
			return
		}
		seed = f
	}
	sc.mu.Lock()
	job.Probed++
	sc.mu.Unlock()

	// passive checks on the seed
	if job.Passive {
		n := sc.passiveChecks(seed)
		sc.mu.Lock()
		job.Issues += n
		sc.mu.Unlock()
	}

	// active checks (rate-limited probes)
	if job.Active {
		for _, check := range activeChecks {
			if !tick() {
				return
			}
			found, err := sc.activeCheck(ctx, check, seed, cfg.BaseURL == "")
			if err != nil {
				if strings.Contains(err.Error(), "out of scope") {
					finish("error", "probe out of scope: "+err.Error())
					return
				}
				continue // probe errors are non-fatal
			}
			sc.mu.Lock()
			job.Probed++
			job.Issues += found
			sc.mu.Unlock()
		}
	}
}

// fetch GETs a URL through the gate.
func (sc *Scanner) fetch(rawURL string) (*flows.Flow, error) {
	u, err := url.Parse(rawURL)
	if err != nil {
		return nil, err
	}
	port := 80
	if u.Scheme == "https" {
		port = 443
	}
	if p := u.Port(); p != "" {
		port, _ = strconv.Atoi(p)
	}
	f := &flows.Flow{
		Started: time.Now(),
		Origin:  flows.OriginScanner,
		Request: &flows.Request{
			Method: "GET", Scheme: u.Scheme, Host: u.Hostname(), Port: port,
			Path: u.RequestURI(), Headers: flows.Headers{{Key: "Host", Value: u.Host}},
		},
	}
	if err := sc.sender.SendToolFlow(f); err != nil {
		return f, err
	}
	return f, nil
}

// probeParam sends GET with param overridden and returns the response body
// and status.
func (sc *Scanner) probeParam(base *flows.Request, param, value string) (string, int, error) {
	req := cloneRequest(base)
	sep := "?"
	if strings.Contains(req.Path, "?") {
		sep = "&"
	}
	req.Path = req.Path + sep + url.QueryEscape(param) + "=" + url.QueryEscape(value)
	f := &flows.Flow{Started: time.Now(), Origin: flows.OriginScanner, Request: req}
	if err := sc.sender.SendToolFlow(f); err != nil {
		return "", 0, err
	}
	if f.Response == nil {
		return "", 0, fmt.Errorf("no response")
	}
	return string(f.Response.Body), f.Response.Status, nil
}

func (sc *Scanner) issue(iss *Issue) {
	_ = sc.store.InsertIssue(context.Background(), iss)
}

// passiveChecks analyzes one flow; returns the issue count.
func (sc *Scanner) passiveChecks(f *flows.Flow) int {
	if f.Response == nil {
		return 0
	}
	n := 0
	hdrs := f.Response.Headers
	body := string(f.Response.Body)
	target := f.Request
	mk := func(check, title, sev, conf, detail string) {
		sc.issue(&Issue{
			CheckID: check, Title: title, Severity: sev, Confidence: conf,
			Host: target.Host, Port: target.Port, Path: target.Path,
			Detail: detail, EvidenceFlowID: f.ID,
		})
		n++
	}

	// --- security headers ---
	if target.Scheme == "https" {
		if v, ok := hdrs.Get("Strict-Transport-Security"); !ok {
			mk("passive.headers.hsts", "Missing Strict-Transport-Security", SevLow, ConfCertain,
				"The response is served over TLS without an HSTS header — clients can be downgraded.")
		} else if !strings.Contains(strings.ToLower(v), "max-age") || strings.Contains(strings.ToLower(v), "max-age=0") {
			mk("passive.headers.hsts-weak", "Weak Strict-Transport-Security", SevLow, ConfCertain,
				"HSTS present but without an effective max-age: "+v)
		}
	}
	if _, ok := hdrs.Get("X-Content-Type-Options"); !ok {
		mk("passive.headers.no-sniff", "Missing X-Content-Type-Options: nosniff", SevInfo, ConfCertain,
			"Without nosniff, browsers may MIME-sniff responses into executable types.")
	}
	_, hasXFO := hdrs.Get("X-Frame-Options")
	csp, hasCSP := hdrs.Get("Content-Security-Policy")
	if !hasXFO && !(hasCSP && strings.Contains(csp, "frame-ancestors")) {
		mk("passive.headers.clickjacking", "No clickjacking protection", SevLow, ConfCertain,
			"Neither X-Frame-Options nor CSP frame-ancestors is set — the page can be framed.")
	}
	if !hasCSP {
		mk("passive.headers.csp", "Missing Content-Security-Policy", SevLow, ConfFirm,
			"No CSP reduces the impact of any injected content.")
	}
	if _, ok := hdrs.Get("Referrer-Policy"); !ok {
		mk("passive.headers.referrer", "Missing Referrer-Policy", SevInfo, ConfCertain,
			"Full URLs (incl. query) may leak to third parties via Referer.")
	}

	// --- cookie flags ---
	for _, h := range hdrs {
		if !strings.EqualFold(h.Key, "Set-Cookie") {
			continue
		}
		v := strings.ToLower(h.Value)
		name := strings.SplitN(h.Value, "=", 2)[0]
		if !strings.Contains(v, "httponly") {
			mk("passive.cookie.httponly", "Cookie without HttpOnly: "+name, SevLow, ConfCertain,
				"Cookie readable by JavaScript — XSS can steal it: "+h.Value)
		}
		if !strings.Contains(v, "secure") {
			mk("passive.cookie.secure", "Cookie without Secure: "+name, SevMedium, ConfCertain,
				"Cookie may be sent over plaintext: "+h.Value)
		}
		if !strings.Contains(v, "samesite") {
			mk("passive.cookie.samesite", "Cookie without SameSite: "+name, SevLow, ConfFirm,
				"Cookie may be sent on cross-site requests (CSRF surface): "+h.Value)
		}
	}

	// --- info disclosure ---
	for _, banner := range []string{"Server", "X-Powered-By", "X-AspNet-Version", "X-AspNetMvc-Version"} {
		if v, ok := hdrs.Get(banner); ok && v != "" {
			mk("passive.info.banner."+strings.ToLower(strings.ReplaceAll(banner, "-", "")),
				"Technology banner disclosed: "+banner, SevInfo, ConfCertain,
				banner+": "+v+" — fingerprintable.")
		}
	}

	// --- CORS ---
	acao, hasACAO := hdrs.Get("Access-Control-Allow-Origin")
	acac, hasACAC := hdrs.Get("Access-Control-Allow-Credentials")
	if hasACAO && strings.TrimSpace(acao) == "*" && hasACAC && strings.Contains(strings.ToLower(acac), "true") {
		mk("passive.cors.wildcard-credentials", "CORS wildcard with credentials", SevHigh, ConfCertain,
			"Access-Control-Allow-Origin: * combined with Allow-Credentials: true — any origin can read credentialed responses.")
	} else if hasACAO && strings.HasPrefix(strings.TrimSpace(acao), "http://") {
		mk("passive.cors.plaintext-origin", "CORS allows plaintext origin", SevLow, ConfFirm,
			"Reflected plaintext origin: "+acao)
	}

	// --- secrets in body ---
	for _, pat := range secretPatterns {
		if m := pat.re.FindString(body); m != "" {
			sc.issue(&Issue{
				CheckID: "passive.secrets." + pat.id, Title: pat.title,
				Severity: pat.sev, Confidence: ConfTentative,
				Host: target.Host, Port: target.Port, Path: target.Path,
				Detail: "Pattern match (first 40 chars): " + truncate(m, 40) +
					" — verify before reporting; tentative by design.",
				EvidenceFlowID: f.ID,
			})
			n++
		}
	}
	return n
}

type secretPattern struct {
	id    string
	title string
	sev   string
	re    *regexp.Regexp
}

var secretPatterns = []secretPattern{
	{"private-key", "Private key material in response", SevCritical,
		regexp.MustCompile(`-----BEGIN (RSA |EC |OPENSSH )?PRIVATE KEY-----`)},
	{"aws-key", "AWS access key in response", SevHigh,
		regexp.MustCompile(`AKIA[0-9A-Z]{16}`)},
	{"jwt", "JWT in response body", SevInfo,
		regexp.MustCompile(`eyJ[A-Za-z0-9_-]{10,}\.eyJ[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]*`)},
	{"generic-api-key", "Possible API key in response", SevMedium,
		regexp.MustCompile(`(?i)(api[_-]?key|secret[_-]?key|access[_-]?token)"?\s*[:=]\s*"?[A-Za-z0-9+/_-]{20,}`)},
}

func truncate(s string, n int) string {
	if len(s) > n {
		return s[:n] + "…"
	}
	return s
}

// activeCheck runs one opt-in check; returns issues found.
func (sc *Scanner) activeCheck(ctx context.Context, check string, seed *flows.Flow, fromFlow bool) (int, error) {
	base := cloneRequest(seed.Request)
	if fromFlow {
		// probing from a captured flow replays exactly that request shape
		base = cloneRequest(seed.Request)
	}
	switch check {
	case "xss-reflect":
		canary := `pfq7x"<script>alert(1)</script>`
		body, _, err := sc.probeParam(base, "q", canary)
		if err != nil {
			return 0, err
		}
		if strings.Contains(body, `<script>alert(1)</script>`) {
			sc.issue(&Issue{
				CheckID: "active.xss.reflect", Title: "Reflected XSS (unescaped canary)",
				Severity: SevHigh, Confidence: ConfFirm,
				Host: base.Host, Port: base.Port, Path: base.Path,
				Detail: "The canary parameter value is reflected into the response as executable markup without encoding.",
			})
			return 1, nil
		}
		return 0, nil
	case "sqli-error":
		body, _, err := sc.probeParam(base, "id", `' " PFSQL`)
		if err != nil {
			return 0, err
		}
		for _, sig := range []string{
			"you have an error in your sql syntax", "unclosed quotation mark",
			"sqlite3.operationalerror", "pg_query", "psql:", "warning: mysql",
			"oracle jdbc", "sqlstate",
		} {
			if strings.Contains(strings.ToLower(body), sig) {
				sc.issue(&Issue{
					CheckID: "active.sqli.error", Title: "SQL injection (error-based)",
					Severity: SevCritical, Confidence: ConfFirm,
					Host: base.Host, Port: base.Port, Path: base.Path,
					Detail: "Database error signature in response after a quote payload: " + truncate(sig, 40),
				})
				return 1, nil
			}
		}
		return 0, nil
	case "open-redirect":
		_, status, _ := sc.probeParam(base, "next", "https://proxyforge-redirect-canary.example/x")
		// 3xx + Location pointing at the canary = open redirect; the probe's
		// own flow is the evidence — refetch it via the last insert? simpler:
		// check via a follow-up HEAD-less probe with an explicit Location read
		// by re-sending and inspecting flow response headers.
		f, err := sc.fetchWithParam(base, "next", "https://proxyforge-redirect-canary.example/x")
		if err != nil {
			return 0, err
		}
		_ = status
		if f.Response != nil && f.Response.Status >= 300 && f.Response.Status < 400 {
			if loc, ok := f.Response.Headers.Get("Location"); ok && strings.Contains(loc, "proxyforge-redirect-canary.example") {
				sc.issue(&Issue{
					CheckID: "active.redirect.open", Title: "Open redirect",
					Severity: SevMedium, Confidence: ConfCertain,
					Host: base.Host, Port: base.Port, Path: base.Path,
					Detail: "next parameter redirects to an attacker-controlled host: " + loc,
				})
				return 1, nil
			}
		}
		return 0, nil
	case "path-traversal":
		body, _, err := sc.probeParam(base, "file", "../../../../../../etc/passwd")
		if err != nil {
			return 0, err
		}
		if strings.Contains(body, "root:") && strings.Contains(body, "/bin/") {
			sc.issue(&Issue{
				CheckID: "active.traversal.file-read", Title: "Path traversal (arbitrary file read)",
				Severity: SevCritical, Confidence: ConfCertain,
				Host: base.Host, Port: base.Port, Path: base.Path,
				Detail: "file parameter returns /etc/passwd contents.",
			})
			return 1, nil
		}
		return 0, nil
	case "ssrf-canary":
		if sc.collab == nil {
			return 0, fmt.Errorf("ssrf-canary requires the collaborator (start with -collab-addr)")
		}
		id, canaryURL, err := sc.collab.NewCanary(ctx, fmt.Sprintf("ssrf probe %s%s", base.Host, base.Path))
		if err != nil {
			return 0, err
		}
		for _, param := range []string{"url", "next", "callback", "webhook", "dest"} {
			if _, _, err := sc.probeParam(base, param, canaryURL); err != nil {
				continue
			}
			// the target may fetch async — poll briefly
			for i := 0; i < 10; i++ {
				select {
				case <-ctx.Done():
					return 0, nil
				case <-time.After(300 * time.Millisecond):
				}
				if sc.collab.HasInteraction(ctx, id) {
					sc.issue(&Issue{
						CheckID: "active.ssrf.canary", Title: "SSRF (out-of-band callback)",
						Severity: SevHigh, Confidence: ConfCertain,
						Host: base.Host, Port: base.Port, Path: base.Path,
						Detail: fmt.Sprintf("The %s parameter triggered an HTTP callback to the collaborator canary %s — the server fetches attacker-influenced URLs.", param, id),
					})
					return 1, nil
				}
			}
		}
		return 0, nil
	case "cmd-inject":
		// time-based: compare a baseline against a sleep payload
		baseStart := time.Now()
		if _, _, err := sc.probeParam(base, "x-pf-baseline", "1"); err != nil {
			return 0, err
		}
		baseline := time.Since(baseStart)
		probeStart := time.Now()
		if _, _, err := sc.probeParam(base, "q", `1;sleep 2;echo`); err != nil {
			return 0, err
		}
		took := time.Since(probeStart)
		if took > baseline+1500*time.Millisecond {
			sc.issue(&Issue{
				CheckID: "active.cmdinject.time", Title: "Command injection (time-based)",
				Severity: SevCritical, Confidence: ConfTentative,
				Host: base.Host, Port: base.Port, Path: base.Path,
				Detail: fmt.Sprintf("sleep payload added %.1fs over baseline (%.1fs) — verify manually; timing can have other causes.", took.Seconds(), baseline.Seconds()),
			})
			return 1, nil
		}
		return 0, nil
	}
	return 0, fmt.Errorf("unknown check %q", check)
}

// fetchWithParam sends a param probe and returns the full flow (for header
// inspection).
func (sc *Scanner) fetchWithParam(base *flows.Request, param, value string) (*flows.Flow, error) {
	req := cloneRequest(base)
	sep := "?"
	if strings.Contains(req.Path, "?") {
		sep = "&"
	}
	req.Path = req.Path + sep + url.QueryEscape(param) + "=" + url.QueryEscape(value)
	f := &flows.Flow{Started: time.Now(), Origin: flows.OriginScanner, Request: req}
	if err := sc.sender.SendToolFlow(f); err != nil {
		return nil, err
	}
	return f, nil
}

// Get snapshots a job.
func (sc *Scanner) Get(id int64) (*ScanJob, error) {
	sc.mu.Lock()
	defer sc.mu.Unlock()
	job, ok := sc.jobs[id]
	if !ok {
		return nil, fmt.Errorf("scan %d: not found", id)
	}
	cp := *job
	return &cp, nil
}

// List returns all jobs.
func (sc *Scanner) List() []ScanJob {
	sc.mu.Lock()
	defer sc.mu.Unlock()
	out := make([]ScanJob, 0, len(sc.jobs))
	for _, j := range sc.jobs {
		out = append(out, *j)
	}
	return out
}
