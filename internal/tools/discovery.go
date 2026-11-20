// Content discovery (P1b): wordlist probing through the outbound gate,
// rate-limited, with 404-baseline differencing. Results land in the site
// map (source=discovery) and in the in-memory job record.
package tools

import (
	"context"
	"fmt"
	"net/url"
	"strings"
	"sync"
	"time"

	"github.com/NitinGavhane/proxyforge/internal/flows"
	"github.com/NitinGavhane/proxyforge/internal/store"
)

// DiscoveryWordlist is the built-in common-path list (kept deliberately
// small; bring your own via the API).
var DiscoveryWordlist = []string{
	"robots.txt", "sitemap.xml", ".env", ".git/config", ".git/HEAD", ".svn/entries",
	".DS_Store", "backup", "backup.zip", "backups", "bak", "admin", "admin/",
	"administrator", "login", "signin", "signup", "register", "api", "api/v1",
	"api/v2", "api/docs", "swagger", "swagger.json", "swagger.yaml",
	"openapi.json", "graphql", "docs", "doc", "health", "healthz", "status",
	"metrics", "debug", "test", "dev", "staging", "beta", "old", "new",
	"config", "configuration.php", "config.json", "config.yml", "settings",
	"uploads", "upload", "files", "static", "assets", "public", "private",
	"tmp", "temp", "cache", "logs", "log", "console", "dashboard", "panel",
	"cpanel", "phpmyadmin", "adminer", "wp-admin", "wp-login.php", "xmlrpc.php",
	"cgi-bin/", ".htaccess", ".htpasswd", "web.config", "crossdomain.xml",
	"clientaccesspolicy.xml", "SECURITY.md", "security.txt", ".well-known/",
	".well-known/security.txt", "server-status", "server-info", "info.php",
	"index.bak", "db", "database", "dump", "dump.sql", "export", "import",
	".aws/credentials", ".ssh/id_rsa", "id_rsa", "Dockerfile", "docker-compose.yml",
	"package.json", "composer.json", "Gemfile", "requirements.txt", ".babelrc",
	"tsconfig.json", "vendor/", "node_modules/", "coverage/", ".idea/",
}

// DiscoveryResult is one probe's outcome.
type DiscoveryResult struct {
	Path        string `json:"path"`
	URL         string `json:"url"`
	Status      int    `json:"status"`
	Size        int    `json:"size"`
	Interesting bool   `json:"interesting"`
	Err         string `json:"err,omitempty"`
}

// DiscoveryJob is a running or finished job.
type DiscoveryJob struct {
	ID       int64             `json:"id"`
	BaseURL  string            `json:"base_url"`
	State    string            `json:"state"` // running | done | stopped | error
	Probed   int               `json:"probed"`
	Total    int               `json:"total"`
	Results  []DiscoveryResult `json:"results"`
	Started  time.Time         `json:"started"`
	Finished time.Time         `json:"finished,omitempty"`
	Err      string            `json:"err,omitempty"`

	cancel context.CancelFunc
}

// Discovery runs jobs.
type Discovery struct {
	store  *store.Store
	sender Sender

	mu   sync.Mutex
	next int64
	jobs map[int64]*DiscoveryJob
}

// NewDiscovery builds the tool.
func NewDiscovery(st *store.Store, sender Sender) *Discovery {
	return &Discovery{store: st, sender: sender, jobs: map[int64]*DiscoveryJob{}}
}

// Start launches a job against baseURL (must be in scope — enforced per
// request by the outbound gate). ratePerSec is clamped to [1, 20];
// wordlist falls back to the built-in list.
func (d *Discovery) Start(baseURL string, wordlist []string, ratePerSec int) (*DiscoveryJob, error) {
	u, err := url.Parse(baseURL)
	if err != nil || u.Host == "" || (u.Scheme != "http" && u.Scheme != "https") {
		return nil, fmt.Errorf("discovery: base URL must be an absolute http(s) URL")
	}
	if len(wordlist) == 0 {
		wordlist = DiscoveryWordlist
	}
	if ratePerSec <= 0 {
		ratePerSec = 5
	}
	if ratePerSec > 20 {
		ratePerSec = 20
	}
	d.mu.Lock()
	d.next++
	job := &DiscoveryJob{
		ID:      d.next,
		BaseURL: strings.TrimSuffix(baseURL, "/"),
		State:   "running",
		Total:   len(wordlist),
		Started: time.Now(),
	}
	job.cancel = func() {}
	d.jobs[job.ID] = job
	d.mu.Unlock()

	ctx, cancel := context.WithCancel(context.Background())
	job.cancel = cancel
	go d.run(ctx, job, u, wordlist, ratePerSec)
	return job, nil
}

func (d *Discovery) run(ctx context.Context, job *DiscoveryJob, base *url.URL, wordlist []string, rate int) {
	defer func() {
		d.mu.Lock()
		job.Finished = time.Now()
		if job.State == "running" {
			job.State = "done"
		}
		d.mu.Unlock()
	}()

	probe := func(path string) DiscoveryResult {
		full := job.BaseURL + "/" + strings.TrimPrefix(path, "/")
		pu, _ := url.Parse(full)
		port := 80
		if pu.Scheme == "https" {
			port = 443
		}
		if p := pu.Port(); p != "" {
			fmt.Sscanf(p, "%d", &port)
		}
		f := &flows.Flow{
			Started: time.Now(),
			Origin:  flows.OriginScanner,
			Request: &flows.Request{
				Method: "GET", Scheme: pu.Scheme, Host: pu.Hostname(), Port: port,
				Path:    pu.RequestURI(),
				Headers: flows.Headers{{Key: "Host", Value: pu.Host}},
			},
		}
		res := DiscoveryResult{Path: path, URL: full}
		if err := d.sender.SendToolFlow(f); err != nil {
			res.Err = err.Error()
			if strings.Contains(err.Error(), "out of scope") {
				d.mu.Lock()
				job.State = "error"
				job.Err = "base URL out of scope: " + err.Error()
				d.mu.Unlock()
				job.cancel()
			}
			return res
		}
		res.Status = 0
		if f.Response != nil {
			res.Status = f.Response.Status
			res.Size = len(f.Response.Body)
		}
		return res
	}

	// baseline: a random-ish nonexistent path learns the 404 signature
	baseRes := probe(fmt.Sprintf("pfnope-%d", time.Now().UnixNano()))
	interval := time.Second / time.Duration(rate)
	for i, path := range wordlist {
		select {
		case <-ctx.Done():
			d.mu.Lock()
			if job.State == "running" {
				job.State = "stopped" // an error cancellation keeps its state
			}
			d.mu.Unlock()
			return
		case <-time.After(interval):
		}
		res := probe(path)
		res.Interesting = isInteresting(res, baseRes)
		d.mu.Lock()
		job.Results = append(job.Results, res)
		job.Probed = i + 1
		d.mu.Unlock()
		// interesting findings are already aggregated into the site map by
		// the pipeline (every probe is a captured flow); the job record
		// carries the interesting-flag verdicts.
	}
}

// isInteresting flags responses that differ from the not-found baseline.
func isInteresting(res, baseline DiscoveryResult) bool {
	if res.Err != "" {
		return false
	}
	if res.Status == baseline.Status && res.Size == baseline.Size {
		return false // same soft-404 signature
	}
	switch res.Status {
	case 200, 201, 204, 301, 302, 303, 307, 308, 401, 403:
		return true
	}
	// a different error status with a different body size is still a signal
	return res.Status != baseline.Status && abs(res.Size-baseline.Size) > 16
}

func abs(n int) int {
	if n < 0 {
		return -n
	}
	return n
}

// Stop cancels a running job.
func (d *Discovery) Stop(id int64) error {
	d.mu.Lock()
	defer d.mu.Unlock()
	job, ok := d.jobs[id]
	if !ok {
		return fmt.Errorf("discovery %d: not found", id)
	}
	if job.State == "running" {
		job.cancel()
		job.State = "stopped"
	}
	return nil
}

// Get returns a job snapshot.
func (d *Discovery) Get(id int64) (*DiscoveryJob, error) {
	d.mu.Lock()
	defer d.mu.Unlock()
	job, ok := d.jobs[id]
	if !ok {
		return nil, fmt.Errorf("discovery %d: not found", id)
	}
	cp := *job
	cp.Results = append([]DiscoveryResult(nil), job.Results...)
	return &cp, nil
}

// List returns all jobs (for the UI).
func (d *Discovery) List() []DiscoveryJob {
	d.mu.Lock()
	defer d.mu.Unlock()
	out := make([]DiscoveryJob, 0, len(d.jobs))
	for _, j := range d.jobs {
		cp := *j
		out = append(out, cp)
	}
	return out
}
