// Intruder (Phase 3 P3): §position§-marked templates, four attack modes,
// payload generators, grep match/extract, rate-limited sends through the
// outbound gate.
package tools

import (
	"context"
	"fmt"
	"regexp"
	"strings"
	"sync"
	"time"

	"github.com/NitinGavhane/proxyforge/internal/flows"
)

// PositionMark brackets a substitution point in the raw template.
const PositionMark = "§"

// Position is one §marked§ slot.
type Position struct {
	Name  string `json:"name"` // may be empty
	Index int    `json:"index"`
	Start int    `json:"start"` // byte offset in template (of the marker)
	End   int    `json:"end"`
}

// markLen is the byte length of the position mark (§ is 2 bytes in UTF-8).
const markLen = len(PositionMark)

// ParsePositions extracts §name§ slots in order of appearance.
func ParsePositions(raw string) []Position {
	var out []Position
	i := 0
	for {
		open := strings.Index(raw[i:], PositionMark)
		if open < 0 {
			return out
		}
		start := i + open
		close := strings.Index(raw[start+markLen:], PositionMark)
		if close < 0 {
			return out // unbalanced: ignore the stray mark
		}
		name := raw[start+markLen : start+markLen+close]
		out = append(out, Position{
			Name:  name,
			Index: len(out),
			Start: start,
			End:   start + markLen + close + markLen,
		})
		i = start + markLen + close + markLen
	}
}

// Render substitutes payloads into the template (payloads indexed by
// position). Missing entries leave the marker in place.
func Render(raw string, positions []Position, payloads []string) string {
	var b strings.Builder
	last := 0
	for i, p := range positions {
		b.WriteString(raw[last:p.Start])
		if i < len(payloads) {
			b.WriteString(payloads[i])
		} else {
			b.WriteString(raw[p.Start:p.End])
		}
		last = p.End
	}
	b.WriteString(raw[last:])
	return b.String()
}

// --- payload sets ---

// PayloadSet generates payloads lazily-ish (materialized with a cap).
type PayloadSet struct {
	Type string `json:"type"` // list | numbers | null | bruteforcer
	// list
	Items []string `json:"items,omitempty"`
	// numbers
	From int `json:"from,omitempty"`
	To   int `json:"to,omitempty"`
	Step int `json:"step,omitempty"`
	// bruteforcer
	Charset string `json:"charset,omitempty"`
	MinLen  int    `json:"min_len,omitempty"`
	MaxLen  int    `json:"max_len,omitempty"`
}

// MaxPayloads caps any generated set (safety).
const MaxPayloads = 20000

// Generate materializes the payload list.
func (ps PayloadSet) Generate() ([]string, error) {
	switch ps.Type {
	case "list":
		if len(ps.Items) == 0 {
			return nil, fmt.Errorf("payload set 'list' needs items")
		}
		return append([]string(nil), ps.Items...), nil
	case "null":
		return []string{""}, nil
	case "numbers":
		step := ps.Step
		if step == 0 {
			step = 1
		}
		if ps.To < ps.From || (step > 0 && ps.To < ps.From) {
			return nil, fmt.Errorf("numbers: to < from")
		}
		if (ps.To-ps.From)/step+1 > MaxPayloads {
			return nil, fmt.Errorf("numbers: range exceeds %d payloads", MaxPayloads)
		}
		out := []string{}
		for n := ps.From; n <= ps.To; n += step {
			out = append(out, fmt.Sprintf("%d", n))
			if len(out) > MaxPayloads {
				return nil, fmt.Errorf("numbers: exceeds %d payloads", MaxPayloads)
			}
		}
		return out, nil
	case "bruteforcer":
		cs := ps.Charset
		if cs == "" {
			cs = "abcdefghijklmnopqrstuvwxyz0123456789"
		}
		minL, maxL := ps.MinLen, ps.MaxLen
		if minL <= 0 {
			minL = 1
		}
		if maxL < minL {
			maxL = minL
		}
		if maxL > 4 {
			return nil, fmt.Errorf("bruteforcer: max_len %d too large (≤4, %d charset)", maxL, len(cs))
		}
		out := []string{}
		var recur func(prefix string, depth int)
		recur = func(prefix string, depth int) {
			if len(out) >= MaxPayloads {
				return
			}
			if depth > maxL {
				return
			}
			if len(prefix) >= minL {
				out = append(out, prefix)
			}
			if depth == maxL {
				return
			}
			for _, c := range cs {
				recur(prefix+string(c), depth+1)
			}
		}
		recur("", 0)
		if len(out) == 0 {
			return nil, fmt.Errorf("bruteforcer: empty result")
		}
		return out, nil
	}
	return nil, fmt.Errorf("unknown payload type %q", ps.Type)
}

// --- grep ---

// GrepSpec is one match/extract rule.
type GrepSpec struct {
	Name  string `json:"name"`
	Regex string `json:"regex"`
}

// IntruderResult is one request's outcome.
type IntruderResult struct {
	Index    int               `json:"index"`
	Payloads []string          `json:"payloads"`
	Rendered string            `json:"rendered"`
	FlowID   int64             `json:"flow_id,omitempty"`
	Status   int               `json:"status"`
	Size     int               `json:"size"`
	Millis   int64             `json:"ms"`
	Err      string            `json:"err,omitempty"`
	Matches  map[string]string `json:"matches,omitempty"`  // grep match → first hit
	Extracts map[string]string `json:"extracts,omitempty"` // extract name → group 1
}

// AttackConfig starts an attack.
type AttackConfig struct {
	AttackType  string       `json:"attack_type"` // sniper | battering_ram | pitchfork | cluster_bomb
	Raw         string       `json:"raw"`
	PayloadSets []PayloadSet `json:"payload_sets"`
	Match       []GrepSpec   `json:"match,omitempty"`
	Extract     []GrepSpec   `json:"extract,omitempty"`
	RatePerSec  int          `json:"rate_per_sec"`
}

// IntruderJob tracks a running or finished attack.
type IntruderJob struct {
	ID         int64            `json:"id"`
	AttackType string           `json:"attack_type"`
	State      string           `json:"state"` // running | done | stopped | error
	Total      int              `json:"total"`
	Sent       int              `json:"sent"`
	Results    []IntruderResult `json:"results"`
	Started    time.Time        `json:"started"`
	Finished   time.Time        `json:"finished,omitempty"`
	Err        string           `json:"err,omitempty"`

	cancel context.CancelFunc
}

// Intruder runs attacks.
type Intruder struct {
	sender Sender

	mu   sync.Mutex
	next int64
	jobs map[int64]*IntruderJob
}

// NewIntruder builds the tool.
func NewIntruder(sender Sender) *Intruder {
	return &Intruder{sender: sender, jobs: map[int64]*IntruderJob{}}
}

// buildPayloadMatrix returns the per-request payload tuples for the four
// attack modes. This is the exact request set — the heart of the tool.
// Sniper keeps the original marker text in unfilled positions (Burp
// semantics), so raw is needed to recover it.
func buildPayloadMatrix(attackType string, raw string, positions []Position, sets []PayloadSet) ([][]string, error) {
	switch attackType {
	case "sniper":
		if len(sets) != 1 {
			return nil, fmt.Errorf("sniper takes exactly one payload set")
		}
		payloads, err := sets[0].Generate()
		if err != nil {
			return nil, err
		}
		var out [][]string
		for pi := range positions {
			for _, p := range payloads {
				row := make([]string, len(positions))
				for j := range positions {
					row[j] = raw[positions[j].Start:positions[j].End]
				}
				row[pi] = p
				out = append(out, row)
			}
		}
		return out, nil
	case "battering_ram":
		if len(sets) != 1 {
			return nil, fmt.Errorf("battering ram takes exactly one payload set")
		}
		payloads, err := sets[0].Generate()
		if err != nil {
			return nil, err
		}
		var out [][]string
		for _, p := range payloads {
			row := make([]string, len(positions))
			for i := range row {
				row[i] = p
			}
			out = append(out, row)
		}
		return out, nil
	case "pitchfork", "cluster_bomb":
		if len(sets) != len(positions) {
			return nil, fmt.Errorf("%s needs one payload set per position (%d positions, %d sets)",
				attackType, len(positions), len(sets))
		}
		cols := make([][]string, len(sets))
		for i, s := range sets {
			ps, err := s.Generate()
			if err != nil {
				return nil, fmt.Errorf("set %d: %w", i, err)
			}
			cols[i] = ps
		}
		var out [][]string
		if attackType == "pitchfork" {
			n := len(cols[0])
			for _, c := range cols {
				if len(c) < n {
					n = len(c)
				}
			}
			for r := 0; r < n; r++ {
				row := make([]string, len(cols))
				for i := range cols {
					row[i] = cols[i][r]
				}
				out = append(out, row)
			}
			return out, nil
		}
		// cluster bomb: cartesian product
		total := 1
		for _, c := range cols {
			total *= len(c)
			if total > MaxPayloads {
				return nil, fmt.Errorf("cluster bomb exceeds %d requests", MaxPayloads)
			}
		}
		idx := make([]int, len(cols))
		for {
			row := make([]string, len(cols))
			for i := range cols {
				row[i] = cols[i][idx[i]]
			}
			out = append(out, row)
			done := true
			for i := len(cols) - 1; i >= 0; i-- {
				idx[i]++
				if idx[i] < len(cols[i]) {
					done = false
					break
				}
				idx[i] = 0
			}
			if done {
				break
			}
		}
		return out, nil
	}
	return nil, fmt.Errorf("unknown attack type %q", attackType)
}

// Start validates and launches an attack.
func (in *Intruder) Start(cfg AttackConfig) (*IntruderJob, error) {
	positions := ParsePositions(cfg.Raw)
	if len(positions) == 0 {
		return nil, fmt.Errorf("intruder: no §positions§ in the template")
	}
	rate := cfg.RatePerSec
	if rate <= 0 {
		rate = 5
	}
	if rate > 20 {
		rate = 20
	}
	matrix, err := buildPayloadMatrix(cfg.AttackType, cfg.Raw, positions, cfg.PayloadSets)
	if err != nil {
		return nil, err
	}
	matches, err := compileGreps(cfg.Match)
	if err != nil {
		return nil, err
	}
	extracts, err := compileGreps(cfg.Extract)
	if err != nil {
		return nil, err
	}

	in.mu.Lock()
	in.next++
	job := &IntruderJob{
		ID:         in.next,
		AttackType: cfg.AttackType,
		State:      "running",
		Total:      len(matrix),
		Started:    time.Now(),
	}
	job.cancel = func() {}
	in.jobs[job.ID] = job
	in.mu.Unlock()

	ctx, cancel := context.WithCancel(context.Background())
	job.cancel = cancel
	go in.run(ctx, job, cfg, positions, matrix, matches, extracts, rate)
	return job, nil
}

type compiledGrep struct {
	name string
	re   *regexp.Regexp
}

func compileGreps(specs []GrepSpec) ([]compiledGrep, error) {
	out := []compiledGrep{}
	for _, s := range specs {
		if s.Name == "" || s.Regex == "" {
			return nil, fmt.Errorf("grep rule needs name and regex")
		}
		re, err := regexp.Compile(s.Regex)
		if err != nil {
			return nil, fmt.Errorf("grep %q: %w", s.Name, err)
		}
		out = append(out, compiledGrep{s.Name, re})
	}
	return out, nil
}

func (in *Intruder) run(ctx context.Context, job *IntruderJob, cfg AttackConfig,
	positions []Position, matrix [][]string, matches, extracts []compiledGrep, rate int) {
	finish := func(state string, errStr string) {
		in.mu.Lock()
		job.Finished = time.Now()
		if job.State == "running" {
			job.State = state
		}
		if errStr != "" {
			job.Err = errStr
		}
		in.mu.Unlock()
	}
	defer finish("done", "")

	interval := time.Second / time.Duration(rate)
	for i, payloads := range matrix {
		select {
		case <-ctx.Done():
			finish("stopped", "")
			return
		case <-time.After(interval):
		}
		rendered := Render(cfg.Raw, positions, payloads)
		started := time.Now()
		res := IntruderResult{Index: i, Payloads: payloads, Rendered: rendered}
		f, err := in.send(rendered)
		if err != nil {
			res.Err = err.Error()
			if strings.Contains(err.Error(), "out of scope") {
				finish("error", "target out of scope: "+err.Error())
				return
			}
		} else if f != nil {
			res.FlowID = f.ID
			if f.Response != nil {
				res.Status = f.Response.Status
				res.Size = len(f.Response.Body)
				applyGreps(&res, f.Response.Body, matches, extracts)
			}
		}
		res.Millis = time.Since(started).Milliseconds()
		in.mu.Lock()
		job.Results = append(job.Results, res)
		job.Sent = i + 1
		in.mu.Unlock()
	}
}

func (in *Intruder) send(rendered string) (*flows.Flow, error) {
	req, err := ParseRawRequest(rendered)
	if err != nil {
		return nil, fmt.Errorf("rendered request: %w", err)
	}
	f := &flows.Flow{
		Started: time.Now(),
		Origin:  flows.OriginIntruder,
		Request: req,
	}
	if err := in.sender.SendToolFlow(f); err != nil {
		return f, err
	}
	return f, nil
}

func applyGreps(res *IntruderResult, body []byte, matches, extracts []compiledGrep) {
	for _, m := range matches {
		if hit := m.re.Find(body); hit != nil {
			if res.Matches == nil {
				res.Matches = map[string]string{}
			}
			res.Matches[m.name] = string(hit)
		}
	}
	for _, e := range extracts {
		g := e.re.FindSubmatch(body)
		if len(g) >= 2 {
			if res.Extracts == nil {
				res.Extracts = map[string]string{}
			}
			res.Extracts[e.name] = string(g[1])
		}
	}
}

// Stop cancels a running attack.
func (in *Intruder) Stop(id int64) error {
	in.mu.Lock()
	defer in.mu.Unlock()
	job, ok := in.jobs[id]
	if !ok {
		return fmt.Errorf("intruder %d: not found", id)
	}
	if job.State == "running" {
		job.cancel()
		job.State = "stopped"
	}
	return nil
}

// Get snapshots a job.
func (in *Intruder) Get(id int64) (*IntruderJob, error) {
	in.mu.Lock()
	defer in.mu.Unlock()
	job, ok := in.jobs[id]
	if !ok {
		return nil, fmt.Errorf("intruder %d: not found", id)
	}
	cp := *job
	cp.Results = append([]IntruderResult(nil), job.Results...)
	return &cp, nil
}

// List returns all jobs.
func (in *Intruder) List() []IntruderJob {
	in.mu.Lock()
	defer in.mu.Unlock()
	out := make([]IntruderJob, 0, len(in.jobs))
	for _, j := range in.jobs {
		out = append(out, *j)
	}
	return out
}
