// Package tags tracks origin tags applied from the browser extension
// ("tag this site"): while a tag is live, flows to that origin are marked
// in history (highlight + comment) so they stand out during triage.
package tags

import (
	"net/url"
	"strings"
	"sync"
	"time"
)

// Manager holds live origin tags.
type Manager struct {
	mu   sync.Mutex
	tags map[string]time.Time // host (lowercased) → expiry
}

// New builds an empty manager.
func New() *Manager { return &Manager{tags: map[string]time.Time{}} }

// NormalizeHost accepts "origin" (scheme://host[:port]) or a bare host and
// returns the host part.
func NormalizeHost(origin string) string {
	s := strings.TrimSpace(origin)
	if i := strings.Index(s, "://"); i >= 0 {
		if u, err := url.Parse(s); err == nil && u.Host != "" {
			s = u.Host
		} else {
			s = s[i+3:]
		}
	}
	// strip path remnants and port? keep port: origin identity includes it
	if i := strings.IndexAny(s, "/?#"); i >= 0 {
		s = s[:i]
	}
	return strings.ToLower(strings.TrimSuffix(s, "."))
}

// Set tags an origin for d (zero → default 10 minutes).
func (m *Manager) Set(origin string, d time.Duration) {
	if d <= 0 {
		d = 10 * time.Minute
	}
	m.mu.Lock()
	defer m.mu.Unlock()
	m.tags[NormalizeHost(origin)] = time.Now().Add(d)
}

// Match reports whether host has a live tag (exact host match; tags carry
// their port, matching Burp-style origin semantics).
func (m *Manager) Match(host string) bool {
	m.mu.Lock()
	defer m.mu.Unlock()
	exp, ok := m.tags[strings.ToLower(host)]
	if !ok {
		return false
	}
	if time.Now().After(exp) {
		delete(m.tags, strings.ToLower(host))
		return false
	}
	return true
}

// Active lists live tags with remaining time.
func (m *Manager) Active() map[string]time.Duration {
	m.mu.Lock()
	defer m.mu.Unlock()
	out := map[string]time.Duration{}
	for host, exp := range m.tags {
		if rem := time.Until(exp); rem > 0 {
			out[host] = rem
		} else {
			delete(m.tags, host)
		}
	}
	return out
}
