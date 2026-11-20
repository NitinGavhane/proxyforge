// Package collab is ProxyForge's self-hosted OOB interaction server: an
// HTTP listener (and an optional minimal DNS responder) that records every
// callback with a per-canary attribution — the Burp Collaborator
// alternative, minus the third party.
package collab

import (
	"context"
	"crypto/rand"
	"encoding/binary"
	"encoding/hex"
	"fmt"
	"log/slog"
	"net"
	"net/http"
	"strings"
	"sync"
	"time"

	"github.com/NitinGavhane/proxyforge/internal/store"
)

// Manager owns canaries and interactions.
type Manager struct {
	store      *store.Store
	log        *slog.Logger
	httpAddr   string // e.g. 127.0.0.1:8767
	publicHost string // host used in canary URLs (default: httpAddr host)
	dnsAddr    string // optional DNS listener (e.g. 127.0.0.1:5353)

	mu       sync.Mutex
	canaries map[string]string // canary id → label
	httpLn   net.Listener
	dnsConn  net.PacketConn
	stopDNS  chan struct{}
}

// NewManager builds the manager (no listeners yet).
func NewManager(st *store.Store, log *slog.Logger, httpAddr, dnsAddr, publicHost string) *Manager {
	if log == nil {
		log = slog.Default()
	}
	host := publicHost
	if host == "" {
		h, _, err := net.SplitHostPort(httpAddr)
		if err != nil {
			host = httpAddr
		} else {
			host = h
		}
	}
	return &Manager{
		store: st, log: log, httpAddr: httpAddr, dnsAddr: dnsAddr,
		publicHost: host, canaries: map[string]string{},
		stopDNS: make(chan struct{}),
	}
}

// Canary is an issued detector.
type Canary struct {
	ID     string `json:"id"`
	Label  string `json:"label"`
	URL    string `json:"url"`    // http://<publicHost>:<port>/<id>
	Host   string `json:"host"`   // <id>.oob — Host-header form
	Domain string `json:"domain"` // <id>.oob.<publicHost> — DNS form
}

// NewCanary issues a fresh detector id (16 hex chars).
func (m *Manager) NewCanary(ctx context.Context, label string) (*Canary, error) {
	b := make([]byte, 8)
	if _, err := rand.Read(b); err != nil {
		return nil, err
	}
	id := hex.EncodeToString(b)
	_, port, _ := net.SplitHostPort(m.httpAddr)
	if port == "" {
		port = "80"
	}
	c := &Canary{
		ID:     id,
		Label:  label,
		URL:    fmt.Sprintf("http://%s:%s/%s", m.publicHost, port, id),
		Host:   id + ".oob",
		Domain: id + ".oob." + m.publicHost,
	}
	m.mu.Lock()
	m.canaries[id] = label
	m.mu.Unlock()
	if err := m.store.InsertCanary(ctx, id, label); err != nil {
		m.log.Error("collab canary insert", "err", err)
	}
	return c, nil
}

// matchCanary extracts a canary id from a Host header or URL path.
func (m *Manager) matchCanary(host, path string) (string, string, bool) {
	// host form: <id>.oob[.anything]
	for _, part := range strings.FieldsFunc(host, func(r rune) bool { return r == '.' }) {
		if _, ok := m.canaries[part]; ok {
			return part, m.canaries[part], true
		}
	}
	// path form: /<id>/... or ?c=<id>
	for _, seg := range strings.FieldsFunc(path, func(r rune) bool { return r == '/' || r == '?' || r == '&' || r == '=' }) {
		if _, ok := m.canaries[seg]; ok {
			return seg, m.canaries[seg], true
		}
	}
	return "", "", false
}

// Interaction is one recorded callback.
type Interaction struct {
	TS     int64  `json:"ts"`
	Canary string `json:"canary"`
	Label  string `json:"label"`
	Proto  string `json:"proto"` // http | dns
	Src    string `json:"src"`
	Method string `json:"method,omitempty"`
	Host   string `json:"host,omitempty"`
	Path   string `json:"path,omitempty"`
	Detail string `json:"detail,omitempty"`
}

func (m *Manager) record(i Interaction) {
	if err := m.store.InsertInteraction(context.Background(), &store.Interaction{
		Canary: i.Canary, Label: i.Label, Proto: i.Proto, Src: i.Src,
		Method: i.Method, Host: i.Host, Path: i.Path, Detail: i.Detail,
	}); err != nil {
		m.log.Error("collab interaction insert", "err", err)
	}
}

// StartHTTP runs the interaction listener (blocking).
func (m *Manager) StartHTTP() error {
	ln, err := net.Listen("tcp", m.httpAddr)
	if err != nil {
		return err
	}
	m.mu.Lock()
	m.httpLn = ln
	m.mu.Unlock()
	mux := http.NewServeMux()
	mux.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
		src, _, _ := net.SplitHostPort(r.RemoteAddr)
		m.mu.Lock()
		id, label, ok := m.matchCanary(r.Host, r.URL.RequestURI())
		m.mu.Unlock()
		if !ok {
			// unknown probe: answer, log without attribution
			w.WriteHeader(200)
			m.record(Interaction{TS: time.Now().UnixMilli(), Proto: "http", Src: src,
				Host: r.Host, Path: r.URL.RequestURI(), Detail: "unmatched canary"})
			return
		}
		w.WriteHeader(200)
		m.record(Interaction{
			TS: time.Now().UnixMilli(), Canary: id, Label: label, Proto: "http",
			Src: src, Method: r.Method, Host: r.Host, Path: r.URL.RequestURI(),
			Detail: fmt.Sprintf("%s %s%s from %s", r.Method, r.Host, r.URL.RequestURI(), src),
		})
	})
	m.log.Info("collaborator http listening", "addr", m.httpAddr)
	return http.Serve(ln, mux)
}

// StartDNS runs a minimal A-record responder: any query whose name contains
// a canary id gets the public host's address and is recorded. All other
// queries get the address too (wildcard) — this listener is meant for
// controlled engagements where the target's resolver points at it.
func (m *Manager) StartDNS() error {
	if m.dnsAddr == "" {
		return nil
	}
	udp, err := net.ListenPacket("udp", m.dnsAddr)
	if err != nil {
		return err
	}
	m.mu.Lock()
	m.dnsConn = udp
	m.mu.Unlock()
	go func() {
		buf := make([]byte, 1500)
		for {
			n, addr, err := udp.ReadFrom(buf)
			if err != nil {
				return
			}
			m.handleDNS(udp, addr, buf[:n])
		}
	}()
	m.log.Info("collaborator dns listening", "addr", m.dnsAddr)
	return nil
}

func (m *Manager) handleDNS(udp net.PacketConn, addr net.Addr, msg []byte) {
	if len(msg) < 12 {
		return
	}
	// parse QNAME
	pos := 12
	var name strings.Builder
	for {
		if pos >= len(msg) {
			return
		}
		l := int(msg[pos])
		if l == 0 {
			pos++
			break
		}
		if l > 63 || pos+1+l > len(msg) {
			return
		}
		if name.Len() > 0 {
			name.WriteByte('.')
		}
		name.Write(msg[pos+1 : pos+1+l])
		pos += 1 + l
	}
	qname := name.String()
	if pos+4 > len(msg) {
		return
	}
	qtype := binary.BigEndian.Uint16(msg[pos : pos+2])

	// resolve answer address: the public host (A) or its IPs
	ip := net.ParseIP(m.publicHost)
	if ip == nil {
		if addrs, err := net.LookupHost(m.publicHost); err == nil && len(addrs) > 0 {
			ip = net.ParseIP(addrs[0])
		}
	}
	if ip == nil || qtype != 1 { // A records only
		return
	}
	ip4 := ip.To4()
	if ip4 == nil {
		return
	}

	// response: header + question + answer
	resp := make([]byte, 0, len(msg)+16)
	resp = append(resp, msg[:2]...) // id
	resp = append(resp, 0x84, 0x00) // response, no error
	qdcount := binary.BigEndian.Uint16(msg[4:6])
	ancount := qdcount
	resp = append(resp, byte(qdcount>>8), byte(qdcount)) // questions
	resp = append(resp, byte(ancount>>8), byte(ancount)) // answers
	resp = append(resp, 0, 0, 0, 0)                      // authority/additional
	resp = append(resp, msg[12:pos+4]...)                // question section verbatim
	// answer: pointer to name (0xc00c), type A, class IN, ttl 60, rdlen 4
	resp = append(resp, 0xc0, 0x0c, 0, 1, 0, 1, 0, 0, 0, 60, 0, 4)
	resp = append(resp, ip4[0], ip4[1], ip4[2], ip4[3])
	_, _ = udp.WriteTo(resp, addr)

	// attribution
	src, _, _ := net.SplitHostPort(addr.String())
	m.mu.Lock()
	id, label, ok := m.matchCanary(qname, "")
	m.mu.Unlock()
	if ok {
		m.record(Interaction{
			TS: time.Now().UnixMilli(), Canary: id, Label: label, Proto: "dns",
			Src: src, Host: qname, Detail: "DNS query for " + qname + " from " + src,
		})
	}
}

// Interactions returns recorded callbacks, optionally filtered by canary.
func (m *Manager) Interactions(ctx context.Context, canary string) ([]store.Interaction, error) {
	return m.store.ListInteractions(ctx, canary)
}

// HasInteraction reports whether a canary has fired (poll helper for the
// scanner's ssrf-canary check).
func (m *Manager) HasInteraction(ctx context.Context, canary string) bool {
	list, err := m.store.ListInteractions(ctx, canary)
	return err == nil && len(list) > 0
}

// Close shuts down listeners.
func (m *Manager) Close() {
	m.mu.Lock()
	defer m.mu.Unlock()
	if m.httpLn != nil {
		m.httpLn.Close()
	}
	if m.dnsConn != nil {
		m.dnsConn.Close()
	}
}

// NewCanaryAdapter adapts the manager to the scanner's narrow interface.
func (m *Manager) NewCanaryAdapter() canaryAdapter { return canaryAdapter{m} }

type canaryAdapter struct{ m *Manager }

func (c canaryAdapter) NewCanary(ctx context.Context, label string) (string, string, error) {
	can, err := c.m.NewCanary(ctx, label)
	if err != nil {
		return "", "", err
	}
	return can.ID, can.URL, nil
}

func (c canaryAdapter) HasInteraction(ctx context.Context, canaryID string) bool {
	return c.m.HasInteraction(ctx, canaryID)
}
