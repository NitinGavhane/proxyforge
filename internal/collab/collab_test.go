package collab

import (
	"context"
	"fmt"
	"log/slog"
	"net"
	"net/http"
	"path/filepath"
	"testing"
	"time"

	"github.com/miekg/dns"

	"github.com/NitinGavhane/proxyforge/internal/store"
)

func freePorts(t *testing.T) (int, int) {
	t.Helper()
	l1, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer l1.Close()
	pc, err := net.ListenUDP("udp", &net.UDPAddr{IP: net.ParseIP("127.0.0.1")})
	if err != nil {
		t.Fatal(err)
	}
	defer pc.Close()
	return l1.Addr().(*net.TCPAddr).Port, pc.LocalAddr().(*net.UDPAddr).Port
}

func newManager(t *testing.T) (*Manager, *store.Store, int, int) {
	t.Helper()
	st, err := store.Open(filepath.Join(t.TempDir(), "collab.pf.sqlite"))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { st.Close() })
	httpPort, dnsPort := freePorts(t)
	m := NewManager(st, slog.Default(),
		fmt.Sprintf("127.0.0.1:%d", httpPort),
		fmt.Sprintf("127.0.0.1:%d", dnsPort),
		"127.0.0.1")
	go m.StartHTTP() //nolint:errcheck
	if err := m.StartDNS(); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(m.Close)
	// wait for the listener
	deadline := time.Now().Add(2 * time.Second)
	for time.Now().Before(deadline) {
		c, err := net.Dial("tcp", fmt.Sprintf("127.0.0.1:%d", httpPort))
		if err == nil {
			c.Close()
			return m, st, httpPort, dnsPort
		}
		time.Sleep(20 * time.Millisecond)
	}
	t.Fatal("http listener never came up")
	return nil, nil, 0, 0
}

func TestHTTPCanaryAttribution(t *testing.T) {
	m, st, httpPort, _ := newManager(t)
	ctx := context.Background()

	c, err := m.NewCanary(ctx, "scan job 1")
	if err != nil {
		t.Fatal(err)
	}
	if len(c.ID) != 16 || c.URL == "" || c.Domain == "" {
		t.Fatalf("canary: %+v", c)
	}

	// path-form callback
	resp, err := http.Get(fmt.Sprintf("http://127.0.0.1:%d/%s/x", httpPort, c.ID))
	if err != nil {
		t.Fatal(err)
	}
	resp.Body.Close()

	// host-form callback
	req, _ := http.NewRequest("GET", fmt.Sprintf("http://127.0.0.1:%d/", httpPort), nil)
	req.Host = c.Host
	resp2, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	resp2.Body.Close()

	// unmatched probe
	resp3, err := http.Get(fmt.Sprintf("http://127.0.0.1:%d/nope", httpPort))
	if err != nil {
		t.Fatal(err)
	}
	resp3.Body.Close()

	list, err := st.ListInteractions(ctx, c.ID)
	if err != nil || len(list) != 2 {
		t.Fatalf("interactions for canary: %v %+v", err, list)
	}
	for _, i := range list {
		if i.Label != "scan job 1" {
			t.Errorf("label = %q", i.Label)
		}
		if i.Proto != "http" || i.Src != "127.0.0.1" {
			t.Errorf("interaction: %+v", i)
		}
	}
	// unmatched logged without canary
	all, _ := st.ListInteractions(ctx, "")
	if len(all) != 3 {
		t.Fatalf("total interactions = %d", len(all))
	}
	if !m.HasInteraction(ctx, c.ID) {
		t.Fatal("HasInteraction false after callbacks")
	}
}

func TestDNSCanary(t *testing.T) {
	m, st, _, dnsPort := newManager(t)
	ctx := context.Background()

	c, err := m.NewCanary(ctx, "dns job")
	if err != nil {
		t.Fatal(err)
	}

	// query <id>.oob.127.0.0.1 — matched by the id label in the name
	q := new(dns.Msg)
	q.SetQuestion(dns.Fqdn(c.Host+".example"), dns.TypeA)
	cli := new(dns.Client)
	cli.Timeout = 2 * time.Second
	r, _, err := cli.Exchange(q, fmt.Sprintf("127.0.0.1:%d", dnsPort))
	if err != nil {
		t.Fatal(err)
	}
	if len(r.Answer) != 1 {
		t.Fatalf("answers = %d", len(r.Answer))
	}
	if a, ok := r.Answer[0].(*dns.A); !ok || a.A.String() != "127.0.0.1" {
		t.Fatalf("answer: %+v", r.Answer[0])
	}
	// attribution
	deadline := time.Now().Add(2 * time.Second)
	for time.Now().Before(deadline) {
		if m.HasInteraction(ctx, c.ID) {
			break
		}
		time.Sleep(50 * time.Millisecond)
	}
	list, _ := st.ListInteractions(ctx, c.ID)
	if len(list) != 1 || list[0].Proto != "dns" || list[0].Label != "dns job" {
		t.Fatalf("dns interaction: %+v", list)
	}
}
