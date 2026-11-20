package config

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func TestLoadCreatesConfigWithToken(t *testing.T) {
	dir := t.TempDir()
	c, err := Load(dir)
	if err != nil {
		t.Fatalf("load: %v", err)
	}
	if len(c.Token) != 64 { // 32 bytes hex
		t.Fatalf("token len = %d", len(c.Token))
	}
	if c.ProxyAddr != DefaultProxyAddr || c.APIAddr != DefaultAPIAddr {
		t.Fatalf("defaults not applied: %+v", c)
	}
	// file exists with 0600
	info, err := os.Stat(filepath.Join(dir, "config.toml"))
	if err != nil {
		t.Fatalf("config file: %v", err)
	}
	if perm := info.Mode().Perm(); perm != 0o600 {
		t.Fatalf("config perms = %o, want 600", perm)
	}
	// reload keeps token
	c2, err := Load(dir)
	if err != nil {
		t.Fatalf("reload: %v", err)
	}
	if c2.Token != c.Token {
		t.Fatalf("token changed across loads")
	}
}

func TestProjectDBPath(t *testing.T) {
	p, err := ProjectDBPath("acme")
	if err != nil {
		t.Fatal(err)
	}
	if !strings.HasSuffix(filepath.ToSlash(p), "/projects/acme.pf.sqlite") {
		t.Errorf("name path = %q", p)
	}
	p2, err := ProjectDBPath("")
	if err != nil || !strings.HasSuffix(filepath.ToSlash(p2), "/projects/default.pf.sqlite") {
		t.Errorf("default path = %q err=%v", p2, err)
	}
	p3, err := ProjectDBPath("/tmp/abs/eng.pf.sqlite")
	if err != nil || p3 != "/tmp/abs/eng.pf.sqlite" {
		t.Errorf("abs path = %q err=%v", p3, err)
	}
}

func TestParsePort(t *testing.T) {
	if ParsePort("127.0.0.1:8765") != 8765 || ParsePort("localhost") != 0 {
		t.Fatal("ParsePort broken")
	}
}

func TestM2SettingsRoundTrip(t *testing.T) {
	dir := t.TempDir()
	c, err := Load(dir)
	if err != nil {
		t.Fatal(err)
	}
	c.PassThrough = []string{"*.pinned.example", "10.0.0.5"}
	c.UpstreamProxy = "socks5://127.0.0.1:1080"
	c.H2Disable = []string{"*.broken-h2.example"}
	c.CAKeyType = "rsa"
	c.ClientCerts = []ClientCertConfig{{Host: "*.mtls.example", Cert: "c.pem", Key: "k.pem"}}
	if err := c.Save(dir); err != nil {
		t.Fatal(err)
	}
	got, err := Load(dir)
	if err != nil {
		t.Fatal(err)
	}
	if len(got.PassThrough) != 2 || got.PassThrough[0] != "*.pinned.example" {
		t.Fatalf("passthrough = %v", got.PassThrough)
	}
	if len(got.H2Disable) != 1 || got.H2Disable[0] != "*.broken-h2.example" {
		t.Fatalf("h2_disable = %v", got.H2Disable)
	}
	if got.UpstreamProxy != "socks5://127.0.0.1:1080" {
		t.Fatalf("upstream = %q", got.UpstreamProxy)
	}
	if got.CAKeyType != "rsa" {
		t.Fatalf("ca_key_type = %q", got.CAKeyType)
	}
	if len(got.ClientCerts) != 1 || got.ClientCerts[0].Host != "*.mtls.example" {
		t.Fatalf("client certs = %+v", got.ClientCerts)
	}
}

func TestLoadWaitsForConcurrentWriter(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "config.toml")
	// simulate the winner creating the file and writing it 150ms later
	f, _ := os.OpenFile(path, os.O_CREATE|os.O_EXCL|os.O_WRONLY, 0o600)
	f.Close()
	go func() {
		time.Sleep(150 * time.Millisecond)
		c := &Config{Token: "winner-token", ProxyAddr: "127.0.0.1:1", APIAddr: "127.0.0.1:2"}
		_ = c.Save(dir)
	}()
	c, err := Load(dir)
	if err != nil {
		t.Fatalf("load during concurrent write: %v", err)
	}
	if c.Token != "winner-token" {
		t.Fatalf("token = %q, want the winner's", c.Token)
	}
}
