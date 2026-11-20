package ca

import (
	"crypto/rsa"
	"crypto/tls"
	"crypto/x509"
	"net"
	"os"
	"path/filepath"
	"testing"
	"time"
)

func TestLoadGeneratesRootWithPermissions(t *testing.T) {
	dir := filepath.Join(t.TempDir(), "ca")
	c, err := Load(dir, Options{})
	if err != nil {
		t.Fatalf("load: %v", err)
	}
	if _, err := os.Stat(filepath.Join(dir, "root.pem")); err != nil {
		t.Fatalf("root.pem: %v", err)
	}
	info, err := os.Stat(filepath.Join(dir, "root.key"))
	if err != nil {
		t.Fatalf("root.key: %v", err)
	}
	if perm := info.Mode().Perm(); perm != 0o600 {
		t.Fatalf("root.key perms = %o, want 600", perm)
	}
	// reload keeps identity
	c2, err := Load(dir, Options{})
	if err != nil {
		t.Fatalf("reload: %v", err)
	}
	if string(c2.RootPEM()) != string(c.RootPEM()) {
		t.Fatal("root changed across loads")
	}
}

func TestLoadRSAOption(t *testing.T) {
	dir := filepath.Join(t.TempDir(), "ca-rsa")
	c, err := Load(dir, Options{KeyType: "rsa"})
	if err != nil {
		t.Fatalf("load rsa: %v", err)
	}
	if _, ok := c.RootCert().PublicKey.(*rsa.PublicKey); !ok {
		t.Fatal("root public key is not RSA")
	}
}

func TestMintLeafChainsAndSANs(t *testing.T) {
	dir := filepath.Join(t.TempDir(), "ca")
	c, _ := Load(dir, Options{})
	leaf, err := c.Mint("api.example.test")
	if err != nil {
		t.Fatalf("mint: %v", err)
	}
	if leaf.Leaf == nil {
		t.Fatal("leaf not parsed")
	}
	if err := c.VerifyLeaf(leaf.Leaf); err != nil {
		t.Fatalf("leaf does not chain to root: %v", err)
	}
	if len(leaf.Leaf.DNSNames) != 1 || leaf.Leaf.DNSNames[0] != "api.example.test" {
		t.Fatalf("SANs = %v", leaf.Leaf.DNSNames)
	}
	valid := leaf.Leaf.NotAfter.Sub(leaf.Leaf.NotBefore)
	if valid < 390*24*time.Hour || valid > 400*24*time.Hour {
		t.Fatalf("leaf validity = %v, want ~396d", valid)
	}
	if leaf.Leaf.IsCA {
		t.Fatal("leaf must not be a CA")
	}
}

func TestMintIPSAN(t *testing.T) {
	c, _ := Load(filepath.Join(t.TempDir(), "ca"), Options{})
	leaf, err := c.Mint("127.0.0.1")
	if err != nil {
		t.Fatalf("mint ip: %v", err)
	}
	if len(leaf.Leaf.IPAddresses) != 1 || !leaf.Leaf.IPAddresses[0].Equal(net.ParseIP("127.0.0.1")) {
		t.Fatalf("IP SANs = %v", leaf.Leaf.IPAddresses)
	}
}

func TestMintCachedInMemoryAndOnDisk(t *testing.T) {
	dir := filepath.Join(t.TempDir(), "ca")
	c, _ := Load(dir, Options{})
	a, _ := c.Mint("cache.test")
	b, _ := c.Mint("cache.test")
	if a.Leaf.SerialNumber.Cmp(b.Leaf.SerialNumber) != 0 {
		t.Fatal("second mint not served from cache")
	}
	// fresh CA instance reads the disk cache
	c2, _ := Load(dir, Options{})
	d, err := c2.Mint("cache.test")
	if err != nil {
		t.Fatalf("disk mint: %v", err)
	}
	if d.Leaf.SerialNumber.Cmp(a.Leaf.SerialNumber) != 0 {
		t.Fatal("disk cache not reused")
	}
}

func TestDiskCacheInvalidatedByRootChange(t *testing.T) {
	dir := filepath.Join(t.TempDir(), "ca")
	c1, _ := Load(dir, Options{})
	a, _ := c1.Mint("rotate.test")
	// rotate the root: wipe and regenerate
	os.RemoveAll(dir)
	c2, _ := Load(dir, Options{})
	b, _ := c2.Mint("rotate.test")
	if err := c2.VerifyLeaf(b.Leaf); err != nil {
		t.Fatalf("re-minted leaf invalid under new root: %v", err)
	}
	if a.Leaf.SerialNumber.Cmp(b.Leaf.SerialNumber) == 0 {
		t.Fatal("stale leaf reused after root rotation")
	}
}

func TestRootPEMUsableAsClientTrust(t *testing.T) {
	dir := filepath.Join(t.TempDir(), "ca")
	c, _ := Load(dir, Options{})
	pool := x509.NewCertPool()
	if !pool.AppendCertsFromPEM(c.RootPEM()) {
		t.Fatal("root PEM rejected by cert pool")
	}
	leaf, _ := c.Mint("verify.test")
	if _, err := leaf.Leaf.Verify(x509.VerifyOptions{
		Roots:     pool,
		DNSName:   "verify.test",
		KeyUsages: []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
	}); err != nil {
		t.Fatalf("tls-style verification failed: %v", err)
	}
}

func TestLeafUsableInTLSHandshake(t *testing.T) {
	c, _ := Load(filepath.Join(t.TempDir(), "ca"), Options{})
	leaf, err := c.Mint("handshake.test")
	if err != nil {
		t.Fatalf("mint: %v", err)
	}
	cfg := &tls.Config{Certificates: []tls.Certificate{leaf}, MinVersion: tls.VersionTLS12}
	clientCfg := &tls.Config{RootCAs: c.Pool(), ServerName: "handshake.test"}
	ln, err := tls.Listen("tcp", "127.0.0.1:0", cfg)
	if err != nil {
		t.Fatal(err)
	}
	defer ln.Close()
	go func() {
		conn, err := ln.Accept()
		if err == nil {
			buf := make([]byte, 8)
			n, _ := conn.Read(buf)
			_, _ = conn.Write(append([]byte("pong:"), buf[:n]...))
			conn.Close()
		}
	}()
	conn, err := tls.Dial("tcp", ln.Addr().String(), clientCfg)
	if err != nil {
		t.Fatalf("handshake with minted leaf failed: %v", err)
	}
	defer conn.Close()
	_, _ = conn.Write([]byte("ping"))
	buf := make([]byte, 32)
	n, _ := conn.Read(buf)
	if string(buf[:n]) != "pong:ping" {
		t.Fatalf("echo = %q", buf[:n])
	}
}
