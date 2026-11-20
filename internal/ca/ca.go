// Package ca manages ProxyForge's per-install root certificate authority and
// minted per-host leaf certificates for HTTPS MITM.
//
// The root key lives at <dir>/root.key with 0600 permissions and never leaves
// the machine except via explicit export. Leaves are ECDSA P-256, valid for
// 396 days (~13 months), cached in memory and on disk.
package ca

import (
	"bytes"
	"crypto"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/rsa"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"errors"
	"fmt"
	"math/big"
	"net"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"time"
)

// Options controls root generation. KeyType: "ecdsa" (default) or "rsa"
// (legacy clients).
type Options struct {
	KeyType string
}

// CA is a loaded (or freshly generated) root with a leaf cache.
type CA struct {
	mu   sync.Mutex
	dir  string
	cert *x509.Certificate
	key  crypto.Signer

	memCache map[string]tls.Certificate
}

const (
	rootValidity  = 10 * 365 * 24 * time.Hour
	leafValidity  = 396 * 24 * time.Hour // ~13 months
	leafMinRemain = 30 * 24 * time.Hour  // reuse window for disk cache
)

// Load reads the root from dir, generating it on first use. Permissions are
// enforced: dir 0700, root.key 0600.
func Load(dir string, opts Options) (*CA, error) {
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return nil, err
	}
	certPath := filepath.Join(dir, "root.pem")
	keyPath := filepath.Join(dir, "root.key")

	certPEM, certErr := os.ReadFile(certPath)
	keyPEM, keyErr := os.ReadFile(keyPath)
	if certErr != nil && keyErr != nil && errors.Is(certErr, os.ErrNotExist) && errors.Is(keyErr, os.ErrNotExist) {
		if err := generateRoot(certPath, keyPath, opts); err != nil {
			return nil, err
		}
		certPEM, _ = os.ReadFile(certPath)
		keyPEM, _ = os.ReadFile(keyPath)
	} else if certErr != nil || keyErr != nil {
		return nil, fmt.Errorf("ca: incomplete CA files in %s (remove the directory to regenerate): cert=%v key=%v", dir, certErr, keyErr)
	}

	cert, err := parseCert(certPEM)
	if err != nil {
		return nil, fmt.Errorf("ca: parse root.pem: %w", err)
	}
	if !cert.IsCA {
		return nil, errors.New("ca: root.pem is not a CA certificate")
	}
	keyAny, err := parseKey(keyPEM)
	if err != nil {
		return nil, fmt.Errorf("ca: parse root.key: %w", err)
	}
	key, ok := keyAny.(crypto.Signer)
	if !ok {
		return nil, errors.New("ca: root.key is not a signer")
	}
	// public key must match the certificate
	switch pub := cert.PublicKey.(type) {
	case *ecdsa.PublicKey:
		if !pub.Equal(key.Public()) {
			return nil, errors.New("ca: root.key does not match root.pem")
		}
	case *rsa.PublicKey:
		if !pub.Equal(key.Public()) {
			return nil, errors.New("ca: root.key does not match root.pem")
		}
	}
	// enforce permissions at startup
	_ = os.Chmod(keyPath, 0o600)
	_ = os.Chmod(dir, 0o700)

	leaves := filepath.Join(dir, "leaves")
	if err := os.MkdirAll(leaves, 0o700); err != nil {
		return nil, err
	}
	return &CA{dir: dir, cert: cert, key: key, memCache: map[string]tls.Certificate{}}, nil
}

// generateRoot writes a fresh self-signed root.
func generateRoot(certPath, keyPath string, opts Options) error {
	var key crypto.Signer
	var err error
	switch strings.ToLower(opts.KeyType) {
	case "", "ecdsa":
		key, err = ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	case "rsa":
		key, err = rsa.GenerateKey(rand.Reader, 2048)
	default:
		return fmt.Errorf("ca: unknown key type %q (ecdsa|rsa)", opts.KeyType)
	}
	if err != nil {
		return err
	}
	serial, err := randomSerial()
	if err != nil {
		return err
	}
	now := time.Now()
	tpl := &x509.Certificate{
		SerialNumber: serial,
		Subject: pkix.Name{
			CommonName:   "ProxyForge Root CA",
			Organization: []string{"ProxyForge"},
		},
		NotBefore:             now.Add(-time.Hour),
		NotAfter:              now.Add(rootValidity),
		KeyUsage:              x509.KeyUsageCertSign | x509.KeyUsageCRLSign | x509.KeyUsageDigitalSignature,
		BasicConstraintsValid: true,
		IsCA:                  true,
		MaxPathLen:            0,
		MaxPathLenZero:        true,
	}
	der, err := x509.CreateCertificate(rand.Reader, tpl, tpl, key.Public(), key)
	if err != nil {
		return err
	}
	if err := writePEM(certPath, "CERTIFICATE", der, 0o644); err != nil {
		return err
	}
	keyDER, err := x509.MarshalPKCS8PrivateKey(key)
	if err != nil {
		return err
	}
	return writePEM(keyPath, "PRIVATE KEY", keyDER, 0o600)
}

// Mint returns a TLS leaf certificate covering host, minting (and caching)
// as needed. IPv6 literals and DNS names both become SANs.
func (c *CA) Mint(host string) (tls.Certificate, error) {
	host = canonicalHost(host)
	c.mu.Lock()
	defer c.mu.Unlock()
	if leaf, ok := c.memCache[host]; ok {
		return leaf, nil
	}
	// disk cache
	leaf, ok, err := c.loadDiskLeaf(host)
	if err != nil {
		return tls.Certificate{}, err
	}
	if !ok {
		leaf, err = c.mintLocked(host)
		if err != nil {
			return tls.Certificate{}, err
		}
		if err := c.storeDiskLeaf(host, leaf); err != nil {
			return tls.Certificate{}, err
		}
	}
	c.memCache[host] = leaf
	return leaf, nil
}

func (c *CA) mintLocked(host string) (tls.Certificate, error) {
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return tls.Certificate{}, err
	}
	serial, err := randomSerial()
	if err != nil {
		return tls.Certificate{}, err
	}
	now := time.Now()
	tpl := &x509.Certificate{
		SerialNumber: serial,
		Subject:      pkix.Name{CommonName: host},
		NotBefore:    now.Add(-24 * time.Hour),
		NotAfter:     now.Add(leafValidity),
		KeyUsage:     x509.KeyUsageDigitalSignature,
		ExtKeyUsage:  []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
	}
	if ip := net.ParseIP(host); ip != nil {
		tpl.IPAddresses = []net.IP{ip}
	} else {
		tpl.DNSNames = []string{host}
	}
	der, err := x509.CreateCertificate(rand.Reader, tpl, c.cert, key.Public(), c.key)
	if err != nil {
		return tls.Certificate{}, err
	}
	leafCert, err := x509.ParseCertificate(der)
	if err != nil {
		return tls.Certificate{}, err
	}
	return tls.Certificate{
		Certificate: [][]byte{der},
		PrivateKey:  key,
		Leaf:        leafCert,
	}, nil
}

// loadDiskLeaf returns a cached leaf valid for at least leafMinRemain and
// signed by this root.
func (c *CA) loadDiskLeaf(host string) (tls.Certificate, bool, error) {
	path := c.leafPath(host)
	raw, err := os.ReadFile(path)
	if err != nil {
		return tls.Certificate{}, false, nil
	}
	cert, err := tls.X509KeyPair(raw, raw)
	if err != nil {
		return tls.Certificate{}, false, nil // corrupt cache: re-mint
	}
	if cert.Leaf == nil {
		if cert.Leaf, err = x509.ParseCertificate(cert.Certificate[0]); err != nil {
			return tls.Certificate{}, false, nil
		}
	}
	if time.Now().After(cert.Leaf.NotAfter.Add(-leafMinRemain)) {
		return tls.Certificate{}, false, nil
	}
	if err := cert.Leaf.CheckSignatureFrom(c.cert); err != nil {
		return tls.Certificate{}, false, nil
	}
	if !certHostMatches(cert.Leaf, host) {
		return tls.Certificate{}, false, nil
	}
	return cert, true, nil
}

func (c *CA) storeDiskLeaf(host string, leaf tls.Certificate) error {
	var buf bytes.Buffer
	for _, der := range leaf.Certificate {
		_ = pem.Encode(&buf, &pem.Block{Type: "CERTIFICATE", Bytes: der})
	}
	keyDER, err := x509.MarshalPKCS8PrivateKey(leaf.PrivateKey)
	if err != nil {
		return err
	}
	_ = pem.Encode(&buf, &pem.Block{Type: "PRIVATE KEY", Bytes: keyDER})
	return os.WriteFile(c.leafPath(host), buf.Bytes(), 0o600)
}

func (c *CA) leafPath(host string) string {
	safe := make([]byte, 0, len(host))
	for _, ch := range []byte(host) {
		switch {
		case ch >= 'a' && ch <= 'z', ch >= 'A' && ch <= 'Z', ch >= '0' && ch <= '9', ch == '.', ch == '-':
			safe = append(safe, ch)
		default:
			safe = append(safe, '_')
		}
	}
	name := string(safe)
	if len(name) > 40 {
		name = name[:40]
	}
	return filepath.Join(c.dir, "leaves", name+"-"+shortHash(host)+".pem")
}

// RootPEM returns the root certificate in PEM form (for export / trust).
func (c *CA) RootPEM() []byte {
	return pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: c.cert.Raw})
}

// RootCert returns the parsed root certificate.
func (c *CA) RootCert() *x509.Certificate { return c.cert }

// Pool returns a CertPool containing the root (for clients trusting us).
func (c *CA) Pool() *x509.CertPool {
	pool := x509.NewCertPool()
	pool.AddCert(c.cert)
	return pool
}

// VerifyLeaf checks that leaf chains to this root (test helper + smoke use).
func (c *CA) VerifyLeaf(leaf *x509.Certificate) error {
	pool := x509.NewCertPool()
	pool.AddCert(c.cert)
	if _, err := leaf.Verify(x509.VerifyOptions{
		Roots:     pool,
		DNSName:   "",
		KeyUsages: []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
	}); err != nil {
		return err
	}
	return nil
}

func canonicalHost(host string) string {
	host = strings.TrimSpace(strings.ToLower(host))
	if ip := net.ParseIP(host); ip != nil {
		return ip.String()
	}
	return strings.TrimSuffix(host, ".")
}

func certHostMatches(cert *x509.Certificate, host string) bool {
	if ip := net.ParseIP(host); ip != nil {
		for _, cip := range cert.IPAddresses {
			if cip.Equal(ip) {
				return true
			}
		}
		return false
	}
	for _, name := range cert.DNSNames {
		if strings.EqualFold(name, host) {
			return true
		}
	}
	return false
}

func randomSerial() (*big.Int, error) {
	limit := new(big.Int).Lsh(big.NewInt(1), 127)
	return rand.Int(rand.Reader, limit)
}

func shortHash(s string) string {
	// cheap non-crypto digest for filenames (FNV over bytes)
	var h uint64 = 0xcbf29ce484222325
	for i := 0; i < len(s); i++ {
		h ^= uint64(s[i])
		h *= 0x100000001b3
	}
	return fmt.Sprintf("%016x", h)[:8]
}

func writePEM(path, blockType string, der []byte, perm os.FileMode) error {
	f, err := os.OpenFile(path, os.O_CREATE|os.O_TRUNC|os.O_WRONLY, perm)
	if err != nil {
		return err
	}
	defer f.Close()
	return pem.Encode(f, &pem.Block{Type: blockType, Bytes: der})
}

func parseCert(pemBytes []byte) (*x509.Certificate, error) {
	block, _ := pem.Decode(pemBytes)
	if block == nil {
		return nil, errors.New("no PEM block")
	}
	return x509.ParseCertificate(block.Bytes)
}

func parseKey(pemBytes []byte) (any, error) {
	block, _ := pem.Decode(pemBytes)
	if block == nil {
		return nil, errors.New("no PEM block")
	}
	if block.Type == "RSA PRIVATE KEY" {
		return x509.ParsePKCS1PrivateKey(block.Bytes)
	}
	return x509.ParsePKCS8PrivateKey(block.Bytes)
}
