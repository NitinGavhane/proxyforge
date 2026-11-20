// Package config manages ProxyForge's global configuration (~/.proxyforge)
// and project (engagement) resolution.
package config

import (
	"crypto/rand"
	"encoding/hex"
	"errors"
	"fmt"
	"net"
	"os"
	"path/filepath"
	"runtime"
	"strconv"
	"time"

	"github.com/BurntSushi/toml"
)

// Defaults for listener addresses. Everything binds localhost; the API/UI is
// never exposed off-box.
const (
	DefaultProxyAddr = "127.0.0.1:8080"
	DefaultAPIAddr   = "127.0.0.1:8765"
)

// ClientCertConfig maps a host pattern to a client certificate pair used
// for upstream mTLS.
type ClientCertConfig struct {
	Host string `toml:"host"` // exact host or leading-wildcard (*.example.com)
	Cert string `toml:"cert"` // PEM file path
	Key  string `toml:"key"`  // PEM file path
}

// Config is the global, per-user configuration.
type Config struct {
	Token         string             `toml:"token"`          // API bearer token (hex, 32 bytes)
	ProxyAddr     string             `toml:"proxy_addr"`     // proxy listener
	APIAddr       string             `toml:"api_addr"`       // API/UI listener
	CAKeyType     string             `toml:"ca_key_type"`    // ecdsa (default) | rsa
	PassThrough   []string           `toml:"passthrough"`    // hosts whose TLS is tunneled, not MITM'd
	UpstreamProxy string             `toml:"upstream_proxy"` // http(s):// or socks5:// egress proxy
	H2Disable     []string           `toml:"h2_disable"`     // force HTTP/1.1 downstream for these hosts
	ClientCerts   []ClientCertConfig `toml:"client_cert"`
}

// Dir returns (and creates) the ProxyForge config directory.
func Dir() (string, error) {
	home, err := os.UserHomeDir()
	if err != nil {
		return "", err
	}
	dir := filepath.Join(home, ".proxyforge")
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return "", err
	}
	return dir, nil
}

// ProjectsDir returns (and creates) the default engagement directory.
func ProjectsDir() (string, error) {
	dir, err := Dir()
	if err != nil {
		return "", err
	}
	p := filepath.Join(dir, "projects")
	if err := os.MkdirAll(p, 0o700); err != nil {
		return "", err
	}
	return p, nil
}

// Load reads config.toml from dir, creating it (with a fresh token) when
// missing. The token is 32 random bytes, hex-encoded.
// Load reads config.toml from dir, creating it (with a fresh token) when
// missing. Concurrent first-time loaders (daemon + `token` CLI) must never
// mint different tokens: creation is exclusive (O_EXCL) and readers treat a
// missing OR EMPTY file as "another process is mid-write" and retry.
func Load(dir string) (*Config, error) {
	path := filepath.Join(dir, "config.toml")
	var lastErr error
	for attempt := 0; attempt < 40; attempt++ {
		raw, err := os.ReadFile(path)
		switch {
		case errors.Is(err, os.ErrNotExist):
			fresh := &Config{
				Token:     NewToken(),
				ProxyAddr: DefaultProxyAddr,
				APIAddr:   DefaultAPIAddr,
			}
			if cerr := createExcl(dir, path, fresh); cerr == nil {
				return fresh, nil
			} else if !errors.Is(cerr, os.ErrExist) {
				return nil, cerr
			}
			// lost the race — loop and read the winner's file
		case err != nil:
			return nil, err
		case len(raw) == 0:
			// writer mid-flight — retry
		default:
			c := &Config{}
			if uerr := toml.Unmarshal(raw, c); uerr != nil {
				return nil, fmt.Errorf("parse %s: %w", path, uerr)
			}
			if c.Token == "" {
				// non-empty file with no token (user-edited): fill and save
				c.Token = NewToken()
				if serr := c.Save(dir); serr != nil {
					return nil, serr
				}
			}
			if c.ProxyAddr == "" {
				c.ProxyAddr = DefaultProxyAddr
			}
			if c.APIAddr == "" {
				c.APIAddr = DefaultAPIAddr
			}
			return c, nil
		}
		time.Sleep(25 * time.Millisecond)
	}
	return nil, fmt.Errorf("config %s: could not settle after concurrent creation: %w", path, lastErr)
}

// Save writes config.toml atomically (temp file + rename) with 0600
// permissions, so concurrent readers never observe a torn file.
func (c *Config) Save(dir string) error {
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return err
	}
	tmp, err := os.CreateTemp(dir, ".config-*.toml")
	if err != nil {
		return err
	}
	defer os.Remove(tmp.Name())
	if err := tmp.Chmod(0o600); err != nil {
		tmp.Close()
		return err
	}
	if err := toml.NewEncoder(tmp).Encode(c); err != nil {
		tmp.Close()
		return err
	}
	if err := tmp.Close(); err != nil {
		return err
	}
	return os.Rename(tmp.Name(), filepath.Join(dir, "config.toml"))
}

// createExcl writes the config only when it does not exist yet; on a race
// the second writer gets os.ErrExist.
func createExcl(dir, path string, c *Config) error {
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return err
	}
	f, err := os.OpenFile(path, os.O_CREATE|os.O_EXCL|os.O_WRONLY, 0o600)
	if err != nil {
		return err
	}
	defer f.Close()
	return toml.NewEncoder(f).Encode(c)
}

// NewToken returns a random 32-byte hex token.
func NewToken() string {
	b := make([]byte, 32)
	if _, err := rand.Read(b); err != nil {
		panic("config: crypto/rand unavailable: " + err.Error())
	}
	return hex.EncodeToString(b)
}

// ProjectDBPath resolves a -project flag (name or path) to a SQLite file
// path. Names resolve under ProjectsDir; a ".pf.sqlite" suffix is appended to
// bare names.
func ProjectDBPath(project string) (string, error) {
	if project == "" {
		project = "default"
	}
	if filepath.IsAbs(project) || runtime.GOOS == "windows" && len(project) > 2 && project[1] == ':' {
		return project, nil
	}
	pdir, err := ProjectsDir()
	if err != nil {
		return "", err
	}
	name := filepath.Base(project)
	if filepath.Ext(name) == "" {
		name += ".pf.sqlite"
	}
	return filepath.Join(pdir, name), nil
}

// FreePort asks the OS for a free TCP port on 127.0.0.1 (used when a
// configured API port is taken).
func FreePort() (int, error) {
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		return 0, err
	}
	defer ln.Close()
	return ln.Addr().(*net.TCPAddr).Port, nil
}

// ParsePort extracts the numeric port from a host:port addr (0 when absent
// or unparseable).
func ParsePort(addr string) int {
	_, port, err := net.SplitHostPort(addr)
	if err != nil {
		return 0
	}
	n, _ := strconv.Atoi(port)
	return n
}
