// Command proxyforge runs the intercepting proxy daemon: proxy listener,
// control-plane API, embedded UI, and (later) MCP server.
package main

import (
	"context"
	"crypto/tls"
	"errors"
	"flag"
	"fmt"
	"log/slog"
	"net"
	"net/http"
	"net/url"
	"os"
	"os/signal"
	"path/filepath"
	"strconv"
	"strings"
	"syscall"
	"time"

	"github.com/NitinGavhane/proxyforge/internal/api"
	"github.com/NitinGavhane/proxyforge/internal/ca"
	"github.com/NitinGavhane/proxyforge/internal/collab"
	"github.com/NitinGavhane/proxyforge/internal/config"
	"github.com/NitinGavhane/proxyforge/internal/extjs"
	"github.com/NitinGavhane/proxyforge/internal/flows"
	"github.com/NitinGavhane/proxyforge/internal/intercept"
	"github.com/NitinGavhane/proxyforge/internal/matchreplace"
	"github.com/NitinGavhane/proxyforge/internal/mcp"
	"github.com/NitinGavhane/proxyforge/internal/pipeline"
	"github.com/NitinGavhane/proxyforge/internal/proxy"
	"github.com/NitinGavhane/proxyforge/internal/scope"
	"github.com/NitinGavhane/proxyforge/internal/store"
	"github.com/NitinGavhane/proxyforge/internal/tags"
	"github.com/NitinGavhane/proxyforge/internal/tools"
	"github.com/NitinGavhane/proxyforge/ui"
)

func main() {
	var (
		project     = flag.String("project", "", "engagement project name or .pf.sqlite path (default: 'default')")
		proxyAddr   = flag.String("proxy-addr", "", "proxy listener addr (default from config, 127.0.0.1:8080)")
		apiAddr     = flag.String("api-addr", "", "API/UI listener addr (default from config, 127.0.0.1:8765)")
		passThrough = flag.String("passthrough", "", "comma-separated hosts to tunnel opaquely (overrides config)")
		upstream    = flag.String("upstream", "", "upstream egress proxy URL: http(s):// or socks5:// (overrides config)")
		h2Disable   = flag.String("h2-disable", "", "comma-separated hosts forced to HTTP/1.1 downstream (overrides config)")
		collabAddr  = flag.String("collab-addr", "", "OOB collaborator HTTP listener (e.g. 127.0.0.1:8767; empty = off)")
		collabDNS   = flag.String("collab-dns", "", "OOB collaborator DNS responder (e.g. 127.0.0.1:5353; empty = off)")
	)
	flag.Parse()
	if flag.NArg() > 0 {
		args := flag.Args()
		switch args[0] {
		case "token":
			if len(args) > 1 && args[1] == "rotate" {
				cmdTokenRotate()
				return
			}
			cmdToken()
		case "ca":
			cmdCA(args[1:])
		case "browse":
			cmdBrowse(args[1:])
		case "mcp":
			cmdMCP(args[1:])
		case "help", "-h":
			flag.Usage()
		default:
			fmt.Fprintf(os.Stderr, "unknown command %q\n", args[0])
			os.Exit(2)
		}
		return
	}
	if err := run(*project, *proxyAddr, *apiAddr, *passThrough, *upstream, *h2Disable, *collabAddr, *collabDNS); err != nil {
		fmt.Fprintln(os.Stderr, "proxyforge:", err)
		os.Exit(1)
	}
}

func cmdToken() {
	dir, err := config.Dir()
	if err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
	cfg, err := config.Load(dir)
	if err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
	fmt.Println(cfg.Token)
}

// cmdTokenRotate replaces the API token. A running daemon keeps its in-memory
// token until restart — rotate, then restart the daemon.
func cmdTokenRotate() {
	dir, err := config.Dir()
	if err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
	cfg, err := config.Load(dir)
	if err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
	old := cfg.Token
	cfg.Token = config.NewToken()
	if err := cfg.Save(dir); err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
	fmt.Println("token rotated")
	fmt.Println("new token:")
	fmt.Println(cfg.Token)
	fmt.Fprintf(os.Stderr, "the old token (%s…) is honored until the daemon restarts; restart proxyforge to apply\n", old[:8])
}

func cmdCA(args []string) {
	// args like: ["export", "out.pem"] or ["remove", "--yes"] — the
	// subcommand comes first, flags after it.
	if len(args) == 0 {
		fmt.Println("usage: proxyforge ca export [file] | proxyforge ca remove [--yes]")
		os.Exit(2)
	}
	sub := args[0]
	fs := flag.NewFlagSet("ca "+sub, flag.ExitOnError)
	yes := fs.Bool("yes", false, "skip confirmation for remove")
	_ = fs.Parse(args[1:])
	dir, err := config.Dir()
	if err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
	caDir := filepath.Join(dir, "ca")
	switch sub {
	case "export":
		// load (generating on first use) then copy the root cert out
		authority, err := ca.Load(caDir, ca.Options{KeyType: caKeyType()})
		if err != nil {
			fmt.Fprintln(os.Stderr, err)
			os.Exit(1)
		}
		out := "proxyforge-root-ca.pem"
		if fs.NArg() > 0 {
			out = fs.Arg(0)
		}
		if err := os.WriteFile(out, authority.RootPEM(), 0o644); err != nil {
			fmt.Fprintln(os.Stderr, err)
			os.Exit(1)
		}
		abs, _ := filepath.Abs(out)
		fmt.Println(abs)
		fmt.Fprintln(os.Stderr, "trust this CA in your browser/OS only for the duration of an engagement")
	case "remove":
		if _, err := os.Stat(caDir); errors.Is(err, os.ErrNotExist) {
			fmt.Println("no CA installed at", caDir)
			return
		}
		if !*yes {
			fmt.Printf("remove %s (root key + cached leaves)? [y/N] ", caDir)
			var answer string
			_, _ = fmt.Scanln(&answer)
			if !strings.EqualFold(answer, "y") && !strings.EqualFold(answer, "yes") {
				fmt.Println("aborted")
				return
			}
		}
		if err := os.RemoveAll(caDir); err != nil {
			fmt.Fprintln(os.Stderr, err)
			os.Exit(1)
		}
		fmt.Println("removed", caDir)
		fmt.Println("also remove 'ProxyForge Root CA' from your OS/browser trust store if you imported it:")
		fmt.Println("  macOS:   Keychain Access → System → ProxyForge Root CA → Delete")
		fmt.Println("  Linux:   sudo rm /usr/local/share/ca-certificates/proxyforge-root-ca.crt && sudo update-ca-certificates")
		fmt.Println("  Windows: certmgr.msc → Trusted Root Certification Authorities → Certificates → ProxyForge Root CA → Delete")
	default:
		fmt.Fprintf(os.Stderr, "unknown ca subcommand %q\n", sub)
		os.Exit(2)
	}
}

func caKeyType() string {
	dir, err := config.Dir()
	if err != nil {
		return ""
	}
	cfg, err := config.Load(dir)
	if err != nil {
		return ""
	}
	return cfg.CAKeyType
}

func run(project, proxyAddr, apiAddr, passThrough, upstream, h2Disable, collabAddr, collabDNS string) error {
	log := slog.New(slog.NewTextHandler(os.Stderr, &slog.HandlerOptions{Level: slog.LevelInfo}))

	cfgDir, err := config.Dir()
	if err != nil {
		return err
	}
	cfg, err := config.Load(cfgDir)
	if err != nil {
		return err
	}
	if proxyAddr != "" {
		cfg.ProxyAddr = proxyAddr
	}
	if apiAddr != "" {
		cfg.APIAddr = apiAddr
	}
	if passThrough != "" {
		cfg.PassThrough = strings.Split(passThrough, ",")
	}
	if upstream != "" {
		cfg.UpstreamProxy = upstream
	}
	if h2Disable != "" {
		cfg.H2Disable = strings.Split(h2Disable, ",")
	}
	dbPath, err := config.ProjectDBPath(project)
	if err != nil {
		return err
	}
	st, err := store.Open(dbPath)
	if err != nil {
		return fmt.Errorf("open project %s: %w", dbPath, err)
	}
	defer st.Close()
	log.Info("project open", "path", dbPath)

	// CA (MITM). Failures are fatal: a broken CA directory must not silently
	// downgrade the engine to no-HTTPS.
	caDir := filepath.Join(cfgDir, "ca")
	authority, err := ca.Load(caDir, ca.Options{KeyType: cfg.CAKeyType})
	if err != nil {
		return fmt.Errorf("load CA: %w", err)
	}

	var upstreamURL *url.URL
	if cfg.UpstreamProxy != "" {
		upstreamURL, err = url.Parse(cfg.UpstreamProxy)
		if err != nil {
			return fmt.Errorf("upstream_proxy: %w", err)
		}
	}

	clientCerts, err := loadClientCerts(cfg.ClientCerts)
	if err != nil {
		return err
	}

	bus := flows.NewBus()
	pipe := pipeline.New(st, bus, log)

	// intercept manager: parked items from a previous run can't survive a
	// restart (their client connections are gone) — mark them recovered.
	icept, err := intercept.New(st, bus)
	if err != nil {
		return fmt.Errorf("intercept: %w", err)
	}
	if n, rerr := icept.Recover(context.Background()); rerr != nil {
		log.Error("intercept recovery", "err", rerr)
	} else if n > 0 {
		log.Info("recovered parked intercept items (marked restarted)", "count", n)
	}

	mr, err := matchreplace.New(st, bus)
	if err != nil {
		return fmt.Errorf("match & replace: %w", err)
	}
	scripts, err := extjs.NewManager(st, log)
	if err != nil {
		return fmt.Errorf("scripts: %w", err)
	}
	sc, err := scope.New(st, bus)
	if err != nil {
		return fmt.Errorf("scope: %w", err)
	}
	tagMgr := tags.New()

	eng := &proxy.Engine{
		Pipeline:       pipe,
		CA:             authority,
		PassThrough:    cfg.PassThrough,
		UpstreamProxy:  upstreamURL,
		H2DisableHosts: cfg.H2Disable,
		ClientCerts:    clientCerts,
		Intercept:      icept,
		MatchReplace:   mr,
		Scope:          sc,
		Tags:           tagMgr,
		Scripts:        scripts,
	}

	rep := tools.NewRepeater(st, eng)
	disc := tools.NewDiscovery(st, eng)
	intr := tools.NewIntruder(eng)
	scn := tools.NewScanner(st, eng)

	var collabMgr *collab.Manager
	if collabAddr != "" {
		collabMgr = collab.NewManager(st, log, collabAddr, collabDNS, "")
		scn.SetCollaborator(collabMgr.NewCanaryAdapter())
		go func() {
			if err := collabMgr.StartHTTP(); err != nil {
				log.Error("collaborator http", "err", err)
			}
		}()
		if err := collabMgr.StartDNS(); err != nil {
			log.Error("collaborator dns", "err", err)
		}
		log.Info("collaborator up", "http", collabAddr, "dns", collabDNS)
	}

	mcpBackend := &mcp.Backend{
		Store: st, Intercept: icept, Repeater: rep, Intruder: intr,
		Scanner: scn, Scope: sc, MatchRep: mr, Scripts: scripts,
		Version: "0.1.0",
	}
	apiSrv := &api.Server{
		Store: st, Bus: bus, Token: cfg.Token, Log: log, Started: time.Now(),
		Intercept:    icept,
		MatchReplace: mr,
		Scope:        sc,
		Tags:         tagMgr,
		Repeater:     rep,
		Discovery:    disc,
		Intruder:     intr,
		Scanner:      scn,
		Collab:       collabMgr,
		Scripts:      scripts,
		MCP:          mcpBackend,
	}

	// API listener: localhost only; fall back to a free port when taken.
	apiLn, err := net.Listen("tcp", cfg.APIAddr)
	if errors.Is(err, syscall.EADDRINUSE) {
		port, perr := config.FreePort()
		if perr != nil {
			return fmt.Errorf("api listen %s: %w", cfg.APIAddr, err)
		}
		apiLn, err = net.Listen("tcp", "127.0.0.1:"+strconv.Itoa(port))
	}
	if err != nil {
		return fmt.Errorf("api listen: %w", err)
	}

	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()

	errCh := make(chan error, 2)
	go func() { errCh <- eng.Listen(cfg.ProxyAddr) }()
	api := &http.Server{Handler: apiSrv.Handler()}
	go func() { errCh <- api.Serve(apiLn) }()

	log.Info("proxyforge up",
		"proxy", cfg.ProxyAddr, "api", "http://"+apiLn.Addr().String(),
		"ca", caDir,
		"passthrough", strings.Join(cfg.PassThrough, ","),
		"upstream", cfg.UpstreamProxy,
		"client_certs", len(clientCerts),
		"ui_built", uiBuilt())

	select {
	case <-ctx.Done():
		log.Info("shutting down")
	case err := <-errCh:
		if err != nil && !errors.Is(err, http.ErrServerClosed) {
			log.Error("server error", "err", err)
		}
	}
	shCtx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()
	_ = api.Shutdown(shCtx)
	_ = eng.Close()
	if collabMgr != nil {
		collabMgr.Close()
	}
	return nil
}

func loadClientCerts(cfgs []config.ClientCertConfig) ([]proxy.ClientCert, error) {
	var out []proxy.ClientCert
	for _, c := range cfgs {
		cert, err := tls.LoadX509KeyPair(c.Cert, c.Key)
		if err != nil {
			return nil, fmt.Errorf("client cert %s for %s: %w", c.Cert, c.Host, err)
		}
		if c.Host == "" {
			return nil, fmt.Errorf("client cert entry missing host pattern")
		}
		out = append(out, proxy.ClientCert{Pattern: c.Host, Cert: cert})
	}
	return out, nil
}

func uiBuilt() bool {
	return ui.IsBuilt()
}
