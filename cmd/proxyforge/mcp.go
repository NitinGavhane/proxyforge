package main

import (
	"bufio"
	"bytes"
	"encoding/json"
	"flag"
	"fmt"
	"net/http"
	"os"

	"github.com/NitinGavhane/proxyforge/internal/config"
	"github.com/NitinGavhane/proxyforge/internal/mcp"
)

// cmdMCP is the stdio transport: a thin relay between the agent's stdio and
// the daemon's streamable-HTTP MCP endpoint (authenticated with the API
// token from config). One line = one JSON-RPC message.
//
//	usage: proxyforge mcp [-api http://127.0.0.1:8765]
func cmdMCP(args []string) {
	fs := flag.NewFlagSet("mcp", flag.ExitOnError)
	apiBase := fs.String("api", "", "daemon API base (default from config)")
	_ = fs.Parse(args)

	cfgDir, err := config.Dir()
	if err != nil {
		exitErr(err)
	}
	cfg, err := config.Load(cfgDir)
	if err != nil {
		exitErr(err)
	}
	if *apiBase != "" {
		cfg.APIAddr = hostPortOnly(*apiBase)
	}
	endpoint := "http://" + cfg.APIAddr + "/api/v1/mcp"

	out := bufio.NewWriter(os.Stdout)
	defer out.Flush()
	scanner := bufio.NewScanner(os.Stdin)
	scanner.Buffer(make([]byte, 0, 64*1024), 8<<20)
	for scanner.Scan() {
		line := bytes.TrimSpace(scanner.Bytes())
		if len(line) == 0 {
			continue
		}
		resp, err := relay(endpoint, cfg.Token, line)
		if err != nil {
			// transport failure surfaces as a JSON-RPC internal error so
			// the agent sees a structured message, not a dead pipe
			errResp := mcp.NewError(nil, mcp.CodeInternal, "proxyforge mcp relay: "+err.Error())
			raw, _ := json.Marshal(errResp)
			fmt.Fprintln(out, string(raw))
			out.Flush()
			continue
		}
		// notifications (no id) produce no response
		var probe struct {
			ID json.RawMessage `json:"id"`
		}
		_ = json.Unmarshal(line, &probe)
		if len(probe.ID) == 0 {
			continue
		}
		fmt.Fprintln(out, resp)
		out.Flush()
	}
}

func relay(endpoint, token string, line []byte) (string, error) {
	req, err := http.NewRequest(http.MethodPost, endpoint, bytes.NewReader(line))
	if err != nil {
		return "", err
	}
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Authorization", "Bearer "+token)
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		return "", err
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return "", fmt.Errorf("daemon replied %s (is it running?)", resp.Status)
	}
	var buf bytes.Buffer
	if _, err := buf.ReadFrom(resp.Body); err != nil {
		return "", err
	}
	return string(bytes.TrimSpace(buf.Bytes())), nil
}

func hostPortOnly(raw string) string {
	// strip scheme/path, keep host:port
	for _, prefix := range []string{"http://", "https://"} {
		if len(raw) > len(prefix) && raw[:len(prefix)] == prefix {
			raw = raw[len(prefix):]
		}
	}
	for i := 0; i < len(raw); i++ {
		if raw[i] == '/' {
			return raw[:i]
		}
	}
	return raw
}
