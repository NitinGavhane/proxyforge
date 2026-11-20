// Importers (Phase 3 P8): cURL commands, OpenAPI/Swagger documents, and
// Postman collections.
package tools

import (
	"fmt"
	"net/url"
	"regexp"
	"strconv"
	"strings"
)

// ParseCURL converts a `curl …` command line into a raw request template.
// Supports: URL (quoted or bare), -X/--request, -H/--header, -d/--data
// (repeatable, joined), --data-raw, -u/--user (basic auth placeholder),
// --compressed, -k, -L (ignored), and $'…' quoting.
func ParseCURL(cmd string) (raw string, err error) {
	cmd = strings.TrimSpace(cmd)
	cmd = strings.TrimPrefix(cmd, "curl ")
	if cmd == "" {
		return "", fmt.Errorf("curl: empty command")
	}
	args, err := shSplit(cmd)
	if err != nil {
		return "", fmt.Errorf("curl: %w", err)
	}

	var (
		method  string
		target  string
		headers []string
		data    []string
		user    string
	)
	for i := 0; i < len(args); i++ {
		a := args[i]
		switch {
		case a == "-X" || a == "--request":
			if i+1 >= len(args) {
				return "", fmt.Errorf("curl: %s needs a value", a)
			}
			i++
			method = args[i]
		case a == "-H" || a == "--header":
			if i+1 >= len(args) {
				return "", fmt.Errorf("curl: -H needs a value")
			}
			i++
			if strings.Contains(args[i], ":") {
				headers = append(headers, args[i])
			} else if strings.HasSuffix(args[i], ";") {
				headers = append(headers, args[i]+" ") // `Name;` = empty value
			}
		case a == "-d" || a == "--data" || a == "--data-raw" || a == "--data-binary" || a == "--data-ascii":
			if i+1 >= len(args) {
				return "", fmt.Errorf("curl: %s needs a value", a)
			}
			i++
			data = append(data, args[i])
			if method == "" {
				method = "POST" // -d implies POST
			}
		case a == "-u" || a == "--user":
			if i+1 >= len(args) {
				return "", fmt.Errorf("curl: -u needs a value")
			}
			i++
			user = args[i]
		case a == "--url":
			if i+1 >= len(args) {
				return "", fmt.Errorf("curl: --url needs a value")
			}
			i++
			target = args[i]
		case strings.HasPrefix(a, "-"):
			// -k, -L, -s, --compressed, -i, $vars: ignored or no-ops here
		default:
			if target == "" && (strings.Contains(a, "://") || !strings.HasPrefix(a, "-")) {
				target = a
			}
		}
	}
	if target == "" {
		return "", fmt.Errorf("curl: no URL found")
	}
	u, err := url.Parse(target)
	if err != nil || u.Host == "" {
		return "", fmt.Errorf("curl: bad URL %q", target)
	}
	if method == "" {
		method = "GET"
	}
	// request line
	path := u.RequestURI()
	if path == "" {
		path = "/"
	}
	var b strings.Builder
	fmt.Fprintf(&b, "%s %s HTTP/1.1\r\n", method, path)
	fmt.Fprintf(&b, "Host: %s\r\n", u.Host)
	if u.Scheme == "https" {
		b.WriteString("X-Scheme: https\r\n")
	}
	if user != "" {
		cred := base64ish(user)
		fmt.Fprintf(&b, "Authorization: Basic %s\r\n", cred)
	}
	for _, h := range headers {
		fmt.Fprintf(&b, "%s\r\n", h)
	}
	body := strings.Join(data, "&")
	if len(data) > 0 {
		if !hasHeader(headers, "Content-Type") {
			b.WriteString("Content-Type: application/x-www-form-urlencoded\r\n")
		}
		b.WriteString("\r\n")
		b.WriteString(body)
	} else {
		b.WriteString("\r\n")
	}
	return b.String(), nil
}

func hasHeader(headers []string, name string) bool {
	for _, h := range headers {
		if k, _, ok := strings.Cut(h, ":"); ok && strings.EqualFold(strings.TrimSpace(k), name) {
			return true
		}
	}
	return false
}

func base64ish(s string) string {
	// std encoding of user:pass
	return stdBase64(s)
}

// shSplit splits a shell-ish command honoring single quotes, double quotes,
// and $'…' literals.
func shSplit(s string) ([]string, error) {
	var out []string
	var cur strings.Builder
	inSingle, inDouble, inDollar, hasTok := false, false, false, false
	flush := func() {
		if hasTok {
			out = append(out, cur.String())
			cur.Reset()
			hasTok = false
		}
	}
	for i := 0; i < len(s); i++ {
		c := s[i]
		switch {
		case inDollar && c == '\\' && i+1 < len(s):
			i++
			esc := s[i]
			switch esc {
			case 'n':
				cur.WriteByte('\n')
			case 't':
				cur.WriteByte('\t')
			case 'r':
				cur.WriteByte('\r')
			default:
				cur.WriteByte(esc)
			}
			hasTok = true
		case inDollar:
			if c == '\'' {
				inDollar = false
			} else {
				cur.WriteByte(c)
				hasTok = true
			}
		case inSingle:
			if c == '\'' {
				inSingle = false
			} else {
				cur.WriteByte(c)
				hasTok = true
			}
		case inDouble:
			if c == '"' {
				inDouble = false
			} else {
				cur.WriteByte(c)
				hasTok = true
			}
		case c == '$' && i+1 < len(s) && s[i+1] == '\'':
			inDollar = true
			i++ // skip $
		case c == '\'':
			inSingle = true
		case c == '"':
			inDouble = true
		case c == ' ' || c == '\t' || c == '\n':
			flush()
		default:
			cur.WriteByte(c)
			hasTok = true
		}
	}
	flush()
	return out, nil
}

var curlLine = regexp.MustCompile(`(?m)^\s*curl\s`)

// CURLFromText finds the first curl command in pasted text.
func CURLFromText(text string) (string, error) {
	if curlLine.MatchString(text) || strings.HasPrefix(strings.TrimSpace(text), "curl") {
		return ParseCURL(text)
	}
	return "", fmt.Errorf("no curl command found in input")
}

// --- OpenAPI ---

// ImportEndpoint is a normalized imported endpoint (also used by sitemap
// import and the Postman parser).
type ImportEndpoint struct {
	Scheme string `json:"scheme"`
	Host   string `json:"host"`
	Port   int    `json:"port"`
	Method string `json:"method"`
	Path   string `json:"path"`
}

// ParseOpenAPI extracts endpoints from an OpenAPI/Swagger document (JSON or
// YAML). The base URL comes from servers[]; paths+operations become
// endpoints. A relative server yields https://spec-host.
func ParseOpenAPI(doc string) ([]ImportEndpoint, error) {
	m, err := decodeAny(doc)
	if err != nil {
		return nil, fmt.Errorf("openapi: %w", err)
	}
	root, ok := m.(map[string]any)
	if !ok {
		return nil, fmt.Errorf("openapi: document is not an object")
	}
	if _, ok := root["paths"]; !ok {
		return nil, fmt.Errorf("openapi: no 'paths' object")
	}
	base := "https://spec-host"
	if servers, ok := root["servers"].([]any); ok && len(servers) > 0 {
		if s, ok := servers[0].(map[string]any); ok {
			if u, ok := s["url"].(string); ok && u != "" {
				if strings.HasPrefix(u, "/") {
					// relative server: keep the placeholder host
				} else {
					base = strings.TrimSuffix(u, "/")
				}
			}
		}
	}
	bu, err := url.Parse(base)
	if err != nil {
		return nil, fmt.Errorf("openapi: bad server url")
	}
	scheme := bu.Scheme
	if scheme == "" {
		scheme = "https"
	}
	port := 0
	if p := bu.Port(); p != "" {
		port, _ = strconv.Atoi(p)
	}
	if port == 0 {
		if scheme == "https" {
			port = 443
		} else {
			port = 80
		}
	}

	out := []ImportEndpoint{}
	paths, _ := root["paths"].(map[string]any)
	for p, item := range paths {
		ops, ok := item.(map[string]any)
		if !ok {
			continue
		}
		for method, op := range ops {
			mu := strings.ToUpper(method)
			switch mu {
			case "GET", "POST", "PUT", "PATCH", "DELETE", "HEAD", "OPTIONS":
			default:
				continue
			}
			_ = op
			out = append(out, ImportEndpoint{
				Scheme: scheme, Host: bu.Hostname(), Port: port,
				Method: mu, Path: p,
			})
		}
	}
	if len(out) == 0 {
		return nil, fmt.Errorf("openapi: no operations found")
	}
	return out, nil
}

// --- Postman ---

// ParsePostman extracts endpoints from a Postman collection (v2.x).
// Variables in {{base_url}} form are resolved from collection variables
// when present.
func ParsePostman(doc string) ([]ImportEndpoint, error) {
	m, err := decodeAny(doc)
	if err != nil {
		return nil, fmt.Errorf("postman: %w", err)
	}
	root, ok := m.(map[string]any)
	if !ok {
		return nil, fmt.Errorf("postman: document is not an object")
	}
	vars := map[string]string{}
	if raw, ok := root["variable"].([]any); ok {
		for _, v := range raw {
			if vm, ok := v.(map[string]any); ok {
				if k, ok := vm["key"].(string); ok {
					if val, ok := vm["value"].(string); ok {
						vars[k] = val
					}
				}
			}
		}
	}
	out := []ImportEndpoint{}
	var walk func(items any)
	walk = func(items any) {
		list, ok := items.([]any)
		if !ok {
			return
		}
		for _, it := range list {
			im, ok := it.(map[string]any)
			if !ok {
				continue
			}
			if sub, ok := im["item"]; ok {
				walk(sub) // folder
				continue
			}
			req, ok := im["request"].(map[string]any)
			if !ok {
				continue
			}
			method, _ := req["method"].(string)
			if method == "" {
				method = "GET"
			}
			rawURL := ""
			switch u := req["url"].(type) {
			case string:
				rawURL = u
			case map[string]any:
				rawURL, _ = u["raw"].(string)
			}
			rawURL = resolveVars(rawURL, vars)
			if rawURL == "" {
				continue
			}
			u, err := url.Parse(rawURL)
			if err != nil || u.Host == "" {
				continue
			}
			port := 0
			if p := u.Port(); p != "" {
				port, _ = strconv.Atoi(p)
			}
			if port == 0 {
				if u.Scheme == "https" {
					port = 443
				} else {
					port = 80
				}
			}
			path := u.RequestURI()
			if path == "" {
				path = "/"
			}
			out = append(out, ImportEndpoint{
				Scheme: orDefaultStr(u.Scheme, "https"), Host: u.Hostname(),
				Port: port, Method: strings.ToUpper(method), Path: path,
			})
		}
	}
	walk(root["item"])
	if len(out) == 0 {
		return nil, fmt.Errorf("postman: no requests found")
	}
	return out, nil
}

func resolveVars(s string, vars map[string]string) string {
	for k, v := range vars {
		s = strings.ReplaceAll(s, "{{"+k+"}}", v)
	}
	return s
}

func orDefaultStr(s, def string) string {
	if s == "" {
		return def
	}
	return s
}
