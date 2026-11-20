// Package ui embeds the built React app (ui/dist) into the binary.
//
// dist/ is gitignored; release and CI builds run `npm run build` in ui/ first.
// When dist/ is absent, the committed placeholder page is served instead.
package ui

import (
	"embed"
	"io/fs"
	"net/http"
	"strings"
)

//go:embed all:dist placeholder/index.html
var files embed.FS

// Dist returns the embedded dist filesystem (may be empty).
func Dist() (fs.FS, error) {
	sub, err := fs.Sub(files, "dist")
	if err != nil {
		return nil, err
	}
	return sub, nil
}

// IsBuilt reports whether the real app (not the placeholder) is embedded.
func IsBuilt() bool {
	_, err := fs.Stat(files, "dist/index.html")
	return err == nil
}

// Handler serves the embedded UI with SPA fallback to index.html.
func Handler() http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if !IsBuilt() {
			b, _ := fs.ReadFile(files, "placeholder/index.html")
			w.Header().Set("Content-Type", "text/html; charset=utf-8")
			_, _ = w.Write(b)
			return
		}
		sub, err := Dist()
		if err != nil {
			http.NotFound(w, r)
			return
		}
		p := strings.TrimPrefix(r.URL.Path, "/")
		if p == "" {
			p = "index.html"
		}
		if _, err := fs.Stat(sub, p); err != nil {
			// SPA fallback: unknown paths render the app
			r2 := new(http.Request)
			*r2 = *r
			r2.URL.Path = "/"
			http.FileServer(http.FS(sub)).ServeHTTP(w, r2)
			return
		}
		http.FileServer(http.FS(sub)).ServeHTTP(w, r)
	})
}
