package store

import (
	"context"
	"strings"
	"time"

	"github.com/NitinGavhane/proxyforge/internal/flows"
)

// Cookie is one jar entry.
type Cookie struct {
	ID       int64  `json:"id"`
	Host     string `json:"host"`
	Port     int    `json:"port"`
	Name     string `json:"name"`
	Value    string `json:"value"`
	Path     string `json:"path"`
	Secure   bool   `json:"secure"`
	HTTPOnly bool   `json:"httponly"`
	SameSite string `json:"samesite"`
	Updated  int64  `json:"updated"`
}

// CaptureCookies parses Set-Cookie headers from a captured flow into the
// jar (upsert per host+name+path). Deletion cookies (empty value) remove
// the entry.
func (s *Store) CaptureCookies(ctx context.Context, f *flows.Flow) error {
	if f == nil || f.Request == nil || f.Response == nil {
		return nil
	}
	host, port := f.Request.Host, f.Request.Port
	for _, h := range f.Response.Headers {
		if !strings.EqualFold(h.Key, "Set-Cookie") {
			continue
		}
		c, ok := parseSetCookie(h.Value)
		if !ok {
			continue
		}
		if c.Value == "" {
			_, err := s.db.ExecContext(ctx,
				`DELETE FROM cookies WHERE host=? AND port=? AND name=? AND path=?`,
				host, port, c.Name, c.Path)
			if err != nil {
				return err
			}
			continue
		}
		_, err := s.db.ExecContext(ctx, `INSERT INTO cookies
			(host, port, name, value, path, secure, httponly, samesite, updated)
			VALUES(?,?,?,?,?,?,?,?,?)
			ON CONFLICT(host, port, name, path) DO UPDATE SET
			  value=excluded.value, secure=excluded.secure,
			  httponly=excluded.httponly, samesite=excluded.samesite,
			  updated=excluded.updated`,
			host, port, c.Name, c.Value, c.Path, c.Secure, c.HTTPOnly, c.SameSite,
			time.Now().UnixMilli())
		if err != nil {
			return err
		}
	}
	return nil
}

type rawCookie struct {
	Name, Value, Path, SameSite string
	Secure, HTTPOnly            bool
}

func parseSetCookie(v string) (rawCookie, bool) {
	parts := strings.Split(v, ";")
	kv := strings.SplitN(parts[0], "=", 2)
	if len(kv) != 2 || strings.TrimSpace(kv[0]) == "" {
		return rawCookie{}, false
	}
	c := rawCookie{Name: strings.TrimSpace(kv[0]), Value: strings.TrimSpace(kv[1]), Path: "/"}
	for _, p := range parts[1:] {
		p = strings.TrimSpace(p)
		lower := strings.ToLower(p)
		switch {
		case lower == "secure":
			c.Secure = true
		case lower == "httponly":
			c.HTTPOnly = true
		case strings.HasPrefix(lower, "path="):
			c.Path = strings.TrimPrefix(p[5:], " ")
		case strings.HasPrefix(lower, "samesite="):
			c.SameSite = strings.ToLower(strings.TrimSpace(p[9:]))
		}
	}
	return c, true
}

// JarCookies returns the jar for a host (exact host[:port]).
func (s *Store) JarCookies(ctx context.Context, host string, port int) ([]Cookie, error) {
	rows, err := s.db.QueryContext(ctx, `SELECT id, host, port, name, value,
		path, secure, httponly, samesite, updated FROM cookies
		WHERE host=? AND port=? ORDER BY name`, host, port)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	out := []Cookie{}
	for rows.Next() {
		var c Cookie
		var sec, http int
		if err := rows.Scan(&c.ID, &c.Host, &c.Port, &c.Name, &c.Value,
			&c.Path, &sec, &http, &c.SameSite, &c.Updated); err != nil {
			return nil, err
		}
		c.Secure, c.HTTPOnly = sec == 1, http == 1
		out = append(out, c)
	}
	return out, rows.Err()
}

// CookieHeader renders the jar as a Cookie header value.
func CookieHeader(cs []Cookie) string {
	var sb strings.Builder
	for i, c := range cs {
		if i > 0 {
			sb.WriteString("; ")
		}
		sb.WriteString(c.Name)
		sb.WriteString("=")
		sb.WriteString(c.Value)
	}
	return sb.String()
}

// --- macros ---

// Macro references a captured flow to replay (e.g. a login).
type Macro struct {
	ID      int64  `json:"id"`
	Name    string `json:"name"`
	FlowID  int64  `json:"flow_id"`
	Created int64  `json:"created"`
}

// InsertMacro stores a macro.
func (s *Store) InsertMacro(ctx context.Context, name string, flowID int64) (int64, error) {
	res, err := s.db.ExecContext(ctx,
		`INSERT INTO macros(name, flow_id, created) VALUES(?,?,?)`,
		name, flowID, time.Now().UnixMilli())
	if err != nil {
		return 0, err
	}
	return res.LastInsertId()
}

// ListMacros returns stored macros.
func (s *Store) ListMacros(ctx context.Context) ([]Macro, error) {
	rows, err := s.db.QueryContext(ctx,
		`SELECT id, name, flow_id, created FROM macros ORDER BY id`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	out := []Macro{}
	for rows.Next() {
		var m Macro
		if err := rows.Scan(&m.ID, &m.Name, &m.FlowID, &m.Created); err != nil {
			return nil, err
		}
		out = append(out, m)
	}
	return out, rows.Err()
}

// DeleteMacro removes a macro.
func (s *Store) DeleteMacro(ctx context.Context, id int64) error {
	_, err := s.db.ExecContext(ctx, `DELETE FROM macros WHERE id=?`, id)
	return err
}

// --- organizer ---

// OrganizerItem is a saved flow with annotations.
type OrganizerItem struct {
	ID      int64  `json:"id"`
	FlowID  int64  `json:"flow_id"`
	Note    string `json:"note"`
	Tags    string `json:"tags"`
	Created int64  `json:"created"`
}

// SaveOrganizerItem bookmarks a flow (idempotent per flow).
func (s *Store) SaveOrganizerItem(ctx context.Context, flowID int64, note, tags string) (int64, error) {
	res, err := s.db.ExecContext(ctx, `INSERT INTO organizer_items(flow_id, note, tags, created)
		VALUES(?,?,?,?)
		ON CONFLICT(flow_id) DO UPDATE SET note=excluded.note, tags=excluded.tags`,
		flowID, note, tags, time.Now().UnixMilli())
	if err != nil {
		return 0, err
	}
	return res.LastInsertId()
}

// ListOrganizer returns saved items newest first.
func (s *Store) ListOrganizer(ctx context.Context) ([]OrganizerItem, error) {
	rows, err := s.db.QueryContext(ctx,
		`SELECT id, flow_id, note, tags, created FROM organizer_items ORDER BY id DESC`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	out := []OrganizerItem{}
	for rows.Next() {
		var o OrganizerItem
		if err := rows.Scan(&o.ID, &o.FlowID, &o.Note, &o.Tags, &o.Created); err != nil {
			return nil, err
		}
		out = append(out, o)
	}
	return out, rows.Err()
}

// DeleteOrganizerItem removes a bookmark.
func (s *Store) DeleteOrganizerItem(ctx context.Context, id int64) error {
	_, err := s.db.ExecContext(ctx, `DELETE FROM organizer_items WHERE id=?`, id)
	return err
}
