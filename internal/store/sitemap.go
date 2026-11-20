package store

import (
	"context"
	"fmt"
	"strings"
	"time"

	"github.com/NitinGavhane/proxyforge/internal/flows"
)

// ErrTabNotFound marks a missing repeater tab.
func ErrTabNotFound(id int64) error { return fmt.Errorf("repeater tab %d: not found", id) }

// Endpoint is one node of the site map.
type Endpoint struct {
	ID        int64  `json:"id"`
	Source    string `json:"source"` // capture | import | discovery
	Scheme    string `json:"scheme"`
	Host      string `json:"host"`
	Port      int    `json:"port"`
	Method    string `json:"method"`
	Path      string `json:"path"`
	Status    int    `json:"status,omitempty"`
	Count     int64  `json:"count"`
	FirstSeen int64  `json:"first_seen"`
	LastSeen  int64  `json:"last_seen"`
}

// UpsertEndpointFromFlow aggregates a captured flow into the site map
// (tunnels excluded). Query strings are stripped: the tree maps paths.
func (s *Store) UpsertEndpointFromFlow(ctx context.Context, f *flows.Flow) error {
	if f == nil || f.Request == nil || f.Tunnel {
		return nil
	}
	req := f.Request
	path := req.Path
	if i := strings.IndexByte(path, '?'); i >= 0 {
		path = path[:i]
	}
	scheme := req.Scheme
	if scheme == "" {
		scheme = "http"
	}
	status := 0
	if f.Response != nil {
		status = f.Response.Status
	}
	now := time.Now().UnixMilli()
	_, err := s.db.ExecContext(ctx, `INSERT INTO endpoints
		(source, scheme, host, port, method, path, status, count, first_seen, last_seen)
		VALUES('capture', ?, ?, ?, ?, ?, ?, 1, ?, ?)
		ON CONFLICT(scheme, host, port, method, path) DO UPDATE SET
		  count = count + 1,
		  last_seen = excluded.last_seen,
		  status = CASE WHEN excluded.status != 0 THEN excluded.status ELSE endpoints.status END`,
		scheme, req.Host, req.Port, req.Method, path, status, now, now)
	return err
}

// InsertEndpoint adds an import/discovery endpoint (no count aggregation).
func (s *Store) InsertEndpoint(ctx context.Context, ep Endpoint) error {
	now := time.Now().UnixMilli()
	if ep.FirstSeen == 0 {
		ep.FirstSeen = now
	}
	if ep.LastSeen == 0 {
		ep.LastSeen = now
	}
	_, err := s.db.ExecContext(ctx, `INSERT INTO endpoints
		(source, scheme, host, port, method, path, status, count, first_seen, last_seen)
		VALUES(?,?,?,?,?,?,?,?,?,?)
		ON CONFLICT(scheme, host, port, method, path) DO UPDATE SET
		  last_seen = excluded.last_seen,
		  status = CASE WHEN excluded.status != 0 THEN excluded.status ELSE endpoints.status END`,
		ep.Source, ep.Scheme, ep.Host, ep.Port, ep.Method, ep.Path, ep.Status, 1, ep.FirstSeen, ep.LastSeen)
	return err
}

// ListEndpoints returns the whole site map ordered for tree building.
func (s *Store) ListEndpoints(ctx context.Context) ([]Endpoint, error) {
	rows, err := s.db.QueryContext(ctx, `SELECT id, source, scheme, host, port,
		method, path, COALESCE(status,0), count, first_seen, last_seen
		FROM endpoints ORDER BY host, port, path, method`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	out := []Endpoint{}
	for rows.Next() {
		var e Endpoint
		if err := rows.Scan(&e.ID, &e.Source, &e.Scheme, &e.Host, &e.Port,
			&e.Method, &e.Path, &e.Status, &e.Count, &e.FirstSeen, &e.LastSeen); err != nil {
			return nil, err
		}
		out = append(out, e)
	}
	return out, rows.Err()
}

// --- repeater tabs ---

// RepeaterTab is a stored raw request template.
type RepeaterTab struct {
	ID      int64  `json:"id"`
	Name    string `json:"name"`
	Raw     string `json:"raw"`
	Created int64  `json:"created"`
	Updated int64  `json:"updated"`
}

// InsertRepeaterTab creates a tab.
func (s *Store) InsertRepeaterTab(ctx context.Context, name, raw string) (int64, error) {
	now := time.Now().UnixMilli()
	res, err := s.db.ExecContext(ctx,
		`INSERT INTO repeater_tabs(name, raw, created, updated) VALUES(?,?,?,?)`,
		name, raw, now, now)
	if err != nil {
		return 0, err
	}
	return res.LastInsertId()
}

// UpdateRepeaterTab saves raw/name edits.
func (s *Store) UpdateRepeaterTab(ctx context.Context, id int64, name, raw string) error {
	res, err := s.db.ExecContext(ctx,
		`UPDATE repeater_tabs SET name=?, raw=?, updated=? WHERE id=?`,
		name, raw, time.Now().UnixMilli(), id)
	if err != nil {
		return err
	}
	n, _ := res.RowsAffected()
	if n == 0 {
		return ErrTabNotFound(id)
	}
	return nil
}

// DeleteRepeaterTab removes a tab.
func (s *Store) DeleteRepeaterTab(ctx context.Context, id int64) error {
	_, err := s.db.ExecContext(ctx, `DELETE FROM repeater_tabs WHERE id=?`, id)
	return err
}

// ListRepeaterTabs returns all tabs.
func (s *Store) ListRepeaterTabs(ctx context.Context) ([]RepeaterTab, error) {
	rows, err := s.db.QueryContext(ctx,
		`SELECT id, name, raw, created, updated FROM repeater_tabs ORDER BY id`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	out := []RepeaterTab{}
	for rows.Next() {
		var t RepeaterTab
		if err := rows.Scan(&t.ID, &t.Name, &t.Raw, &t.Created, &t.Updated); err != nil {
			return nil, err
		}
		out = append(out, t)
	}
	return out, rows.Err()
}
