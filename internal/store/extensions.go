package store

import (
	"context"
	"errors"
	"time"
)

// Extension is a stored JS script with runtime stats.
type Extension struct {
	ID        int64  `json:"id"`
	Name      string `json:"name"`
	Enabled   bool   `json:"enabled"`
	Code      string `json:"code"`
	Runs      int64  `json:"runs"`
	Errors    int64  `json:"errors"`
	LastError string `json:"last_error,omitempty"`
	Created   int64  `json:"created"`
	Updated   int64  `json:"updated"`
}

// InsertExtension stores a script.
func (s *Store) InsertExtension(ctx context.Context, name, code string, enabled bool) (int64, error) {
	now := time.Now().UnixMilli()
	en := 0
	if enabled {
		en = 1
	}
	res, err := s.db.ExecContext(ctx,
		`INSERT INTO extensions(name, enabled, code, created, updated) VALUES(?,?,?,?,?)`,
		name, en, code, now, now)
	if err != nil {
		return 0, err
	}
	return res.LastInsertId()
}

// UpdateExtension replaces code/name/enabled.
func (s *Store) UpdateExtension(ctx context.Context, id int64, name *string, code *string, enabled *bool) error {
	set := []string{"updated=?"}
	args := []any{time.Now().UnixMilli()}
	if name != nil {
		set = append(set, "name=?")
		args = append(args, *name)
	}
	if code != nil {
		set = append(set, "code=?")
		args = append(args, *code)
		// fresh code resets stats
		set = append(set, "runs=0", "errors=0", "last_error=''")
	}
	if enabled != nil {
		set = append(set, "enabled=?")
		if *enabled {
			args = append(args, 1)
		} else {
			args = append(args, 0)
		}
	}
	args = append(args, id)
	res, err := s.db.ExecContext(ctx,
		`UPDATE extensions SET `+joinSet(set)+` WHERE id=?`, args...)
	if err != nil {
		return err
	}
	n, _ := res.RowsAffected()
	if n == 0 {
		return errors.New("extension not found")
	}
	return nil
}

func joinSet(parts []string) string {
	out := ""
	for i, p := range parts {
		if i > 0 {
			out += ", "
		}
		out += p
	}
	return out
}

// DeleteExtension removes a script.
func (s *Store) DeleteExtension(ctx context.Context, id int64) error {
	_, err := s.db.ExecContext(ctx, `DELETE FROM extensions WHERE id=?`, id)
	return err
}

// ListExtensions returns scripts in stable order.
func (s *Store) ListExtensions(ctx context.Context) ([]Extension, error) {
	rows, err := s.db.QueryContext(ctx, `SELECT id, name, enabled, code, runs,
		errors, last_error, created, updated FROM extensions ORDER BY id`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	out := []Extension{}
	for rows.Next() {
		var e Extension
		var en int
		if err := rows.Scan(&e.ID, &e.Name, &en, &e.Code, &e.Runs, &e.Errors,
			&e.LastError, &e.Created, &e.Updated); err != nil {
			return nil, err
		}
		e.Enabled = en == 1
		out = append(out, e)
	}
	return out, rows.Err()
}

// RecordExtensionRun bumps stats.
func (s *Store) RecordExtensionRun(ctx context.Context, id int64, runErr string) {
	if runErr == "" {
		_, _ = s.db.ExecContext(ctx,
			`UPDATE extensions SET runs = runs + 1 WHERE id=?`, id)
		return
	}
	_, _ = s.db.ExecContext(ctx,
		`UPDATE extensions SET runs = runs + 1, errors = errors + 1, last_error=? WHERE id=?`,
		runErr, id)
}
