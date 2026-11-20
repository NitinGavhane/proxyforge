package store

import (
	"context"
	"errors"
)

// ScopeRuleRow is a stored scope rule.
type ScopeRuleRow struct {
	ID      int64  `json:"id"`
	Kind    string `json:"kind"` // include | exclude
	Pattern string `json:"pattern"`
	Enabled bool   `json:"enabled"`
}

// ListScopeRules returns all scope rules.
func (s *Store) ListScopeRules(ctx context.Context) ([]ScopeRuleRow, error) {
	rows, err := s.db.QueryContext(ctx, `SELECT id, kind, pattern, enabled FROM scope_rules ORDER BY id`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	out := []ScopeRuleRow{}
	for rows.Next() {
		var r ScopeRuleRow
		var en int
		if err := rows.Scan(&r.ID, &r.Kind, &r.Pattern, &en); err != nil {
			return nil, err
		}
		r.Enabled = en == 1
		out = append(out, r)
	}
	return out, rows.Err()
}

// InsertScopeRule stores a rule and returns its id.
func (s *Store) InsertScopeRule(ctx context.Context, kind, pattern string, enabled bool) (int64, error) {
	en := 0
	if enabled {
		en = 1
	}
	res, err := s.db.ExecContext(ctx,
		`INSERT INTO scope_rules(kind, pattern, enabled) VALUES(?,?,?)`, kind, pattern, en)
	if err != nil {
		return 0, err
	}
	return res.LastInsertId()
}

// SetScopeEnabled toggles a rule.
func (s *Store) SetScopeEnabled(ctx context.Context, id int64, enabled bool) error {
	en := 0
	if enabled {
		en = 1
	}
	res, err := s.db.ExecContext(ctx, `UPDATE scope_rules SET enabled=? WHERE id=?`, en, id)
	if err != nil {
		return err
	}
	n, _ := res.RowsAffected()
	if n == 0 {
		return errors.New("scope rule not found")
	}
	return nil
}

// DeleteScopeRule removes a rule.
func (s *Store) DeleteScopeRule(ctx context.Context, id int64) error {
	_, err := s.db.ExecContext(ctx, `DELETE FROM scope_rules WHERE id=?`, id)
	return err
}
