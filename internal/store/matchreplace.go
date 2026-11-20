package store

import (
	"context"
	"errors"
)

// MRRuleRow is a stored match & replace rule.
type MRRuleRow struct {
	ID        int64  `json:"id"`
	Name      string `json:"name"`
	Enabled   bool   `json:"enabled"`
	Direction string `json:"direction"` // request | response
	Spec      string `json:"-"`         // JSON predicate
	Action    string `json:"-"`         // JSON action
	Hits      int64  `json:"hits"`
}

// ListMRRules returns all match & replace rules in stable id order.
func (s *Store) ListMRRules(ctx context.Context) ([]MRRuleRow, error) {
	rows, err := s.db.QueryContext(ctx,
		`SELECT id, name, enabled, direction, spec, action, hits FROM match_replace_rules ORDER BY id`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	out := []MRRuleRow{}
	for rows.Next() {
		var r MRRuleRow
		var en int
		if err := rows.Scan(&r.ID, &r.Name, &en, &r.Direction, &r.Spec, &r.Action, &r.Hits); err != nil {
			return nil, err
		}
		r.Enabled = en == 1
		out = append(out, r)
	}
	return out, rows.Err()
}

// InsertMRRule stores a rule and returns its id.
func (s *Store) InsertMRRule(ctx context.Context, name string, enabled bool, direction, spec, action string) (int64, error) {
	en := 0
	if enabled {
		en = 1
	}
	res, err := s.db.ExecContext(ctx,
		`INSERT INTO match_replace_rules(name, enabled, direction, spec, action) VALUES(?,?,?,?,?)`,
		name, en, direction, spec, action)
	if err != nil {
		return 0, err
	}
	return res.LastInsertId()
}

// SetMREnabled toggles a rule.
func (s *Store) SetMREnabled(ctx context.Context, id int64, enabled bool) error {
	en := 0
	if enabled {
		en = 1
	}
	res, err := s.db.ExecContext(ctx, `UPDATE match_replace_rules SET enabled=? WHERE id=?`, en, id)
	if err != nil {
		return err
	}
	n, _ := res.RowsAffected()
	if n == 0 {
		return errors.New("match & replace rule not found")
	}
	return nil
}

// DeleteMRRule removes a rule.
func (s *Store) DeleteMRRule(ctx context.Context, id int64) error {
	_, err := s.db.ExecContext(ctx, `DELETE FROM match_replace_rules WHERE id=?`, id)
	return err
}

// BumpMRHits increments a rule's hit counter.
func (s *Store) BumpMRHits(ctx context.Context, id int64) {
	_, _ = s.db.ExecContext(ctx, `UPDATE match_replace_rules SET hits = hits + 1 WHERE id=?`, id)
}
