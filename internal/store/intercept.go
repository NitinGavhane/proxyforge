package store

import (
	"context"
	"database/sql"
	"errors"
	"time"
)

// Intercept settings live in the meta table.
const (
	metaInterceptEnabled   = "intercept_enabled"
	metaInterceptResponses = "intercept_responses"
)

// InterceptSettings returns the persisted master toggles.
func (s *Store) InterceptSettings(ctx context.Context) (enabled, responses bool, err error) {
	get := func(key string) (bool, error) {
		var v string
		err := s.db.QueryRowContext(ctx, `SELECT value FROM meta WHERE key=?`, key).Scan(&v)
		if errors.Is(err, sql.ErrNoRows) {
			return false, nil
		}
		if err != nil {
			return false, err
		}
		return v == "1", nil
	}
	if enabled, err = get(metaInterceptEnabled); err != nil {
		return
	}
	responses, err = get(metaInterceptResponses)
	return
}

// SaveInterceptSettings persists the master toggles.
func (s *Store) SaveInterceptSettings(ctx context.Context, enabled, responses bool) error {
	set := func(key string, v bool) error {
		val := "0"
		if v {
			val = "1"
		}
		_, err := s.db.ExecContext(ctx,
			`INSERT INTO meta(key, value) VALUES(?, ?)
			 ON CONFLICT(key) DO UPDATE SET value=excluded.value`, key, val)
		return err
	}
	if err := set(metaInterceptEnabled, enabled); err != nil {
		return err
	}
	return set(metaInterceptResponses, responses)
}

// RuleRow is a stored intercept rule (spec is JSON, interpreted by the
// intercept package).
type RuleRow struct {
	ID      int64  `json:"id"`
	Name    string `json:"name"`
	Enabled bool   `json:"enabled"`
	Spec    string `json:"spec"`
}

// ListInterceptRules returns all rules.
func (s *Store) ListInterceptRules(ctx context.Context) ([]RuleRow, error) {
	rows, err := s.db.QueryContext(ctx, `SELECT id, name, enabled, spec FROM intercept_rules ORDER BY id`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	out := []RuleRow{}
	for rows.Next() {
		var r RuleRow
		var en int
		if err := rows.Scan(&r.ID, &r.Name, &en, &r.Spec); err != nil {
			return nil, err
		}
		r.Enabled = en == 1
		out = append(out, r)
	}
	return out, rows.Err()
}

// InsertInterceptRule stores a rule and returns its id.
func (s *Store) InsertInterceptRule(ctx context.Context, name string, enabled bool, spec string) (int64, error) {
	en := 0
	if enabled {
		en = 1
	}
	res, err := s.db.ExecContext(ctx,
		`INSERT INTO intercept_rules(name, enabled, spec) VALUES(?,?,?)`, name, en, spec)
	if err != nil {
		return 0, err
	}
	return res.LastInsertId()
}

// UpdateInterceptRule replaces a rule's fields.
func (s *Store) UpdateInterceptRule(ctx context.Context, id int64, name string, enabled bool, spec string) error {
	en := 0
	if enabled {
		en = 1
	}
	res, err := s.db.ExecContext(ctx,
		`UPDATE intercept_rules SET name=?, enabled=?, spec=? WHERE id=?`, name, en, spec, id)
	if err != nil {
		return err
	}
	n, _ := res.RowsAffected()
	if n == 0 {
		return errors.New("rule not found")
	}
	return nil
}

// DeleteInterceptRule removes a rule.
func (s *Store) DeleteInterceptRule(ctx context.Context, id int64) error {
	_, err := s.db.ExecContext(ctx, `DELETE FROM intercept_rules WHERE id=?`, id)
	return err
}

// Queue states.
const (
	QueuePendingReq  = "pending_req"
	QueuePendingResp = "pending_resp"
	QueueForwarded   = "forwarded"
	QueueCompleted   = "completed"
	QueueDropped     = "dropped"
	QueueRestarted   = "restarted"
)

// QueueRow is one intercept queue entry.
type QueueRow struct {
	ID         int64  `json:"id"`
	TS         int64  `json:"ts"`
	State      string `json:"state"`
	IsResponse bool   `json:"is_response"`
	Snapshot   string `json:"-"`
}

// InsertQueueItem parks an item.
func (s *Store) InsertQueueItem(ctx context.Context, isResponse bool, snapshot string) (int64, error) {
	ir := 0
	if isResponse {
		ir = 1
	}
	state := QueuePendingReq
	if isResponse {
		state = QueuePendingResp
	}
	res, err := s.db.ExecContext(ctx,
		`INSERT INTO intercept_queue(ts, state, is_response, snapshot) VALUES(?,?,?,?)`,
		time.Now().UnixMilli(), state, ir, snapshot)
	if err != nil {
		return 0, err
	}
	return res.LastInsertId()
}

// UpdateQueueState transitions an item.
func (s *Store) UpdateQueueState(ctx context.Context, id int64, state string) error {
	_, err := s.db.ExecContext(ctx, `UPDATE intercept_queue SET state=? WHERE id=?`, state, id)
	return err
}

// ListQueue returns queue rows for the given states (empty = all).
func (s *Store) ListQueue(ctx context.Context, states []string) ([]QueueRow, error) {
	q := `SELECT id, ts, state, is_response, snapshot FROM intercept_queue`
	args := []any{}
	if len(states) > 0 {
		ph := ""
		for i, st := range states {
			if i > 0 {
				ph += ","
			}
			ph += "?"
			args = append(args, st)
		}
		q += ` WHERE state IN (` + ph + `)`
	}
	q += ` ORDER BY id`
	rows, err := s.db.QueryContext(ctx, q, args...)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	out := []QueueRow{}
	for rows.Next() {
		var r QueueRow
		var ir int
		if err := rows.Scan(&r.ID, &r.TS, &r.State, &ir, &r.Snapshot); err != nil {
			return nil, err
		}
		r.IsResponse = ir == 1
		out = append(out, r)
	}
	return out, rows.Err()
}

// PendingQueue returns snapshots of items still parked (restart recovery).
func (s *Store) PendingQueue(ctx context.Context) ([]QueueRow, error) {
	return s.ListQueue(ctx, []string{QueuePendingReq, QueuePendingResp})
}
