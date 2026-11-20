package store

import (
	"context"
	"time"
)

// Interaction is one collaborator callback.
type Interaction struct {
	ID     int64  `json:"id"`
	TS     int64  `json:"ts"`
	Canary string `json:"canary"`
	Label  string `json:"label"`
	Proto  string `json:"proto"`
	Src    string `json:"src"`
	Method string `json:"method,omitempty"`
	Host   string `json:"host,omitempty"`
	Path   string `json:"path,omitempty"`
	Detail string `json:"detail,omitempty"`
}

// InsertCanary records an issued canary.
func (s *Store) InsertCanary(ctx context.Context, canary, label string) error {
	_, err := s.db.ExecContext(ctx,
		`INSERT INTO collab_canaries(canary, label, created) VALUES(?,?,?)
		 ON CONFLICT(canary) DO UPDATE SET label=excluded.label`,
		canary, label, time.Now().UnixMilli())
	return err
}

// InsertInteraction records a callback.
func (s *Store) InsertInteraction(ctx context.Context, in *Interaction) error {
	if in.TS == 0 {
		in.TS = time.Now().UnixMilli()
	}
	res, err := s.db.ExecContext(ctx, `INSERT INTO collab_interactions
		(ts, canary, label, proto, src, method, host, path, detail)
		VALUES(?,?,?,?,?,?,?,?,?)`,
		in.TS, in.Canary, in.Label, in.Proto, in.Src, in.Method, in.Host, in.Path, in.Detail)
	if err != nil {
		return err
	}
	in.ID, _ = res.LastInsertId()
	return nil
}

// ListInteractions returns callbacks newest first, filtered by canary when
// non-empty.
func (s *Store) ListInteractions(ctx context.Context, canary string) ([]Interaction, error) {
	q := `SELECT id, ts, canary, label, proto, src, method, host, path, detail
		FROM collab_interactions`
	args := []any{}
	if canary != "" {
		q += ` WHERE canary = ?`
		args = append(args, canary)
	}
	q += ` ORDER BY id DESC LIMIT 500`
	rows, err := s.db.QueryContext(ctx, q, args...)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	out := []Interaction{}
	for rows.Next() {
		var i Interaction
		if err := rows.Scan(&i.ID, &i.TS, &i.Canary, &i.Label, &i.Proto,
			&i.Src, &i.Method, &i.Host, &i.Path, &i.Detail); err != nil {
			return nil, err
		}
		out = append(out, i)
	}
	return out, rows.Err()
}
