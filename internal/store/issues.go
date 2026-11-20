package store

import (
	"context"
	"strings"
	"time"
)

// Issue is one scanner finding.
type Issue struct {
	ID             int64  `json:"id"`
	CheckID        string `json:"check_id"`
	Title          string `json:"title"`
	Severity       string `json:"severity"`   // info | low | medium | high | critical
	Confidence     string `json:"confidence"` // certain | firm | tentative
	Host           string `json:"host"`
	Port           int    `json:"port"`
	Path           string `json:"path"`
	Detail         string `json:"detail"`
	EvidenceFlowID int64  `json:"evidence_flow_id,omitempty"`
	ScanID         int64  `json:"scan_id"`
	Created        int64  `json:"created"`
}

// InsertIssue records a finding (dedup per check+target+scan).
func (s *Store) InsertIssue(ctx context.Context, iss *Issue) error {
	if iss.Created == 0 {
		iss.Created = time.Now().UnixMilli()
	}
	res, err := s.db.ExecContext(ctx, `INSERT INTO issues
		(check_id, title, severity, confidence, host, port, path, detail, evidence_flow_id, scan_id, created)
		VALUES(?,?,?,?,?,?,?,?,?,?,?)
		ON CONFLICT(check_id, host, port, path, scan_id) DO UPDATE SET
		  detail = excluded.detail,
		  evidence_flow_id = excluded.evidence_flow_id,
		  severity = excluded.severity`,
		iss.CheckID, iss.Title, iss.Severity, iss.Confidence,
		iss.Host, iss.Port, iss.Path, iss.Detail, nullInt64(iss.EvidenceFlowID), iss.ScanID, iss.Created)
	if err != nil {
		return err
	}
	iss.ID, _ = res.LastInsertId()
	return nil
}

func nullInt64(v int64) any {
	if v == 0 {
		return nil
	}
	return v
}

// IssueFilter selects issues.
type IssueFilter struct {
	Host     string
	Severity string // exact or class (4xx-style not used here)
	Limit    int
}

// ListIssues returns findings newest first.
func (s *Store) ListIssues(ctx context.Context, f IssueFilter) ([]Issue, error) {
	where := []string{"1=1"}
	args := []any{}
	if f.Host != "" {
		where = append(where, "host LIKE ?")
		args = append(args, "%"+f.Host+"%")
	}
	if f.Severity != "" {
		where = append(where, "severity = ?")
		args = append(args, strings.ToLower(f.Severity))
	}
	limit := f.Limit
	if limit <= 0 || limit > 500 {
		limit = 200
	}
	args = append(args, limit)
	rows, err := s.db.QueryContext(ctx, `SELECT id, check_id, title, severity,
		confidence, host, port, path, detail, COALESCE(evidence_flow_id,0), scan_id, created
		FROM issues WHERE `+strings.Join(where, " AND ")+`
		ORDER BY id DESC LIMIT ?`, args...)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	out := []Issue{}
	for rows.Next() {
		var i Issue
		if err := rows.Scan(&i.ID, &i.CheckID, &i.Title, &i.Severity, &i.Confidence,
			&i.Host, &i.Port, &i.Path, &i.Detail, &i.EvidenceFlowID, &i.ScanID, &i.Created); err != nil {
			return nil, err
		}
		out = append(out, i)
	}
	return out, rows.Err()
}

// GetIssue loads one finding.
func (s *Store) GetIssue(ctx context.Context, id int64) (*Issue, error) {
	var i Issue
	err := s.db.QueryRowContext(ctx, `SELECT id, check_id, title, severity,
		confidence, host, port, path, detail, COALESCE(evidence_flow_id,0), scan_id, created
		FROM issues WHERE id=?`, id).
		Scan(&i.ID, &i.CheckID, &i.Title, &i.Severity, &i.Confidence,
			&i.Host, &i.Port, &i.Path, &i.Detail, &i.EvidenceFlowID, &i.ScanID, &i.Created)
	if err != nil {
		return nil, err
	}
	return &i, nil
}
