// Package store persists flows, blobs, and audit entries in a per-engagement
// SQLite database (WAL mode).
package store

import (
	"context"
	"database/sql"
	"embed"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"net/url"
	"strconv"
	"strings"
	"time"

	_ "modernc.org/sqlite" // pure-Go SQLite driver

	"github.com/klauspost/compress/zstd"

	"github.com/NitinGavhane/proxyforge/internal/flows"
)

//go:embed migrations/*.sql
var migrationsFS embed.FS

// blobKind values.
const (
	BlobReqHeaders  = "req_headers"
	BlobReqBody     = "req_body"
	BlobReqTrailer  = "req_trailer"
	BlobRespHeaders = "resp_headers"
	BlobRespBody    = "resp_body"
	BlobRespTrailer = "resp_trailer"
)

// Store wraps the engagement database.
type Store struct {
	db  *sql.DB
	dec *zstd.Decoder
	enc *zstd.Encoder
}

// Open opens (creating if needed) the engagement database and applies
// migrations.
func Open(path string) (*Store, error) {
	dsn := "file:" + url.PathEscape(path) +
		"?_pragma=journal_mode(WAL)" +
		"&_pragma=busy_timeout(5000)" +
		"&_pragma=foreign_keys(1)" +
		"&_pragma=synchronous(NORMAL)"
	db, err := sql.Open("sqlite", dsn)
	if err != nil {
		return nil, err
	}
	// SQLite doesn't like concurrent writers; serialize through one conn.
	db.SetMaxOpenConns(1)
	s := &Store{db: db}
	if s.dec, err = zstd.NewReader(nil); err != nil {
		db.Close()
		return nil, err
	}
	if s.enc, err = zstd.NewWriter(nil, zstd.WithEncoderLevel(zstd.SpeedFastest)); err != nil {
		db.Close()
		return nil, err
	}
	if err := s.migrate(); err != nil {
		db.Close()
		return nil, err
	}
	return s, nil
}

// Close releases the database handle.
func (s *Store) Close() error {
	s.dec.Close()
	s.enc.Close()
	return s.db.Close()
}

func (s *Store) migrate() error {
	if _, err := s.db.Exec(`CREATE TABLE IF NOT EXISTS schema_migrations (
		id INTEGER PRIMARY KEY, applied_at INTEGER NOT NULL)`); err != nil {
		return err
	}
	applied := map[int]bool{}
	rows, err := s.db.Query(`SELECT id FROM schema_migrations`)
	if err != nil {
		return err
	}
	for rows.Next() {
		var id int
		if err := rows.Scan(&id); err != nil {
			rows.Close()
			return err
		}
		applied[id] = true
	}
	rows.Close()

	entries, err := migrationsFS.ReadDir("migrations")
	if err != nil {
		return err
	}
	for _, e := range entries {
		name := e.Name()
		if !strings.HasSuffix(name, ".sql") {
			continue
		}
		id, err := strconv.Atoi(strings.SplitN(name, "_", 2)[0])
		if err != nil {
			return fmt.Errorf("migration %s: bad id", name)
		}
		if applied[id] {
			continue
		}
		body, err := migrationsFS.ReadFile("migrations/" + name)
		if err != nil {
			return err
		}
		tx, err := s.db.Begin()
		if err != nil {
			return err
		}
		if _, err := tx.Exec(string(body)); err != nil {
			tx.Rollback()
			return fmt.Errorf("migration %s: %w", name, err)
		}
		if _, err := tx.Exec(`INSERT INTO schema_migrations(id, applied_at) VALUES(?, ?)`, id, time.Now().Unix()); err != nil {
			tx.Rollback()
			return err
		}
		if err := tx.Commit(); err != nil {
			return err
		}
	}
	return nil
}

// headersJSON encodes ordered headers deterministically.
func headersJSON(h flows.Headers) []byte {
	if len(h) == 0 {
		return []byte("[]")
	}
	b, _ := json.Marshal(h)
	return b
}

func headersFromJSON(raw []byte) flows.Headers {
	var h flows.Headers
	if len(raw) > 0 {
		_ = json.Unmarshal(raw, &h)
	}
	return h
}

// ftsText builds the searchable text for a header list (key: value lines).
func ftsHeaders(h flows.Headers) string {
	var sb strings.Builder
	for _, hd := range h {
		sb.WriteString(hd.Key)
		sb.WriteString(": ")
		sb.WriteString(hd.Value)
		sb.WriteString("\n")
	}
	return sb.String()
}

const ftsBodyCap = 64 << 10 // index at most 64 KiB of body text

func ftsBody(b []byte) string {
	if len(b) > ftsBodyCap {
		b = b[:ftsBodyCap]
	}
	return string(b)
}

// InsertFlow persists f (assigning f.ID) including blobs and the FTS row.
func (s *Store) InsertFlow(ctx context.Context, f *flows.Flow) error {
	if f.Request == nil {
		return errors.New("store: flow has no request")
	}
	req := f.Request
	started := f.Started.UnixMilli()
	finished := int64(0)
	if !f.Finished.IsZero() {
		finished = f.Finished.UnixMilli()
	}
	scheme := req.Scheme
	if scheme == "" {
		scheme = "http"
	}
	path, query := req.Path, ""
	if i := strings.IndexByte(req.Path, '?'); i >= 0 {
		path, query = req.Path[:i], req.Path[i+1:]
	}
	mitm := 0
	if f.MITM {
		mitm = 1
	}
	tunnel := 0
	if f.Tunnel {
		tunnel = 1
	}
	inScope := 0
	if f.InScope {
		inScope = 1
	}
	trunc := 0
	if f.Truncated {
		trunc = 1
	}
	respSize := 0
	if f.RespBytes > 0 {
		respSize = int(f.RespBytes)
	} else if f.Response != nil {
		respSize = len(f.Response.Body)
	}
	reqSize := len(req.Body)
	if f.ReqBytes > 0 {
		reqSize = int(f.ReqBytes)
	}
	res, err := s.db.ExecContext(ctx, `INSERT INTO flows(
		started, finished, duration_ms, client_addr, server_addr,
		scheme, http_version, method, host, port, path, query,
		status, resp_version, err, origin, mitm, tunnel, in_scope, truncated,
		tls_client, tls_server,
		req_size, resp_size, ws_count, tool_ref, comment, highlight)
		VALUES(?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)`,
		started, nullInt(finished), f.DurationMS, f.ClientAddr, f.ServerAddr,
		scheme, req.HTTPVersion, req.Method, req.Host, req.Port, path, query,
		respStatus(f), nullStr(respVersion(f)), nullStr(f.Err), f.Origin, mitm, tunnel, inScope, trunc,
		nullStr(f.TLSClient), nullStr(f.TLSServer),
		reqSize, respSize, f.WSCount, f.ToolRef, f.Comment, f.Highlight)
	if err != nil {
		return err
	}
	f.ID, err = res.LastInsertId()
	if err != nil {
		return err
	}

	type blob struct {
		kind string
		raw  []byte
	}
	blobs := []blob{
		{BlobReqHeaders, headersJSON(req.Headers)},
		{BlobReqBody, req.Body},
	}
	if len(req.Trailer) > 0 {
		blobs = append(blobs, blob{BlobReqTrailer, headersJSON(req.Trailer)})
	}
	if resp := f.Response; resp != nil {
		blobs = append(blobs,
			blob{BlobRespHeaders, headersJSON(resp.Headers)},
			blob{BlobRespBody, resp.Body})
		if len(resp.Trailer) > 0 {
			blobs = append(blobs, blob{BlobRespTrailer, headersJSON(resp.Trailer)})
		}
	}
	for _, b := range blobs {
		if err := s.putBlob(ctx, f.ID, b.kind, b.raw); err != nil {
			return err
		}
	}

	_, err = s.db.ExecContext(ctx,
		`INSERT INTO flows_fts(rowid, method, host, path, headers, body) VALUES(?,?,?,?,?,?)`,
		f.ID, req.Method, req.Host, req.Path, ftsHeaders(req.Headers), ftsBody(req.Body))
	if err != nil {
		return err
	}
	if resp := f.Response; resp != nil {
		// response text is searchable too: append into the body column is not
		// possible post-insert, so we store response text on the same row via
		// an update with concatenation kept simple — response body only.
		_, _ = s.db.ExecContext(ctx, `UPDATE flows_fts SET body = body || char(10) || ? WHERE rowid = ?`,
			ftsBody(resp.Body), f.ID)
	}
	return nil
}

func respStatus(f *flows.Flow) any {
	if f.Response == nil {
		return nil
	}
	return f.Response.Status
}

func respVersion(f *flows.Flow) string {
	if f.Response == nil {
		return ""
	}
	return f.Response.HTTPVersion
}

func nullInt(v int64) any {
	if v == 0 {
		return nil
	}
	return v
}

func nullStr(v string) any {
	if v == "" {
		return nil
	}
	return v
}

func (s *Store) putBlob(ctx context.Context, flowID int64, kind string, raw []byte) error {
	if raw == nil {
		raw = []byte{}
	}
	var content []byte
	encoding := "raw"
	if len(raw) > 256 {
		content = s.enc.EncodeAll(raw, nil)
		encoding = "zstd"
	} else {
		content = raw
	}
	_, err := s.db.ExecContext(ctx, `INSERT OR REPLACE INTO flow_blobs
		(flow_id, kind, encoding, size, sha256, content) VALUES(?,?,?,?,?,?)`,
		flowID, kind, encoding, len(raw), flows.SHA256(raw), content)
	return err
}

func (s *Store) getBlob(ctx context.Context, flowID int64, kind string) ([]byte, error) {
	var encoding string
	var content []byte
	err := s.db.QueryRowContext(ctx,
		`SELECT encoding, content FROM flow_blobs WHERE flow_id=? AND kind=?`, flowID, kind).
		Scan(&encoding, &content)
	if errors.Is(err, sql.ErrNoRows) {
		return nil, nil
	}
	if err != nil {
		return nil, err
	}
	if encoding == "zstd" {
		return s.dec.DecodeAll(content, nil)
	}
	return content, nil
}

// FlowRow is the list-view projection of a flow (metadata only).
type FlowRow struct {
	ID         int64  `json:"id"`
	Started    int64  `json:"started"`
	DurationMS int64  `json:"duration_ms"`
	Scheme     string `json:"scheme"`
	HTTPVer    string `json:"http_version"`
	Method     string `json:"method"`
	Host       string `json:"host"`
	Port       int    `json:"port"`
	Path       string `json:"path"`
	Query      string `json:"query"`
	Status     int    `json:"status"`
	Err        string `json:"err,omitempty"`
	Origin     string `json:"origin"`
	ToolRef    int64  `json:"tool_ref,omitempty"`
	MITM       bool   `json:"mitm"`
	Tunnel     bool   `json:"tunnel"`
	TLSClient  string `json:"tls_client,omitempty"`
	TLSServer  string `json:"tls_server,omitempty"`
	Truncated  bool   `json:"truncated"`
	ReqSize    int    `json:"req_size"`
	RespSize   int    `json:"resp_size"`
	WSCount    int64  `json:"ws_count"`
	Comment    string `json:"comment"`
	Highlight  string `json:"highlight"`
}

// Filter selects flows. Zero fields match everything.
type Filter struct {
	Query  string // FTS query (method/host/path/headers/body)
	Host   string // substring match
	Method string // exact
	Status string // exact, or "2xx"/"4xx"/"5xx" class
	Search string // LIKE over host+path
	Sort   string // started|id|host|status|duration (default started desc)
	Limit  int
	Offset int
}

// ListFlows returns rows matching f, newest first by default.
func (s *Store) ListFlows(ctx context.Context, f Filter) ([]FlowRow, error) {
	where := []string{"1=1"}
	args := []any{}
	if f.Query != "" {
		where = append(where, "flows.id IN (SELECT rowid FROM flows_fts WHERE flows_fts MATCH ?)")
		args = append(args, ftsQuery(f.Query))
	}
	if f.Host != "" {
		where = append(where, "flows.host LIKE ?")
		args = append(args, "%"+f.Host+"%")
	}
	if f.Method != "" {
		where = append(where, "flows.method = ?")
		args = append(args, strings.ToUpper(f.Method))
	}
	if f.Status != "" {
		if len(f.Status) == 3 && strings.HasSuffix(f.Status, "xx") && f.Status[0] >= '1' && f.Status[0] <= '5' {
			lo := int(f.Status[0]-'0') * 100
			where = append(where, "flows.status >= ? AND flows.status < ?")
			args = append(args, lo, lo+100)
		} else if n, err := strconv.Atoi(f.Status); err == nil {
			where = append(where, "flows.status = ?")
			args = append(args, n)
		}
	}
	if f.Search != "" {
		pat := "%" + f.Search + "%"
		where = append(where, "(flows.host LIKE ? OR flows.path LIKE ?)")
		args = append(args, pat, pat)
	}
	orderBy := map[string]string{
		"started_asc": "flows.started ASC, flows.id ASC",
		"id":          "flows.id DESC",
		"id_asc":      "flows.id ASC",
		"host":        "flows.host ASC, flows.id DESC",
		"status":      "flows.status ASC, flows.id DESC",
		"duration":    "flows.duration_ms DESC, flows.id DESC",
	}
	order, ok := orderBy[f.Sort]
	if !ok {
		order = "flows.started DESC, flows.id DESC"
	}
	limit := f.Limit
	if limit <= 0 || limit > 500 {
		limit = 100
	}
	q := `SELECT flows.id, started, COALESCE(duration_ms,0), COALESCE(scheme,''),
		COALESCE(http_version,''), COALESCE(method,''), COALESCE(host,''),
		COALESCE(port,0), COALESCE(path,''), COALESCE(query,''),
		COALESCE(status,0), COALESCE(err,''), origin, mitm, tunnel,
		COALESCE(tls_client,''), COALESCE(tls_server,''), truncated,
		COALESCE(req_size,0), COALESCE(resp_size,0), ws_count, tool_ref, comment, highlight
		FROM flows WHERE ` + strings.Join(where, " AND ") + `
		ORDER BY ` + order + ` LIMIT ? OFFSET ?`
	args = append(args, limit, f.Offset)
	rows, err := s.db.QueryContext(ctx, q, args...)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	out := []FlowRow{}
	for rows.Next() {
		var r FlowRow
		var mitm, tunnel, trunc int
		if err := rows.Scan(&r.ID, &r.Started, &r.DurationMS, &r.Scheme, &r.HTTPVer,
			&r.Method, &r.Host, &r.Port, &r.Path, &r.Query, &r.Status, &r.Err,
			&r.Origin, &mitm, &tunnel, &r.TLSClient, &r.TLSServer, &trunc,
			&r.ReqSize, &r.RespSize, &r.WSCount, &r.ToolRef, &r.Comment, &r.Highlight); err != nil {
			return nil, err
		}
		r.MITM = mitm == 1
		r.Tunnel = tunnel == 1
		r.Truncated = trunc == 1
		out = append(out, r)
	}
	return out, rows.Err()
}

// ftsQuery sanitizes user input into a basic FTS5 prefix query: every token
// becomes "token*" joined by AND, so typing "login juice" matches both
// anywhere. Tokens with FTS syntax characters are quoted.
func ftsQuery(in string) string {
	fields := strings.Fields(in)
	parts := make([]string, 0, len(fields))
	for _, tok := range fields {
		if tok == "" {
			continue
		}
		parts = append(parts, `"`+strings.ReplaceAll(tok, `"`, ``)+`" *`)
	}
	if len(parts) == 0 {
		return `""`
	}
	return strings.Join(parts, " AND ")
}

// CountFlows returns the number of stored flows (for status display).
func (s *Store) CountFlows(ctx context.Context) (int64, error) {
	var n int64
	err := s.db.QueryRowContext(ctx, `SELECT COUNT(*) FROM flows`).Scan(&n)
	return n, err
}

// GetFlow loads one flow with request/response headers and bodies.
func (s *Store) GetFlow(ctx context.Context, id int64) (*flows.Flow, error) {
	var r FlowRow
	var started, finished, duration sql.NullInt64
	var clientAddr, serverAddr, respVersion sql.NullString
	var mitm, tunnel, inScope, trunc int
	err := s.db.QueryRowContext(ctx, `SELECT id, started, finished, duration_ms,
		client_addr, server_addr, COALESCE(scheme,''), COALESCE(http_version,''),
		COALESCE(method,''), COALESCE(host,''), COALESCE(port,0), COALESCE(path,''),
		COALESCE(query,''), COALESCE(status,0), resp_version, COALESCE(err,''),
		origin, mitm, tunnel, in_scope, truncated,
		COALESCE(tls_client,''), COALESCE(tls_server,''),
		ws_count, tool_ref, COALESCE(comment,''), COALESCE(highlight,'')
		FROM flows WHERE id=?`, id).
		Scan(&r.ID, &started, &finished, &duration, &clientAddr, &serverAddr,
			&r.Scheme, &r.HTTPVer, &r.Method, &r.Host, &r.Port, &r.Path, &r.Query,
			&r.Status, &respVersion, &r.Err, &r.Origin, &mitm, &tunnel, &inScope, &trunc,
			&r.TLSClient, &r.TLSServer,
			&r.WSCount, &r.ToolRef, &r.Comment, &r.Highlight)
	if errors.Is(err, sql.ErrNoRows) {
		return nil, fmt.Errorf("flow %d: not found", id)
	}
	if err != nil {
		return nil, err
	}

	f := &flows.Flow{
		ID:         r.ID,
		Started:    time.UnixMilli(started.Int64),
		Finished:   time.UnixMilli(finished.Int64),
		DurationMS: duration.Int64,
		ClientAddr: clientAddr.String,
		ServerAddr: serverAddr.String,
		Origin:     r.Origin,
		MITM:       mitm == 1,
		Tunnel:     tunnel == 1,
		TLSClient:  r.TLSClient,
		TLSServer:  r.TLSServer,
		InScope:    inScope == 1,
		Truncated:  trunc == 1,
		Err:        r.Err,
		Comment:    r.Comment,
		Highlight:  r.Highlight,
		WSCount:    r.WSCount,
		ToolRef:    r.ToolRef,
	}
	fullPath := r.Path
	if r.Query != "" {
		fullPath += "?" + r.Query
	}
	reqHdrs, err := s.getBlob(ctx, id, BlobReqHeaders)
	if err != nil {
		return nil, err
	}
	reqBody, err := s.getBlob(ctx, id, BlobReqBody)
	if err != nil {
		return nil, err
	}
	reqTrailer, err := s.getBlob(ctx, id, BlobReqTrailer)
	if err != nil {
		return nil, err
	}
	f.Request = &flows.Request{
		Method:      r.Method,
		Scheme:      r.Scheme,
		Host:        r.Host,
		Port:        r.Port,
		Path:        fullPath,
		HTTPVersion: r.HTTPVer,
		Headers:     headersFromJSON(reqHdrs),
		Body:        reqBody,
		Trailer:     headersFromJSON(reqTrailer),
		BodyTrunc:   trunc == 1,
	}
	if r.Status != 0 || respVersion.Valid {
		respHdrs, err := s.getBlob(ctx, id, BlobRespHeaders)
		if err != nil {
			return nil, err
		}
		respBody, err := s.getBlob(ctx, id, BlobRespBody)
		if err != nil {
			return nil, err
		}
		respTrailer, err := s.getBlob(ctx, id, BlobRespTrailer)
		if err != nil {
			return nil, err
		}
		f.Response = &flows.Response{
			Status:      r.Status,
			StatusText:  http.StatusText(r.Status),
			HTTPVersion: respVersion.String,
			Headers:     headersFromJSON(respHdrs),
			Body:        respBody,
			Trailer:     headersFromJSON(respTrailer),
			BodyTrunc:   trunc == 1,
		}
	}
	return f, nil
}

// SetAnnotation updates a flow's comment and/or highlight (empty string =
// unchanged when useXXX is false; use pointers for tri-state).
func (s *Store) SetAnnotation(ctx context.Context, id int64, comment, highlight *string) error {
	set := []string{}
	args := []any{}
	if comment != nil {
		set = append(set, "comment=?")
		args = append(args, *comment)
	}
	if highlight != nil {
		set = append(set, "highlight=?")
		args = append(args, *highlight)
	}
	if len(set) == 0 {
		return nil
	}
	args = append(args, id)
	res, err := s.db.ExecContext(ctx,
		`UPDATE flows SET `+strings.Join(set, ", ")+` WHERE id=?`, args...)
	if err != nil {
		return err
	}
	n, _ := res.RowsAffected()
	if n == 0 {
		return fmt.Errorf("flow %d: not found", id)
	}
	return nil
}

// InsertWSMessage persists one captured WebSocket frame immediately (the
// parent flow should already be inserted).
func (s *Store) InsertWSMessage(ctx context.Context, m *flows.WSMessage) error {
	var content []byte
	encoding := "raw"
	if len(m.Payload) > 256 {
		content = s.enc.EncodeAll(m.Payload, nil)
		encoding = "zstd"
	} else if m.Payload == nil {
		content, m.Payload = []byte{}, []byte{}
	} else {
		content = m.Payload
	}
	fin, comp := 0, 0
	if m.FIN {
		fin = 1
	}
	if m.Compressed {
		comp = 1
	}
	res, err := s.db.ExecContext(ctx, `INSERT INTO ws_messages
		(flow_id, ts, direction, opcode, fin, compressed, size, encoding, payload)
		VALUES(?,?,?,?,?,?,?,?,?)`,
		m.FlowID, m.TS, m.Direction, m.Opcode, fin, comp, m.Size, encoding, content)
	if err != nil {
		return err
	}
	m.ID, _ = res.LastInsertId()
	return nil
}

// WSMessageRow is the list projection of a captured frame (payload base64).
type WSMessageRow struct {
	ID         int64  `json:"id"`
	TS         int64  `json:"ts"`
	Direction  string `json:"direction"`
	Opcode     int    `json:"opcode"`
	OpcodeName string `json:"opcode_name"`
	FIN        bool   `json:"fin"`
	Compressed bool   `json:"compressed"`
	Size       int    `json:"size"`
	PayloadB64 string `json:"payload_b64"`
}

// ListWSMessages returns captured frames for a flow, oldest first, paged.
// Bodies over listBodyCap bytes are returned empty (fetch-by-id later).
const wsListBodyCap = 256 << 10

func (s *Store) ListWSMessages(ctx context.Context, flowID int64, limit, offset int) ([]WSMessageRow, error) {
	if limit <= 0 || limit > 1000 {
		limit = 200
	}
	rows, err := s.db.QueryContext(ctx, `SELECT id, ts, direction, opcode, fin,
		compressed, size, encoding, payload FROM ws_messages
		WHERE flow_id=? ORDER BY id LIMIT ? OFFSET ?`, flowID, limit, offset)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	out := []WSMessageRow{}
	for rows.Next() {
		var r WSMessageRow
		var fin, comp int
		var encoding string
		var content []byte
		if err := rows.Scan(&r.ID, &r.TS, &r.Direction, &r.Opcode, &fin, &comp,
			&r.Size, &encoding, &content); err != nil {
			return nil, err
		}
		r.FIN, r.Compressed = fin == 1, comp == 1
		r.OpcodeName = flows.OpcodeName(r.Opcode)
		if encoding == "zstd" {
			content, _ = s.dec.DecodeAll(content, nil)
		}
		if len(content) <= wsListBodyCap {
			r.PayloadB64 = base64.StdEncoding.EncodeToString(content)
		}
		out = append(out, r)
	}
	return out, rows.Err()
}

// UpdateFlowWSClose records the terminal state of a WebSocket flow.
func (s *Store) UpdateFlowWSClose(ctx context.Context, flowID int64, finished int64, durationMS, wsCount int64) error {
	_, err := s.db.ExecContext(ctx, `UPDATE flows
		SET finished=?, duration_ms=?, ws_count=? WHERE id=?`,
		finished, durationMS, wsCount, flowID)
	return err
}

// AppendAudit records an auditable action.
func (s *Store) AppendAudit(ctx context.Context, actor, action, target, detail string) error {
	_, err := s.db.ExecContext(ctx,
		`INSERT INTO audit_log(ts, actor, action, target, detail) VALUES(?,?,?,?,?)`,
		time.Now().UnixMilli(), actor, action, target, detail)
	return err
}

// AuditEntries returns audit rows newest-first, optionally as JSONL text.
func (s *Store) AuditJSONL(ctx context.Context) (string, error) {
	rows, err := s.db.QueryContext(ctx, `SELECT ts, actor, action, COALESCE(target,''), COALESCE(detail,'')
		FROM audit_log ORDER BY id`)
	if err != nil {
		return "", err
	}
	defer rows.Close()
	var sb strings.Builder
	for rows.Next() {
		var ts int64
		var actor, action, target, detail string
		if err := rows.Scan(&ts, &actor, &action, &target, &detail); err != nil {
			return "", err
		}
		b, _ := json.Marshal(map[string]string{
			"ts": time.UnixMilli(ts).Format(time.RFC3339Nano), "actor": actor,
			"action": action, "target": target, "detail": detail,
		})
		sb.Write(b)
		sb.WriteByte('\n')
	}
	return sb.String(), rows.Err()
}
