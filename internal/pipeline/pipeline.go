// Package pipeline connects capture sources (proxy engine, tools) to
// persistence and the event bus. Phase 1: store + publish; the intercept
// gate and match&replace stages arrive in M5/M6 and wrap here.
package pipeline

import (
	"context"
	"log/slog"
	"time"

	"github.com/NitinGavhane/proxyforge/internal/flows"
	"github.com/NitinGavhane/proxyforge/internal/store"
)

// Pipeline owns the post-capture path of every flow.
type Pipeline struct {
	Store *store.Store
	Bus   *flows.Bus
	Log   *slog.Logger
}

// New builds a pipeline.
func New(st *store.Store, bus *flows.Bus, log *slog.Logger) *Pipeline {
	if log == nil {
		log = slog.Default()
	}
	return &Pipeline{Store: st, Bus: bus, Log: log}
}

// Save persists f and broadcasts flow.new. A store failure is logged and
// returned; callers decide whether to fail the exchange (they generally
// should not block traffic on logging failures, but must surface it).
func (p *Pipeline) Save(ctx context.Context, f *flows.Flow) error {
	if f.Origin == "" {
		f.Origin = flows.OriginProxy
	}
	if err := p.Store.InsertFlow(ctx, f); err != nil {
		p.Log.Error("store flow", "err", err, "host", flowHost(f))
		return err
	}
	if err := p.Store.UpsertEndpointFromFlow(ctx, f); err != nil {
		p.Log.Error("site map upsert", "err", err, "host", flowHost(f))
	}
	if err := p.Store.CaptureCookies(ctx, f); err != nil {
		p.Log.Error("cookie capture", "err", err, "host", flowHost(f))
	}
	p.Bus.PublishJSON(flows.EventFlowNew, rowOf(f))
	return nil
}

// SaveWS persists one captured WebSocket frame and notifies subscribers
// (throttled consumers may ignore; the store is the source of truth).
func (p *Pipeline) SaveWS(ctx context.Context, m *flows.WSMessage) error {
	if err := p.Store.InsertWSMessage(ctx, m); err != nil {
		p.Log.Error("store ws message", "err", err, "flow", m.FlowID)
		return err
	}
	p.Bus.PublishJSON("ws.message", map[string]any{
		"flow_id": m.FlowID, "direction": m.Direction, "opcode": m.Opcode, "size": m.Size,
	})
	return nil
}

// CloseWS finalizes a WebSocket flow after both directions ended.
func (p *Pipeline) CloseWS(ctx context.Context, flowID int64, finished time.Time, dur time.Duration, count int64) error {
	if err := p.Store.UpdateFlowWSClose(ctx, flowID, finished.UnixMilli(), dur.Milliseconds(), count); err != nil {
		p.Log.Error("close ws flow", "err", err, "flow", flowID)
		return err
	}
	p.Bus.PublishJSON(flows.EventFlowUpdated, map[string]any{"id": flowID, "ws_count": count})
	return nil
}

func flowHost(f *flows.Flow) string {
	if f.Request != nil {
		return f.Request.Host
	}
	return ""
}

func rowOf(f *flows.Flow) store.FlowRow {
	r := store.FlowRow{
		ID:         f.ID,
		Started:    f.Started.UnixMilli(),
		DurationMS: f.DurationMS,
		Origin:     f.Origin,
		MITM:       f.MITM,
		Truncated:  f.Truncated,
		Comment:    f.Comment,
		Highlight:  f.Highlight,
		Err:        f.Err,
	}
	if f.Request != nil {
		r.Scheme = f.Request.Scheme
		r.HTTPVer = f.Request.HTTPVersion
		r.Method = f.Request.Method
		r.Host = f.Request.Host
		r.Port = f.Request.Port
		r.Path = f.Request.Path
		r.ReqSize = len(f.Request.Body)
		if i := indexByte(f.Request.Path, '?'); i >= 0 {
			r.Query = f.Request.Path[i+1:]
		}
	}
	if f.Response != nil {
		r.Status = f.Response.Status
		r.RespSize = len(f.Response.Body)
	}
	return r
}

func indexByte(s string, b byte) int {
	for i := 0; i < len(s); i++ {
		if s[i] == b {
			return i
		}
	}
	return -1
}
