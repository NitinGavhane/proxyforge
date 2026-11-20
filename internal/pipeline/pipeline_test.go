package pipeline

import (
	"context"
	"path/filepath"
	"testing"
	"time"

	"github.com/NitinGavhane/proxyforge/internal/flows"
	"github.com/NitinGavhane/proxyforge/internal/store"
)

func TestSavePersistsAndPublishes(t *testing.T) {
	st, err := store.Open(filepath.Join(t.TempDir(), "p.pf.sqlite"))
	if err != nil {
		t.Fatal(err)
	}
	defer st.Close()
	bus := flows.NewBus()
	sub, cancel := bus.Subscribe()
	defer cancel()

	p := New(st, bus, nil)
	now := time.Now()
	err = p.Save(context.Background(), &flows.Flow{
		Started: now,
		Origin:  flows.OriginProxy,
		Request: &flows.Request{
			Method: "GET", Scheme: "http", Host: "x.test", Port: 80,
			Path: "/", HTTPVersion: "HTTP/1.1",
		},
	})
	if err != nil {
		t.Fatalf("save: %v", err)
	}
	rows, err := st.ListFlows(context.Background(), store.Filter{})
	if err != nil || len(rows) != 1 {
		t.Fatalf("rows: %v %+v", err, rows)
	}
	if rows[0].Origin != flows.OriginProxy {
		t.Errorf("origin = %q", rows[0].Origin)
	}
	select {
	case ev := <-sub:
		if ev.Type != flows.EventFlowNew {
			t.Errorf("event type = %q", ev.Type)
		}
	case <-time.After(time.Second):
		t.Fatal("no event published")
	}
}

func TestSaveDefaultsOrigin(t *testing.T) {
	st, _ := store.Open(filepath.Join(t.TempDir(), "p2.pf.sqlite"))
	defer st.Close()
	bus := flows.NewBus()
	p := New(st, bus, nil)
	f := &flows.Flow{
		Started: time.Now(),
		Request: &flows.Request{Method: "GET", Scheme: "http", Host: "y.test", Path: "/"},
	}
	if err := p.Save(context.Background(), f); err != nil {
		t.Fatal(err)
	}
	if f.Origin != flows.OriginProxy {
		t.Fatalf("default origin = %q", f.Origin)
	}
}
