package flows

import (
	"encoding/json"
	"sync"
)

// Event types published on the bus.
const (
	EventFlowNew     = "flow.new"
	EventFlowUpdated = "flow.updated"
	EventIntercept   = "intercept.changed"
	EventNotice      = "notice"
)

// Event is a control-plane notification.
type Event struct {
	Type    string          `json:"type"`
	Payload json.RawMessage `json:"payload,omitempty"`
}

// Bus is a fan-out event bus. Subscribers get a buffered channel; a slow
// subscriber drops events rather than blocking publishers (event delivery is
// best-effort — the store is the source of truth).
type Bus struct {
	mu   sync.Mutex
	subs map[chan Event]struct{}
}

// NewBus returns an empty bus.
func NewBus() *Bus {
	return &Bus{subs: make(map[chan Event]struct{})}
}

// Subscribe returns a channel of events and a cancel func.
func (b *Bus) Subscribe() (<-chan Event, func()) {
	ch := make(chan Event, 128)
	b.mu.Lock()
	b.subs[ch] = struct{}{}
	b.mu.Unlock()
	cancel := func() {
		b.mu.Lock()
		delete(b.subs, ch)
		b.mu.Unlock()
	}
	return ch, cancel
}

// Publish delivers ev to all subscribers without blocking.
func (b *Bus) Publish(ev Event) {
	b.mu.Lock()
	defer b.mu.Unlock()
	for ch := range b.subs {
		select {
		case ch <- ev:
		default: // drop for slow consumer
		}
	}
}

// PublishJSON is Publish with a marshaled payload.
func (b *Bus) PublishJSON(typ string, v any) {
	payload, err := json.Marshal(v)
	if err != nil {
		return
	}
	b.Publish(Event{Type: typ, Payload: payload})
}
