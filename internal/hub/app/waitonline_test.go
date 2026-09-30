package app

import (
	"context"
	"errors"
	"sync"
	"testing"

	"github.com/phabioo/nexara/internal/hub/grid"
)

type fakeSource struct {
	mu     sync.Mutex
	online map[grid.HostID]bool
	subs   []chan grid.Event
	// onSubscribe runs after the subscription exists (to simulate a race).
	onSubscribe func(*fakeSource)
}

func (f *fakeSource) Host(id grid.HostID) (grid.HostInfo, bool) {
	f.mu.Lock()
	defer f.mu.Unlock()
	on, ok := f.online[id]
	return grid.HostInfo{ID: id, Online: on}, ok
}

func (f *fakeSource) Subscribe(context.Context) <-chan grid.Event {
	ch := make(chan grid.Event, 8)
	f.mu.Lock()
	f.subs = append(f.subs, ch)
	hook := f.onSubscribe
	f.mu.Unlock()
	if hook != nil {
		hook(f)
	}
	return ch
}

func TestWaitOnline(t *testing.T) {
	const id = grid.HostID("h1")
	t.Run("already online", func(t *testing.T) {
		src := &fakeSource{online: map[grid.HostID]bool{id: true}}
		if err := waitOnline(src)(context.Background(), id); err != nil {
			t.Fatal(err)
		}
	})
	t.Run("comes online after other events", func(t *testing.T) {
		src := &fakeSource{online: map[grid.HostID]bool{id: false}}
		src.onSubscribe = func(s *fakeSource) {
			for _, ev := range []grid.Event{
				{Kind: grid.EventHostOnline, Host: "other"},
				{Kind: grid.EventMetrics, Host: id},
				{Kind: grid.EventHostOnline, Host: id},
			} {
				s.subs[0] <- ev // buffered; delivered once the waiter reads
			}
		}
		if err := waitOnline(src)(context.Background(), id); err != nil {
			t.Fatal(err)
		}
	})
	t.Run("online between subscribe and check is not missed", func(t *testing.T) {
		src := &fakeSource{online: map[grid.HostID]bool{}}
		src.onSubscribe = func(s *fakeSource) { s.online[id] = true }
		if err := waitOnline(src)(context.Background(), id); err != nil {
			t.Fatal(err)
		}
	})
	t.Run("context ends", func(t *testing.T) {
		src := &fakeSource{online: map[grid.HostID]bool{id: false}}
		ctx, cancel := context.WithCancel(context.Background())
		cancel()
		if err := waitOnline(src)(ctx, id); !errors.Is(err, context.Canceled) {
			t.Fatalf("err = %v, want context.Canceled", err)
		}
	})
	t.Run("hub shutting down is an error, not success", func(t *testing.T) {
		src := &fakeSource{online: map[grid.HostID]bool{id: false}}
		src.onSubscribe = func(s *fakeSource) { close(s.subs[0]); s.subs = nil }
		if err := waitOnline(src)(context.Background(), id); !errors.Is(err, errSubscriptionClosed) {
			t.Fatalf("err = %v, want errSubscriptionClosed", err)
		}
	})
}
