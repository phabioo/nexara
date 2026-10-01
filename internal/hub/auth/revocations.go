package auth

import "sync"

// revocations is a broadcast: wait returns a channel that notify closes.
// After a notify the next wait returns a fresh channel.
type revocations struct {
	mu sync.Mutex
	ch chan struct{}
}

func newRevocations() *revocations { return &revocations{ch: make(chan struct{})} }

func (r *revocations) wait() <-chan struct{} {
	r.mu.Lock()
	defer r.mu.Unlock()
	return r.ch
}

func (r *revocations) notify() {
	r.mu.Lock()
	close(r.ch)
	r.ch = make(chan struct{})
	r.mu.Unlock()
}
