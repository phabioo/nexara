package runtime

import (
	"sync"

	"github.com/phabioo/nexara/internal/protocol"
)

// sample is one buffered metrics sample. seq orders samples and lets the
// consumer remove exactly the sample it has handed over.
type sample struct {
	seq uint64
	m   protocol.Metrics
}

// ring is a bounded FIFO of metrics samples. When full, push drops the oldest
// sample. It is written by the sampler and drained by the connection's pump, so
// live samples and samples taken while disconnected share one ordered queue.
type ring struct {
	mu   sync.Mutex
	buf  []sample
	head int
	n    int
	seq  uint64

	// notify receives a token (non-blocking) after every push.
	notify chan struct{}
}

func newRing(capacity int) *ring {
	if capacity < 1 {
		capacity = 1
	}
	return &ring{buf: make([]sample, capacity), notify: make(chan struct{}, 1)}
}

func (r *ring) push(m protocol.Metrics) {
	r.mu.Lock()
	if r.n == len(r.buf) {
		r.head = (r.head + 1) % len(r.buf)
		r.n--
	}
	r.seq++
	r.buf[(r.head+r.n)%len(r.buf)] = sample{seq: r.seq, m: m}
	r.n++
	r.mu.Unlock()
	select {
	case r.notify <- struct{}{}:
	default:
	}
}

// peek returns the oldest sample without removing it.
func (r *ring) peek() (sample, bool) {
	r.mu.Lock()
	defer r.mu.Unlock()
	if r.n == 0 {
		return sample{}, false
	}
	return r.buf[r.head], true
}

// ack removes the oldest sample if it is the one with the given seq (it may
// already have been dropped by an overflow).
func (r *ring) ack(seq uint64) {
	r.mu.Lock()
	defer r.mu.Unlock()
	if r.n > 0 && r.buf[r.head].seq == seq {
		r.buf[r.head] = sample{}
		r.head = (r.head + 1) % len(r.buf)
		r.n--
	}
}

func (r *ring) len() int {
	r.mu.Lock()
	defer r.mu.Unlock()
	return r.n
}
