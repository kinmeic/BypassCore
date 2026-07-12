// Package done is a one-shot close notification utility.
package done

import "sync"

// Instance is a utility for notifications of something being done.
type Instance struct {
	access sync.Mutex
	c      chan struct{}
	closed bool
}

// New returns a new done Instance.
func New() *Instance {
	return &Instance{c: make(chan struct{})}
}

// Done returns true if Close has been called.
func (d *Instance) Done() bool {
	select {
	case <-d.Wait():
		return true
	default:
		return false
	}
}

// Wait returns a channel that is closed when Close is called.
func (d *Instance) Wait() <-chan struct{} {
	return d.c
}

// Close marks the instance as done. Subsequent calls are no-ops.
func (d *Instance) Close() error {
	d.access.Lock()
	defer d.access.Unlock()
	if !d.closed {
		d.closed = true
		close(d.c)
	}
	return nil
}
