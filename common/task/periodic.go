// Package task provides simple concurrency helpers: a periodic runner and a
// parallel error-collecting runner.
package task

import (
	"context"
	"sync"
	"time"

	"github.com/eugene/bypasscore/common/errors"
)

// Periodic runs Execute at the given Interval until Close is called.
type Periodic struct {
	// Interval of the task being run.
	Interval time.Duration
	// Execute is the task function.
	Execute func() error
	// OnError observes execution failures. Failures no longer silently stop the
	// periodic chain; the next run remains scheduled.
	OnError func(error)

	access  sync.Mutex
	timer   *time.Timer
	running bool
}

func (t *Periodic) hasClosed() bool {
	t.access.Lock()
	defer t.access.Unlock()
	return !t.running
}

func (t *Periodic) checkedExecute() {
	if t.hasClosed() {
		return
	}
	if err := t.Execute(); err != nil {
		if t.OnError != nil {
			t.OnError(err)
		} else {
			errors.LogWarning(context.Background(), "periodic task failed; retrying after ", t.Interval, ": ", err)
		}
	}
	t.access.Lock()
	defer t.access.Unlock()
	if !t.running {
		return
	}
	t.timer = time.AfterFunc(t.Interval, func() {
		t.checkedExecute()
	})
}

// Start begins the periodic execution.
func (t *Periodic) Start() error {
	if t.Execute == nil {
		return errors.New("periodic task has no Execute function")
	}
	if t.Interval <= 0 {
		return errors.New("periodic task interval must be positive")
	}
	t.access.Lock()
	if t.running {
		t.access.Unlock()
		return nil
	}
	t.running = true
	t.timer = time.AfterFunc(0, func() {
		t.checkedExecute()
	})
	t.access.Unlock()
	return nil
}

// Close stops the periodic execution.
func (t *Periodic) Close() error {
	t.access.Lock()
	defer t.access.Unlock()
	t.running = false
	if t.timer != nil {
		t.timer.Stop()
		t.timer = nil
	}
	return nil
}

// OnSuccess executes g() after f() returns nil.
func OnSuccess(f func() error, g func() error) func() error {
	return func() error {
		if err := f(); err != nil {
			return err
		}
		return g()
	}
}

// Run executes tasks in parallel and returns the first error encountered, or
// nil if all succeed. It uses a buffered channel as a semaphore.
func Run(ctx context.Context, tasks ...func() error) error {
	n := len(tasks)
	sem := make(chan struct{}, n)
	for i := 0; i < n; i++ {
		sem <- struct{}{}
	}
	done := make(chan error, 1)

	for _, task := range tasks {
		<-sem
		go func(f func() error) {
			err := f()
			if err == nil {
				sem <- struct{}{}
				return
			}
			select {
			case done <- err:
			default:
			}
		}(task)
	}

	for i := 0; i < n; i++ {
		select {
		case err := <-done:
			return err
		case <-ctx.Done():
			return ctx.Err()
		case <-sem:
		}
	}
	return nil
}
