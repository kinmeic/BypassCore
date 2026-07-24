package task

import (
	"errors"
	"sync/atomic"
	"testing"
	"time"
)

func TestPeriodicStartsAsynchronouslyAndRetriesErrors(t *testing.T) {
	var calls atomic.Int32
	started := make(chan struct{}, 1)
	task := &Periodic{
		Interval: 10 * time.Millisecond,
		Execute: func() error {
			calls.Add(1)
			select {
			case started <- struct{}{}:
			default:
			}
			return errors.New("retry")
		},
		OnError: func(error) {},
	}
	start := time.Now()
	if err := task.Start(); err != nil {
		t.Fatal(err)
	}
	defer task.Close()
	if time.Since(start) > 20*time.Millisecond {
		t.Fatal("Start blocked on Execute")
	}
	<-started
	deadline := time.Now().Add(time.Second)
	for calls.Load() < 2 && time.Now().Before(deadline) {
		time.Sleep(time.Millisecond)
	}
	if calls.Load() < 2 {
		t.Fatal("periodic task stopped after an execution error")
	}
}
