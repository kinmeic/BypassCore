// Package pubsub is a minimal publish/subscribe service used by the DNS cache
// for invalidation broadcasts.
package pubsub

import (
	"errors"
	"sync"
	"time"

	"github.com/eugene/bypasscore/common/signal/done"
	"github.com/eugene/bypasscore/common/task"
)

// Subscriber receives published messages on its buffer channel.
type Subscriber struct {
	buffer chan interface{}
	done   *done.Instance
}

func (s *Subscriber) push(msg interface{}) {
	select {
	case s.buffer <- msg:
	default:
	}
}

// Wait returns the channel on which messages are received.
func (s *Subscriber) Wait() <-chan interface{} { return s.buffer }

// Close unsubscribes.
func (s *Subscriber) Close() error { return s.done.Close() }

// IsClosed reports whether Close has been called.
func (s *Subscriber) IsClosed() bool { return s.done.Done() }

// Service manages named subscriber groups and cleans up closed subscribers.
type Service struct {
	sync.RWMutex
	subs  map[string][]*Subscriber
	ctask *task.Periodic
}

// NewService creates a new pubsub Service.
func NewService() *Service {
	s := &Service{subs: make(map[string][]*Subscriber)}
	s.ctask = &task.Periodic{
		Execute:  s.Cleanup,
		Interval: time.Second * 30,
	}
	return s
}

// Cleanup removes closed subscribers. Returns an error when there is nothing
// to do (which stops the periodic task from spinning).
func (s *Service) Cleanup() error {
	s.Lock()
	defer s.Unlock()
	if len(s.subs) == 0 {
		return errors.New("nothing to do")
	}
	for name, subs := range s.subs {
		newSub := make([]*Subscriber, 0, len(s.subs))
		for _, sub := range subs {
			if !sub.IsClosed() {
				newSub = append(newSub, sub)
			}
		}
		if len(newSub) == 0 {
			delete(s.subs, name)
		} else {
			s.subs[name] = newSub
		}
	}
	if len(s.subs) == 0 {
		s.subs = make(map[string][]*Subscriber)
	}
	return nil
}

// Subscribe creates a new Subscriber for the named topic.
func (s *Service) Subscribe(name string) *Subscriber {
	sub := &Subscriber{
		buffer: make(chan interface{}, 16),
		done:   done.New(),
	}
	s.Lock()
	s.subs[name] = append(s.subs[name], sub)
	s.Unlock()
	_ = s.ctask.Start()
	return sub
}

// Publish broadcasts a message to all live subscribers of the named topic.
func (s *Service) Publish(name string, message interface{}) {
	s.RLock()
	defer s.RUnlock()
	for _, sub := range s.subs[name] {
		if !sub.IsClosed() {
			sub.push(message)
		}
	}
}
