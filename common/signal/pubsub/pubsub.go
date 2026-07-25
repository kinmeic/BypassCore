// Package pubsub is a minimal publish/subscribe service used by the DNS cache
// for invalidation broadcasts.
package pubsub

import (
	"sync"
	"time"

	"github.com/eugene/bypasscore/common/signal/done"
	"github.com/eugene/bypasscore/common/task"
)

// Subscriber receives published messages on its buffer channel.
type Subscriber struct {
	buffer  chan interface{}
	done    *done.Instance
	service *Service
	topic   string
}

func (s *Subscriber) push(msg interface{}) {
	select {
	case s.buffer <- msg:
	default:
		select {
		case <-s.buffer:
		default:
		}
		select {
		case s.buffer <- msg:
		default:
		}
	}
}

// Wait returns the channel on which messages are received.
func (s *Subscriber) Wait() <-chan interface{} { return s.buffer }

// Close unsubscribes.
func (s *Subscriber) Close() error {
	if s.done.Done() {
		return nil
	}
	err := s.done.Close()
	// Remove the subscriber from the service map immediately instead of
	// waiting for the periodic Cleanup sweep, so the map does not grow with
	// churn between sweeps. Removal is idempotent, so racing Closes are safe.
	if s.service != nil {
		s.service.unsubscribe(s.topic, s)
	}
	return err
}

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

// unsubscribe removes target from the named topic right away.
func (s *Service) unsubscribe(name string, target *Subscriber) {
	s.Lock()
	defer s.Unlock()
	subs := s.subs[name]
	if len(subs) == 0 {
		return
	}
	filtered := make([]*Subscriber, 0, len(subs))
	for _, sub := range subs {
		if sub != target {
			filtered = append(filtered, sub)
		}
	}
	if len(filtered) == 0 {
		delete(s.subs, name)
	} else {
		s.subs[name] = filtered
	}
}

// Cleanup removes closed subscribers. It is a backstop: Subscriber.Close
// already removes entries eagerly, this sweep only catches subscribers that
// were closed through some other path.
func (s *Service) Cleanup() error {
	s.Lock()
	defer s.Unlock()
	if len(s.subs) == 0 {
		return nil
	}
	for name, subs := range s.subs {
		newSub := make([]*Subscriber, 0, len(subs))
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
		buffer:  make(chan interface{}, 16),
		done:    done.New(),
		service: s,
		topic:   name,
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

// Close stops background cleanup and releases subscriber references.
func (s *Service) Close() error {
	_ = s.ctask.Close()
	s.Lock()
	s.subs = make(map[string][]*Subscriber)
	s.Unlock()
	return nil
}
