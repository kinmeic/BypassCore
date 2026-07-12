package common

import "github.com/eugene/bypasscore/common/errors"

// Closable is the interface for objects that can release its resources.
type Closable interface {
	Close() error
}

// Interruptible is an interface for objects that can be stopped before completion.
type Interruptible interface {
	Interrupt()
}

// Close closes obj if it is Closable.
func Close(obj interface{}) error {
	if c, ok := obj.(Closable); ok {
		return c.Close()
	}
	return nil
}

// Interrupt calls Interrupt() if the object implements Interruptible, else Close().
func Interrupt(obj interface{}) error {
	if c, ok := obj.(Interruptible); ok {
		c.Interrupt()
		return nil
	}
	return Close(obj)
}

// Runnable is the interface for objects that can start to work and stop on demand.
type Runnable interface {
	Start() error
	Closable
}

// HasType is the interface for objects that knows its type.
type HasType interface {
	Type() interface{}
}

// ChainedClosable is a Closable that consists of multiple Closable objects.
type ChainedClosable []Closable

// Close implements Closable.
func (cc ChainedClosable) Close() error {
	var errs []error
	for _, c := range cc {
		if err := c.Close(); err != nil {
			errs = append(errs, err)
		}
	}
	return errors.Combine(errs...)
}
