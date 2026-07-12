// Package log provides a minimal logging facility. It defines a Message
// interface and a Record function that routes messages to the standard library
// logger by default. A custom Handler can be registered via RegisterHandler.
package log

import (
	stdlog "log"
	"sync"
)

// Message is a unit of log output.
type Message interface {
	String() string
}

// Handler processes log messages.
type Handler interface {
	Handle(msg Message)
}

// Record writes a message to the configured handler.
func Record(msg Message) {
	if msg == nil {
		return
	}
	handlerMu.RLock()
	h := registeredHandler
	handlerMu.RUnlock()
	if h != nil {
		h.Handle(msg)
		return
	}
	stdlog.Println(msg.String())
}

var (
	handlerMu         sync.RWMutex
	registeredHandler Handler
)

// RegisterHandler installs a custom handler. Pass nil to restore the default
// (stdlib log).
func RegisterHandler(handler Handler) {
	handlerMu.Lock()
	defer handlerMu.Unlock()
	registeredHandler = handler
}
