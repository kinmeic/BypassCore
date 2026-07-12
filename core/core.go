// Package core provides a lightweight dependency-injection shim based on a
// context-carried feature registry. Features (the DNS client, outbound manager,
// dispatcher, and observatory) are stored in the context, and RequireFeatures
// reads them back by type.
package core // import "github.com/eugene/bypasscore/core"

import (
	"context"
	"reflect"

	"github.com/eugene/bypasscore/common/errors"
	"github.com/eugene/bypasscore/features/dns"
	"github.com/eugene/bypasscore/features/extension"
	"github.com/eugene/bypasscore/features/outbound"
	"github.com/eugene/bypasscore/features/routing"
)

type featureKey struct{}

// allFeatures is the registry carried inside a context.
type allFeatures struct {
	dns        dns.Client
	ohm        outbound.Manager
	dispatcher routing.Dispatcher
	observer   extension.Observatory
}

// ContextWithFeatures returns a context carrying the given features so that
// RequireFeatures can resolve them downstream.
func ContextWithFeatures(
	ctx context.Context,
	d dns.Client,
	ohm outbound.Manager,
	dispatcher routing.Dispatcher,
	observer extension.Observatory,
) context.Context {
	return context.WithValue(ctx, featureKey{}, &allFeatures{
		dns:        d,
		ohm:        ohm,
		dispatcher: dispatcher,
		observer:   observer,
	})
}

func fromContext(ctx context.Context) *allFeatures {
	if v, ok := ctx.Value(featureKey{}).(*allFeatures); ok {
		return v
	}
	return &allFeatures{}
}

// RequireFeatures resolves features by the parameter types of fn and invokes it.
// It supports the four feature interfaces used by the routing subsystem:
// dns.Client, outbound.Manager, routing.Dispatcher, extension.Observatory.
// Missing features are passed as nil; consumers guard nil usage themselves.
func RequireFeatures(ctx context.Context, fn interface{}) error {
	fv := reflect.ValueOf(fn)
	ft := fv.Type()
	if ft.Kind() != reflect.Func {
		return errors.New("RequireFeatures: fn must be a function")
	}
	n := ft.NumIn()
	args := make([]reflect.Value, n)
	feats := fromContext(ctx)
	for i := 0; i < n; i++ {
		args[i] = resolveByType(ft.In(i), feats)
	}
	out := fv.Call(args)
	// If fn returns an error as its last result, propagate it.
	if len(out) > 0 {
		if err, ok := out[len(out)-1].Interface().(error); ok && err != nil {
			return err
		}
	}
	return nil
}

func resolveByType(t reflect.Type, feats *allFeatures) reflect.Value {
	switch t {
	case reflect.TypeOf((*dns.Client)(nil)).Elem():
		if feats.dns != nil {
			return reflect.ValueOf(feats.dns)
		}
	case reflect.TypeOf((*outbound.Manager)(nil)).Elem():
		if feats.ohm != nil {
			return reflect.ValueOf(feats.ohm)
		}
	case reflect.TypeOf((*routing.Dispatcher)(nil)).Elem():
		if feats.dispatcher != nil {
			return reflect.ValueOf(feats.dispatcher)
		}
	case reflect.TypeOf((*extension.Observatory)(nil)).Elem():
		if feats.observer != nil {
			return reflect.ValueOf(feats.observer)
		}
	}
	// Not found: pass a zero value of the interface type (nil).
	return reflect.Zero(t)
}
