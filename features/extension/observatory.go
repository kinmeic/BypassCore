package extension

import (
	"context"

	"github.com/eugene/bypasscore/features"
	"google.golang.org/protobuf/proto"
)

// Observatory observes the status of outbounds and provides observation results.
type Observatory interface {
	features.Feature
	GetObservation(ctx context.Context) (proto.Message, error)
}

// BurstObservatory extends Observatory with an explicit check trigger.
type BurstObservatory interface {
	Observatory
	Check(tag []string)
}

// ObservatoryType returns the type of Observatory interface.
func ObservatoryType() interface{} {
	return (*Observatory)(nil)
}
