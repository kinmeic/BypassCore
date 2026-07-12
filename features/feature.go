package features

import (
	"github.com/eugene/bypasscore/common"
)

// Feature is the interface for objects that can be started and stopped.
type Feature interface {
	common.HasType
	common.Runnable
}
