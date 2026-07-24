package router

import (
	"context"

	"github.com/eugene/bypasscore/app/observatory"
	"github.com/eugene/bypasscore/common"
	"github.com/eugene/bypasscore/common/dice"
	"github.com/eugene/bypasscore/core"
	"github.com/eugene/bypasscore/features/extension"
)

// RandomStrategy represents a random balancing strategy
type RandomStrategy struct {
	FallbackTag string

	ctx         context.Context
	observatory extension.Observatory
}

func (s *RandomStrategy) InjectContext(ctx context.Context) {
	s.ctx = ctx
	if len(s.FallbackTag) > 0 {
		common.Must(core.RequireFeatures(s.ctx, func(observatory extension.Observatory) error {
			s.observatory = observatory
			return nil
		}))
	}
}

func (s *RandomStrategy) GetPrincipleTarget(strings []string) []string {
	return strings
}

func (s *RandomStrategy) PickOutbound(candidates []string) string {
	if s.observatory != nil {
		observeReport, err := s.observatory.GetObservation(s.ctx)
		if err == nil {
			if result, ok := observeReport.(*observatory.ObservationResult); ok {
				candidates = filterAliveCandidates(candidates, result.Status)
			}
		}
	}

	count := len(candidates)
	if count == 0 {
		// goes to fallbackTag
		return ""
	}
	return candidates[dice.Roll(count)]
}
