package dispatcher

import (
	"context"
	stderrors "errors"
	"testing"

	"github.com/eugene/bypasscore/app/dialer"
	bcnet "github.com/eugene/bypasscore/common/net"
	"github.com/eugene/bypasscore/features/routing"
)

type operationalErrorRouter struct{ routing.DefaultRouter }

func (operationalErrorRouter) PickRoute(routing.Context) (routing.Route, error) {
	return nil, stderrors.New("observer unavailable")
}

type trackingDialerManager struct{ defaults int }

func (*trackingDialerManager) GetDialer(string) dialer.Dialer { return nil }
func (m *trackingDialerManager) GetDefaultDialer() dialer.Dialer {
	m.defaults++
	return nil
}

func TestDialOutboundDoesNotFailOpenOnRouterError(t *testing.T) {
	manager := new(trackingDialerManager)
	dispatcher := New(operationalErrorRouter{}, manager, nil)
	_, err := dispatcher.DialOutbound(context.Background(), bcnet.TCPDestination(bcnet.ParseAddress("1.1.1.1"), 443))
	if err == nil {
		t.Fatal("operational router error was ignored")
	}
	if manager.defaults != 0 {
		t.Fatalf("default outbound requested %d times", manager.defaults)
	}
}
