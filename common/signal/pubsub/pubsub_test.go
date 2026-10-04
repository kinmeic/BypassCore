package pubsub

import "testing"

func TestSubscribeAfterCloseStaysClosed(t *testing.T) {
	service := NewService()
	old := service.Subscribe("topic")
	_ = service.Close()
	if !old.IsClosed() {
		t.Fatal("Close left an existing subscriber live")
	}
	sub := service.Subscribe("topic")
	if !sub.IsClosed() || len(service.subs) != 0 {
		t.Fatal("Subscribe revived a closed service")
	}
	_ = service.Close()
}
