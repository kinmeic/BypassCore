package router

// Webhook support is not provided (rule-hit HTTP notifications are out of
// scope). A no-op WebhookNotifier is kept so the Router code that references it
// compiles: NewWebhookNotifier always returns nil, and a nil
// *WebhookNotifier is safe to call — Fire/Close on a nil receiver do nothing.
//
// The WebhookConfig message is retained by config.pb.go but is never populated,
// so rule.GetWebhook() returns nil in practice.

// WebhookNotifier is a no-op webhook notifier.
type WebhookNotifier struct{}

// NewWebhookNotifier always returns nil (webhook support removed).
func NewWebhookNotifier(_ *WebhookConfig) (*WebhookNotifier, error) {
	return nil, nil
}

// Fire is a no-op on a nil receiver.
func (n *WebhookNotifier) Fire(_ interface{}, _ string) {}

// Close is a no-op on a nil receiver.
func (n *WebhookNotifier) Close() {}
