package desktop

import (
	"context"

	"github.com/jihuayu/locklark/internal/browserhost"
)

// handleCLIRunUnit is the test-only entry for direct desktop fixtures. It is
// compiled only in tests; the production broker callback always enters
// handleCLIRun, which requires the sealed live CTTY proof.
func (a *App) handleCLIRunUnit(ctx context.Context, peer browserhost.Peer, req browserhost.BrokerCLIRequest) (browserhost.BrokerCLIResponse, error) {
	return a.handleCLIRunWithProof(ctx, peer, req, false)
}
