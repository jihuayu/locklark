package desktop

import (
	"context"
	"time"
)

const (
	nativeFenceMaxChildren     = 64
	nativeFenceInputFrameLimit = 16
	nativeFenceProductionWait  = 20 * time.Second
	nativeFenceProductionWrite = 500 * time.Millisecond
	nativeFenceProductionTerm  = 30 * time.Second
	nativeFenceReadWritePoll   = time.Millisecond
)

type nativeFenceConfig uint8

const (
	nativeFenceConfigDisabled nativeFenceConfig = iota
	nativeFenceConfigValid
	nativeFenceConfigInvalid
)

type nativeFencePhase uint8

const (
	nativeFencePhaseUnclaimed nativeFencePhase = iota
	nativeFencePhaseClaimed
	nativeFencePhaseWaiting
	nativeFencePhaseReleased
	nativeFencePhaseAborted
)

type nativeFenceClaimState uint8

const (
	nativeFenceClaimDisabled nativeFenceClaimState = iota
	nativeFenceClaimInvalid
	nativeFenceClaimBound
	nativeFenceClaimAlreadyBound
)

type nativeFenceVerdict uint8

const (
	nativeFenceVerdictDisabled nativeFenceVerdict = iota
	nativeFenceVerdictInvalid
	nativeFenceVerdictReleased
	nativeFenceVerdictAborted
)

type nativeFenceReason uint8

const (
	nativeFenceReasonNone nativeFenceReason = iota
	nativeFenceReasonDisabled
	nativeFenceReasonConfig
	nativeFenceReasonState
	nativeFenceReasonCancelled
	nativeFenceReasonEOF
	nativeFenceReasonTimeout
	nativeFenceReasonFrame
	nativeFenceReasonRead
	nativeFenceReasonWrite
	nativeFenceReasonCount
	nativeFenceReasonAttempt
	nativeFenceReasonTerminal
	nativeFenceReasonUnavailable
)

type nativeFenceNotifyStatus uint8

const (
	nativeFenceNotifyIgnored nativeFenceNotifyStatus = iota
	nativeFenceNotifyDone
	nativeFenceNotifyRejected
	nativeFenceNotifyTransportFailed
)

type nativeFenceClaimResult struct {
	state  nativeFenceClaimState
	reason nativeFenceReason
}

type nativeFenceHoldResult struct {
	verdict         nativeFenceVerdict
	reason          nativeFenceReason
	transportFailed bool
}

type nativeFenceNotifyResult struct {
	status          nativeFenceNotifyStatus
	reason          nativeFenceReason
	transportFailed bool
}

// nativeFenceTransportAPI keeps the default, tagged Unix and tagged
// unsupported implementations on the same private finite signatures.
type nativeFenceTransportAPI interface {
	claim(attemptID uint64, childCount int) nativeFenceClaimResult
	hold(ctx context.Context) nativeFenceHoldResult
	publishDrained(attemptID uint64, closedCount int, parentLocked bool) nativeFenceNotifyResult
	publishAdopted(attemptID uint64, childCount int) nativeFenceNotifyResult
	close()
}

var _ nativeFenceTransportAPI = (*nativeFenceTransport)(nil)
