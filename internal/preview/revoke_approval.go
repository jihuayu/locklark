package preview

import (
	"strings"

	bolt "go.etcd.io/bbolt"
)

// A per-approval cancellation competes in the same writer transaction as
// the execution intent. Once consumed it cannot be retroactively revoked.
func RevokeApproval(device, request, review, reason string) (UseReport, error) {
	if !validID(request) || !hexSize(review, 32) || !validReason(reason) {
		return UseReport{}, errInvoke
	}
	id, err := mailIdentity(device)
	if err != nil {
		return UseReport{}, err
	}
	key, err := localSigner(device, "decision")
	if err != nil {
		return UseReport{}, err
	}
	defer clear(key)
	audit, err := localSigner(device, "journal")
	if err != nil {
		return UseReport{}, err
	}
	defer clear(audit)
	var report UseReport
	err = withHistory(device, id, true, func(b *bolt.Bucket, h history) error {
		if old, ok := h.uses[request]; ok {
			if old.State == "revoked" && old.Review == review && old.Reason == strings.TrimSpace(reason) {
				report = old.UseReport
				return nil
			}
			return errInvoke
		}
		for _, d := range h.decisions {
			if d.Request.ID == request && d.Request.Review == review && d.Result == "approved" {
				report = UseReport{Pull: d.Request.Pull, ID: request, Session: d.Request.Session, Review: review, State: "revoked", Reason: strings.TrimSpace(reason)}
				return appendUse(b, h, useRecord{UseReport: report}, key, audit, id)
			}
		}
		return errInvoke
	})
	if err != nil {
		return UseReport{}, err
	}
	return report, nil
}
