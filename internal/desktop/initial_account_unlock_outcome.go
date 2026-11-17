package desktop

import "github.com/jihuayu/locklark/internal/vaultfileclient"

const initialAccountUnlockChildLimit = 64

type initialAccountUnlockMetadata struct {
	valid          bool
	uniqueChildren int
}

type initialAccountUnlockOutcome struct {
	batch    *localVaultFileInitialBatch
	metadata initialAccountUnlockMetadata
	fence    nativeInitialUnlockFenceLifecycle
}

func newInitialAccountUnlockOutcome(batch *localVaultFileInitialBatch,
	results []vaultfileclient.LocalGenesisBatchResult) *initialAccountUnlockOutcome {
	outcome := &initialAccountUnlockOutcome{}
	if batch == nil {
		return outcome
	}
	outcome.batch = batch
	seen := make(map[*vaultfileclient.LocalGenesisSession]struct{}, len(results))
	unique := 0
	valid := true
	for index := range results {
		result := results[index]
		if result.Wrapper != nil {
			if result.Err != nil {
				valid = false
			}
			if _, exists := seen[result.Wrapper]; exists {
				continue
			}
			seen[result.Wrapper] = struct{}{}
			if unique == initialAccountUnlockChildLimit {
				valid = false
				unique = initialAccountUnlockChildLimit
				break
			}
			unique++
			continue
		}
		if result.Err == nil {
			valid = false
		}
	}
	outcome.metadata = initialAccountUnlockMetadata{valid: valid, uniqueChildren: unique}
	return outcome
}

func (o *initialAccountUnlockOutcome) finiteMetadata() initialAccountUnlockMetadata {
	if o == nil {
		return initialAccountUnlockMetadata{}
	}
	return o.metadata
}
