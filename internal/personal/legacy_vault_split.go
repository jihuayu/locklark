package personal

import "github.com/jihuayu/locklark/internal/vault"

// LegacyVaultSplitGroup locates records in the verified legacy archive by
// zero-based item index. IndexedAttachments counts the separate attachment
// records. Legacy document bytes stay part of their item record.
type LegacyVaultSplitGroup struct {
	ItemIndexes        []int
	HistoryEntries     int
	IndexedAttachments int
}

// PreflightLegacyVaultSplit verifies encrypted archive bytes with the existing
// recovery factors and pinned archive digest. It returns the implicit default
// group followed by the declared groups in signed source order, including
// empty groups. It performs no I/O and returns no record contents.
//
// The result accounts for records in this archive only. Import and recovery
// into independent VaultFiles require per-vault trusted checkpoints (#123).
func PreflightLegacyVaultSplit(archive []byte, pw string, key []byte, kit string) ([]LegacyVaultSplitGroup, error) {
	p, err := verifyRecoveryArchive(archive, pw, key, kit, true)
	if err != nil {
		return nil, err
	}
	defer clearAuthenticatedItems(p.Items)
	return reconcileLegacyVaultSplit(p)
}

// reconcileLegacyVaultSplit runs only after the verifier has checked item
// identity, vault declarations, and the attachment-to-item bindings.
func reconcileLegacyVaultSplit(p *payload) ([]LegacyVaultSplitGroup, error) {
	groups := make([]LegacyVaultSplitGroup, len(p.Vaults)+1)
	groupByVault := make(map[string]int, len(groups))
	groupByVault[vault.DefaultVaultID] = 0
	for i, declaration := range p.Vaults {
		groupByVault[declaration.ID] = i + 1
	}

	attachments := 0
	for i := range p.Items {
		item := &p.Items[i]
		groupIndex, ok := groupByVault[item.EffectiveVaultID()]
		if !ok {
			return nil, ErrBackupMissingSubVault
		}
		group := &groups[groupIndex]
		group.ItemIndexes = append(group.ItemIndexes, i)
		group.HistoryEntries += len(item.History)
		group.IndexedAttachments += len(item.Attachments)
		attachments += len(item.Attachments)
	}
	// The legacy decoder can reconstruct an omitted zero-byte attachment.
	// Reconciliation requires an explicit source record even in that case.
	if attachments != len(p.Attachments) {
		return nil, invalid
	}
	return groups, nil
}
