package personal

import (
	"bytes"
	"testing"

	"github.com/jihuayu/locklark/internal/vault"
)

func TestClearDecodedArchiveSensitiveOwnsAllByteBuffers(t *testing.T) {
	itemAttachment := []byte{1, 2, 3}
	itemV2Attachment := []byte{4, 5, 6}
	itemImportSource := []byte{7, 8, 9}
	itemSSHSeed := []byte{10, 11, 12}
	backupOnlyAttachment := []byte{13, 14, 15}
	rootSeed := []byte{16, 17, 18}
	recoverySigningSeed := []byte{19, 20, 21}
	recoveryAgeIdentity := []byte{22, 23, 24}
	p := &payload{
		Items: []vault.Item{{Attachment: itemAttachment,
			Attachments:  []vault.AttachmentMeta{{Content: itemV2Attachment}},
			ImportSource: itemImportSource, SSHSeed: itemSSHSeed}},
		Attachments: []backupAttachment{{Content: backupOnlyAttachment}},
		VaultFileOwners: []vaultFileOwnerRecord{{OwnerRootSeed: rootSeed,
			RecoverySigningSeed: recoverySigningSeed, RecoveryAgeIdentity: recoveryAgeIdentity}},
	}
	clearDecodedArchiveSensitive(p)
	for _, buffer := range [][]byte{itemAttachment, itemV2Attachment, itemImportSource, itemSSHSeed,
		backupOnlyAttachment, rootSeed, recoverySigningSeed, recoveryAgeIdentity} {
		if !bytes.Equal(buffer, make([]byte, len(buffer))) {
			t.Fatal("RECOVERY_DECODED_BUFFER_NOT_ZEROED")
		}
	}
	clearDecodedArchiveSensitive(nil)
}
