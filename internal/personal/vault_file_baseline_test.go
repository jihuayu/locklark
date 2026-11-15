package personal

import (
	"bytes"
	"crypto/ed25519"
	"testing"

	"github.com/jihuayu/locklark/pkg/vaultfile"
)

// The duplicate case is deliberately malformed input defense: the current
// vault-file validator forbids identical device key material in a valid policy.
func TestLocalVaultFileReaderDevicePairAndAmbiguity(t *testing.T) {
	key := ed25519.PublicKey(bytes.Repeat([]byte{0x2a}, ed25519.PublicKeySize))
	device := vaultfile.Device{DeviceID: "reader-device", PrincipalID: "reader", AgeEncryptionKey: "age1owned",
		ContentSigningKey: vaultfile.PublicKey{Alg: vaultfile.SigAlgEd25519, PublicKey: key}}
	policy := &vaultfile.Policy{Readers: []vaultfile.Member{{PrincipalID: "reader"}}, Devices: []vaultfile.Device{device}}
	if got, ok := localVaultFileReaderDevice(policy, device.AgeEncryptionKey, key); !ok || got != device.DeviceID {
		t.Fatal("MATCHING_READER_NOT_SELECTED")
	}
	if _, ok := localVaultFileReaderDevice(policy, device.AgeEncryptionKey, bytes.Repeat([]byte{0x3b}, ed25519.PublicKeySize)); ok {
		t.Fatal("FOREIGN_SIGNING_KEY_SELECTED")
	}
	if _, ok := localVaultFileReaderDevice(policy, "age1foreign", key); ok {
		t.Fatal("FOREIGN_AGE_RECIPIENT_SELECTED")
	}
	policy.Readers = nil
	if _, ok := localVaultFileReaderDevice(policy, device.AgeEncryptionKey, key); ok {
		t.Fatal("NO_ROLE_DEVICE_SELECTED")
	}
	policy.Readers = []vaultfile.Member{{PrincipalID: "reader"}}
	copyDevice := device
	copyDevice.DeviceID = "reader-duplicate"
	policy.Devices = append(policy.Devices, copyDevice)
	if _, ok := localVaultFileReaderDevice(policy, device.AgeEncryptionKey, key); ok {
		t.Fatal("AMBIGUOUS_DEVICE_SELECTED")
	}
}
