package main

import (
	"errors"
	"io"

	"github.com/jihuayu/locklark/internal/vaultfileinspect"
)

const vaultfileHelp = `usage: locklark vaultfile inspect --file PATH --checkpoint FILE

Read-only metadata inspection of one sealed vault file. The checkpoint file is
an explicit caller trust input; it is not derived from the file. Policy chain
and content signature are verified, but the KDBX payload is not decrypted or
AEAD-verified. No profile, account, session, provider, network, or write path
is opened.

Checkpoint JSON fields:
  v, vault_id, owner_root_key_id, owner_root_public_key, policy_seq,
  policy_digest
The key and digest use canonical 32-byte RawURL base64.

Output is a single JSON object with fixed result enums, counts, and hashes.
`

func runVaultfile(args []string, out io.Writer) error {
	if len(args) == 0 || args[0] == "help" || args[0] == "--help" || args[0] == "-h" {
		_, err := io.WriteString(out, vaultfileHelp)
		return err
	}
	if args[0] != "inspect" {
		return errors.New("unknown vaultfile command")
	}
	if len(args) > 1 && (args[1] == "help" || args[1] == "--help" || args[1] == "-h") {
		_, err := io.WriteString(out, vaultfileHelp)
		return err
	}
	return vaultfileinspect.Run(args[1:], out)
}
