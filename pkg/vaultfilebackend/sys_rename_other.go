//go:build !darwin && !linux

package vaultfilebackend

import "os"

// renameNoReplace renames tmp to final on a platform without a local
// directory driver; only the unsupported-platform stubs reach it.
func renameNoReplace(tmp, final string) error { return os.Rename(tmp, final) }
