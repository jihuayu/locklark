package teamfiles

// ValidatePrivateParent accepts an existing directory used as a manifest or
// profile-list parent. On Unix it requires a real directory with no group or
// world permission bits (Perm&0077==0), so 0500 and 0700 both pass. On Windows
// it validates the target leaf DACL and the existing trusted-ancestor policy.
// It never changes the path.
func ValidatePrivateParent(path string) error {
	return validatePrivateParent(path)
}

// ValidatePrivateWorkspace accepts an existing exact workspace or settings
// leaf. On Unix that means a real 0700 directory; on Windows it means the
// target-leaf private DACL. It never changes the path.
func ValidatePrivateWorkspace(path string) error {
	return validatePrivateWorkspace(path)
}

// ValidatePrivateFile accepts an existing exact private file. On Unix that
// means a real 0600 regular file; on Windows it means the private file DACL.
// It never changes the path.
func ValidatePrivateFile(path string) error {
	return validatePrivateFile(path)
}

// EnsurePrivateWorkspace creates a missing workspace leaf with the exact
// workspace policy and validates it. An existing leaf is validated only and is
// never chmodded or have its DACL rewritten. On Unix a missing leaf requires an
// existing real parent whose mode has no group or world write bits
// (Perm&0022==0); the new leaf is created 0700. On Windows a missing leaf is
// created with a protected current-user-only DACL and then validated.
func EnsurePrivateWorkspace(path string) error {
	return ensurePrivateWorkspace(path)
}
