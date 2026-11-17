package vaultfileclient

import (
	"os"
	"path/filepath"
	"strings"
)

// SeparateStatusState uses backend path metadata only for namespace separation.
// A missing path is safe only when an existing, resolved directory has an
// absent child; dangling links, loops, non-directories and inaccessible paths
// are refused. Mutating commands retain their stricter existing-backend check.
func SeparateStatusState(backendRoot string, paths ...string) error {
	namespacePath := filepath.Join(backendRoot, "vaultfile-backend")
	for _, path := range paths {
		if path == namespacePath || strings.HasPrefix(path, namespacePath+string(os.PathSeparator)) {
			return ErrConfig
		}
	}
	root, absent, err := statusExistingDir(backendRoot)
	if err != nil {
		return ErrBackend
	}
	if absent {
		return nil
	}
	namespace, err := os.Lstat(filepath.Join(root, "vaultfile-backend"))
	if os.IsNotExist(err) {
		return nil
	}
	if err != nil || !namespace.IsDir() || namespace.Mode()&os.ModeSymlink != 0 {
		return ErrBackend
	}
	for _, path := range paths {
		if info, err := os.Stat(path); err == nil && os.SameFile(namespace, info) {
			return ErrConfig
		}
		parent, err := filepath.EvalSymlinks(filepath.Dir(path))
		if err != nil {
			return ErrConfig
		}
		for {
			info, err := os.Stat(parent)
			if err != nil || !info.IsDir() || os.SameFile(namespace, info) {
				return ErrConfig
			}
			next := filepath.Dir(parent)
			if next == parent {
				break
			}
			parent = next
		}
	}
	return nil
}

// Resolve each existing component separately so ENOENT means a truly absent
// child, not the target of a dangling ancestor symlink.
func statusExistingDir(path string) (string, bool, error) {
	root, components := statusPathRootComponents(path, filepath.VolumeName(path), string(os.PathSeparator))
	// An absent drive or UNC share is not an absent child of a trusted parent.
	// Prove the volume root before accepting ENOENT in the walk below.
	resolved, err := filepath.EvalSymlinks(root)
	if err != nil {
		return "", false, err
	}
	info, err := os.Stat(resolved)
	if err != nil || !info.IsDir() {
		return "", false, ErrBackend
	}
	for _, component := range components {
		if component == "" {
			continue
		}
		next := filepath.Join(resolved, component)
		if _, err := os.Lstat(next); os.IsNotExist(err) {
			return "", true, nil
		} else if err != nil {
			return "", false, err
		}
		resolved, err = filepath.EvalSymlinks(next)
		if err != nil {
			return "", false, err
		}
		info, err := os.Stat(resolved)
		if err != nil || !info.IsDir() {
			return "", false, ErrBackend
		}
	}
	return resolved, false, nil
}

// The volume is part of the walk's root on Windows (drive or UNC share).
// Keeping the split pure also makes its platform-specific starting point
// testable without probing a host drive or share.
func statusPathRootComponents(path, volume, separator string) (string, []string) {
	rest := strings.TrimPrefix(path[len(volume):], separator)
	return volume + separator, strings.Split(rest, separator)
}
