package personal

import (
	"errors"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"unicode/utf8"

	"github.com/jihuayu/locklark/internal/cliprofile"
)

// writeRunBundleFiles materializes rendered files without following symlinks at
// the final component and only below an existing, real directory root. Every
// parent is created owner-only and revalidated before a child is opened.
func writeRunBundleFiles(root string, files []cliprofile.RenderedFile) error {
	if root == "" || !filepath.IsAbs(root) || filepath.Clean(root) != root || !utf8.ValidString(root) || strings.ContainsRune(root, 0) {
		return errors.New("invalid run bundle root")
	}
	info, err := os.Lstat(root)
	if err != nil || !info.IsDir() || info.Mode()&os.ModeSymlink != 0 {
		return errors.New("run bundle root is not a real directory")
	}
	for _, file := range files {
		if file.RelPath == "" || filepath.IsAbs(file.RelPath) || strings.ContainsRune(file.RelPath, 0) || file.Mode != 0600 && file.Mode != 0700 {
			return errors.New("invalid run bundle file specification")
		}
		rel := filepath.FromSlash(file.RelPath)
		if filepath.IsAbs(rel) || strings.HasPrefix(rel, string(filepath.Separator)) || filepath.Clean(rel) != rel || strings.HasPrefix(rel, "..") {
			return errors.New("run bundle file path escapes root")
		}
		target := filepath.Join(root, rel)
		check, err := filepath.Rel(root, target)
		if err != nil || check == "." || strings.HasPrefix(check, "..") {
			return errors.New("run bundle file path escapes root")
		}
		if err = ensureRunBundleParents(root, filepath.Dir(target)); err != nil {
			return err
		}
		if err = writePrivateRunFile(target, file.Content, file.Mode); err != nil {
			return err
		}
	}
	return nil
}

func ensureRunBundleParents(root, parent string) error {
	rel, err := filepath.Rel(root, parent)
	if err != nil || strings.HasPrefix(rel, "..") {
		return errors.New("run bundle parent escapes root")
	}
	if rel == "." {
		return nil
	}
	current := root
	for _, part := range strings.Split(rel, string(filepath.Separator)) {
		current = filepath.Join(current, part)
		info, err := os.Lstat(current)
		if os.IsNotExist(err) {
			if err = os.Mkdir(current, 0700); err != nil {
				return err
			}
			info, err = os.Lstat(current)
		}
		if err != nil || !info.IsDir() || info.Mode()&os.ModeSymlink != 0 {
			return errors.New("run bundle parent is not a real directory")
		}
		if runtime.GOOS != "windows" && info.Mode().Perm() != 0700 {
			return errors.New("run bundle parent is not owner-only")
		}
	}
	return nil
}
