//go:build android

package personal

// Android SELinux forbids hard links for untrusted applications, including
// links within their own private data. Publish the complete fsynced database
// with a kernel-enforced, non-overwriting rename instead.
func publish(tmp, path string) error { return publishRenameNoReplace(tmp, path) }
