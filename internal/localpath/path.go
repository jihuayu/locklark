// Package localpath validates local temporary directories before use by
// credential-bearing processes and local IPC endpoints.
package localpath

import "errors"

var ErrUntrusted = errors.New("local temporary directory is not trusted")
