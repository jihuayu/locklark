package vaultfilebackend

import "fmt"

// deniedMsg wraps ErrDenied (and cause, when non-nil) with context.
func deniedMsg(cause error, msg string) error {
	if cause == nil {
		return fmt.Errorf("%w: %s", ErrDenied, msg)
	}
	return fmt.Errorf("%w: %s: %w", ErrDenied, msg, cause)
}
