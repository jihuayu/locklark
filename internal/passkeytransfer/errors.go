package passkeytransfer

import "errors"

// ErrRefused is the only error surfaced by this package. It deliberately
// carries no age/JSON/path/provider detail so callers cannot leak secrets or
// environment information through error text.
var ErrRefused = errors.New("passkey transfer refused")
