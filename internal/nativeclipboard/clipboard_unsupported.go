//go:build (!linux && !windows && !darwin) || ((linux || windows || darwin) && !amd64 && !arm64)

package nativeclipboard

const leaseSupported = false

func write([]byte) (*Lease, error) { return nil, ErrUnsupported }
func clearOwned(*Lease) Result     { return Unavailable }
