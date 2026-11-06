// Package teamclient coordinates local team identities. It is native-only and
// never derives team keys from personal-vault or quick-unlock material.
package teamclient

import (
	"errors"

	"github.com/jihuayu/locklark/internal/directory"
)

type SystemStore interface {
	Store(string, []byte) error
	Load(string) ([]byte, error)
	Delete(string) error
}

type DeviceState string

const (
	DevicePreparing DeviceState = "preparing"
	DevicePending   DeviceState = "pending"
	DeviceUnknown   DeviceState = "unknown"
)

var ErrIdentity = errors.New("invalid trusted team device identity")
var ErrProtection = errors.New("system device identity protection unavailable")
var ErrCancelled = errors.New("team device operation cancelled")
var ErrConsumed = errors.New("team device operation already used")
var ErrAdmission = errors.New("team device admission refused")

type DeviceDescriptor struct {
	Version   int              `json:"version"`
	Role      string           `json:"role"`
	ProfileID string           `json:"profile_id"`
	InstallID string           `json:"install_id"`
	Scope     string           `json:"scope"`
	Pins      directory.Pins   `json:"pins"`
	Device    directory.Device `json:"device"`
	State     DeviceState      `json:"state"`
}
