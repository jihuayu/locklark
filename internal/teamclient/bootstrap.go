package teamclient

import (
	"errors"

	"github.com/jihuayu/locklark/internal/directory"
	"github.com/jihuayu/locklark/internal/vault"
)

var ErrProfile = errors.New("team bootstrap profile unavailable or invalid")
var ErrBootstrapUnknown = errors.New("team bootstrap outcome unknown; reconcile the original operation")
var ErrBootstrapConflict = errors.New("team bootstrap does not match the original operation")

type BootstrapPhase string

const (
	BootstrapPreparing BootstrapPhase = "preparing"
	BootstrapPending   BootstrapPhase = "pending"
	BootstrapUnknown   BootstrapPhase = "unknown"
	BootstrapActive    BootstrapPhase = "active"
)

type SequencerDescriptor struct {
	Version   int            `json:"version"`
	ProfileID string         `json:"profile_id"`
	InstallID string         `json:"install_id"`
	ServiceID string         `json:"service_id"`
	Signing   string         `json:"signing"`
	State     BootstrapPhase `json:"state"`
}
type RoleDescriptor struct {
	Version   int    `json:"version"`
	Role      string `json:"role"`
	ProfileID string `json:"profile_id"`
	InstallID string `json:"install_id"`
	Scope     string `json:"scope"`
	Signing   string `json:"signing"`
}
type OwnerDescriptor struct {
	Service   SequencerDescriptor `json:"service"`
	Version   int                 `json:"version"`
	ProfileID string              `json:"profile_id"`
	InstallID string              `json:"install_id"`
	MemberID  string              `json:"member_id"`
	Pins      directory.Pins      `json:"pins"`
	Owner     RoleDescriptor      `json:"owner"`
	Publisher RoleDescriptor      `json:"publisher"`
	Device    DeviceDescriptor    `json:"device"`
	Anchor    string              `json:"anchor"`
	State     BootstrapPhase      `json:"state"`
}
type BootstrapArtifact struct {
	Version  int                 `json:"version"`
	Service  SequencerDescriptor `json:"service"`
	Pins     directory.Pins      `json:"pins"`
	Proposal directory.Proposal  `json:"proposal"`
	Snapshot vault.Snapshot      `json:"snapshot"`
}
type ServiceInitRequest struct {
	Expected    SequencerDescriptor
	TrustedPins directory.Pins
	Artifact    BootstrapArtifact
	Directory   string
	Anchor      string
}
type InitResult struct {
	State          BootstrapPhase
	Checkpoint     directory.Checkpoint
	ArtifactDigest string
}
type InitialResult struct {
	State      BootstrapPhase
	Checkpoint directory.Checkpoint
	DeviceID   string
	ItemCount  int
}
