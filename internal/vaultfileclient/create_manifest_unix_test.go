//go:build darwin || linux

package vaultfileclient

import (
	"bytes"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/jihuayu/locklark/internal/personal"
	"github.com/jihuayu/locklark/internal/teamfiles"
)

func createManifestFixture(t *testing.T) (string, Manifest) {
	t.Helper()
	root := t.TempDir()
	private := filepath.Join(root, "private")
	if os.Mkdir(private, 0700) != nil {
		t.Fatal("RESERVE_PRIVATE_FIXTURE_FAILED")
	}
	manifest := Manifest{Version: 1, Kind: CreateKind,
		PersonalFile: filepath.Join(root, "personal.ll"), BackendRoot: filepath.Join(root, "backend"),
		Name: "owned-g", Journal: filepath.Join(private, "genesis.journal"),
		Archive: filepath.Join(root, "published.llb")}
	if personal.Create(manifest.PersonalFile, "reserve-fixture-factor", bytes.Repeat([]byte{0x5d}, 16)) != nil {
		t.Fatal("RESERVE_PERSONAL_FIXTURE_FAILED")
	}
	return filepath.Join(private, "create.json"), manifest
}

func TestReserveManifestUnknownKeepsPublishedInode(t *testing.T) {
	path, input := createManifestFixture(t)
	var owned os.FileInfo
	var original []byte
	writeThenUnknown := func(path string, raw []byte) error {
		if err := teamfiles.WriteNew(path, raw); err != nil {
			return err
		}
		var err error
		owned, err = os.Lstat(path)
		if err != nil {
			return err
		}
		original = bytes.Clone(raw)
		return teamfiles.ErrPublicationUnknown
	}
	got, err := reserveManifestWithWriter(path, input, writeThenUnknown)
	if err != ErrLocalUnknown || got != (Manifest{}) {
		t.Fatal("RESERVE_UNKNOWN_ADOPTED")
	}
	stat, err := os.Lstat(path)
	if err != nil || owned == nil || !os.SameFile(owned, stat) {
		t.Fatal("RESERVE_UNKNOWN_INODE_CHANGED")
	}
	current, err := os.ReadFile(path)
	if err != nil || !bytes.Equal(current, original) {
		t.Fatal("RESERVE_UNKNOWN_BYTES_CHANGED")
	}
	if _, exists, err := ReadManifest(path); err != nil || !exists {
		t.Fatal("RESERVE_UNKNOWN_NOT_READABLE")
	}
}

func TestReserveManifestAdoptsOnlyExactPublisherWinner(t *testing.T) {
	for _, foreign := range []bool{false, true} {
		name := "exact"
		if foreign {
			name = "foreign"
		}
		t.Run(name, func(t *testing.T) {
			path, input := createManifestFixture(t)
			winner := input
			winner.VaultID = strings.Repeat("a", 32)
			if foreign {
				winner.Name = "foreign-g"
			}
			winnerBytes, err := json.Marshal(winner)
			if err != nil {
				t.Fatal("RESERVE_WINNER_ENCODE_FAILED")
			}
			var published os.FileInfo
			writeWinner := func(path string, _ []byte) error {
				if err := teamfiles.WriteNew(path, winnerBytes); err != nil {
					return err
				}
				published, err = os.Lstat(path)
				if err != nil {
					return err
				}
				return teamfiles.ErrFile
			}
			got, err := reserveManifestWithWriter(path, input, writeWinner)
			if foreign {
				if err != ErrLocalUnknown || got != (Manifest{}) {
					t.Fatal("RESERVE_FOREIGN_ADOPTED")
				}
			} else if err != nil || got != winner {
				t.Fatal("RESERVE_EXACT_WINNER_REJECTED")
			}
			stat, err := os.Lstat(path)
			if err != nil || published == nil || !os.SameFile(published, stat) {
				t.Fatal("RESERVE_WINNER_INODE_CHANGED")
			}
			current, err := os.ReadFile(path)
			if err != nil || !bytes.Equal(current, winnerBytes) {
				t.Fatal("RESERVE_WINNER_BYTES_CHANGED")
			}
		})
	}
}

func TestReserveManifestNormalRetryKeepsVaultID(t *testing.T) {
	path, input := createManifestFixture(t)
	first, err := ReserveManifest(path, input)
	if err != nil || first.VaultID == "" {
		t.Fatal("RESERVE_FIRST_FAILED")
	}
	owned, err := os.Lstat(path)
	if err != nil {
		t.Fatal("RESERVE_FIRST_INODE_MISSING")
	}
	second, err := ReserveManifest(path, input)
	if err != nil || second != first {
		t.Fatal("RESERVE_RETRY_CHANGED_ID")
	}
	stat, err := os.Lstat(path)
	if err != nil || !os.SameFile(owned, stat) {
		t.Fatal("RESERVE_RETRY_CHANGED_INODE")
	}
}
