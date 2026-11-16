//go:build darwin || linux

package main

import (
	"bytes"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"testing"

	"github.com/jihuayu/locklark/internal/personal"
	"github.com/jihuayu/locklark/internal/teamfiles"
)

func TestVaultFileCreateRejectsCompanionPathAliasesBeforeMutation(t *testing.T) {
	for _, alias := range []string{"personal", "journal", "archive", "backend-root"} {
		t.Run(alias, func(t *testing.T) {
			root := t.TempDir()
			private := filepath.Join(root, "private")
			journalDir := filepath.Join(root, "journal")
			if os.Mkdir(private, 0700) != nil || os.Mkdir(journalDir, 0700) != nil {
				t.Fatal("CREATE_ALIAS_PRIVATE_FIXTURE_FAILED")
			}
			config := filepath.Join(private, "create.json")
			companion := config + ".baseline"
			manifest := vaultFileCreateManifest{Version: 1, Kind: vaultFileCreateKind,
				PersonalFile: filepath.Join(root, "personal.ll"), BackendRoot: filepath.Join(root, "backend"),
				Name: "owned-g", Journal: filepath.Join(journalDir, "genesis.journal"),
				Archive: filepath.Join(root, "published.llb")}
			switch alias {
			case "personal":
				manifest.PersonalFile = companion
			case "journal":
				manifest.Journal = companion
			case "archive":
				manifest.Archive = companion
			case "backend-root":
				manifest.BackendRoot = companion
			}
			if personal.Create(manifest.PersonalFile, "alias-full-factor", bytes.Repeat([]byte{0x5a}, 16)) != nil {
				t.Fatal("CREATE_ALIAS_PERSONAL_FIXTURE_FAILED")
			}
			personalBefore, err := os.ReadFile(manifest.PersonalFile)
			if err != nil {
				t.Fatal("CREATE_ALIAS_PERSONAL_READ_FAILED")
			}
			if validVaultFileCreateManifestPhase(config, manifest, false, false) {
				t.Fatal("CREATE_ALIAS_INITIAL_VALIDATION_ACCEPTED")
			}
			var output bytes.Buffer
			err = runVaultFileCreate([]string{"--config", config, "--personal-file", manifest.PersonalFile,
				"--backend-root", manifest.BackendRoot, "--name", manifest.Name,
				"--journal", manifest.Journal, "--archive", manifest.Archive}, &output)
			if !errors.Is(err, errVaultFileConfig) || output.Len() != 0 {
				t.Fatal("CREATE_ALIAS_INITIAL_CALL_DID_NOT_REJECT")
			}
			if _, err := os.Lstat(config); !os.IsNotExist(err) {
				t.Fatal("CREATE_ALIAS_INITIAL_CALL_WROTE_MANIFEST")
			}
			if after, err := os.ReadFile(manifest.PersonalFile); err != nil || !bytes.Equal(after, personalBefore) {
				t.Fatal("CREATE_ALIAS_INITIAL_CALL_CHANGED_PERSONAL")
			}
			if alias == "backend-root" {
				if _, err := os.Lstat(companion); !os.IsNotExist(err) {
					t.Fatal("CREATE_ALIAS_BACKEND_CREATED_COMPANION")
				}
				if _, err := os.Lstat(filepath.Join(companion, "vaultfile-backend")); !os.IsNotExist(err) {
					t.Fatal("CREATE_ALIAS_BACKEND_MUTATED")
				}
			}
			manifest.VaultID = "a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1"
			encoded, err := json.Marshal(manifest)
			if err != nil || teamfiles.WriteNew(config, encoded) != nil {
				t.Fatal("CREATE_ALIAS_PERSISTED_FIXTURE_FAILED")
			}
			if _, _, err := readVaultFileCreateManifest(config); !errors.Is(err, errVaultFileLocalReview) {
				t.Fatal("CREATE_ALIAS_PERSISTED_VALIDATION_ACCEPTED")
			}
			output.Reset()
			if err := runVaultFileCreate([]string{"--config", config}, &output); !errors.Is(err, errVaultFileLocalReview) || output.Len() != 0 {
				t.Fatal("CREATE_ALIAS_PERSISTED_CALL_DID_NOT_REJECT")
			}
			if after, err := os.ReadFile(config); err != nil || !bytes.Equal(after, encoded) {
				t.Fatal("CREATE_ALIAS_PERSISTED_MANIFEST_CHANGED")
			}
		})
	}
}
