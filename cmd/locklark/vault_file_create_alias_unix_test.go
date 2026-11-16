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

func TestVaultFileCreateRejectsMissingCaseOnlyAliases(t *testing.T) {
	for _, alias := range []string{"journal", "archive", "backend-root", "archive-parent-link", "backend-namespace"} {
		t.Run(alias, func(t *testing.T) {
			root := t.TempDir()
			private := filepath.Join(root, "private")
			backend := filepath.Join(root, "backend")
			if os.Mkdir(private, 0700) != nil || os.Mkdir(backend, 0700) != nil {
				t.Fatal("CREATE_CASE_ALIAS_PRIVATE_FIXTURE_FAILED")
			}
			config := filepath.Join(private, "create.json")
			companion := config + ".baseline"
			manifest := vaultFileCreateManifest{Version: 1, Kind: vaultFileCreateKind,
				PersonalFile: filepath.Join(root, "personal.ll"), BackendRoot: backend,
				Name: "owned-g", Journal: filepath.Join(private, "genesis.journal"),
				Archive: filepath.Join(root, "published.llb")}
			caseAlias := config + ".BASELINE"
			switch alias {
			case "journal":
				manifest.Journal = caseAlias
			case "archive":
				manifest.Archive = caseAlias
			case "backend-root":
				manifest.BackendRoot = caseAlias
			case "archive-parent-link":
				link := filepath.Join(root, "linked-private")
				if os.Symlink(private, link) != nil {
					t.Fatal("CREATE_CASE_ALIAS_PARENT_LINK_FAILED")
				}
				manifest.Archive = filepath.Join(link, "create.json.BASELINE")
			case "backend-namespace":
				manifest.Archive = filepath.Join(backend, "VAULTFILE-BACKEND")
			}
			if personal.Create(manifest.PersonalFile, "case-alias-factor", bytes.Repeat([]byte{0x6b}, 16)) != nil {
				t.Fatal("CREATE_CASE_ALIAS_PERSONAL_FIXTURE_FAILED")
			}
			personalBefore, err := os.ReadFile(manifest.PersonalFile)
			if err != nil {
				t.Fatal("CREATE_CASE_ALIAS_PERSONAL_READ_FAILED")
			}
			if validVaultFileCreateManifestPhase(config, manifest, false, false) {
				t.Fatal("CREATE_CASE_ALIAS_INITIAL_VALIDATION_ACCEPTED")
			}
			var output bytes.Buffer
			err = runVaultFileCreate([]string{"--config", config, "--personal-file", manifest.PersonalFile,
				"--backend-root", manifest.BackendRoot, "--name", manifest.Name,
				"--journal", manifest.Journal, "--archive", manifest.Archive}, &output)
			if !errors.Is(err, errVaultFileConfig) || output.Len() != 0 {
				t.Fatal("CREATE_CASE_ALIAS_INITIAL_CALL_DID_NOT_REJECT")
			}
			if _, err := os.Lstat(config); !os.IsNotExist(err) {
				t.Fatal("CREATE_CASE_ALIAS_INITIAL_CALL_WROTE_MANIFEST")
			}
			if _, err := os.Lstat(companion); !os.IsNotExist(err) {
				t.Fatal("CREATE_CASE_ALIAS_INITIAL_CALL_WROTE_COMPANION")
			}
			if after, err := os.ReadFile(manifest.PersonalFile); err != nil || !bytes.Equal(after, personalBefore) {
				t.Fatal("CREATE_CASE_ALIAS_INITIAL_CALL_CHANGED_PERSONAL")
			}
			if entries, err := os.ReadDir(backend); err != nil || len(entries) != 0 {
				t.Fatal("CREATE_CASE_ALIAS_INITIAL_CALL_CHANGED_BACKEND")
			}
			manifest.VaultID = "a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1"
			encoded, err := json.Marshal(manifest)
			if err != nil || teamfiles.WriteNew(config, encoded) != nil {
				t.Fatal("CREATE_CASE_ALIAS_PERSISTED_FIXTURE_FAILED")
			}
			if _, _, err := readVaultFileCreateManifest(config); !errors.Is(err, errVaultFileLocalReview) {
				t.Fatal("CREATE_CASE_ALIAS_PERSISTED_VALIDATION_ACCEPTED")
			}
			output.Reset()
			if err := runVaultFileCreate([]string{"--config", config}, &output); !errors.Is(err, errVaultFileLocalReview) || output.Len() != 0 {
				t.Fatal("CREATE_CASE_ALIAS_PERSISTED_CALL_DID_NOT_REJECT")
			}
			if after, err := os.ReadFile(config); err != nil || !bytes.Equal(after, encoded) {
				t.Fatal("CREATE_CASE_ALIAS_PERSISTED_MANIFEST_CHANGED")
			}
		})
	}
}

func TestVaultFileCreateRejectsMissingUnicodeNormalizationAliases(t *testing.T) {
	for _, alias := range []string{"journal", "backend-root", "backend-namespace"} {
		t.Run(alias, func(t *testing.T) {
			root := t.TempDir()
			private := filepath.Join(root, "private")
			if os.Mkdir(private, 0700) != nil {
				t.Fatal("CREATE_NORM_ALIAS_PRIVATE_FIXTURE_FAILED")
			}
			config := filepath.Join(private, "cr\u00e9ate.json")
			companion := config + ".baseline"
			decomposedCompanion := filepath.Join(private, "cre\u0301ate.json.baseline")
			if companion == decomposedCompanion {
				t.Fatal("CREATE_NORM_ALIAS_FIXTURE_NOT_DISTINCT")
			}
			manifest := vaultFileCreateManifest{Version: 1, Kind: vaultFileCreateKind,
				PersonalFile: filepath.Join(root, "personal.ll"), BackendRoot: filepath.Join(root, "backend"),
				Name: "owned-g", Journal: filepath.Join(private, "genesis.journal"),
				Archive: filepath.Join(root, "published.llb")}
			switch alias {
			case "journal":
				manifest.Journal = decomposedCompanion
			case "backend-root":
				manifest.BackendRoot = decomposedCompanion
			case "backend-namespace":
				manifest.BackendRoot = filepath.Join(root, "b\u00e9ckend")
				decomposedRoot := filepath.Join(root, "be\u0301ckend")
				if os.Mkdir(manifest.BackendRoot, 0700) != nil {
					t.Fatal("CREATE_NORM_ALIAS_BACKEND_FIXTURE_FAILED")
				}
				if err := os.Mkdir(decomposedRoot, 0700); err != nil && !os.IsExist(err) {
					t.Fatal("CREATE_NORM_ALIAS_BACKEND_PARENT_FAILED")
				}
				manifest.Archive = filepath.Join(decomposedRoot, "vaultfile-backend")
			}
			if personal.Create(manifest.PersonalFile, "norm-alias-factor", bytes.Repeat([]byte{0x7c}, 16)) != nil {
				t.Fatal("CREATE_NORM_ALIAS_PERSONAL_FIXTURE_FAILED")
			}
			personalBefore, err := os.ReadFile(manifest.PersonalFile)
			if err != nil {
				t.Fatal("CREATE_NORM_ALIAS_PERSONAL_READ_FAILED")
			}
			if validVaultFileCreateManifestPhase(config, manifest, false, false) {
				t.Fatal("CREATE_NORM_ALIAS_INITIAL_VALIDATION_ACCEPTED")
			}
			var output bytes.Buffer
			err = runVaultFileCreate([]string{"--config", config, "--personal-file", manifest.PersonalFile,
				"--backend-root", manifest.BackendRoot, "--name", manifest.Name,
				"--journal", manifest.Journal, "--archive", manifest.Archive}, &output)
			if !errors.Is(err, errVaultFileConfig) || output.Len() != 0 {
				t.Fatal("CREATE_NORM_ALIAS_INITIAL_CALL_DID_NOT_REJECT")
			}
			if _, err := os.Lstat(config); !os.IsNotExist(err) {
				t.Fatal("CREATE_NORM_ALIAS_INITIAL_CALL_WROTE_MANIFEST")
			}
			if _, err := os.Lstat(companion); !os.IsNotExist(err) {
				t.Fatal("CREATE_NORM_ALIAS_INITIAL_CALL_WROTE_COMPANION")
			}
			if after, err := os.ReadFile(manifest.PersonalFile); err != nil || !bytes.Equal(after, personalBefore) {
				t.Fatal("CREATE_NORM_ALIAS_INITIAL_CALL_CHANGED_PERSONAL")
			}
			if alias == "backend-namespace" {
				if entries, err := os.ReadDir(manifest.BackendRoot); err != nil || len(entries) != 0 {
					t.Fatal("CREATE_NORM_ALIAS_INITIAL_CALL_CHANGED_BACKEND")
				}
			}
			manifest.VaultID = "a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1"
			encoded, err := json.Marshal(manifest)
			if err != nil || teamfiles.WriteNew(config, encoded) != nil {
				t.Fatal("CREATE_NORM_ALIAS_PERSISTED_FIXTURE_FAILED")
			}
			if _, _, err := readVaultFileCreateManifest(config); !errors.Is(err, errVaultFileLocalReview) {
				t.Fatal("CREATE_NORM_ALIAS_PERSISTED_VALIDATION_ACCEPTED")
			}
			output.Reset()
			if err := runVaultFileCreate([]string{"--config", config}, &output); !errors.Is(err, errVaultFileLocalReview) || output.Len() != 0 {
				t.Fatal("CREATE_NORM_ALIAS_PERSISTED_CALL_DID_NOT_REJECT")
			}
			if after, err := os.ReadFile(config); err != nil || !bytes.Equal(after, encoded) {
				t.Fatal("CREATE_NORM_ALIAS_PERSISTED_MANIFEST_CHANGED")
			}
		})
	}
}
