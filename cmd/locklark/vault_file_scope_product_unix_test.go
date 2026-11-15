//go:build darwin || linux

package main

import (
	"bytes"
	"context"
	"encoding/json"
	"os"
	"os/exec"
	"path/filepath"
	"testing"
	"time"

	"github.com/jihuayu/locklark/pkg/vaultfilebackend"
)

func writeResumeScopeConfig(t *testing.T, c resumeProductCase) {
	t.Helper()
	raw, err := json.Marshal(c.cfg)
	if err != nil || os.WriteFile(c.configPath, raw, 0600) != nil {
		t.Fatal("SCOPE_CONFIGURATION_CREATE_FAILED")
	}
}

func moveResumeScopeJournal(t *testing.T, c *resumeProductCase, target string) {
	t.Helper()
	if os.Rename(c.cfg.Journal, target) != nil {
		t.Fatal("SCOPE_JOURNAL_MOVE_FAILED")
	}
	c.cfg.Journal = target
}

func moveResumeScopeConfig(t *testing.T, c *resumeProductCase, target string) {
	t.Helper()
	if os.Rename(c.configPath, target) != nil {
		t.Fatal("SCOPE_CONFIGURATION_MOVE_FAILED")
	}
	c.configPath = target
}

func resumeScopeAlias(t *testing.T, c resumeProductCase, target string) string {
	t.Helper()
	alias := filepath.Join(c.root, "ancestor-alias")
	if os.Symlink(target, alias) != nil {
		t.Fatal("SCOPE_ANCESTOR_ALIAS_CREATE_FAILED")
	}
	return alias
}

// Capability is established by two real lookups of the same existing inode.
// Case-sensitive filesystems do not run or claim a case-alias product case.
func resumeScopeCaseAliases(t *testing.T) bool {
	t.Helper()
	root := t.TempDir()
	path := filepath.Join(root, "case-probe")
	if os.Mkdir(path, 0700) != nil {
		t.Fatal("CASE_PROBE_CREATE_FAILED")
	}
	a, err := os.Stat(path)
	if err != nil {
		t.Fatal("CASE_PROBE_STAT_FAILED")
	}
	b, err := os.Stat(filepath.Join(root, "CASE-PROBE"))
	if os.IsNotExist(err) {
		t.Log("CASE_ALIAS_UNAVAILABLE")
		return false
	}
	if err != nil || !os.SameFile(a, b) {
		t.Fatal("CASE_PROBE_IDENTITY_FAILED")
	}
	t.Log("CASE_ALIAS_CONFIRMED")
	return true
}

func assertResumeScopeRefusal(t *testing.T, product string, c resumeProductCase, material resumeProductMaterial) {
	t.Helper()
	before := resumeDisk(t, c.root)
	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
	defer cancel()
	cmd := exec.CommandContext(ctx, product, "vault-file", "resume-prepared", "--config", c.configPath)
	var stdout, stderr bytes.Buffer
	cmd.Stdout, cmd.Stderr = &stdout, &stderr
	err := cmd.Run()
	if ctx.Err() != nil {
		t.Fatal("SCOPE_PRODUCT_TIMED_OUT")
	}
	refused := err != nil && stdout.Len() == 0 && stderr.String() == "locklark: CONFIG_REJECTED\n"
	if !refused {
		// The original-product red run records only fixed evidence enums,
		// never the child output, configuration, pin, path or underlying error.
		t.Error("SCOPE_PRECHECK_DID_NOT_REJECT")
		if _, err := os.Lstat(c.cfg.Journal); os.IsNotExist(err) {
			t.Log("SCOPE_JOURNAL_UNLINKED")
		}
		backend, openErr := vaultfilebackend.OpenExistingDir(c.cfg.BackendRoot)
		if openErr == nil {
			remote, readErr := backend.Read(context.Background(), c.cfg.Name)
			closed := backend.Close()
			if readErr == nil && closed == nil && bytes.Equal(remote.Bytes, material.p) {
				t.Log("SCOPE_REMOTE_CHANGED_TO_EXACT_P")
			}
		}
	}
	after := resumeDisk(t, c.root)
	if len(before) != len(after) {
		t.Error("SCOPE_REFUSAL_CHANGED_DISK")
		return
	}
	for path, original := range before {
		if got, exists := after[path]; !exists || got != original {
			t.Error("SCOPE_REFUSAL_CHANGED_DISK")
			return
		}
	}
}

func TestVaultFileResumeProductManagedScope(t *testing.T) {
	product := vaultFileProductBinary(t)
	material := newResumeProductMaterial(t)
	cases := []string{
		"JOURNAL_TMP_OP", "CONFIG_TMP_OP", "JOURNAL_DATA", "CONFIG_NAMESPACE_OTHER",
		"JOURNAL_NAMESPACE_ROOT", "ROOT_ANCESTOR_SYMLINK", "JOURNAL_ANCESTOR_SYMLINK",
		"CONFIG_ANCESTOR_SYMLINK", "NEAR_PREFIX_SIBLING",
	}
	if resumeScopeCaseAliases(t) {
		cases = append(cases, "ROOT_CASE_ALIAS", "CONFIG_NAMESPACE_CASE_ALIAS")
	}
	for _, name := range cases {
		t.Run(name, func(t *testing.T) {
			c := newResumeProductCase(t, material, true)
			ns := filepath.Join(c.cfg.BackendRoot, "vaultfile-backend")
			tmp := filepath.Join(ns, "v1", "tmp")
			op := "op-00112233445566778899aabbccddeeff"
			switch name {
			case "JOURNAL_TMP_OP", "ROOT_ANCESTOR_SYMLINK", "JOURNAL_ANCESTOR_SYMLINK", "ROOT_CASE_ALIAS":
				moveResumeScopeJournal(t, &c, filepath.Join(tmp, op))
				if name == "ROOT_ANCESTOR_SYMLINK" {
					alias := resumeScopeAlias(t, c, c.root)
					c.cfg.BackendRoot = filepath.Join(alias, "backend")
				} else if name == "JOURNAL_ANCESTOR_SYMLINK" {
					alias := resumeScopeAlias(t, c, filepath.Join(ns, "v1"))
					c.cfg.Journal = filepath.Join(alias, "tmp", op)
				} else if name == "ROOT_CASE_ALIAS" {
					c.cfg.BackendRoot = filepath.Join(c.root, "BACKEND")
				}
			case "CONFIG_TMP_OP", "CONFIG_ANCESTOR_SYMLINK", "CONFIG_NAMESPACE_CASE_ALIAS":
				moveResumeScopeConfig(t, &c, filepath.Join(tmp, op))
				if name == "CONFIG_ANCESTOR_SYMLINK" {
					alias := resumeScopeAlias(t, c, filepath.Join(ns, "v1"))
					c.configPath = filepath.Join(alias, "tmp", op)
				} else if name == "CONFIG_NAMESPACE_CASE_ALIAS" {
					c.configPath = filepath.Join(c.cfg.BackendRoot, "VAULTFILE-BACKEND", "v1", "tmp", op)
				}
			case "JOURNAL_DATA":
				moveResumeScopeJournal(t, &c, filepath.Join(ns, "v1", "data", "journal.db"))
			case "CONFIG_NAMESPACE_OTHER":
				other := filepath.Join(ns, "future-version", "metadata")
				if os.MkdirAll(other, 0700) != nil {
					t.Fatal("SCOPE_OTHER_SUBDIRECTORY_CREATE_FAILED")
				}
				moveResumeScopeConfig(t, &c, filepath.Join(other, "operator.json"))
			case "JOURNAL_NAMESPACE_ROOT":
				moveResumeScopeJournal(t, &c, filepath.Join(ns, "journal.db"))
			case "NEAR_PREFIX_SIBLING":
				sibling := filepath.Join(c.cfg.BackendRoot, "vaultfile-backend-owned")
				if os.Mkdir(sibling, 0700) != nil {
					t.Fatal("SCOPE_SIBLING_CREATE_FAILED")
				}
				moveResumeScopeJournal(t, &c, filepath.Join(sibling, "journal.db"))
				moveResumeScopeConfig(t, &c, filepath.Join(sibling, "operator.json"))
			}
			writeResumeScopeConfig(t, c)
			if name == "NEAR_PREFIX_SIBLING" {
				invokeResumeProduct(t, product, c.configPath, "RESUMED")
				verifyResumeProductResult(t, c, material, "")
				return
			}
			assertResumeScopeRefusal(t, product, c, material)
		})
	}
}
