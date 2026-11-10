//go:build linux || darwin || windows

package sshagent

import (
	"bytes"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"
	"testing"

	"golang.org/x/crypto/ssh"
)

func TestNativeOpenSSHGitCommitSigning(t *testing.T) {
	if os.Getenv("LOCKLARK_TEST_OPENSSH") != "1" {
		t.Skip("explicit native OpenSSH runtime gate disabled")
	}
	git, err := exec.LookPath("git")
	if err != nil {
		t.Fatal("native Git unavailable")
	}
	keygen := nativeSSHKeygen(t)
	endpoint := nativeTestEndpoint(t)
	handler := newTestHandler(t)
	service, err := Start(endpoint, handler)
	if err != nil {
		t.Fatal("native SSH agent endpoint unavailable")
	}
	defer service.Close()

	repo := t.TempDir()
	publicFile := filepath.Join(repo, "signing.pub")
	emptyConfig := filepath.Join(repo, "empty.gitconfig")
	if err = os.WriteFile(publicFile, ssh.MarshalAuthorizedKey(handler.signer.PublicKey()), 0600); err != nil {
		t.Fatal("signing public key fixture failed")
	}
	if err = os.WriteFile(emptyConfig, nil, 0600); err != nil {
		t.Fatal("empty Git configuration fixture failed")
	}
	environment := append([]string(nil), os.Environ()...)
	environment = append(environment,
		"SSH_AUTH_SOCK="+service.Endpoint(),
		"GIT_CONFIG_GLOBAL="+emptyConfig,
		"GIT_CONFIG_NOSYSTEM=1",
		"GIT_TERMINAL_PROMPT=0",
	)
	run := func(args ...string) []byte {
		t.Helper()
		command := exec.Command(git, args...)
		command.Dir = repo
		command.Env = environment
		var stderr bytes.Buffer
		command.Stderr = &stderr
		output, err := command.Output()
		if err != nil {
			t.Fatalf("Git command failed: %s", fixedGitFailure(stderr.Bytes()))
		}
		return output
	}

	run("init", "-q")
	run("config", "user.name", "Locklark fixture")
	run("config", "user.email", "locklark@example.invalid")
	run("config", "gpg.format", "ssh")
	run("config", "user.signingkey", publicFile)
	run("config", "gpg.ssh.program", keygen)
	if err = os.WriteFile(filepath.Join(repo, "signed.txt"), []byte("signed fixture\n"), 0600); err != nil {
		t.Fatal("Git fixture file failed")
	}
	run("add", "signed.txt")
	run("-c", "commit.gpgsign=true", "commit", "-q", "-m", "signed fixture")
	object := run("cat-file", "-p", "HEAD")
	if !bytes.Contains(object, []byte("\ngpgsig -----BEGIN SSH SIGNATURE-----\n")) || handler.calls.Load() < 1 {
		t.Fatal("Git commit did not use the private custom SSH agent")
	}
}

func nativeSSHKeygen(t *testing.T) string {
	t.Helper()
	if runtime.GOOS == "windows" {
		path := filepath.Join(os.Getenv("WINDIR"), "System32", "OpenSSH", "ssh-keygen.exe")
		if info, err := os.Stat(path); err != nil || info.IsDir() {
			t.Fatal("native Windows ssh-keygen unavailable")
		}
		return path
	}
	path, err := exec.LookPath("ssh-keygen")
	if err != nil {
		t.Fatal("native ssh-keygen unavailable")
	}
	return path
}

func fixedGitFailure(stderr []byte) string {
	for _, marker := range []string{
		"failed to write commit object",
		"failed to sign",
		"ssh-keygen",
		"signing failed",
		"error:",
	} {
		if strings.Contains(strings.ToLower(string(stderr)), marker) {
			return "signing category: " + marker
		}
	}
	return "fixed category"
}
