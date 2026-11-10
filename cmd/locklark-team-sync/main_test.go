package main

import (
	"bytes"
	"crypto/ed25519"
	"encoding/hex"
	"encoding/json"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"

	"github.com/jihuayu/locklark/internal/directory"
	"github.com/jihuayu/locklark/internal/teamsync"
)

func configFixture(t *testing.T) (string, serverConfig) {
	t.Helper()
	root := t.TempDir()
	key := func(n byte) string {
		k := ed25519.NewKeyFromSeed(bytes.Repeat([]byte{n}, 32))
		return hex.EncodeToString(k.Public().(ed25519.PublicKey))
	}
	pins := directory.Pins{Team: strings.Repeat("a", 32), Vault: strings.Repeat("b", 32), Owners: []string{key(1)}, Sequencer: key(2), Publisher: key(3)}
	c, e := directory.NewConfigWithWriterACL(pins)
	if e != nil {
		t.Fatal(e)
	}
	conf := serverConfig{Pins: pins, Minimum: c.Genesis(), Directory: filepath.Join(root, "team.db"), Anchor: filepath.Join(root, "server.anchor"), Listen: "127.0.0.1:8443", Certificate: filepath.Join(root, "cert.pem"), TLSKey: filepath.Join(root, "key.pem")}
	raw, _ := json.Marshal(conf)
	path := filepath.Join(root, "config.json")
	if os.WriteFile(path, raw, 0600) != nil {
		t.Fatal("configuration fixture failed")
	}
	return path, conf
}
func TestServerCLIRejectsSecretArgumentsWithoutEcho(t *testing.T) {
	for _, arg := range []string{"--seed", "--sequencer-key", "--key-file", "--password", "--token"} {
		var out bytes.Buffer
		if run([]string{"serve", arg, "private-cli-secret-canary"}, &out) == nil || strings.Contains(out.String(), "private-cli-secret-canary") {
			t.Fatal("server accepted or echoed a secret argument")
		}
	}
}
func TestServerCLIExplicitAnchorInitialization(t *testing.T) {
	path, conf := configFixture(t)
	var out bytes.Buffer
	if run([]string{"init-anchor", "--config", path}, &out) != nil {
		t.Fatal("explicit anchor initialization failed")
	}
	store, e := teamsync.OpenFileAnchorStore(conf.Anchor)
	if e != nil {
		t.Fatal(e)
	}
	cp, e := store.Load()
	if e != nil || cp != conf.Minimum {
		t.Fatal("anchor did not use independent configured minimum")
	}
	if run([]string{"init-anchor", "--config", path}, &out) == nil {
		t.Fatal("existing server anchor overwritten")
	}
	if strings.Contains(out.String(), "private-cli") {
		t.Fatal("CLI output disclosed a value")
	}
}
func TestServerConfigRejectsAmbiguousOrUntrustedFiles(t *testing.T) {
	path, conf := configFixture(t)
	raw, _ := json.Marshal(conf)
	if _, _, e := readConfig(path); e != nil {
		t.Fatal("valid configuration refused")
	}
	for _, bad := range [][]byte{
		append(append([]byte(nil), raw...), []byte(`{}`)...),
		bytes.Replace(raw, []byte(`"listen":`), []byte(`"listen":"127.0.0.1:443","listen":`), 1),
		bytes.Replace(raw, []byte(`"listen":`), []byte(`"private_seed":"must-not-load","listen":`), 1),
	} {
		if os.WriteFile(path, bad, 0600) != nil {
			t.Fatal("fixture rewrite failed")
		}
		if _, _, e := readConfig(path); e == nil {
			t.Fatal("ambiguous/unknown server configuration accepted")
		}
	}
	if os.WriteFile(path, raw, 0600) != nil {
		t.Fatal("fixture restore failed")
	}
	if runtime.GOOS != "windows" {
		if os.Chmod(path, 0644) != nil {
			t.Fatal("fixture chmod failed")
		}
		if _, _, e := readConfig(path); e == nil {
			t.Fatal("publicly readable private server config accepted")
		}
		_ = os.Chmod(path, 0600)
	}
	alias := filepath.Join(filepath.Dir(path), "alias.json")
	if os.Symlink(path, alias) == nil {
		if _, _, e := readConfig(alias); e == nil {
			t.Fatal("server config symlink accepted")
		}
	}
}

func TestServerHelpFlagsEmitStructuredUsage(t *testing.T) {
	for _, arg := range []string{"help", "--help", "-h"} {
		var out bytes.Buffer
		if err := run([]string{arg}, &out); err != nil {
			t.Fatalf("run(%q) failed: %v", arg, err)
		}
		text := out.String()
		for _, want := range []string{"USAGE", "init-anchor", "serve", "prepare-identity", "EXIT CODES"} {
			if !strings.Contains(text, want) {
				t.Fatalf("team-sync help (%s) missing %q: %s", arg, want, text)
			}
		}
	}
}
