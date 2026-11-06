// This is an explicitly selected trusted acceptance executable, not a product
// transport override. It observes the actual incoming environment, then runs gh.
package main

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"time"

	"golang.org/x/term"
)

type configuration struct{ Record, Mode, GH, Proxy, CA string }

func main() {
	defer func() {
		if recover() != nil {
			fmt.Fprintln(os.Stderr, "owned CLI fixture failed")
			os.Exit(95)
		}
	}()
	if len(os.Args) < 2 {
		panic("configuration required")
	}
	if os.Args[1] == "ctty" {
		if len(os.Args) < 4 || !filepath.IsAbs(os.Args[2]) || !filepath.IsAbs(os.Args[3]) {
			panic("invalid controlling terminal launcher")
		}
		execControllingTTY(os.Args[2], os.Args[3], os.Args[3:], os.Environ())
		return
	}
	raw, e := os.ReadFile(os.Args[1])
	if e != nil {
		panic("configuration unavailable")
	}
	var c configuration
	if json.Unmarshal(raw, &c) != nil {
		panic("invalid configuration")
	}
	allowed := map[string]bool{}
	for _, key := range []string{"GH_TOKEN", "PATH", "HOME", "GH_CONFIG_DIR", "XDG_CONFIG_HOME", "XDG_CACHE_HOME", "XDG_DATA_HOME", "TMPDIR", "TMP", "TEMP"} {
		allowed[key] = true
	}
	keys := []string{}
	only := len(os.Environ()) == len(allowed)
	for _, entry := range os.Environ() {
		key, _, ok := strings.Cut(entry, "=")
		if !ok || !allowed[key] {
			only = false
		}
		keys = append(keys, key)
	}
	sort.Strings(keys)
	paths := map[string]string{}
	private := true
	for key := range allowed {
		if key == "GH_TOKEN" || key == "PATH" {
			continue
		}
		path := os.Getenv(key)
		paths[key] = path
		st, err := os.Stat(path)
		if err != nil || !st.IsDir() || st.Mode().Perm()&0077 != 0 {
			private = false
		}
	}
	hash := sha256.Sum256([]byte(os.Getenv("GH_TOKEN")))
	record := map[string]any{"started": true, "environment_keys": keys, "only_reviewed_environment": only, "token_digest": hex.EncodeToString(hash[:]),
		"paths": paths, "helper_path": os.Getenv("PATH"), "private_directories": private, "stdio_tty": []bool{term.IsTerminal(0), term.IsTerminal(1), term.IsTerminal(2)}, "terminal_echo_restored": terminalEcho()}
	raw, e = json.Marshal(record)
	if e != nil || os.WriteFile(c.Record, raw, 0600) != nil {
		panic("record failed")
	}
	if os.Getenv("GH_TOKEN") == "" || !only || !private || !terminalEcho() {
		os.Exit(92)
	}
	for _, path := range paths {
		if os.WriteFile(filepath.Join(path, "owned-nonsecret-proof"), []byte("private child configuration area\n"), 0600) != nil {
			panic("private directory not writable")
		}
	}
	switch c.Mode {
	case "stdio":
		line := make([]byte, len("owned stdin marker\n"))
		if _, e = io.ReadFull(os.Stdin, line); e != nil || string(line) != "owned stdin marker\n" {
			os.Exit(93)
		}
		fmt.Fprintln(os.Stdout, "owned child stdout")
		fmt.Fprintln(os.Stderr, "owned child stderr")
		os.Exit(23)
	case "slow":
		time.Sleep(time.Minute)
		return
	case "gh":
		env := append(os.Environ(), "HTTPS_PROXY="+c.Proxy, "HTTP_PROXY="+c.Proxy, "NO_PROXY=", "SSL_CERT_FILE="+c.CA, "GH_NO_UPDATE_NOTIFIER=1", "GH_PROMPT_DISABLED=1")
		execGH(c.GH, append([]string{c.GH}, os.Args[2:]...), env)
	default:
		os.Exit(94)
	}
}
