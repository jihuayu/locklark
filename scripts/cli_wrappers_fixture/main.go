// Command cli-wrappers-fixture is an independently built fake CLI used by the
// cli-wrappers acceptance controller. It is intentionally small: help/version
// must work without any credential, and report mode hashes whatever credential
// environment or files the runner materialized without printing their values.
package main

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"runtime"
	"strings"
)

type fileReport struct {
	Mode   string `json:"mode,omitempty"`
	SHA256 string `json:"sha256,omitempty"`
	OK     bool   `json:"ok"`
	Error  string `json:"error,omitempty"`
}

type report struct {
	Tool      string                `json:"tool,omitempty"`
	OK        bool                  `json:"ok"`
	EnvSHA256 map[string]string     `json:"env_sha256,omitempty"`
	Files     map[string]fileReport `json:"files,omitempty"`
	Errors    []string              `json:"errors,omitempty"`
}

var secretEnvironmentNames = map[string]bool{
	"GH_TOKEN":                    true,
	"GITHUB_TOKEN":                true,
	"AWS_ACCESS_KEY_ID":           true,
	"AWS_SECRET_ACCESS_KEY":       true,
	"AWS_SESSION_TOKEN":           true,
	"TF_TOKEN_app_terraform_io":   true,
	"OPENAI_API_KEY":              true,
	"ANTHROPIC_API_KEY":           true,
	"STRIPE_API_KEY":              true,
	"FLY_API_TOKEN":               true,
	"VERCEL_TOKEN":                true,
	"LOCKLARK_TEST_SECRET_CANARY": true,
}

func isSecretEnvironmentName(name string) bool {
	if secretEnvironmentNames[name] {
		return true
	}
	upper := strings.ToUpper(name)
	for _, suffix := range []string{"_TOKEN", "_API_KEY", "_ACCESS_KEY", "_SECRET", "_PASSWORD"} {
		if strings.HasSuffix(upper, suffix) {
			return true
		}
	}
	return false
}

func digestFile(path string) (string, error) {
	file, err := os.Open(path)
	if err != nil {
		return "", err
	}
	defer file.Close()
	hash := sha256.New()
	if _, err = io.Copy(hash, io.LimitReader(file, 1<<20)); err != nil {
		return "", err
	}
	return hex.EncodeToString(hash.Sum(nil)), nil
}

func inspectFile(path string, wantMode os.FileMode) fileReport {
	result := fileReport{OK: false}
	info, err := os.Lstat(path)
	if err != nil || !info.Mode().IsRegular() {
		result.Error = "unavailable"
		return result
	}
	result.Mode = fmt.Sprintf("%04o", info.Mode().Perm())
	if runtime.GOOS != "windows" && info.Mode().Perm() != wantMode {
		result.Error = "unsafe mode"
		return result
	}
	digest, err := digestFile(path)
	if err != nil {
		result.Error = "unreadable"
		return result
	}
	result.SHA256 = digest
	result.OK = true
	return result
}

func environmentPath(name string) (path, expectedName string, wantMode os.FileMode, present bool) {
	value := os.Getenv(name)
	if value == "" {
		return "", "", 0, false
	}
	switch name {
	case "DOCKER_CONFIG":
		return filepath.Join(value, "config.json"), "DOCKER_CONFIG/config.json", 0600, true
	case "GIT_ASKPASS":
		return value, "GIT_ASKPASS", 0700, true
	default:
		return value, name, 0600, true
	}
}

func buildReport(tool string) report {
	result := report{
		Tool:      tool,
		OK:        true,
		EnvSHA256: map[string]string{},
		Files:     map[string]fileReport{},
	}
	for _, entry := range os.Environ() {
		name, value, ok := strings.Cut(entry, "=")
		if !ok || value == "" || !isSecretEnvironmentName(name) {
			continue
		}
		sum := sha256.Sum256([]byte(value))
		result.EnvSHA256[name] = hex.EncodeToString(sum[:])
	}

	for _, name := range []string{"KUBECONFIG", "DOCKER_CONFIG", "NPM_CONFIG_USERCONFIG", "PGPASSFILE", "GIT_ASKPASS", "NETRC", "LOCKLARK_GIT_SECRET_FILE", "GIT_CONFIG_GLOBAL"} {
		path, key, wantMode, present := environmentPath(name)
		if !present {
			continue
		}
		file := inspectFile(path, wantMode)
		result.Files[key] = file
		if !file.OK {
			result.OK = false
			result.Errors = append(result.Errors, key+": "+file.Error)
		}
	}
	return result
}

func writeReport(path string, value report) error {
	raw, err := json.MarshalIndent(value, "", "  ")
	if err != nil {
		return err
	}
	raw = append(raw, '\n')
	file, err := os.OpenFile(path, os.O_WRONLY|os.O_CREATE|os.O_TRUNC, 0600)
	if err != nil {
		return err
	}
	failed := true
	defer func() {
		if failed {
			file.Close()
			os.Remove(path)
		}
	}()
	if err = file.Chmod(0600); err != nil {
		return err
	}
	if _, err = file.Write(raw); err != nil {
		return err
	}
	if err = file.Sync(); err != nil {
		return err
	}
	if err = file.Close(); err != nil {
		return err
	}
	failed = false
	return nil
}

func main() {
	for _, arg := range os.Args[1:] {
		if arg == "--help" || arg == "-h" || arg == "--version" {
			fmt.Print("fixture help output\n")
			return
		}
	}
	if len(os.Args) < 2 || os.Args[1] == "" {
		os.Exit(2)
	}
	tool := ""
	if len(os.Args) > 2 {
		tool = os.Args[2]
	}
	if err := writeReport(os.Args[1], buildReport(tool)); err != nil {
		os.Exit(3)
	}
}
