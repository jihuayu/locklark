package cliprofile

import (
	"bytes"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"net/url"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"unicode/utf8"
)

const maxSlotBytes = 1 << 20

// RenderedFile is one file that must be materialized below the run root.
type RenderedFile struct {
	RelPath string
	Mode    os.FileMode
	Content []byte
}

// RenderedBundle is the complete deterministic child environment and file set.
type RenderedBundle struct {
	Env   []string
	Files []RenderedFile
	Dirs  []string
}

// Render validates a profile binding and produces the exact environment and
// files for one child process. It performs no filesystem or process side
// effects; the caller materializes the result in an isolated root.
func Render(spec Spec, root string, tokenEnvName string, slots map[string][]byte, passthrough map[string]string) (RenderedBundle, error) {
	if root == "" || !filepath.IsAbs(root) || !utf8.ValidString(root) || strings.ContainsRune(root, 0) {
		return RenderedBundle{}, fmt.Errorf("cliprofile: invalid run root")
	}
	known, err := validateSlotValues(spec, slots)
	if err != nil {
		return RenderedBundle{}, err
	}
	if spec.DynamicTokenEnv {
		if !ValidTokenEnvName(tokenEnvName) {
			return RenderedBundle{}, fmt.Errorf("cliprofile: invalid dynamic token environment name")
		}
	} else if tokenEnvName != "" {
		return RenderedBundle{}, fmt.Errorf("cliprofile: dynamic token environment is not enabled")
	}
	for name, value := range passthrough {
		if !ValidPassthroughName(spec, name, value) {
			return RenderedBundle{}, fmt.Errorf("cliprofile: passthrough environment variable refused")
		}
	}

	files := make([]RenderedFile, 0, len(spec.Files))
	for _, file := range spec.Files {
		content, err := renderFile(file, known, slots, root)
		if err != nil {
			return RenderedBundle{}, err
		}
		files = append(files, RenderedFile{RelPath: file.RelPath, Mode: os.FileMode(file.Mode), Content: content})
	}

	env := make(map[string]string, len(spec.Env)+len(passthrough)+1)
	names := make([]string, 0, len(spec.Env))
	for name := range spec.Env {
		names = append(names, name)
	}
	sort.Strings(names)
	for _, name := range names {
		value := spec.Env[name]
		kind, argument, ok := strings.Cut(value, ":")
		if !ok {
			return RenderedBundle{}, fmt.Errorf("cliprofile: invalid environment binding")
		}
		switch kind {
		case "slot":
			slot, ok := known[argument]
			if !ok {
				return RenderedBundle{}, fmt.Errorf("cliprofile: environment references an unknown slot")
			}
			value, present := slots[argument]
			if !present {
				if slot.Optional {
					continue
				}
				return RenderedBundle{}, fmt.Errorf("cliprofile: required slot is missing")
			}
			if bytes.IndexByte(value, 0) >= 0 {
				return RenderedBundle{}, fmt.Errorf("cliprofile: slot contains NUL")
			}
			env[name] = string(value)
		case "file":
			target, err := safeJoin(root, argument, false)
			if err != nil {
				return RenderedBundle{}, err
			}
			env[name] = target
		case "root":
			target, err := safeJoin(root, argument, true)
			if err != nil {
				return RenderedBundle{}, err
			}
			env[name] = target
		case "literal":
			if strings.ContainsRune(argument, 0) {
				return RenderedBundle{}, fmt.Errorf("cliprofile: literal environment value contains NUL")
			}
			env[name] = argument
		default:
			return RenderedBundle{}, fmt.Errorf("cliprofile: unknown environment binding")
		}
	}
	if spec.DynamicTokenEnv {
		env[tokenEnvName] = string(slots["token"])
	}
	for name, value := range passthrough {
		if _, exists := env[name]; !exists {
			env[name] = value
		}
	}

	envNames := make([]string, 0, len(env))
	for name := range env {
		envNames = append(envNames, name)
	}
	sort.Strings(envNames)
	renderedEnv := make([]string, 0, len(envNames))
	for _, name := range envNames {
		renderedEnv = append(renderedEnv, name+"="+env[name])
	}

	return RenderedBundle{
		Env:   renderedEnv,
		Files: files,
		Dirs:  append([]string(nil), spec.Dirs...),
	}, nil
}

func validateSlotValues(spec Spec, slots map[string][]byte) (map[string]Slot, error) {
	known := make(map[string]Slot, len(spec.Slots))
	for _, slot := range spec.Slots {
		if slot.Name == "" {
			return nil, fmt.Errorf("cliprofile: slot without a name")
		}
		if _, exists := known[slot.Name]; exists {
			return nil, fmt.Errorf("cliprofile: duplicate slot name")
		}
		switch slot.Kind {
		case "login":
			switch slot.Field {
			case FieldUsername, FieldPassword, FieldURL, FieldNotes:
			default:
				return nil, fmt.Errorf("cliprofile: invalid login slot field")
			}
		case "document":
			if slot.Field != FieldAttachment && slot.Field != FieldFilename {
				return nil, fmt.Errorf("cliprofile: invalid document slot field")
			}
		default:
			return nil, fmt.Errorf("cliprofile: invalid slot kind")
		}
		known[slot.Name] = slot
	}
	for name, value := range slots {
		if _, ok := known[name]; !ok {
			return nil, fmt.Errorf("cliprofile: value supplied for an unknown slot")
		}
		if len(value) > maxSlotBytes || !utf8.Valid(value) || bytes.IndexByte(value, 0) >= 0 {
			return nil, fmt.Errorf("cliprofile: invalid slot value")
		}
	}
	allOptional := len(spec.Slots) > 0
	anyNonBlank := false
	for _, slot := range spec.Slots {
		value, present := slots[slot.Name]
		if !slot.Optional {
			allOptional = false
			if !present {
				return nil, fmt.Errorf("cliprofile: required slot is missing")
			}
		}
		if !present {
			continue
		}
		blank := len(bytes.TrimSpace(value)) == 0
		if slot.RequireNonBlank && blank {
			return nil, fmt.Errorf("cliprofile: required slot is blank")
		}
		if !blank {
			anyNonBlank = true
		}
	}
	if allOptional && !anyNonBlank {
		return nil, fmt.Errorf("cliprofile: at least one credential value is required")
	}
	access, hasAccess := slots["aws_access_key_id"]
	secret, hasSecret := slots["aws_secret_access_key"]
	if hasAccess || hasSecret {
		if !hasAccess || !hasSecret || len(bytes.TrimSpace(access)) == 0 || len(bytes.TrimSpace(secret)) == 0 {
			return nil, fmt.Errorf("cliprofile: incomplete AWS credential pair")
		}
	}
	return known, nil
}

func renderFile(file FileSpec, known map[string]Slot, slots map[string][]byte, root string) ([]byte, error) {
	switch {
	case file.Format == "empty-v1":
		return []byte{}, nil
	case strings.HasPrefix(file.Format, "raw-slot:"):
		name := strings.TrimPrefix(file.Format, "raw-slot:")
		if _, ok := known[name]; !ok {
			return nil, fmt.Errorf("cliprofile: raw file references an unknown slot")
		}
		value, present := slots[name]
		if !present || len(value) == 0 || len(value) > maxSlotBytes || bytes.IndexByte(value, 0) >= 0 || !utf8.Valid(value) {
			return nil, fmt.Errorf("cliprofile: raw file slot is missing or invalid")
		}
		return bytes.Clone(value), nil
	case file.Format == "docker-auths-v1":
		return renderDockerAuths(slots)
	case file.Format == "npmrc-v1":
		return renderNPMRC(slots)
	case file.Format == "pgpass-v1":
		return renderPGPass(slots)
	case file.Format == "netrc-v1":
		return renderNetrc(slots)
	case file.Format == "git-askpass-secret-v1":
		return renderAskpassSecret(slots)
	case file.Format == "git-askpass-helper-v1":
		return []byte("#!/bin/sh\ncase \"$1\" in\n*Username*|*username*) sed -n '1p' \"$LOCKLARK_GIT_SECRET_FILE\" ;;\n*) sed -n '2p' \"$LOCKLARK_GIT_SECRET_FILE\" ;;\nesac\n"), nil
	case file.Format == "git-credentials-v1":
		return renderGitCredentials(slots)
	case file.Format == "git-config-store-v1":
		return renderGitConfig(root)
	case file.Format == "codex-auth-v1":
		return renderCodexAuth(slots)
	default:
		return nil, fmt.Errorf("cliprofile: unknown file format")
	}
}

func slotText(slots map[string][]byte, name string) string {
	return string(slots[name])
}

func nonBlank(s string) bool { return len(strings.TrimSpace(s)) > 0 }

func renderDockerAuths(slots map[string][]byte) ([]byte, error) {
	username, password := slotText(slots, "username"), slotText(slots, "password")
	if !nonBlank(username) || !nonBlank(password) {
		return nil, fmt.Errorf("cliprofile: docker credentials are blank")
	}
	if strings.Contains(username, ":") {
		return nil, fmt.Errorf("cliprofile: docker username contains a colon")
	}
	if strings.ContainsAny(username, "\r\n\x00") || strings.ContainsAny(password, "\r\n\x00") {
		return nil, fmt.Errorf("cliprofile: docker credentials contain a line break or NUL")
	}
	registry := strings.TrimSpace(slotText(slots, "registry"))
	if registry == "" {
		registry = "https://index.docker.io/v1/"
	}
	if containsWhitespaceOrControl(registry) {
		return nil, fmt.Errorf("cliprofile: docker registry contains whitespace or control characters")
	}
	auth := base64.StdEncoding.EncodeToString([]byte(username + ":" + password))
	type dockerAuth struct {
		Auth string `json:"auth"`
	}
	document := struct {
		Auths map[string]dockerAuth `json:"auths"`
	}{Auths: map[string]dockerAuth{registry: {Auth: auth}}}
	raw, err := json.Marshal(document)
	if err != nil {
		return nil, fmt.Errorf("cliprofile: docker config encoding failed")
	}
	return append(raw, '\n'), nil
}

func normalizeNPMRegistry(raw string) (string, error) {
	raw = strings.TrimSpace(raw)
	if raw == "" {
		raw = "https://registry.npmjs.org/"
	}
	if containsWhitespaceOrControl(raw) {
		return "", fmt.Errorf("cliprofile: npm registry contains whitespace or control characters")
	}
	lower := strings.ToLower(raw)
	if strings.Contains(lower, "://") && !strings.HasPrefix(lower, "https://") && !strings.HasPrefix(lower, "http://") {
		return "", fmt.Errorf("cliprofile: unsupported npm registry scheme")
	}
	switch {
	case strings.HasPrefix(lower, "https://"):
		raw = raw[len("https://"):]
	case strings.HasPrefix(lower, "http://"):
		raw = raw[len("http://"):]
	}
	raw = strings.TrimPrefix(raw, "//")
	if raw == "" {
		return "", fmt.Errorf("cliprofile: npm registry is empty")
	}
	parsed, err := url.Parse("https://" + raw)
	if err != nil || parsed.Host == "" || parsed.User != nil || parsed.RawQuery != "" || parsed.Fragment != "" {
		return "", fmt.Errorf("cliprofile: invalid npm registry")
	}
	registry := parsed.Host + parsed.EscapedPath()
	if registry == "" {
		return "", fmt.Errorf("cliprofile: invalid npm registry")
	}
	if !strings.HasSuffix(registry, "/") {
		registry += "/"
	}
	return registry, nil
}

func renderNPMRC(slots map[string][]byte) ([]byte, error) {
	token := slotText(slots, "token")
	if !nonBlank(token) {
		return nil, fmt.Errorf("cliprofile: npm token is blank")
	}
	if containsWhitespaceOrControl(token) {
		return nil, fmt.Errorf("cliprofile: npm token contains whitespace or control characters")
	}
	registry, err := normalizeNPMRegistry(slotText(slots, "registry"))
	if err != nil {
		return nil, err
	}
	return []byte("//" + registry + ":_authToken=" + token + "\n"), nil
}

func parsePGURL(raw string) (host, port, database string, err error) {
	host, port, database = "*", "*", "*"
	raw = strings.TrimSpace(raw)
	if raw == "" {
		return host, port, database, nil
	}
	candidate := raw
	if !strings.Contains(candidate, "://") {
		candidate = "postgres://" + candidate
	}
	parsed, err := url.Parse(candidate)
	if err != nil || parsed.Hostname() == "" {
		return "", "", "", fmt.Errorf("cliprofile: invalid PostgreSQL URL")
	}
	host = parsed.Hostname()
	if parsed.Port() != "" {
		port = parsed.Port()
	}
	if parsed.Path != "" && parsed.Path != "/" {
		database = strings.TrimPrefix(parsed.Path, "/")
	}
	return host, port, database, nil
}

func escapePGPass(value string) string {
	value = strings.ReplaceAll(value, `\`, `\\`)
	return strings.ReplaceAll(value, ":", `\:`)
}

func renderPGPass(slots map[string][]byte) ([]byte, error) {
	username, password := slotText(slots, "username"), slotText(slots, "password")
	if !nonBlank(username) || !nonBlank(password) {
		return nil, fmt.Errorf("cliprofile: PostgreSQL credentials are blank")
	}
	host, port, database, err := parsePGURL(slotText(slots, "url"))
	if err != nil {
		return nil, err
	}
	fields := []string{host, port, database, username, password}
	for _, field := range fields {
		if strings.ContainsAny(field, "\r\n\x00") {
			return nil, fmt.Errorf("cliprofile: PostgreSQL field contains a line break or NUL")
		}
	}
	return []byte(strings.Join([]string{
		escapePGPass(host), escapePGPass(port), escapePGPass(database),
		escapePGPass(username), escapePGPass(password),
	}, ":") + "\n"), nil
}

func hostOnly(raw, fallback string) (string, error) {
	raw = strings.TrimSpace(raw)
	if raw == "" {
		return fallback, nil
	}
	candidate := raw
	if !strings.Contains(candidate, "://") {
		candidate = "https://" + candidate
	}
	parsed, err := url.Parse(candidate)
	if err != nil || parsed.Hostname() == "" {
		return "", fmt.Errorf("cliprofile: invalid URL host")
	}
	return parsed.Hostname(), nil
}

func renderNetrc(slots map[string][]byte) ([]byte, error) {
	username, password := slotText(slots, "username"), slotText(slots, "password")
	if !nonBlank(username) || !nonBlank(password) {
		return nil, fmt.Errorf("cliprofile: netrc credentials are blank")
	}
	host, err := hostOnly(slotText(slots, "url"), "github.com")
	if err != nil {
		return nil, err
	}
	if containsWhitespaceOrControl(username) || containsWhitespaceOrControl(password) || containsWhitespaceOrControl(host) {
		return nil, fmt.Errorf("cliprofile: netrc fields contain whitespace or control characters")
	}
	return []byte("machine " + host + " login " + username + " password " + password + "\n"), nil
}

func renderAskpassSecret(slots map[string][]byte) ([]byte, error) {
	username, password := slotText(slots, "username"), slotText(slots, "password")
	if !nonBlank(username) || !nonBlank(password) {
		return nil, fmt.Errorf("cliprofile: askpass credentials are blank")
	}
	if strings.ContainsAny(username, "\r\n\x00") || strings.ContainsAny(password, "\r\n\x00") {
		return nil, fmt.Errorf("cliprofile: askpass credentials contain a line break or NUL")
	}
	return []byte(username + "\n" + password + "\n"), nil
}

func renderGitCredentials(slots map[string][]byte) ([]byte, error) {
	raw := strings.TrimSpace(slotText(slots, "url"))
	scheme, host := "https", "github.com"
	if raw != "" {
		candidate := raw
		if !strings.Contains(candidate, "://") {
			candidate = "https://" + candidate
		}
		parsed, err := url.Parse(candidate)
		if err != nil || parsed.Host == "" {
			return nil, fmt.Errorf("cliprofile: invalid git credential URL")
		}
		if parsed.Scheme == "http" || parsed.Scheme == "https" {
			scheme = parsed.Scheme
		}
		host = parsed.Host
	}
	credentials := url.UserPassword(slotText(slots, "username"), slotText(slots, "password")).String()
	return []byte(scheme + "://" + credentials + "@" + host + "\n"), nil
}

func renderGitConfig(root string) ([]byte, error) {
	credentialPath := filepath.ToSlash(filepath.Join(root, "git", "credentials"))
	if strings.ContainsAny(credentialPath, "\r\n\"") {
		return nil, fmt.Errorf("cliprofile: git credential path contains an unsafe character")
	}
	return []byte("[credential]\n\thelper = store --file=" + credentialPath + "\n"), nil
}

func renderCodexAuth(slots map[string][]byte) ([]byte, error) {
	token := slotText(slots, "token")
	if !nonBlank(token) {
		return nil, fmt.Errorf("cliprofile: Codex API key is blank")
	}
	if strings.ContainsAny(token, "\r\n\x00") {
		return nil, fmt.Errorf("cliprofile: Codex API key contains a line break or NUL")
	}
	raw, err := json.Marshal(struct {
		AuthMode string `json:"auth_mode"`
		APIKey   string `json:"OPENAI_API_KEY"`
	}{AuthMode: "apikey", APIKey: token})
	if err != nil {
		return nil, fmt.Errorf("cliprofile: Codex auth document unavailable")
	}
	return append(raw, '\n'), nil
}

func safeJoin(root, relative string, allowEmpty bool) (string, error) {
	if strings.ContainsRune(relative, 0) || !utf8.ValidString(relative) {
		return "", fmt.Errorf("cliprofile: invalid relative path")
	}
	rel := filepath.FromSlash(relative)
	if rel == "" {
		if allowEmpty {
			return root, nil
		}
		return "", fmt.Errorf("cliprofile: empty relative path")
	}
	if filepath.IsAbs(rel) || strings.HasPrefix(rel, string(filepath.Separator)) || filepath.Clean(rel) != rel || rel == "." || rel == ".." || strings.HasPrefix(rel, ".."+string(filepath.Separator)) {
		return "", fmt.Errorf("cliprofile: relative path escapes the run root")
	}
	target := filepath.Join(root, rel)
	check, err := filepath.Rel(root, target)
	if err != nil || check == "." || strings.HasPrefix(check, "..") {
		return "", fmt.Errorf("cliprofile: relative path escapes the run root")
	}
	return target, nil
}
