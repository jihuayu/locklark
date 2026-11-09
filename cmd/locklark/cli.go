package main

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"os/exec"
	"os/signal"
	"path/filepath"
	"regexp"
	"sort"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"syscall"
	"unicode/utf8"

	"github.com/jihuayu/locklark/internal/clibinding"
	"github.com/jihuayu/locklark/internal/cliprofile"
	"github.com/jihuayu/locklark/internal/personal"
	"golang.org/x/term"
)

var cliUsage = errors.New("invalid cli arguments; see locklark help")

var errCLIRecursion = errors.New("recursive locklark cli run is not allowed")

var errCLIChildFailed = errors.New("CLI child process failed to start or did not exit normally")

var (
	cliToolPattern    = regexp.MustCompile(`^[a-z0-9][a-z0-9_-]{0,63}$`)
	cliTargetID       = regexp.MustCompile(`^[0-9a-f]{32}$`)
	cliTargetRevision = regexp.MustCompile(`^[0-9a-f]{64}$`)
)

var cliCoreTools = []string{"aws", "docker", "gh", "git", "kubectl", "npm", "psql", "terraform"}

var cliCommandHelp = map[string]string{
	"profiles":   "usage: locklark cli profiles\n\nList the built-in CLI wrapper profiles as JSON. No binding or vault is read.\n",
	"list":       "usage: locklark cli list [--binding PATH] [--config PATH]\n\nPrint the non-secret CLI binding store as JSON.\n",
	"init":       "usage: locklark cli init|bind <tool> --file PATH --program ABS_PROGRAM [--profile PROFILE] [--binding PATH] [--id ID --revision REV] [--slot-<name> ID:REV] [--helper-path ABS_DIR_LIST] [--passthrough ENV_LIST] [--timeout SECONDS] [--name ENV] [--pin-sha256 true|false]\n\nBind a tool to one profile, one owner-only vault and one pinned executable.\n",
	"bind":       "usage: locklark cli init|bind <tool> --file PATH --program ABS_PROGRAM [--profile PROFILE] [--binding PATH] [--id ID --revision REV] [--slot-<name> ID:REV] [--helper-path ABS_DIR_LIST] [--passthrough ENV_LIST] [--timeout SECONDS] [--name ENV] [--pin-sha256 true|false]\n\nBind a tool to one profile, one owner-only vault and one pinned executable.\n",
	"show":       "usage: locklark cli show <tool> [--binding PATH] [--config PATH]\n\nPrint one non-secret CLI binding as JSON.\n",
	"remove":     "usage: locklark cli remove <tool> [--binding PATH] [--config PATH]\n\nRemove one CLI binding from the store.\n",
	"shell-init": "usage: locklark cli shell-init [bash|zsh|fish|powershell|pwsh] [--shell SHELL] [--binding PATH] [--tools TOOL_LIST]\n\nPrint shell functions that forward to locklark cli run.\n",
	"run":        "usage: locklark cli run <tool> [--binding PATH] [--cwd ABS_DIR] [--timeout SECONDS] -- [ARG...]\n\nRun a bound tool in the foreground. Informational --help/--version commands use the credential-free fast path.\n",
}

var cliTopLevelHelp = `usage: locklark cli <command> [options]

  cli profiles
  cli list [--binding PATH]
  cli init|bind <tool> --file PATH --program ABS_PROGRAM [options]
  cli show|remove <tool> [--binding PATH]
  cli shell-init [bash|zsh|fish|powershell|pwsh] [--binding PATH] [--tools TOOL_LIST]
  cli run <tool> [--binding PATH] [--cwd ABS_DIR] [--timeout SECONDS] -- [ARG...]

Use "locklark cli <command> --help" for command-specific usage.
`

func writeCLIHelp(out io.Writer, text string) error {
	_, err := io.WriteString(out, text)
	return err
}

func runCLICommand(args []string, out io.Writer) error {
	if len(args) == 0 {
		return cliUsage
	}
	if len(args) == 1 && (args[0] == "--help" || args[0] == "-h") {
		return writeCLIHelp(out, cliTopLevelHelp)
	}
	if len(args) == 2 && (args[1] == "--help" || args[1] == "-h") {
		if help, ok := cliCommandHelp[args[0]]; ok {
			return writeCLIHelp(out, help)
		}
	}
	switch args[0] {
	case "profiles":
		return runCLIProfiles(args[1:], out)
	case "list":
		return runCLIList(args[1:], out)
	case "init", "bind":
		return runCLIInit(args[1:], out)
	case "show":
		return runCLIShow(args[1:], out)
	case "remove":
		return runCLIRemove(args[1:], out)
	case "shell-init":
		return runCLIShellInit(args[1:], out)
	case "run":
		return runCLIRun(args[1:])
	default:
		return cliUsage
	}
}

// parseCLIFlags accepts long options anywhere relative to positional arguments.
// It intentionally has no support for short options: every flag carries an
// explicit value so paths beginning with '-' remain unambiguous.
func parseCLIFlags(args []string, valueFlags map[string]bool, allowSlot bool) (map[string]string, []string, error) {
	values := make(map[string]string, len(valueFlags))
	var positionals []string
	for i := 0; i < len(args); i++ {
		arg := args[i]
		if arg == "--" {
			return nil, nil, cliUsage
		}
		if strings.HasPrefix(arg, "--") {
			name, value, hasValue := strings.Cut(arg[2:], "=")
			if name == "" {
				return nil, nil, cliUsage
			}
			slot := allowSlot && strings.HasPrefix(name, "slot-") && len(name) > len("slot-")
			if !valueFlags[name] && !slot {
				return nil, nil, cliUsage
			}
			if _, duplicate := values[name]; duplicate {
				return nil, nil, cliUsage
			}
			if !hasValue {
				i++
				if i >= len(args) {
					return nil, nil, cliUsage
				}
				value = args[i]
			}
			values[name] = value
			continue
		}
		if strings.HasPrefix(arg, "-") {
			return nil, nil, cliUsage
		}
		positionals = append(positionals, arg)
	}
	return values, positionals, nil
}

func cliBindingArgument(values map[string]string) (string, bool, error) {
	binding, hasBinding := values["binding"]
	config, hasConfig := values["config"]
	if hasBinding && hasConfig {
		return "", false, cliUsage
	}
	explicit := hasBinding || hasConfig
	if hasConfig {
		binding = config
	}
	if !explicit {
		path, err := clibinding.DefaultPath()
		if err != nil {
			return "", false, err
		}
		return path, false, nil
	}
	if binding == "" || !utf8.ValidString(binding) || strings.ContainsRune(binding, 0) {
		return "", false, cliUsage
	}
	path, err := filepath.Abs(binding)
	if err != nil || filepath.Clean(path) != path {
		return "", false, cliUsage
	}
	return path, true, nil
}

func cliFileExists(path string) (bool, error) {
	_, err := os.Lstat(path)
	if err == nil {
		return true, nil
	}
	if errors.Is(err, os.ErrNotExist) {
		return false, nil
	}
	return false, err
}

func loadCLIStore(path string) (clibinding.Store, error) {
	exists, err := cliFileExists(path)
	if err != nil {
		return clibinding.Store{}, err
	}
	if !exists {
		return clibinding.Store{}, os.ErrNotExist
	}
	return clibinding.Load(path)
}

func loadCLIStoreOrEmpty(path string) (clibinding.Store, error) {
	exists, err := cliFileExists(path)
	if err != nil {
		return clibinding.Store{}, err
	}
	if !exists {
		return clibinding.NewStore(), nil
	}
	store, err := clibinding.Load(path)
	if errors.Is(err, os.ErrNotExist) {
		return clibinding.NewStore(), nil
	}
	return store, err
}

func writeCLIJSON(out io.Writer, value any) error {
	return json.NewEncoder(out).Encode(value)
}

func validCLITool(name string) bool {
	return cliToolPattern.MatchString(name)
}

type cliProfileDescription struct {
	Name           string            `json:"name"`
	ID             string            `json:"id"`
	Executables    []string          `json:"executables"`
	Slots          []cliprofile.Slot `json:"slots"`
	PassthroughEnv []string          `json:"passthrough_env"`
	MaxTimeout     int               `json:"max_timeout"`
}

func nonNilStrings(values []string) []string {
	if values == nil {
		return []string{}
	}
	return values
}

func runCLIProfiles(args []string, out io.Writer) error {
	if len(args) != 0 {
		return cliUsage
	}
	profiles := cliprofile.List()
	descriptions := make([]cliProfileDescription, 0, len(profiles))
	for _, profile := range profiles {
		spec := profile.Spec()
		descriptions = append(descriptions, cliProfileDescription{
			Name:           profile.Name(),
			ID:             spec.ID,
			Executables:    nonNilStrings(profile.Executables()),
			Slots:          spec.Slots,
			PassthroughEnv: nonNilStrings(spec.PassthroughEnv),
			MaxTimeout:     spec.MaxTimeout,
		})
	}
	return writeCLIJSON(out, descriptions)
}

func runCLIList(args []string, out io.Writer) error {
	values, positionals, err := parseCLIFlags(args, map[string]bool{"binding": true, "config": true}, false)
	if err != nil || len(positionals) != 0 {
		return cliUsage
	}
	bindingPath, _, err := cliBindingArgument(values)
	if err != nil {
		return err
	}
	store, err := loadCLIStoreOrEmpty(bindingPath)
	if err != nil {
		return err
	}
	return writeCLIJSON(out, store)
}

func resolveCLIToolName(values map[string]string, positionals []string) (string, bool, error) {
	tool, hasTool := values["tool"]
	profile, hasProfile := values["profile"]
	if len(positionals) > 1 {
		return "", false, cliUsage
	}
	if len(positionals) == 1 {
		if hasTool {
			return "", false, cliUsage
		}
		tool, hasTool = positionals[0], true
	}
	if hasTool && tool == "" {
		return "", false, cliUsage
	}
	if !hasTool && hasProfile {
		tool, hasTool = profile, true
	}
	if !hasTool || !validCLITool(tool) {
		return "", false, cliUsage
	}
	return tool, true, nil
}

func runCLIInit(args []string, out io.Writer) error {
	valueFlags := map[string]bool{
		"profile": true, "tool": true, "file": true, "program": true,
		"binding": true, "config": true, "id": true, "revision": true,
		"login": true, "document": true, "session-token": true,
		"helper-path": true, "passthrough": true, "timeout": true,
		"name": true, "pin-sha256": true,
	}
	values, positionals, err := parseCLIFlags(args, valueFlags, true)
	if err != nil {
		return cliUsage
	}
	if len(positionals) > 1 {
		return cliUsage
	}
	if tool, present := values["tool"]; present && tool == "" {
		return cliUsage
	}
	if profile, present := values["profile"]; present && profile == "" {
		return cliUsage
	}
	if program, present := values["program"]; present && program == "" {
		return cliUsage
	}
	tool := values["tool"]
	if len(positionals) == 1 {
		if _, conflict := values["tool"]; conflict {
			return cliUsage
		}
		tool = positionals[0]
	}
	if tool == "" {
		tool = values["profile"]
	}
	if !validCLITool(tool) {
		return cliUsage
	}
	profileName := values["profile"]
	if profileName == "" {
		profileName = tool
	}

	prof, ok := cliprofile.Lookup(profileName)
	if !ok {
		return cliUsage
	}
	spec := prof.Spec()
	if values["file"] == "" {
		return cliUsage
	}
	vaultPath, err := filepath.Abs(values["file"])
	if err != nil {
		return cliUsage
	}
	program, err := resolveCLIProgram(tool, prof, values["program"])
	if err != nil {
		return err
	}
	info, err := os.Stat(program)
	if err != nil || !info.Mode().IsRegular() {
		return cliUsage
	}
	targets, err := buildCLITargets(spec, values)
	if err != nil {
		return err
	}
	helperPath := []string{filepath.Dir(program)}
	if raw, present := values["helper-path"]; present {
		if raw == "" {
			helperPath = nil
		} else {
			helperPath = filepath.SplitList(raw)
		}
	}
	passthrough := []string{}
	if raw, present := values["passthrough"]; present {
		if raw != "" {
			for _, name := range strings.Split(raw, ",") {
				name = strings.TrimSpace(name)
				if name == "" {
					return cliUsage
				}
				passthrough = append(passthrough, name)
			}
		}
	}
	maxTimeout := spec.MaxTimeout
	if maxTimeout <= 0 {
		maxTimeout = 300
	}
	defaultTimeout := maxTimeout
	if defaultTimeout > 300 {
		defaultTimeout = 300
	}
	timeout := defaultTimeout
	if raw, present := values["timeout"]; present {
		seconds, parseErr := strconv.Atoi(raw)
		if parseErr != nil || strconv.Itoa(seconds) != raw || seconds < 1 || seconds > maxTimeout {
			return cliUsage
		}
		timeout = seconds
	}
	pin := true
	if raw, present := values["pin-sha256"]; present {
		switch raw {
		case "true":
			pin = true
		case "false":
			pin = false
		default:
			return cliUsage
		}
	}
	programSHA256 := ""
	if pin {
		programSHA256, err = clibinding.ComputeProgramSHA256(program)
		if err != nil {
			return err
		}
	}
	binding := clibinding.ToolBinding{
		Profile:        profileName,
		VaultPath:      vaultPath,
		Program:        program,
		ProgramSHA256:  programSHA256,
		Targets:        targets,
		HelperPath:     helperPath,
		PassthroughEnv: passthrough,
		TimeoutSeconds: timeout,
		TokenEnvName:   values["name"],
	}
	if err = binding.Validate(); err != nil {
		return err
	}
	bindingPath, _, err := cliBindingArgument(values)
	if err != nil {
		return err
	}
	store, err := loadCLIStoreOrEmpty(bindingPath)
	if err != nil {
		return err
	}
	store.Bindings[tool] = binding
	if err = clibinding.Save(bindingPath, store); err != nil {
		return err
	}
	return writeCLIJSON(out, struct {
		Status        string `json:"status"`
		Tool          string `json:"tool"`
		Profile       string `json:"profile"`
		Program       string `json:"program"`
		ProgramSHA256 string `json:"program_sha256"`
		BindingFile   string `json:"binding_file"`
	}{
		Status:        "bound",
		Tool:          tool,
		Profile:       binding.Profile,
		Program:       binding.Program,
		ProgramSHA256: binding.ProgramSHA256,
		BindingFile:   bindingPath,
	})
}

func resolveCLIProgram(tool string, prof cliprofile.Profile, explicit string) (string, error) {
	if explicit != "" {
		if !filepath.IsAbs(explicit) || filepath.Clean(explicit) != explicit ||
			!utf8.ValidString(explicit) || strings.ContainsRune(explicit, 0) {
			return "", cliUsage
		}
		return explicit, nil
	}
	if prof.Spec().RequireExplicitProgram {
		return "", cliUsage
	}
	candidates := []string{tool}
	candidates = append(candidates, prof.Executables()...)
	seen := map[string]bool{}
	for _, candidate := range candidates {
		if candidate == "" || seen[candidate] {
			continue
		}
		seen[candidate] = true
		found, err := exec.LookPath(candidate)
		if err != nil {
			continue
		}
		absolute, err := filepath.Abs(found)
		if err != nil {
			continue
		}
		info, err := os.Stat(absolute)
		if err == nil && info.Mode().IsRegular() {
			return absolute, nil
		}
	}
	return "", cliUsage
}

func parseCLISlotPair(value string) (string, string, error) {
	id, revision, ok := strings.Cut(value, ":")
	if !ok || strings.ContainsRune(revision, ':') ||
		!cliTargetID.MatchString(id) || !cliTargetRevision.MatchString(revision) {
		return "", "", cliUsage
	}
	return id, revision, nil
}

func buildCLITargets(spec cliprofile.Spec, values map[string]string) ([]clibinding.SlotTarget, error) {
	slots := make(map[string]cliprofile.Slot, len(spec.Slots))
	for _, slot := range spec.Slots {
		slots[slot.Name] = slot
	}
	explicit := make(map[string]clibinding.SlotTarget, len(spec.Slots))
	for name, value := range values {
		if !strings.HasPrefix(name, "slot-") {
			continue
		}
		slotName := strings.TrimPrefix(name, "slot-")
		slot, ok := slots[slotName]
		if !ok {
			return nil, cliUsage
		}
		id, revision, err := parseCLISlotPair(value)
		if err != nil {
			return nil, err
		}
		explicit[slotName] = clibinding.SlotTarget{Slot: slotName, ID: id, Revision: revision, Field: string(slot.Field)}
	}
	apply := func(slotName, id, revision string) {
		if _, exists := explicit[slotName]; exists {
			return
		}
		explicit[slotName] = clibinding.SlotTarget{
			Slot: slotName, ID: id, Revision: revision, Field: string(slots[slotName].Field),
		}
	}
	applyKind := func(kind, id, revision string) int {
		count := 0
		for _, slot := range spec.Slots {
			if slot.Kind == kind && !slot.Optional {
				apply(slot.Name, id, revision)
				count++
			}
		}
		return count
	}
	id, hasID := values["id"]
	revision, hasRevision := values["revision"]
	login, hasLogin := values["login"]
	document, hasDocument := values["document"]
	if hasID != hasRevision {
		return nil, cliUsage
	}
	if hasID {
		if login != "" && login != id+":"+revision {
			return nil, cliUsage
		}
		if len(spec.Slots) == 1 {
			apply(spec.Slots[0].Name, id, revision)
		} else {
			if applyKind("login", id, revision) == 0 {
				return nil, cliUsage
			}
		}
	}
	if hasLogin {
		loginID, loginRevision, err := parseCLISlotPair(login)
		if err != nil {
			return nil, err
		}
		if hasID {
			if loginID != id || loginRevision != revision {
				return nil, cliUsage
			}
		}
		if applyKind("login", loginID, loginRevision) == 0 {
			return nil, cliUsage
		}
	}
	if hasDocument {
		documentID, documentRevision, err := parseCLISlotPair(document)
		if err != nil {
			return nil, err
		}
		if applyKind("document", documentID, documentRevision) == 0 {
			return nil, cliUsage
		}
	}
	if session, present := values["session-token"]; present {
		slot, ok := slots["session_token"]
		if !ok {
			return nil, cliUsage
		}
		sessionID, sessionRevision, err := parseCLISlotPair(session)
		if err != nil {
			return nil, err
		}
		apply(slot.Name, sessionID, sessionRevision)
	}
	targets := make([]clibinding.SlotTarget, 0, len(spec.Slots))
	seen := make(map[string]bool, len(spec.Slots))
	for _, slot := range spec.Slots {
		target, ok := explicit[slot.Name]
		if !ok {
			continue
		}
		targets = append(targets, target)
		seen[slot.Name] = true
	}
	if len(targets) == 0 {
		return nil, cliUsage
	}
	for _, slot := range spec.Slots {
		if !slot.Optional && !seen[slot.Name] {
			return nil, cliUsage
		}
	}
	return targets, nil
}

func runCLIShow(args []string, out io.Writer) error {
	values, positionals, err := parseCLIFlags(args, map[string]bool{
		"binding": true, "config": true, "profile": true, "tool": true,
	}, false)
	if err != nil {
		return cliUsage
	}
	tool, _, err := resolveCLIToolName(values, positionals)
	if err != nil {
		return err
	}
	bindingPath, _, err := cliBindingArgument(values)
	if err != nil {
		return err
	}
	store, err := loadCLIStore(bindingPath)
	if errors.Is(err, os.ErrNotExist) {
		return clibinding.ErrBindingNotFound
	}
	if err != nil {
		return err
	}
	binding, ok := store.Bindings[tool]
	if !ok {
		return clibinding.ErrBindingNotFound
	}
	return writeCLIJSON(out, binding)
}

func runCLIRemove(args []string, out io.Writer) error {
	values, positionals, err := parseCLIFlags(args, map[string]bool{
		"binding": true, "config": true, "profile": true, "tool": true,
	}, false)
	if err != nil {
		return cliUsage
	}
	tool, _, err := resolveCLIToolName(values, positionals)
	if err != nil {
		return err
	}
	bindingPath, _, err := cliBindingArgument(values)
	if err != nil {
		return err
	}
	store, err := loadCLIStore(bindingPath)
	if errors.Is(err, os.ErrNotExist) {
		return clibinding.ErrBindingNotFound
	}
	if err != nil {
		return err
	}
	if _, ok := store.Bindings[tool]; !ok {
		return clibinding.ErrBindingNotFound
	}
	delete(store.Bindings, tool)
	if err = clibinding.Save(bindingPath, store); err != nil {
		return err
	}
	return writeCLIJSON(out, struct {
		Status string `json:"status"`
		Tool   string `json:"tool"`
	}{Status: "removed", Tool: tool})
}

func runCLIShellInit(args []string, out io.Writer) error {
	values, positionals, err := parseCLIFlags(args, map[string]bool{
		"binding": true, "config": true, "shell": true, "tools": true,
	}, false)
	if err != nil {
		return cliUsage
	}
	shell := values["shell"]
	if shell == "" {
		if len(positionals) == 0 {
			return cliUsage
		}
		shell, positionals = positionals[0], positionals[1:]
	} else if len(positionals) > 0 && isCLIShell(positionals[0]) {
		return cliUsage
	}
	if !isCLIShell(shell) {
		return fmt.Errorf("%w: unsupported shell %q; supported shells: bash, zsh, fish, powershell, pwsh", cliUsage, shell)
	}
	if _, provided := values["tools"]; provided && len(positionals) != 0 {
		return cliUsage
	}
	var tools []string
	if raw, provided := values["tools"]; provided {
		if raw != "" {
			for _, name := range strings.Split(raw, ",") {
				name = strings.TrimSpace(name)
				if !validCLITool(name) {
					return cliUsage
				}
				tools = append(tools, name)
			}
		}
	} else if len(positionals) > 0 {
		for _, name := range positionals {
			if !validCLITool(name) {
				return cliUsage
			}
			tools = append(tools, name)
		}
	}
	bindingPath, explicitBinding, err := cliBindingArgument(values)
	if err != nil {
		return err
	}
	if len(tools) == 0 {
		_, toolsProvided := values["tools"]
		if !toolsProvided && len(positionals) == 0 {
			exists, existsErr := cliFileExists(bindingPath)
			if existsErr != nil {
				return existsErr
			}
			if exists {
				store, loadErr := clibinding.Load(bindingPath)
				if loadErr != nil {
					return loadErr
				}
				for tool := range store.Bindings {
					tools = append(tools, tool)
				}
			} else {
				tools = append(tools, cliCoreTools...)
			}
		}
	}
	sort.Strings(tools)
	unique := tools[:0]
	for _, tool := range tools {
		if len(unique) == 0 || unique[len(unique)-1] != tool {
			unique = append(unique, tool)
		}
	}
	tools = unique
	script, err := renderCLIShellInit(shell, tools, bindingPath, explicitBinding)
	if err != nil {
		return err
	}
	_, err = io.WriteString(out, script)
	return err
}

func isCLIShell(shell string) bool {
	switch shell {
	case "bash", "zsh", "fish", "powershell", "pwsh":
		return true
	default:
		return false
	}
}

func shellQuotePOSIX(value string) string {
	return "'" + strings.ReplaceAll(value, "'", "'\\''") + "'"
}

func shellQuoteFish(value string) string {
	return "'" + strings.ReplaceAll(value, "'", "\\'") + "'"
}

func shellQuotePowerShell(value string) string {
	return "'" + strings.ReplaceAll(value, "'", "''") + "'"
}

func renderCLIShellInit(shell string, tools []string, bindingPath string, includeBinding bool) (string, error) {
	var script strings.Builder
	switch shell {
	case "bash", "zsh":
		script.WriteString("# Locklark CLI wrappers (bash/zsh)\n")
		for _, tool := range tools {
			fmt.Fprintf(&script, "%s() {\n  command locklark cli run %s", tool, tool)
			if includeBinding {
				fmt.Fprintf(&script, " --binding %s", shellQuotePOSIX(bindingPath))
			}
			script.WriteString(" -- \"$@\"\n}\n")
		}
	case "fish":
		script.WriteString("# Locklark CLI wrappers (fish)\n")
		for _, tool := range tools {
			fmt.Fprintf(&script, "function %s --wraps=%s\n  command locklark cli run %s", tool, tool, tool)
			if includeBinding {
				fmt.Fprintf(&script, " --binding %s", shellQuoteFish(bindingPath))
			}
			script.WriteString(" -- $argv\nend\n")
		}
	case "powershell", "pwsh":
		script.WriteString("# Locklark CLI wrappers (pwsh)\n")
		for _, tool := range tools {
			function := "Invoke-LocklarkCli_" + tool
			fmt.Fprintf(&script, "function %s {\n  & locklark cli run %s", function, tool)
			if includeBinding {
				fmt.Fprintf(&script, " --binding %s", shellQuotePowerShell(bindingPath))
			}
			script.WriteString(" -- @args\n}\n")
			fmt.Fprintf(&script, "Set-Alias -Name %s -Value %s\n", tool, function)
		}
	default:
		return "", cliUsage
	}
	return script.String(), nil
}

func resolveCLIRunTool(values map[string]string, positionals []string, separated bool) (string, string, []string, error) {
	tool, hasTool := values["tool"]
	profile, hasProfile := values["profile"]
	if hasTool && hasProfile && tool != profile {
		return "", "", nil, cliUsage
	}
	if !hasTool && hasProfile {
		tool, hasTool = profile, true
	}
	var child []string
	switch {
	case hasTool:
		if tool == "" || !validCLITool(tool) {
			return "", "", nil, cliUsage
		}
		if len(positionals) > 0 {
			if separated {
				return "", "", nil, cliUsage
			}
			child = append(child, positionals...)
		}
	case len(positionals) > 0:
		tool = positionals[0]
		if !validCLITool(tool) {
			return "", "", nil, cliUsage
		}
		child = append(child, positionals[1:]...)
	default:
		return "", "", nil, cliUsage
	}
	if !hasProfile {
		profile = tool
	}
	return tool, profile, child, nil
}

func runCLIRun(args []string) error {
	if os.Getenv("LOCKLARK_CLI_ACTIVE") != "" {
		return errCLIRecursion
	}
	arguments := args
	var childArgs []string
	separated := false
	for i, arg := range args {
		if arg == "--" {
			arguments = args[:i]
			childArgs = append(childArgs, args[i+1:]...)
			separated = true
			break
		}
	}
	values, positionals, err := parseCLIFlags(arguments, map[string]bool{
		"binding": true, "config": true, "tool": true, "profile": true,
		"cwd": true, "timeout": true,
	}, false)
	if err != nil {
		return cliUsage
	}
	tool, _, extra, err := resolveCLIRunTool(values, positionals, separated)
	if err != nil {
		return err
	}
	childArgs = append(childArgs, extra...)
	bindingPath, _, err := cliBindingArgument(values)
	if err != nil {
		return err
	}
	store, err := loadCLIStore(bindingPath)
	if errors.Is(err, os.ErrNotExist) {
		return clibinding.ErrBindingNotFound
	}
	if err != nil {
		return err
	}
	binding, ok := store.Bindings[tool]
	if !ok {
		return clibinding.ErrBindingNotFound
	}
	if err = clibinding.VerifyProgram(binding); err != nil {
		return err
	}
	prof, ok := cliprofile.Lookup(binding.Profile)
	if !ok {
		return clibinding.ErrBinding
	}
	spec := prof.Spec()
	cwd, err := os.Getwd()
	if err != nil {
		return err
	}
	if raw, present := values["cwd"]; present {
		if raw == "" || !utf8.ValidString(raw) || strings.ContainsRune(raw, 0) {
			return cliUsage
		}
		cwd, err = filepath.Abs(raw)
		if err != nil || filepath.Clean(cwd) != cwd {
			return cliUsage
		}
	}
	if info, statErr := os.Stat(cwd); statErr != nil || !info.IsDir() {
		return cliUsage
	}
	maxTimeout := spec.MaxTimeout
	if maxTimeout <= 0 {
		maxTimeout = 300
	}
	timeout := binding.TimeoutSeconds
	if timeout == 0 {
		timeout = maxTimeout
		if timeout > 300 {
			timeout = 300
		}
	}
	if raw, present := values["timeout"]; present {
		seconds, parseErr := strconv.Atoi(raw)
		if parseErr != nil || strconv.Itoa(seconds) != raw || seconds < 1 || seconds > maxTimeout {
			return cliUsage
		}
		timeout = seconds
	}
	if err = cliprofile.ValidateArgs(spec, childArgs); err != nil {
		return cliUsage
	}
	if !prof.NeedsAuth(childArgs) {
		return executeCLIFastPath(tool, binding, spec, childArgs, cwd, timeout)
	}
	return executeCLIAuthenticated(tool, binding, spec, childArgs, cwd, timeout)
}

func executeCLIFastPath(tool string, binding clibinding.ToolBinding, spec cliprofile.Spec, args []string, cwd string, timeout int) error {
	passthrough := make(map[string]string)
	for _, name := range binding.PassthroughEnv {
		value, present := os.LookupEnv(name)
		if present && cliprofile.ValidPassthroughName(spec, name, value) {
			passthrough[name] = value
		}
	}
	targets := make([]personal.BundleTarget, len(binding.Targets))
	for i, target := range binding.Targets {
		targets[i] = personal.BundleTarget{Slot: target.Slot, ID: target.ID, Revision: target.Revision, Field: target.Field}
	}
	request := personal.RunBundleRequest{
		Program:        binding.Program,
		Args:           append([]string(nil), args...),
		Directory:      cwd,
		TimeoutSeconds: timeout,
		HelperPath:     append([]string(nil), binding.HelperPath...),
		Passthrough:    passthrough,
		TokenEnvName:   binding.TokenEnvName,
		Spec:           spec,
	}
	code, err := personal.RunCLIInformational(context.Background(), request, targets, tool)
	if err != nil {
		return err
	}
	if code != 0 {
		return &childExitStatus{code: code}
	}
	return nil
}

func executeCLIAuthenticated(tool string, binding clibinding.ToolBinding, spec cliprofile.Spec, childArgs []string, cwd string, timeout int) error {
	passthrough := make(map[string]string)
	for _, name := range binding.PassthroughEnv {
		value, present := os.LookupEnv(name)
		if present && cliprofile.ValidPassthroughName(spec, name, value) {
			passthrough[name] = value
		}
	}
	targets := make([]personal.BundleTarget, len(binding.Targets))
	for i, target := range binding.Targets {
		targets[i] = personal.BundleTarget{Slot: target.Slot, ID: target.ID, Revision: target.Revision, Field: target.Field}
	}
	request := personal.RunBundleRequest{
		Program:        binding.Program,
		Args:           append([]string(nil), childArgs...),
		Directory:      cwd,
		TimeoutSeconds: timeout,
		HelperPath:     append([]string(nil), binding.HelperPath...),
		Passthrough:    passthrough,
		TokenEnvName:   binding.TokenEnvName,
		Spec:           spec,
	}
	if err := request.Validate(targets); err != nil {
		return cliUsage
	}
	controlInput, controlOutput, err := openRunCLIConsole()
	if err != nil {
		return errRunCLIConsole
	}
	defer controlInput.Close()
	if controlOutput != controlInput {
		defer controlOutput.Close()
	}
	signals := make(chan os.Signal, 1)
	signal.Notify(signals, os.Interrupt, syscall.SIGTERM, syscall.SIGHUP)
	defer signal.Stop(signals)
	fd := int(controlInput.Fd())
	state, err := term.MakeRaw(fd)
	if err != nil {
		return errors.New("cannot disable terminal echo")
	}
	var once sync.Once
	var cliRunning atomic.Bool
	var resetErr error
	restore := func() { once.Do(func() { resetErr = term.Restore(fd, state) }) }
	childContext, cancelChild := context.WithCancel(context.Background())
	defer cancelChild()
	done := make(chan struct{})
	defer func() {
		close(done)
		restore()
	}()
	go func() {
		select {
		case <-signals:
			restore()
			if cliRunning.Load() {
				cancelChild()
				return
			}
			os.Exit(130)
		case <-done:
		}
	}()
	c := console{reader: consoleByteReader{controlInput}, writer: controlOutput}
	password, err := c.field("主密码")
	if err != nil {
		return err
	}
	defer clear(password)
	keyInput, err := c.field("Secret Key")
	if err != nil {
		return err
	}
	key, err := personal.ParseSecret(string(keyInput))
	clear(keyInput)
	if err != nil {
		return errors.New("invalid Secret Key")
	}
	defer clear(key)
	if err = confirmRunBundle(&c, tool, binding, targets, request); err != nil {
		return err
	}
	cliRunning.Store(true)
	restore()
	if resetErr != nil {
		return errors.New("cannot restore terminal mode; process not started")
	}
	receipt, err := personal.RunBundle(childContext, binding.VaultPath, string(password), key, targets, request)
	if err != nil {
		return err
	}
	if receipt.ExitCode != 0 {
		return &childExitStatus{code: receipt.ExitCode}
	}
	return nil
}

func confirmRunBundle(c *console, tool string, binding clibinding.ToolBinding, targets []personal.BundleTarget, request personal.RunBundleRequest) error {
	if c == nil {
		return errors.New("local process cancelled")
	}
	var summary strings.Builder
	fmt.Fprintf(&summary, "将以下一次性凭据交给本次可信本地程序。\r\n")
	fmt.Fprintf(&summary, "这不是沙箱，也不能收回已披露的值：程序及后代可读取、打印、联网或保存凭据。\r\n")
	fmt.Fprintf(&summary, "使用真实标准输入/输出/错误；Locklark 不捕获或记录子进程正文。\r\n")
	fmt.Fprintf(&summary, "命令及其参数会显示在终端和进程列表中；不要把秘密写入参数。\r\n")
	fmt.Fprintf(&summary, "超时只尝试终止直接子进程，后代可能继续运行；中断或清理失败结果可能未知。\r\n")
	fmt.Fprintf(&summary, "工具：%s\r\n", strconv.QuoteToASCII(tool))
	fmt.Fprintf(&summary, "profile：%s\r\n", strconv.QuoteToASCII(binding.Profile))
	fmt.Fprintf(&summary, "库：%s\r\n", strconv.QuoteToASCII(binding.VaultPath))
	fmt.Fprintf(&summary, "程序：%s\r\n", strconv.QuoteToASCII(binding.Program))
	if binding.ProgramSHA256 != "" {
		fmt.Fprintf(&summary, "SHA-256：%s\r\n", binding.ProgramSHA256)
	} else {
		fmt.Fprintf(&summary, "SHA-256：未固定（仍会校验为普通文件）\r\n")
	}
	fmt.Fprintf(&summary, "目录：%s\r\n", strconv.QuoteToASCII(request.Directory))
	fmt.Fprintf(&summary, "超时：%d 秒\r\n", request.TimeoutSeconds)
	fmt.Fprintf(&summary, "槽位目标（读取不可变修订）：\r\n")
	for _, target := range targets {
		fmt.Fprintf(&summary, "  %s = %s @ %s 字段 %s\r\n", strconv.QuoteToASCII(target.Slot),
			target.ID, target.Revision, strconv.QuoteToASCII(target.Field))
	}
	envNames := make([]string, 0, len(request.Spec.Env)+1)
	for name := range request.Spec.Env {
		envNames = append(envNames, name)
	}
	if request.Spec.DynamicTokenEnv {
		envNames = append(envNames, request.TokenEnvName)
	}
	sort.Strings(envNames)
	fmt.Fprintf(&summary, "环境变量键（不显示值）：\r\n")
	if len(envNames) == 0 {
		fmt.Fprintf(&summary, "  （无）\r\n")
	}
	for _, name := range envNames {
		fmt.Fprintf(&summary, "  %s\r\n", name)
	}
	fmt.Fprintf(&summary, "临时凭据文件（位于本次 0700 临时根，结束删除）：\r\n")
	if len(request.Spec.Files) == 0 {
		fmt.Fprintf(&summary, "  （无）\r\n")
	}
	for _, file := range request.Spec.Files {
		fmt.Fprintf(&summary, "  %s（%04o）\r\n", strconv.QuoteToASCII(file.RelPath), file.Mode)
	}
	names := make([]string, 0, len(request.Passthrough))
	for name := range request.Passthrough {
		names = append(names, name)
	}
	sort.Strings(names)
	fmt.Fprintf(&summary, "透传环境变量：\r\n")
	if len(names) == 0 {
		fmt.Fprintf(&summary, "  （无）\r\n")
	}
	for _, name := range names {
		fmt.Fprintf(&summary, "  %s\r\n", name)
	}
	fmt.Fprintf(&summary, "辅助 PATH：\r\n")
	if len(request.HelperPath) == 0 {
		fmt.Fprintf(&summary, "  （无）\r\n")
	}
	for _, directory := range request.HelperPath {
		fmt.Fprintf(&summary, "  %s\r\n", strconv.QuoteToASCII(directory))
	}
	fmt.Fprintf(&summary, "参数：\r\n")
	if len(request.Args) == 0 {
		fmt.Fprintf(&summary, "  （无）\r\n")
	}
	for i, arg := range request.Args {
		fmt.Fprintf(&summary, "  [%d] %s\r\n", i, strconv.QuoteToASCII(arg))
	}
	if _, err := io.WriteString(c.output(), summary.String()); err != nil {
		return err
	}
	consent, err := c.field("输入 RUN 确认本次可信命令披露")
	defer clear(consent)
	if err != nil {
		return err
	}
	if string(consent) != "RUN" {
		return errors.New("local process cancelled")
	}
	return nil
}
