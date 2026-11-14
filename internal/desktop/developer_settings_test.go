package desktop

import (
	"context"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
	"time"

	"github.com/egoist/mygo/ui"
	"github.com/jihuayu/locklark/internal/browserhost"
	"github.com/jihuayu/locklark/internal/clibinding"
	"github.com/jihuayu/locklark/internal/cliprofile"
	"github.com/jihuayu/locklark/internal/personal"
	"github.com/jihuayu/locklark/internal/vault"
)

func TestSettingsDeveloperTabExposesImplementedDesktopTools(t *testing.T) {
	a := newOnevraTestApp()
	a.session = &personal.Session{}
	a.launch = func(func()) {}
	a.v2Mode = true
	a.settingsPath = filepath.Join(t.TempDir(), "settings.json")
	a.openSettings()

	tester := newOnevraTestTesterSize(a, 1280, 1000)
	if err := tester.Click("开发者"); err != nil {
		t.Fatalf("developer settings tab is missing: %v", err)
	}

	for _, label := range []string{
		"开发者工具",
		"SSH Agent",
		"已停止",
		"打开 SSH 密钥与 Agent",
		"CLI 集成",
		"GitHub CLI",
		"Vercel CLI",
		"打开 CLI 配置",
		"CLI 请求活动",
		"命令行与自动化",
		"MCP / Agent 桥接",
		"安全审计日志",
		"导入与导出",
		"查看开发者文档",
	} {
		if !tester.HasText(label) {
			t.Fatalf("developer settings missing %q", label)
		}
	}
	for _, unsupported := range []string{"SDK 集成", "Watchtower", "SSH 私钥扫描"} {
		if tester.HasText(unsupported) {
			t.Fatalf("developer settings exposed unsupported capability %q", unsupported)
		}
	}

	if err := tester.Click("打开 SSH 密钥与 Agent"); err != nil {
		t.Fatal(err)
	}
	if !a.v2Mode || !a.v2.settingsOpen || a.v2.settingsSection != settingsSectionSSH || !tester.HasText("SSH 与 Agent") {
		t.Fatalf("SSH Agent action did not open its settings section: settingsOpen=%v section=%q page=%q", a.v2.settingsOpen, a.v2.settingsSection, a.page)
	}
}

func TestSettingsDeveloperOpensCLIConfigurationAndRequestActivity(t *testing.T) {
	for _, tc := range []struct {
		label   string
		section string
		title   string
	}{
		{"打开 CLI 配置", "cli", "CLI 集成配置"},
		{"CLI 请求活动", "cli-activity", "CLI 请求活动"},
	} {
		t.Run(tc.label, func(t *testing.T) {
			a := newOnevraTestApp()
			a.launch = func(func()) {}
			a.v2Mode = true
			a.settingsPath = filepath.Join(t.TempDir(), "settings.json")
			a.openSettings()
			tester := newOnevraTestTesterSize(a, 1280, 1000)
			if err := tester.Click("开发者"); err != nil {
				t.Fatal(err)
			}
			if err := tester.Click(tc.label); err != nil {
				t.Fatal(err)
			}
			if !a.v2.settingsOpen || a.v2.settingsSection != tc.section {
				t.Fatalf("%q opened section %q with settingsOpen=%v", tc.label, a.v2.settingsSection, a.v2.settingsOpen)
			}
			if !tester.HasText(tc.title) {
				t.Fatalf("%q did not render %q", tc.label, tc.title)
			}
		})
	}
}

func TestSettingsDeveloperAuditAndImportActionsOpenExistingPages(t *testing.T) {
	for _, tc := range []struct {
		label   string
		section string
		title   string
	}{
		{"安全审计日志", settingsSectionAudit, "活动审计"},
		{"打开导入与导出", settingsSectionTransfer, "导入与导出"},
		{"导入与导出", settingsSectionTransfer, "导入与导出"},
	} {
		t.Run(tc.label, func(t *testing.T) {
			a := newOnevraTestApp()
			a.session = &personal.Session{}
			a.launch = func(func()) {}
			a.v2Mode = true
			a.settingsPath = filepath.Join(t.TempDir(), "settings.json")
			a.openSettings()
			tester := newOnevraTestTesterSize(a, 1280, 1000)
			if err := tester.Click("开发者"); err != nil {
				t.Fatal(err)
			}
			if err := tester.Click(tc.label); err != nil {
				t.Fatal(err)
			}
			if !a.v2.settingsOpen || a.v2.settingsSection != tc.section {
				t.Fatalf("%q opened section %q with settingsOpen=%v", tc.label, a.v2.settingsSection, a.v2.settingsOpen)
			}
			if !tester.HasText(tc.title) {
				t.Fatalf("%q did not render %q", tc.label, tc.title)
			}
		})
	}
}

func TestCLIRequestActivityShowsApprovedAndRefusedRequestsAfterRestart(t *testing.T) {
	path, key, _, row := desktopFixture(t)
	session, err := personal.UnlockSession(path, []byte("fixture"), key, time.Minute)
	if err != nil {
		t.Fatal(err)
	}
	defer session.Lock()

	a := New()
	a.launch = func(fn func()) { fn() }
	a.settingsPath = filepath.Join(t.TempDir(), "settings.json")
	a.session = session
	a.brokerSession = session
	a.brokerEpoch = 1
	approved := false
	a.cliApprover = func(context.Context, browserhost.Peer, browserhost.BrokerCLIRequest) (bool, error) {
		return approved, nil
	}
	request := browserhost.BrokerCLIRequest{
		V:         1,
		VaultPath: path,
		Targets:   []personal.CLIBrokerTarget{{Slot: "TOKEN", ID: row.ID, Revision: row.Revision, Field: "password"}},
	}
	peer := browserhost.Peer{User: "fixture", PID: 4242, Process: `C:\Tools\gh.exe`}

	if _, err := a.handleCLIRun(context.Background(), peer, request); err == nil {
		t.Fatal("refused CLI request disclosed values")
	}
	approved = true
	if _, err := a.handleCLIRun(context.Background(), peer, request); err != nil {
		t.Fatalf("approved CLI request failed: %v", err)
	}

	// A fresh App proves the audit page reads owner-only, non-secret request
	// metadata persisted beside the settings file rather than only showing a
	// transient process list.
	restarted := New()
	restarted.settingsPath = a.settingsPath
	restarted.session = session
	restarted.audit = []personal.Event{{
		UTC:    "2026-11-13T10:00:00Z",
		Action: "item.run.bundle",
		Result: "intent",
		Item:   row.ID,
	}}
	restarted.v2Mode = true
	restarted.openSettings()
	restarted.v2.settingsSection = "cli-activity"
	tester := newOnevraTestTesterSize(restarted, 1280, 1000)

	for _, want := range []string{"CLI 请求活动", "gh.exe", "已拒绝", "已批准", "CLI 执行", "item.run.bundle"} {
		if !tester.HasText(want) {
			t.Fatalf("CLI request activity missing %q", want)
		}
	}
	if tester.HasText("desktop-password") {
		t.Fatal("CLI request activity exposed a credential value")
	}
}

func TestCLIConfigurationCreatesPinnedGitHubBindingWithoutCredentialData(t *testing.T) {
	privateRoot := newPrivateCLIConfigDir(t)
	path := filepath.Join(privateRoot, "desktop.ll")
	key := []byte("0123456789abcdef")
	if err := personal.Create(path, "fixture", key); err != nil {
		t.Fatal(err)
	}
	session, err := personal.UnlockSession(path, []byte("fixture"), key, time.Minute)
	if err != nil {
		t.Fatal(err)
	}
	defer session.Lock()
	if _, err := session.AddLogin("Desktop login", "desktop-user", "desktop-password"); err != nil {
		t.Fatal(err)
	}
	rows, err := session.List("active")
	if err != nil || len(rows) != 1 {
		t.Fatalf("CLI target fixture: rows=%d err=%v", len(rows), err)
	}
	row := rows[0]

	programDir := t.TempDir()
	program := writeFakeCLIExecutable(t, programDir, "gh")
	t.Setenv("PATH", programDir)

	a := New()
	a.launch = func(fn func()) { fn() }
	a.path = path
	a.session = session
	a.settingsPath = filepath.Join(t.TempDir(), "settings.json")
	a.v2.selectedID = row.ID
	a.v2.selectedRevision = row.Revision
	a.v2.detail = &personal.ItemDetail{
		ID:       row.ID,
		Revision: row.Revision,
		Kind:     row.Kind,
		Category: vault.CategoryLogin,
		Title:    row.Title,
		State:    row.State,
	}
	a.v2Mode = true
	a.openSettings()
	a.v2.settingsSection = "cli"
	tester := newOnevraTestTesterSize(a, 1280, 1100)

	for _, want := range []string{"CLI 绑定文件", "GitHub CLI", "Vercel CLI", "保存 gh 绑定"} {
		if !tester.HasText(want) {
			t.Fatalf("CLI configuration missing %q", want)
		}
	}
	if err := tester.Click("配置 vercel"); err != nil {
		t.Fatal(err)
	}
	if a.cliSettings.profile != "vercel" {
		t.Fatalf("Vercel configuration action selected %q", a.cliSettings.profile)
	}
	if err := tester.Click("配置 gh"); err != nil {
		t.Fatal(err)
	}
	if a.cliSettings.profile != "gh" {
		t.Fatalf("GitHub configuration action selected %q", a.cliSettings.profile)
	}
	if err := tester.Click("保存 gh 绑定"); err != nil {
		t.Fatal(err)
	}

	bindingPath := filepath.Join(filepath.Dir(path), clibinding.DefaultFileName)
	store, err := clibinding.Load(bindingPath)
	if err != nil {
		raw, _ := os.ReadFile(bindingPath)
		t.Fatalf("load saved CLI binding: %v; status=%q path=%q program=%q raw=%s", err, a.cliSettings.status, a.cliSettings.bindingPath, a.cliSettings.program, raw)
	}
	binding, ok := store.Bindings["gh"]
	if !ok {
		t.Fatal("saved CLI binding does not contain gh")
	}
	if binding.Profile != "gh" || binding.Program != program || binding.ProgramSHA256 == "" {
		t.Fatalf("saved binding is not pinned to gh: %#v", binding)
	}
	if len(binding.Targets) != 1 || binding.Targets[0].ID != row.ID || binding.Targets[0].Revision != row.Revision || binding.Targets[0].Field != "password" {
		t.Fatalf("saved binding targets are wrong: %#v", binding.Targets)
	}
	raw, err := os.ReadFile(bindingPath)
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(string(raw), "desktop-password") {
		t.Fatal("CLI binding persisted a credential value")
	}
}

func TestSettingsUnknownSectionFallsBackToSecurity(t *testing.T) {
	a := newOnevraTestApp()
	a.v2.settingsSection = "unknown"
	a.openSettings()
	tester := newOnevraTestTesterSize(a, 1280, 1000)

	if !tester.HasText("自动锁定") {
		t.Fatal("unknown settings section did not render the security page")
	}
	if tester.HasText("开发者工具") {
		t.Fatal("unknown settings section rendered the developer page")
	}
	if a.v2.settingsSection != settingsSectionSecurity {
		t.Fatalf("unknown section remained selected: %q", a.v2.settingsSection)
	}
}

func writeFakeCLIExecutable(t *testing.T, dir, name string) string {
	t.Helper()
	filename := name
	if runtime.GOOS == "windows" {
		filename += ".exe"
	}
	full := filepath.Join(dir, filename)
	if err := os.WriteFile(full, []byte("fixture executable "+name), 0o700); err != nil {
		t.Fatal(err)
	}
	return full
}

func TestCLIWorkbenchSupportsAll24ProfilesMultiSlotTokenAndPrecheck(t *testing.T) {
	if got := len(cliprofile.List()); got != 24 {
		t.Fatalf("cliprofile count = %d, want 24", got)
	}
	programDir := t.TempDir()
	writeFakeCLIExecutable(t, programDir, "aws")
	writeFakeCLIExecutable(t, programDir, "git")
	writeFakeCLIExecutable(t, programDir, "kubectl")
	myToolPath := writeFakeCLIExecutable(t, programDir, "my-tool")
	t.Setenv("PATH", programDir)

	a := newOnevraTestApp()
	a.v2.all = append(a.v2.all, personal.ItemSummary{
		ID:       "doc-1",
		Revision: "rev-doc-1",
		Kind:     "document",
		Category: vault.CategoryDocument,
		VaultID:  vault.DefaultVaultID,
		Title:    "Prod Kubeconfig",
		State:    "active",
	})
	a.session = nil // Precheck must work without an unlocked session or credentials.

	a.selectCLIProfile("aws")
	a.precheckCLIProgram()
	if !a.cliSettings.precheckOK || len(a.cliSettings.precheckDigest) != 64 {
		t.Fatalf("precheckCLIProgram failed while locked: ok=%v digest=%q status=%q", a.cliSettings.precheckOK, a.cliSettings.precheckDigest, a.cliSettings.precheckStatus)
	}

	awsSpec, ok := cliprofile.Lookup("aws")
	if !ok {
		t.Fatal("missing aws profile")
	}
	awsTargets, err := a.buildSlotTargets(awsSpec.Spec())
	if err != nil || len(awsTargets) < 2 {
		t.Fatalf("aws multi-slot targets failed: len=%d err=%v", len(awsTargets), err)
	}

	kubeSpec, ok := cliprofile.Lookup("kubectl")
	if !ok {
		t.Fatal("missing kubectl profile")
	}
	kubeTargets, err := a.buildSlotTargets(kubeSpec.Spec())
	if err != nil || len(kubeTargets) != 1 || kubeTargets[0].ID != "doc-1" {
		t.Fatalf("kubectl document slot targets = %+v err=%v", kubeTargets, err)
	}

	tokenBinding := clibinding.ToolBinding{
		Profile:       "token",
		VaultPath:     filepath.Join(t.TempDir(), "personal.ll"),
		Program:       myToolPath,
		ProgramSHA256: a.cliSettings.precheckDigest,
		TokenEnvName:  "MY_CUSTOM_TOKEN",
		Targets: []clibinding.SlotTarget{{
			Slot:     "token",
			ID:       "0123456789abcdef0123456789abcdef",
			Revision: "fedcba9876543210fedcba9876543210fedcba9876543210fedcba9876543210",
			Field:    "password",
		}},
	}
	if err := tokenBinding.Validate(); err != nil {
		t.Fatalf("token binding with TokenEnvName failed validation: %v", err)
	}
}

func TestCLIRequestActivityStatusFilterChips(t *testing.T) {
	path, key, _, row := desktopFixture(t)
	session, err := personal.UnlockSession(path, []byte("fixture"), key, time.Minute)
	if err != nil {
		t.Fatal(err)
	}
	defer session.Lock()

	a := New()
	a.launch = func(fn func()) { fn() }
	a.settingsPath = filepath.Join(t.TempDir(), "settings.json")
	a.session = session
	a.brokerSession = session
	a.brokerEpoch = 1
	approved := false
	a.cliApprover = func(context.Context, browserhost.Peer, browserhost.BrokerCLIRequest) (bool, error) {
		return approved, nil
	}
	request := browserhost.BrokerCLIRequest{
		V:         1,
		VaultPath: path,
		Targets:   []personal.CLIBrokerTarget{{Slot: "TOKEN", ID: row.ID, Revision: row.Revision, Field: "password"}},
	}
	peer := browserhost.Peer{User: "fixture", PID: 4242, Process: `C:\Tools\gh.exe`}
	_, _ = a.handleCLIRun(context.Background(), peer, request)
	approved = true
	_, _ = a.handleCLIRun(context.Background(), peer, request)

	a.v2Mode = true
	a.openSettings()
	a.v2.settingsSection = settingsSectionCLIActivity
	tester := newOnevraTestTesterSize(a, 1280, 1000)

	if err := tester.Click("已批准"); err != nil {
		t.Fatal(err)
	}
	if a.cliActivity.filter != "approved" {
		t.Fatalf("filter = %q, want approved", a.cliActivity.filter)
	}
	if err := tester.Click("已拒绝"); err != nil {
		t.Fatal(err)
	}
	if a.cliActivity.filter != "refused" {
		t.Fatalf("filter = %q, want refused", a.cliActivity.filter)
	}
	if err := tester.Click("失败"); err != nil {
		t.Fatal(err)
	}
	if a.cliActivity.filter != "failed" || tester.HasText("desktop-password") {
		t.Fatalf("failed filter=%q or exposed password", a.cliActivity.filter)
	}
	if err := tester.Click("全部"); err != nil {
		t.Fatal(err)
	}
	if a.cliActivity.filter != "all" {
		t.Fatalf("filter = %q, want all", a.cliActivity.filter)
	}
}

func TestStandaloneCLIApprovalPopupView(t *testing.T) {
	a := New()
	decision := make(chan bool, 1)
	a.cliPending = &cliRunPending{
		id:   "pending-1",
		peer: browserhost.Peer{PID: 99, User: "tester", Process: "gh.exe"},
		request: browserhost.BrokerCLIRequest{
			VaultPath: filepath.Join(t.TempDir(), "personal.ll"),
			Targets: []personal.CLIBrokerTarget{{
				Slot:     "GH_TOKEN",
				ID:       "0123456789abcdef0123456789abcdef",
				Revision: "fedcba9876543210fedcba9876543210",
				Field:    "password",
			}},
		},
		decision: decision,
	}
	tester := ui.NewTester(a.cliApprovalPopupView, 560, 430)
	for _, want := range []string{"批准本地 CLI 凭据请求", "打开主窗口", "拒绝本次请求", "仅批准本次 CLI 请求"} {
		if !tester.HasText(want) {
			t.Fatalf("standalone CLI approval popup missing %q", want)
		}
	}
	if err := tester.Click("仅批准本次 CLI 请求"); err != nil {
		t.Fatal(err)
	}
	select {
	case ok := <-decision:
		if !ok {
			t.Fatal("CLI approval popup recorded refusal instead of approval")
		}
	default:
		t.Fatal("CLI approval popup did not send decision")
	}
}
