package desktop

import (
	"errors"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"time"

	"github.com/egoist/mygo"
	"github.com/egoist/mygo/ui"
	"github.com/jihuayu/locklark/internal/clibinding"
	"github.com/jihuayu/locklark/internal/cliprofile"
	"github.com/jihuayu/locklark/internal/vault"
	oneui "github.com/oneo-me/onevra/source/components"
	"github.com/oneo-me/onevra/source/icons/lucide"
)

type cliIntegrationState struct {
	bindingPath        string
	profile            string
	program            string
	status             string
	loaded             bool
	loadErr            string
	store              clibinding.Store
	storeAttemptedPath string
	query              string
	selectedItemID     string
	slotItemIDs        map[string]string
	tokenEnvName       string
	precheckDigest     string
	precheckStatus     string
	precheckOK         bool
	prechecking        bool
	wizardOpen         bool
	wizardStep         int
	detectedPathEnv    string
	detectedReady      bool
	detecting          bool
	detected           map[string]string
	probedProfile      string
	filterMode         string
}

var cliProfileDisplayNames = map[string]string{
	"anthropic":       "Anthropic CLI",
	"aws":             "AWS CLI",
	"codex":           "Codex CLI",
	"deepseek":        "DeepSeek Harness",
	"docker":          "Docker",
	"flyctl":          "Fly.io",
	"gemini":          "Gemini CLI",
	"gh":              "GitHub CLI",
	"git":             "Git",
	"glab":            "GitLab CLI",
	"huggingface":     "Hugging Face",
	"kubectl":         "Kubernetes",
	"netrc":           "cURL / netrc",
	"npm":             "npm / pnpm / Yarn",
	"openai":          "OpenAI CLI",
	"psql":            "PostgreSQL",
	"railway":         "Railway",
	"railway-account": "Railway account",
	"stripe":          "Stripe CLI",
	"supabase":        "Supabase CLI",
	"terraform":       "Terraform / OpenTofu",
	"token":           "自定义 Token",
	"vercel":          "Vercel CLI",
	"wrangler":        "Cloudflare Wrangler",
}

func cliProfileDisplayName(name string) string {
	if label := cliProfileDisplayNames[name]; label != "" {
		return label
	}
	return name
}

func (a *App) defaultCLIBindingPath() string {
	if strings.TrimSpace(a.path) != "" {
		return filepath.Join(filepath.Dir(a.path), clibinding.DefaultFileName)
	}
	path, err := clibinding.DefaultPath()
	if err != nil {
		return clibinding.DefaultFileName
	}
	return path
}

func cliProgramForProfile(profile string) string {
	p, ok := cliprofile.Lookup(profile)
	if !ok {
		return ""
	}
	for _, executable := range p.Executables() {
		if path, err := exec.LookPath(executable); err == nil && filepath.IsAbs(path) {
			return filepath.Clean(path)
		}
	}
	return ""
}

func (a *App) ensureCLIDetection() {
	pathEnv := os.Getenv("PATH")
	if a.win == nil {
		if a.cliSettings.detectedReady && a.cliSettings.detectedPathEnv == pathEnv {
			return
		}
		profiles := cliprofile.List()
		found := make(map[string]string, len(profiles))
		for _, item := range profiles {
			name := item.Name()
			found[name] = cliProgramForProfile(name)
		}
		a.cliSettings.detected = found
		a.cliSettings.detectedPathEnv = pathEnv
		a.cliSettings.detectedReady = true
		a.cliSettings.detecting = false
		return
	}
	if a.cliSettings.detectedReady || a.cliSettings.detecting {
		return
	}
	a.cliSettings.detecting = true
	a.launch(func() {
		profiles := cliprofile.List()
		found := make(map[string]string, len(profiles))
		for _, item := range profiles {
			name := item.Name()
			found[name] = cliProgramForProfile(name)
		}
		a.dispatch(func() {
			a.cliSettings.detected = found
			a.cliSettings.detectedPathEnv = pathEnv
			a.cliSettings.detectedReady = true
			a.cliSettings.detecting = false
			if a.cliSettings.program == "" && a.cliSettings.profile != "" {
				a.cliSettings.program = found[a.cliSettings.profile]
			}
		})
	})
}

func (a *App) cliDetectedProgram(profile string) string {
	a.ensureCLIDetection()
	if a.cliSettings.detected == nil {
		return ""
	}
	return a.cliSettings.detected[profile]
}

func (a *App) detectCurrentCLIProgram() {
	profile := a.cliSettings.profile
	if profile == "" {
		return
	}
	applyDetected := func(program string) {
		if a.cliSettings.detected == nil {
			a.cliSettings.detected = map[string]string{}
		}
		a.cliSettings.detected[profile] = program
		if a.cliSettings.profile == profile {
			a.cliSettings.program = program
			a.cliSettings.probedProfile = profile
			if program == "" {
				a.cliSettings.status = "PATH 中未找到此工具的默认可执行文件"
			} else {
				a.cliSettings.status = "已检测到 " + program
			}
		}
	}
	if a.win == nil {
		applyDetected(cliProgramForProfile(profile))
		a.touchActivity()
		return
	}
	a.cliSettings.status = "正在检测 " + profile + " 可执行文件…"
	a.touchActivity()
	a.launch(func() {
		program := cliProgramForProfile(profile)
		a.dispatch(func() {
			applyDetected(program)
		})
	})
}

func (a *App) resetCLIIntegrationSettings() {
	if a.cliSettings.profile == "" {
		a.cliSettings.profile = "gh"
	}
	if a.cliSettings.bindingPath == "" {
		a.cliSettings.bindingPath = a.defaultCLIBindingPath()
	}
	if a.cliSettings.program == "" && a.cliSettings.probedProfile != a.cliSettings.profile {
		a.cliSettings.program = a.cliDetectedProgram(a.cliSettings.profile)
		if a.cliSettings.detectedReady {
			a.cliSettings.probedProfile = a.cliSettings.profile
		}
	} else if a.cliSettings.program != "" && a.cliSettings.detectedReady {
		a.cliSettings.probedProfile = a.cliSettings.profile
	}
	if a.cliSettings.slotItemIDs == nil {
		a.cliSettings.slotItemIDs = map[string]string{}
	}
}

func (a *App) selectCLIProfile(name string) {
	a.cliSettings.profile = name
	if existing, ok := a.cliSettings.store.Bindings[name]; ok {
		a.cliSettings.program = existing.Program
		a.cliSettings.tokenEnvName = existing.TokenEnvName
		a.cliSettings.probedProfile = name
	} else {
		a.cliSettings.program = a.cliDetectedProgram(name)
		a.cliSettings.tokenEnvName = ""
		if a.cliSettings.detectedReady {
			a.cliSettings.probedProfile = name
		} else {
			a.cliSettings.probedProfile = ""
		}
	}
	a.cliSettings.precheckDigest = ""
	a.cliSettings.precheckStatus = ""
	a.cliSettings.precheckOK = false
	a.cliSettings.status = ""
}

func (a *App) loadCLIIntegrationStore() {
	a.cliSettings.storeAttemptedPath = a.cliSettings.bindingPath
	path := strings.TrimSpace(a.cliSettings.bindingPath)
	if path == "" {
		a.cliSettings.store = clibinding.NewStore()
		a.cliSettings.loaded = false
		a.cliSettings.loadErr = "CLI 绑定文件路径不能为空"
		return
	}
	if !filepath.IsAbs(path) || filepath.Clean(path) != path {
		a.cliSettings.store = clibinding.NewStore()
		a.cliSettings.loaded = false
		a.cliSettings.loadErr = "CLI 绑定文件必须是规范化绝对路径"
		return
	}
	if _, statErr := os.Lstat(path); errors.Is(statErr, os.ErrNotExist) {
		a.cliSettings.store = clibinding.NewStore()
		a.cliSettings.loaded = true
		a.cliSettings.loadErr = ""
		return
	}
	store, err := clibinding.Load(path)
	if errors.Is(err, os.ErrNotExist) {
		store = clibinding.NewStore()
		err = nil
	}
	if err != nil {
		a.cliSettings.store = clibinding.NewStore()
		a.cliSettings.loaded = false
		a.cliSettings.loadErr = "CLI 绑定文件无效或权限不可用"
		return
	}
	a.cliSettings.store = store
	a.cliSettings.loaded = true
	a.cliSettings.loadErr = ""
}

func (a *App) resolveCLITargetItem(slot cliprofile.Slot) (id, rev string, ok bool) {
	if specific := strings.TrimSpace(a.cliSettings.slotItemIDs[slot.Name]); specific != "" {
		for _, row := range a.v2.all {
			if row.ID == specific && row.State != "trashed" {
				return row.ID, row.Revision, true
			}
		}
		if a.v2.detail != nil && a.v2.selectedID == specific {
			return a.v2.selectedID, a.v2.selectedRevision, true
		}
	}
	if sel := strings.TrimSpace(a.cliSettings.selectedItemID); sel != "" {
		for _, row := range a.v2.all {
			if row.ID == sel && row.State != "trashed" {
				return row.ID, row.Revision, true
			}
		}
		if a.v2.detail != nil && a.v2.selectedID == sel {
			return a.v2.selectedID, a.v2.selectedRevision, true
		}
	}
	if a.v2.detail != nil && a.v2.selectedID != "" && a.v2.selectedRevision != "" &&
		(slot.Kind != "document" || a.v2.detail.Category == vault.CategoryDocument) {
		return a.v2.selectedID, a.v2.selectedRevision, true
	}
	if len(a.v2.all) > 0 {
		for _, row := range a.v2.all {
			if row.State == "trashed" {
				continue
			}
			if slot.Kind == "document" && row.Category == vault.CategoryDocument {
				return row.ID, row.Revision, true
			}
		}
		for _, row := range a.v2.all {
			if row.State != "trashed" {
				return row.ID, row.Revision, true
			}
		}
	}
	return "", "", false
}

func launchTargetsForProfile(profile cliprofile.Spec, id, revision string) ([]clibinding.SlotTarget, error) {
	if id == "" || revision == "" {
		return nil, errors.New("missing vault target item")
	}
	targets := make([]clibinding.SlotTarget, 0, len(profile.Slots))
	for _, slot := range profile.Slots {
		if slot.Optional {
			continue
		}
		targets = append(targets, clibinding.SlotTarget{
			Slot:     slot.Name,
			ID:       id,
			Revision: revision,
			Field:    string(slot.Field),
		})
	}
	if len(targets) == 0 && len(profile.Slots) > 0 {
		slot := profile.Slots[0]
		targets = append(targets, clibinding.SlotTarget{
			Slot:     slot.Name,
			ID:       id,
			Revision: revision,
			Field:    string(slot.Field),
		})
	}
	if len(targets) == 0 {
		return nil, errors.New("profile defines no bindable slots")
	}
	return targets, nil
}

func (a *App) buildSlotTargets(spec cliprofile.Spec) ([]clibinding.SlotTarget, error) {
	if len(spec.Slots) == 0 {
		return nil, errors.New("profile defines no bindable slots")
	}
	var targets []clibinding.SlotTarget
	for _, slot := range spec.Slots {
		id, rev, ok := a.resolveCLITargetItem(slot)
		if !ok {
			if slot.Optional {
				continue
			}
			return nil, fmt.Errorf("槽位 %s 尚未选择凭据条目", slot.Name)
		}
		// Include optional slots when explicitly mapped or when sharing the primary login item.
		if slot.Optional && slot.Kind != "login" && a.cliSettings.slotItemIDs[slot.Name] == "" {
			continue
		}
		targets = append(targets, clibinding.SlotTarget{
			Slot:     slot.Name,
			ID:       id,
			Revision: rev,
			Field:    string(slot.Field),
		})
	}
	if len(targets) == 0 {
		return nil, errors.New("请先选择一个金库凭据条目")
	}
	return targets, nil
}

// precheckCLIProgram inspects the executable SHA-256 without touching any vault secret.
func (a *App) precheckCLIProgram() {
	a.resetCLIIntegrationSettings()
	if a.cliSettings.prechecking {
		return
	}
	program := strings.TrimSpace(a.cliSettings.program)
	if program == "" {
		program = a.cliDetectedProgram(a.cliSettings.profile)
		a.cliSettings.program = program
	}
	if program == "" {
		a.cliSettings.precheckDigest = ""
		a.cliSettings.precheckOK = false
		a.cliSettings.precheckStatus = "未在 PATH 找到可执行文件；请填写或选择绝对路径后再预检。"
		return
	}
	program = filepath.Clean(program)
	if !filepath.IsAbs(program) {
		a.cliSettings.precheckDigest = ""
		a.cliSettings.precheckOK = false
		a.cliSettings.precheckStatus = "可执行文件路径必须为规范化绝对路径。"
		return
	}
	applyResult := func(digest string, err error) {
		if err != nil {
			a.cliSettings.precheckDigest = ""
			a.cliSettings.precheckOK = false
			a.cliSettings.precheckStatus = "无法计算二进制 SHA-256；请检查文件是否存在或为常规可执行文件。"
			return
		}
		a.cliSettings.program = program
		a.cliSettings.precheckDigest = digest
		a.cliSettings.precheckOK = true
		a.cliSettings.precheckStatus = "预检通过（无凭据读取）：SHA-256 " + shortDigest(digest)
	}
	if a.win == nil {
		digest, err := clibinding.ComputeProgramSHA256(program)
		applyResult(digest, err)
		return
	}
	profile := a.cliSettings.profile
	a.cliSettings.prechecking = true
	a.cliSettings.precheckDigest = ""
	a.cliSettings.precheckOK = false
	a.cliSettings.precheckStatus = "正在计算二进制 SHA-256…"
	a.launch(func() {
		digest, err := clibinding.ComputeProgramSHA256(program)
		a.dispatch(func() {
			a.cliSettings.prechecking = false
			if a.cliSettings.profile != profile || filepath.Clean(strings.TrimSpace(a.cliSettings.program)) != program {
				return
			}
			applyResult(digest, err)
		})
	})
}

func (a *App) saveCurrentCLIBinding() {
	a.resetCLIIntegrationSettings()
	if a.session == nil || !a.session.Unlocked() {
		a.cliSettings.status = "金库已锁定；请先完整解锁"
		return
	}
	profile, ok := cliprofile.Lookup(a.cliSettings.profile)
	if !ok {
		a.cliSettings.status = "未知 CLI 配置"
		return
	}
	spec := profile.Spec()
	targets, err := a.buildSlotTargets(spec)
	if err != nil {
		a.cliSettings.status = "请先在金库中选择一个凭据条目"
		return
	}
	if spec.DynamicTokenEnv && !cliprofile.ValidTokenEnvName(strings.TrimSpace(a.cliSettings.tokenEnvName)) {
		a.cliSettings.status = "自定义 Token 需要合法的环境变量名（如 MY_API_TOKEN，且不能与受保护环境变量冲突）"
		return
	}
	program := strings.TrimSpace(a.cliSettings.program)
	if program == "" && !spec.RequireExplicitProgram {
		program = a.cliDetectedProgram(a.cliSettings.profile)
		a.cliSettings.program = program
	}
	if program == "" {
		a.cliSettings.status = "未找到可执行文件；请选择程序完整路径"
		return
	}
	program = filepath.Clean(program)
	if !filepath.IsAbs(program) {
		a.cliSettings.status = "可执行文件必须是绝对路径"
		return
	}
	digest, err := clibinding.ComputeProgramSHA256(program)
	if err != nil {
		a.cliSettings.status = "无法读取可执行文件；请检查路径与权限"
		return
	}
	a.cliSettings.storeAttemptedPath = ""
	a.loadCLIIntegrationStore()
	if !a.cliSettings.loaded {
		a.cliSettings.status = a.cliSettings.loadErr
		return
	}
	store := a.cliSettings.store
	if store.Bindings == nil {
		store = clibinding.NewStore()
	}
	tool := a.cliSettings.profile
	binding := clibinding.ToolBinding{
		Profile:       tool,
		VaultPath:     filepath.Clean(a.path),
		Program:       program,
		ProgramSHA256: digest,
		Targets:       targets,
	}
	if spec.DynamicTokenEnv {
		binding.TokenEnvName = strings.TrimSpace(a.cliSettings.tokenEnvName)
	}
	if err := binding.Validate(); err != nil {
		a.cliSettings.status = "绑定校验未通过：请检查目标条目、槽位或自定义环境变量设置"
		return
	}
	store.Bindings[tool] = binding
	if err := clibinding.Save(a.cliSettings.bindingPath, store); err != nil {
		if errors.Is(err, clibinding.ErrBinding) {
			a.cliSettings.status = "保存失败：目标目录（或其上级目录）包含其他账户的写入权限，安全策略拒绝写入；请点击「选择文件…」更换至仅当前用户可写的独立目录"
		} else {
			a.cliSettings.status = "CLI 绑定保存失败；配置未写入"
		}
		return
	}
	a.cliSettings.store = store
	a.cliSettings.loaded = true
	a.cliSettings.loadErr = ""
	a.cliSettings.precheckDigest = digest
	a.cliSettings.precheckOK = true
	a.cliSettings.status = "已保存 " + tool + " 绑定；程序指纹与条目修订已固定"
	a.touchActivity()
}

func cliBindingTargetSummary(binding clibinding.ToolBinding) string {
	parts := make([]string, 0, len(binding.Targets))
	for _, target := range binding.Targets {
		id := target.ID
		if len(id) > 8 {
			id = id[:8]
		}
		parts = append(parts, target.Slot+" ← "+target.Field+" · "+id)
	}
	return strings.Join(parts, "；")
}

func (a *App) cliWorkbenchMetrics() (total, detected, bound int) {
	all := cliprofile.List()
	total = len(all)
	for _, item := range all {
		name := item.Name()
		if _, ok := a.cliSettings.store.Bindings[name]; ok {
			bound++
		}
		if a.cliDetectedProgram(name) != "" {
			detected++
		}
	}
	return total, detected, bound
}

func (a *App) cliItemSelectionOptions(spec cliprofile.Spec) ([]oneui.NativeSelectOption[string], string) {
	var options []oneui.NativeSelectOption[string]
	hasDocSlot := false
	for _, s := range spec.Slots {
		if s.Kind == "document" {
			hasDocSlot = true
			break
		}
	}
	seen := map[string]bool{}
	for _, row := range a.v2.all {
		if row.State == "trashed" {
			continue
		}
		label := visible(row.Title)
		if label == "" {
			label = row.ID
		}
		if hasDocSlot && row.Category == vault.CategoryDocument {
			label = "[文档] " + label
		}
		options = append(options, oneui.NativeSelectOption[string]{
			Value: row.ID,
			Label: label + " (" + CategoryDisplayName(row.Category) + ")",
		})
		seen[row.ID] = true
	}
	if a.v2.detail != nil && a.v2.selectedID != "" && !seen[a.v2.selectedID] {
		options = append(options, oneui.NativeSelectOption[string]{
			Value: a.v2.selectedID,
			Label: visible(a.v2.detail.Title) + " (当前条目)",
		})
	}
	selected := strings.TrimSpace(a.cliSettings.selectedItemID)
	if selected == "" {
		selected = a.v2.selectedID
	}
	if selected == "" && len(options) > 0 {
		selected = options[0].Value
	}
	return options, selected
}

func (a *App) cliIntegrationsView(c *ui.Context) {
	t := c.Theme()
	a.resetCLIIntegrationSettings()
	if !a.cliSettings.loaded && a.cliSettings.storeAttemptedPath != a.cliSettings.bindingPath {
		a.loadCLIIntegrationStore()
	}

	profiles := cliprofile.List()
	totalProfiles, detectedCount, boundCount := a.cliWorkbenchMetrics()

	ui.Column(c).FillWidth().Gap(t.Space(1.5)).Children(func() {
		ui.Row(c).FillWidth().Wrap().AlignItems(ui.Center).Gap(t.Space(1.5)).Children(func() {
			onevraPill(c, fmt.Sprintf("全部 %d 个工具", totalProfiles), t.TextMuted)
			onevraPill(c, fmt.Sprintf("已检测 %d", detectedCount), t.Accent)
			onevraPill(c, fmt.Sprintf("已绑定 %d", boundCount), t.Success)
			onevraPill(c, "逐次确认 · 零驻留", t.TextMuted)
			ui.Box(c).Grow(1)
			oneui.Button(c, "重新扫描 PATH", oneui.ButtonOutline).Disabled(a.cliSettings.detecting).OnClick(func() {
				a.cliSettings.detectedReady = false
				a.cliSettings.probedProfile = ""
				a.ensureCLIDetection()
				if a.win == nil && a.cliSettings.program == "" {
					a.cliSettings.program = a.cliDetectedProgram(a.cliSettings.profile)
				}
				a.touchActivity()
			})
			oneui.Button(c, "+ 添加集成向导…", oneui.ButtonSecondary).Disabled(a.uiBusy(c)).OnClick(func() {
				a.cliSettings.wizardOpen = true
				a.cliSettings.wizardStep = 1
			})
			oneui.Button(c, "返回开发者设置", oneui.ButtonGhost).OnClick(func() {
				a.v2.settingsSection = settingsSectionDeveloper
				a.touchActivity()
			})
		})
		oneui.Text(c, "支持全部 24 个内置 CLI 工具配置；选择左侧工具后，指定金库条目与可执行程序指纹即可保存绑定。").
			FontSize(t.Rem(.78)).TextColor(t.TextMuted).Wrap()
	})

	// 2-column CLI Workbench: filterable list of all 24 profiles + unified inspector
	renderProfileList := func(panel ui.Element, scrollable bool) {
		panel.Border(1, t.Border).Radius(t.Radius*1.25).Background(t.Surface).
			Padding(t.Space(2)).Gap(t.Space(1.25)).Children(func() {
			oneui.Text(c, "全部 CLI 工具 ("+intString(len(profiles))+")").FontSize(t.Rem(.78)).Bold().TextColor(t.TextMuted)
			oneui.TextBox(c, &a.cliSettings.query, oneui.TextBoxOptions{LeadingIcon: lucide.Search()}).
				Label("筛选 CLI 配置").Placeholder("搜索 gh / aws / kubectl / codex…").FillWidth()
			ui.Row(c).FillWidth().Gap(t.Space(.5)).Children(func() {
				for _, tab := range []struct {
					id, label string
				}{
					{"", "全部"},
					{"detected", "已检测"},
					{"bound", "已配置"},
				} {
					tab := tab
					variant := oneui.ButtonGhost
					if a.cliSettings.filterMode == tab.id {
						variant = oneui.ButtonSecondary
					}
					if oneui.Button(c.Key("cli-filter-"+tab.id), tab.label, variant).OnClick(func() {
						a.cliSettings.filterMode = tab.id
					}).Clicked() {
						a.touchActivity()
					}
				}
			})

			needle := strings.ToLower(strings.TrimSpace(a.cliSettings.query))
			renderRows := func() {
				ui.Column(c).FillWidth().Gap(t.Space(.25)).Children(func() {
					matched := 0
					for _, item := range profiles {
						item := item
						name := item.Name()
						display := cliProfileDisplayName(name)
						if needle != "" && !strings.Contains(strings.ToLower(name), needle) && !strings.Contains(strings.ToLower(display), needle) {
							continue
						}
						_, configured := a.cliSettings.store.Bindings[name]
						detectedProg := a.cliDetectedProgram(name)
						switch a.cliSettings.filterMode {
						case "detected":
							if detectedProg == "" {
								continue
							}
						case "bound":
							if !configured {
								continue
							}
						}
						matched++
						active := a.cliSettings.profile == name
						bg := ui.Transparent
						if active {
							bg = t.Accent.Alpha(.10)
						}
						rowBtn := ui.ButtonBase(c.Key("cli-profile-row-"+name)).FillWidth().Radius(t.Radius).Background(bg).
							Padding(t.Space(1), t.Space(1.75)).Label("配置 " + name).OnClick(func() {
							a.selectCLIProfile(name)
							a.touchActivity()
						})
						rowBtn.Children(func() {
							ui.Row(c).FillWidth().AlignItems(ui.Center).Gap(t.Space(1)).Children(func() {
								ui.Row(c).Grow(1).MinWidth(0).AlignItems(ui.Center).Gap(t.Space(1)).Children(func() {
									title := oneui.Text(c, display).FontSize(t.Rem(.8)).Bold().SingleLine().Ellipsis("…")
									if active {
										title.TextColor(t.Accent)
									}
									oneui.Text(c, name).FontSize(t.Rem(.70)).TextColor(t.TextMuted).SingleLine().Shrink(0)
								})
								if configured {
									onevraPill(c, "已配置", t.Success)
								} else if detectedProg != "" {
									onevraPill(c, "已检测", t.TextMuted)
								}
							})
						})
					}
					if matched == 0 {
						oneui.Text(c, "没有匹配的 CLI 工具配置").FontSize(t.Rem(.78)).TextColor(t.TextMuted).Wrap()
					}
				})
			}
			if scrollable {
				oneui.ScrollView(c, oneui.ScrollViewOptions{}).Grow(1).FillWidth().Children(renderRows)
			} else {
				renderRows()
			}
		})
	}

	renderInspector := func(col ui.Element) {
		selectedProfile, ok := cliprofile.Lookup(a.cliSettings.profile)
		if !ok && len(profiles) > 0 {
			selectedProfile = profiles[0]
			a.cliSettings.profile = selectedProfile.Name()
		}
		spec := selectedProfile.Spec()
		boundBinding, isBound := a.cliSettings.store.Bindings[a.cliSettings.profile]

		col.Gap(t.Space(2.5)).Children(func() {
			ui.Row(c).FillWidth().AlignItems(ui.Center).Gap(t.Space(1.5)).Children(func() {
				oneui.Text(c, cliProfileDisplayName(a.cliSettings.profile)).FontSize(t.Rem(1.1)).Bold().Grow(1)
				onevraPill(c, a.cliSettings.profile, t.TextMuted)
				if isBound {
					onevraPill(c, "已绑定", t.Success)
				} else if a.cliDetectedProgram(a.cliSettings.profile) != "" {
					onevraPill(c, "已检测到程序", t.Accent)
				}
			})

			itemOpts, selectedItem := a.cliItemSelectionOptions(spec)
			onevraGroup(c, "1. 选择凭据条目与注入字段", func(row func(func())) {
				for _, slot := range spec.Slots {
					slot := slot
					reqText := "必需"
					reqColor := t.Accent
					if slot.Optional {
						reqText = "可选"
						reqColor = t.TextMuted
					}
					kindText := "登录字段"
					if slot.Kind == "document" {
						kindText = "加密附件文档"
					}
					row(func() {
						oneui.Text(c, slot.Name).FontSize(t.Rem(.82)).Bold().MinWidth(0).Grow(1)
						oneui.Text(c, fmt.Sprintf("%s · 字段 %s", kindText, slot.Field)).FontSize(t.Rem(.76)).TextColor(t.TextMuted)
						onevraPill(c, reqText, reqColor)
					})
				}
				row(func() {
					ui.Column(c).FillWidth().Gap(t.Space(1.5)).Children(func() {
						if len(itemOpts) > 0 {
							itemSel := oneui.NativeSelect(c, &selectedItem, itemOpts)
							itemSel.Trigger.Label("绑定金库条目").FillWidth()
							if itemSel.Changed() {
								a.cliSettings.selectedItemID = selectedItem
							}
						} else if a.v2.detail != nil {
							oneui.Text(c, "当前绑定条目："+a.v2.detail.Title+" · 修订 "+shortDigest(a.v2.selectedRevision)).
								FontSize(t.Rem(.78)).TextColor(t.TextMuted).Wrap()
						} else {
							ui.Row(c).FillWidth().Wrap().AlignItems(ui.Center).Gap(t.Space(1.5)).Children(func() {
								oneui.Text(c, "当前金库暂无可用条目；请先新建或选中凭据条目后再绑定。").
									FontSize(t.Rem(.78)).TextColor(t.Warning).Grow(1).MinWidth(180).Wrap()
								oneui.Button(c, "+ 新建凭据条目", oneui.ButtonOutline).
									Disabled(a.uiBusy(c) || a.session == nil).
									OnClick(func() {
										a.newItem(vault.CategoryAPICredential)
									})
							})
						}
						if spec.DynamicTokenEnv {
							oneui.TextBox(c, &a.cliSettings.tokenEnvName, oneui.TextBoxOptions{}).
								Label("目标环境变量名").Placeholder("例如 MY_SERVICE_TOKEN（大写字母+数字+下划线）").FillWidth()
						}
					})
				})
			})

			onevraGroup(c, "2. 锁定可执行程序指纹 (SHA-256)", func(row func(func())) {
				row(func() {
					ui.Column(c).FillWidth().Gap(t.Space(1.5)).Children(func() {
						oneui.TextBox(c, &a.cliSettings.program, oneui.TextBoxOptions{}).
							Label("可执行文件").Placeholder("选择或自动检测程序的绝对路径").FillWidth()
						ui.Row(c).FillWidth().Wrap().Gap(t.Space(1.5)).Children(func() {
							oneui.Button(c, "自动检测程序", oneui.ButtonOutline).OnClick(a.detectCurrentCLIProgram)
							oneui.Button(c, "预检二进制指纹", oneui.ButtonOutline).Disabled(a.cliSettings.prechecking).OnClick(a.precheckCLIProgram)
						})
						if a.cliSettings.precheckStatus != "" {
							tone := t.TextMuted
							if a.cliSettings.precheckOK {
								tone = t.Success
							} else {
								tone = t.Warning
							}
							oneui.Text(c, a.cliSettings.precheckStatus).FontSize(t.Rem(.76)).TextColor(tone).Wrap()
						}
					})
				})
			})

			onevraGroup(c, "3. CLI 绑定文件与运行命令", func(row func(func())) {
				row(func() {
					ui.Column(c).FillWidth().Gap(t.Space(1.25)).Children(func() {
						oneui.Text(c, "仅保存非机密的条目 ID、修订号与程序 SHA-256，供项目目录中的 locklark cli run 读取。").
							FontSize(t.Rem(.74)).TextColor(t.TextMuted).Wrap()
						oneui.TextBox(c, &a.cliSettings.bindingPath, oneui.TextBoxOptions{}).
							Label("CLI 绑定文件").Placeholder(`绝对路径，例如 C:\project\.locklark-cli.json`).FillWidth()
						ui.Row(c).FillWidth().Wrap().Gap(t.Space(1)).Children(func() {
							oneui.Button(c, "选择文件…", oneui.ButtonOutline).Disabled(a.uiBusy(c)).OnClick(func() {
								win := a.win
								curPath := strings.TrimSpace(a.cliSettings.bindingPath)
								if curPath == "" {
									curPath = a.defaultCLIBindingPath()
								}
								a.runInteractive(func() outcome {
									picked, err := mygo.Dialog.Save(mygo.SaveDialogOptions{
										Parent:      win,
										Title:       "选择 CLI 绑定文件保存位置",
										DefaultPath: curPath,
										Filters:     []mygo.FileFilter{{Name: "Locklark CLI Binding", Extensions: []string{"json"}}},
									})
									return outcome{err: err, apply: func() {
										if strings.TrimSpace(picked) != "" {
											a.cliSettings.bindingPath = filepath.Clean(picked)
											a.cliSettings.loaded = false
											a.cliSettings.storeAttemptedPath = ""
											a.loadCLIIntegrationStore()
										}
									}}
								})
							})
							oneui.Button(c, "重新载入绑定", oneui.ButtonOutline).OnClick(func() {
								a.cliSettings.loaded = false
								a.cliSettings.storeAttemptedPath = ""
								a.loadCLIIntegrationStore()
								a.touchActivity()
							})
							oneui.Button(c, "使用当前金库目录", oneui.ButtonGhost).OnClick(func() {
								a.cliSettings.bindingPath = a.defaultCLIBindingPath()
								a.cliSettings.loaded = false
								a.cliSettings.storeAttemptedPath = ""
								a.loadCLIIntegrationStore()
								a.touchActivity()
							})
						})
						if a.cliSettings.loadErr != "" {
							oneui.Text(c, a.cliSettings.loadErr).FontSize(t.Rem(.76)).TextColor(t.Warning).Wrap()
						}
					})
				})
				command := `locklark cli run ` + a.cliSettings.profile + ` --binding "` + a.cliSettings.bindingPath + `" -- ...`
				row(func() {
					ui.Column(c).FillWidth().Gap(t.Space(1)).Children(func() {
						ui.Row(c).FillWidth().AlignItems(ui.Center).Children(func() {
							oneui.Text(c, "运行命令预览").FontSize(t.Rem(.74)).TextColor(t.TextMuted).Grow(1)
							oneui.Button(c, "复制 CLI 命令", oneui.ButtonGhost).OnClick(func() {
								if err := a.writeClipboard([]byte(command), time.Now().Add(30*time.Second), func() bool { return true }); err != nil {
									a.cliSettings.status = message(err)
									return
								}
								a.cliSettings.status = clipboardStatus(30 * time.Second)
							})
						})
						oneui.Text(c, command).FontSize(t.Rem(.76)).TextColor(t.Text).Selectable().Wrap()
					})
				})
			})

			ui.Row(c).FillWidth().Wrap().AlignItems(ui.Center).Gap(t.Space(1.5)).Children(func() {
				canSave := !a.uiBusy(c) && a.session != nil && (len(itemOpts) > 0 || a.v2.detail != nil)
				oneui.Button(c, "保存 "+a.cliSettings.profile+" 绑定", oneui.ButtonPrimary).
					Disabled(!canSave).
					OnClick(a.saveCurrentCLIBinding)
				if isBound {
					oneui.Button(c, "删除 "+a.cliSettings.profile, oneui.ButtonOutline).TextColor(t.Danger).OnClick(func() {
						next := a.cliSettings.store
						delete(next.Bindings, a.cliSettings.profile)
						if err := clibinding.Save(a.cliSettings.bindingPath, next); err != nil {
							a.cliSettings.status = "CLI 绑定删除失败"
							return
						}
						a.cliSettings.store = next
						a.cliSettings.status = "已删除 " + a.cliSettings.profile + " 绑定"
						a.touchActivity()
					})
				}
			})

			if isBound {
				onevraBanner(c, lucide.CircleCheck(), "当前固定绑定："+cliBindingTargetSummary(boundBinding)+" · SHA-256 "+shortDigest(boundBinding.ProgramSHA256), t.Success, nil)
			}
			if a.cliSettings.status != "" {
				oneui.Text(c, a.cliSettings.status).FontSize(t.Rem(.78)).TextColor(t.Text).Wrap()
			}
		})
	}

	availW, _ := c.Size()
	if availW < 760 {
		ui.Column(c).FillWidth().MinWidth(0).Gap(t.Space(2.5)).Children(func() {
			renderProfileList(ui.Column(c).FillWidth().Height(260), true)
			renderInspector(ui.Column(c).FillWidth().MinWidth(0))
		})
	} else {
		ui.Row(c).FillWidth().MinWidth(0).AlignItems(ui.Start).Gap(t.Space(3)).Children(func() {
			renderProfileList(ui.Column(c).Width(272).Shrink(0), false)
			renderInspector(ui.Column(c).Grow(1).MinWidth(0))
		})
	}

	// 4-step Add Integration Wizard modal
	ui.Column(c.Key("dialog-cli-wizard")).Children(func() {
		oneui.Dialog(c, &a.cliSettings.wizardOpen, oneui.DialogOptions{Label: "添加 CLI 集成向导"}, func(panel ui.Element) {
			panel.Width(520).Background(t.Surface).Border(1, t.Border).Radius(t.Radius*1.25).Padding(t.Space(4))
			panel.Children(func() {
				step := a.cliSettings.wizardStep
				if step < 1 || step > 4 {
					step = 1
					a.cliSettings.wizardStep = 1
				}
				ui.Column(c).FillWidth().Gap(t.Space(2.5)).Children(func() {
					ui.Row(c).FillWidth().AlignItems(ui.Center).Children(func() {
						oneui.Text(c, "添加 CLI 集成向导").FontSize(t.Rem(1.12)).Bold().Grow(1)
						onevraPill(c, fmt.Sprintf("第 %d / 4 步", step), t.Accent)
					})
					switch step {
					case 1:
						oneui.Text(c, "步骤 1：选择要集成的 CLI 工具").Bold()
						p := a.cliSettings.profile
						opts := make([]oneui.NativeSelectOption[string], 0, len(profiles))
						for _, item := range profiles {
							opts = append(opts, oneui.NativeSelectOption[string]{
								Value: item.Name(),
								Label: cliProfileDisplayName(item.Name()) + " · " + item.Name(),
							})
						}
						sel := oneui.NativeSelect(c, &p, opts)
						sel.Trigger.Label("目标 CLI Profile").FillWidth()
						if sel.Changed() {
							a.selectCLIProfile(p)
						}
					case 2:
						oneui.Text(c, "步骤 2：指定金库条目与槽位").Bold()
						if selProf, ok := cliprofile.Lookup(a.cliSettings.profile); ok {
							spec := selProf.Spec()
							itemOpts, chosen := a.cliItemSelectionOptions(spec)
							if len(itemOpts) > 0 {
								sel := oneui.NativeSelect(c, &chosen, itemOpts)
								sel.Trigger.Label("凭据条目").FillWidth()
								if sel.Changed() {
									a.cliSettings.selectedItemID = chosen
								}
							} else {
								oneui.Text(c, "当前金库暂无条目，请先创建一个凭据条目。").FontSize(t.Rem(.78)).TextColor(t.Warning).Wrap()
							}
							if spec.DynamicTokenEnv {
								oneui.TextBox(c, &a.cliSettings.tokenEnvName, oneui.TextBoxOptions{}).
									Label("环境变量名").Placeholder("MY_TOKEN").FillWidth()
							}
						}
					case 3:
						oneui.Text(c, "步骤 3：校验可执行文件与 SHA-256 指纹").Bold()
						oneui.TextBox(c, &a.cliSettings.program, oneui.TextBoxOptions{}).Label("可执行程序绝对路径").FillWidth()
						oneui.Button(c, "执行无凭据 SHA-256 预检", oneui.ButtonOutline).Disabled(a.cliSettings.prechecking).OnClick(a.precheckCLIProgram)
						if a.cliSettings.precheckStatus != "" {
							oneui.Text(c, a.cliSettings.precheckStatus).FontSize(t.Rem(.78)).Wrap()
						}
					case 4:
						oneui.Text(c, "步骤 4：确认固定策略并写入绑定文件").Bold()
						onevraGroup(c, "", func(row func(func())) {
							row(func() {
								oneui.Text(c, "工具").FontSize(t.Rem(.78)).TextColor(t.TextMuted).Width(90)
								oneui.Text(c, cliProfileDisplayName(a.cliSettings.profile)+" ("+a.cliSettings.profile+")").FontSize(t.Rem(.82)).Grow(1)
							})
							row(func() {
								oneui.Text(c, "可执行程序").FontSize(t.Rem(.78)).TextColor(t.TextMuted).Width(90)
								oneui.Text(c, a.cliSettings.program).FontSize(t.Rem(.76)).Grow(1).Wrap()
							})
							row(func() {
								oneui.Text(c, "绑定文件").FontSize(t.Rem(.78)).TextColor(t.TextMuted).Width(90)
								oneui.Text(c, a.cliSettings.bindingPath).FontSize(t.Rem(.76)).Grow(1).Wrap()
							})
						})
					}
					ui.Row(c).FillWidth().Justify(ui.SpaceBetween).Children(func() {
						if oneui.Button(c, "关闭向导", oneui.ButtonGhost).Clicked() {
							a.cliSettings.wizardOpen = false
						}
						ui.Row(c).Gap(t.Space(1.5)).Children(func() {
							if step > 1 && oneui.Button(c, "上一步", oneui.ButtonOutline).Clicked() {
								a.cliSettings.wizardStep--
							}
							if step < 4 {
								if oneui.Button(c, "下一步", oneui.ButtonPrimary).Clicked() {
									a.cliSettings.wizardStep++
								}
							} else if oneui.Button(c, "完成并保存绑定", oneui.ButtonPrimary).
								Disabled(a.uiBusy(c) || a.session == nil).Clicked() {
								a.saveCurrentCLIBinding()
								if _, bound := a.cliSettings.store.Bindings[a.cliSettings.profile]; bound {
									a.cliSettings.wizardOpen = false
								}
							}
						})
					})
				})
			})
		})
	})
}

func shortDigest(value string) string {
	if len(value) > 12 {
		return value[:12]
	}
	if value == "" {
		return "未选择"
	}
	return value
}
