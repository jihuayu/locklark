package desktop

import (
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"time"

	"github.com/egoist/mygo/ui"
	"github.com/jihuayu/locklark/internal/browserhost"
	"github.com/jihuayu/locklark/internal/personal"
	oneui "github.com/oneo-me/onevra/source/components"
	"github.com/oneo-me/onevra/source/icons/lucide"
)

const (
	cliActivitySchemaVersion = 1
	cliActivityLimit         = 250
)

type cliActivityTarget struct {
	Slot  string `json:"slot"`
	Field string `json:"field"`
	ID    string `json:"id"`
}

// cliActivityEntry deliberately contains no credential values, command
// arguments, environment values or full vault path. It records the local
// disclosure boundary so an owner can review which process requested which
// slots and whether the request was approved.
type cliActivityEntry struct {
	UTC     string              `json:"utc"`
	Outcome string              `json:"outcome"`
	User    string              `json:"user,omitempty"`
	PID     uint32              `json:"pid,omitempty"`
	Process string              `json:"process,omitempty"`
	Vault   string              `json:"vault,omitempty"`
	Targets []cliActivityTarget `json:"targets,omitempty"`
}

type cliActivityLog struct {
	Version int                `json:"version"`
	Entries []cliActivityEntry `json:"entries"`
}

type cliActivityState struct {
	mu      sync.Mutex
	path    string
	loaded  bool
	entries []cliActivityEntry
	filter  string
}

func cliActivityPathForSettings(path string) string {
	if strings.TrimSpace(path) == "" {
		path = SettingsPath()
	}
	return filepath.Join(filepath.Dir(path), "cli-activity.json")
}

func readCLIActivity(path string) ([]cliActivityEntry, error) {
	raw, err := os.ReadFile(path)
	if errors.Is(err, os.ErrNotExist) {
		return nil, nil
	}
	if err != nil {
		return nil, err
	}
	var log cliActivityLog
	if err := json.Unmarshal(raw, &log); err != nil || log.Version != cliActivitySchemaVersion {
		return nil, errors.New("invalid CLI activity log")
	}
	if len(log.Entries) > cliActivityLimit {
		log.Entries = log.Entries[len(log.Entries)-cliActivityLimit:]
	}
	for i := range log.Entries {
		if _, err := time.Parse(time.RFC3339Nano, log.Entries[i].UTC); err != nil {
			return nil, errors.New("invalid CLI activity timestamp")
		}
		switch log.Entries[i].Outcome {
		case "approved", "refused", "unavailable", "failed":
		default:
			return nil, errors.New("invalid CLI activity outcome")
		}
	}
	return append([]cliActivityEntry(nil), log.Entries...), nil
}

func writeCLIActivity(path string, entries []cliActivityEntry) error {
	if len(entries) > cliActivityLimit {
		entries = entries[len(entries)-cliActivityLimit:]
	}
	raw, err := json.MarshalIndent(cliActivityLog{Version: cliActivitySchemaVersion, Entries: entries}, "", "  ")
	if err != nil {
		return err
	}
	raw = append(raw, '\n')
	dir := filepath.Dir(path)
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return err
	}
	tmp, err := os.CreateTemp(dir, ".cli-activity-*.tmp")
	if err != nil {
		return err
	}
	name := tmp.Name()
	defer os.Remove(name)
	if err := tmp.Chmod(0o600); err != nil {
		tmp.Close()
		return err
	}
	if _, err := tmp.Write(raw); err != nil {
		tmp.Close()
		return err
	}
	if err := tmp.Sync(); err != nil {
		tmp.Close()
		return err
	}
	if err := tmp.Close(); err != nil {
		return err
	}
	if err := os.Rename(name, path); err != nil {
		return err
	}
	return os.Chmod(path, 0o600)
}

func (a *App) ensureCLIActivityLoadedLocked(path string) error {
	if a.cliActivity.loaded && a.cliActivity.path == path {
		return nil
	}
	entries, err := readCLIActivity(path)
	if err != nil {
		a.cliActivity.path = path
		a.cliActivity.loaded = false
		a.cliActivity.entries = nil
		return err
	}
	a.cliActivity.path = path
	a.cliActivity.loaded = true
	a.cliActivity.entries = entries
	return nil
}

func activityTargets(targets []personal.CLIBrokerTarget) []cliActivityTarget {
	out := make([]cliActivityTarget, 0, len(targets))
	for _, target := range targets {
		out = append(out, cliActivityTarget{Slot: target.Slot, Field: target.Field, ID: target.ID})
	}
	return out
}

func peerProcessName(process string) string {
	name := strings.ReplaceAll(process, "\\", "/")
	name = filepath.Base(name)
	if name == "." || name == "/" || name == "" {
		return "未知进程"
	}
	return name
}

// recordCLIActivity commits one non-secret request boundary. Approval fails
// closed if this entry cannot be written.
func (a *App) recordCLIActivity(outcome string, peer browserhost.Peer, req browserhost.BrokerCLIRequest) error {
	path := cliActivityPathForSettings(a.settingsPath)
	entry := cliActivityEntry{
		UTC:     time.Now().UTC().Format(time.RFC3339Nano),
		Outcome: outcome,
		User:    peer.User,
		PID:     peer.PID,
		Process: peerProcessName(peer.Process),
		Vault:   filepath.Base(req.VaultPath),
		Targets: activityTargets(req.Targets),
	}

	a.cliActivity.mu.Lock()
	defer a.cliActivity.mu.Unlock()
	if err := a.ensureCLIActivityLoadedLocked(path); err != nil {
		return err
	}
	entries := append(append([]cliActivityEntry(nil), a.cliActivity.entries...), entry)
	if len(entries) > cliActivityLimit {
		entries = entries[len(entries)-cliActivityLimit:]
	}
	if err := writeCLIActivity(path, entries); err != nil {
		return err
	}
	a.cliActivity.entries = entries
	return nil
}

func (a *App) loadCLIActivity() ([]cliActivityEntry, string) {
	path := cliActivityPathForSettings(a.settingsPath)
	a.cliActivity.mu.Lock()
	defer a.cliActivity.mu.Unlock()
	err := a.ensureCLIActivityLoadedLocked(path)
	entries := append([]cliActivityEntry(nil), a.cliActivity.entries...)
	if err != nil {
		return entries, "CLI 请求活动无法读取；不会显示未经校验的记录"
	}
	return entries, ""
}

func cliOutcomeLabel(outcome string) string {
	switch outcome {
	case "approved":
		return "已批准"
	case "refused":
		return "已拒绝"
	case "unavailable":
		return "金库未解锁"
	default:
		return "失败"
	}
}

func cliActivityMatchesFilter(entry cliActivityEntry, filter string) bool {
	switch filter {
	case "", "all":
		return true
	case "approved":
		return entry.Outcome == "approved"
	case "refused":
		return entry.Outcome == "refused"
	case "failed":
		return entry.Outcome == "failed" || entry.Outcome == "unavailable"
	default:
		return true
	}
}

func (a *App) cliRequestActivityView(c *ui.Context) {
	t := c.Theme()
	entries, loadErr := a.loadCLIActivity()

	ui.Row(c).FillWidth().AlignItems(ui.Center).Gap(t.Space(2)).Children(func() {
		oneui.Icon(c, lucide.ScrollText()).Size(t.Space(4), t.Space(4)).TextColor(t.Accent)
		oneui.Text(c, "CLI 请求活动").FontSize(t.Rem(1.15)).Bold().Grow(1)
		oneui.Button(c, "返回开发者设置", oneui.ButtonOutline).OnClick(func() {
			a.v2.settingsSection = settingsSectionDeveloper
			a.touchActivity()
		})
	})
	oneui.Text(c, "每次本机 CLI 凭据请求都会记录时间、调用进程、金库文件名和字段槽位。记录不含主密码、Secret Key、凭据值、命令参数或完整金库路径；本机请求记录不是签名账本，签名执行事件在下方单独显示。").FontSize(t.Rem(.78)).TextColor(t.TextMuted).Wrap()

	filter := a.cliActivity.filter
	if filter == "" {
		filter = "all"
	}
	var allCount, approvedCount, refusedCount, failedCount int
	var filtered []cliActivityEntry
	for _, entry := range entries {
		allCount++
		switch entry.Outcome {
		case "approved":
			approvedCount++
		case "refused":
			refusedCount++
		default:
			failedCount++
		}
		if cliActivityMatchesFilter(entry, filter) {
			filtered = append(filtered, entry)
		}
	}

	ui.Row(c).FillWidth().Wrap().AlignItems(ui.Center).Gap(t.Space(1.5)).Children(func() {
		chips := []struct {
			id, label string
			count     int
		}{
			{"all", "全部", allCount},
			{"approved", "已批准", approvedCount},
			{"refused", "已拒绝", refusedCount},
			{"failed", "失败", failedCount},
		}
		for _, chip := range chips {
			chip := chip
			variant := oneui.ButtonOutline
			if filter == chip.id {
				variant = oneui.ButtonSecondary
			}
			oneui.Button(c, chip.label, variant).OnClick(func() {
				a.cliActivity.filter = chip.id
			})
		}
		oneui.Badge(c, "显示 "+intString(len(filtered))+" / "+intString(len(entries)), oneui.BadgeOptions{Tone: oneui.BadgeNeutral})
	})

	ui.Column(c).FillWidth().Border(1, t.Border).Radius(t.Radius).Background(t.Surface).
		Padding(t.Space(3)).Gap(t.Space(1.5)).Children(func() {
		if loadErr != "" {
			oneui.Text(c, loadErr).TextColor(t.Warning).Wrap()
			return
		}
		if len(entries) == 0 {
			oneui.Text(c, "暂无 CLI 请求。通过 locklark cli run 或已连接工具请求字段后会显示在这里；也可在「CLI 集成」中完成工具绑定后测试运行。").TextColor(t.TextMuted).Wrap()
			return
		}
		if len(filtered) == 0 {
			oneui.Text(c, "当前筛选状态下没有 CLI 请求记录；切换回「全部」即可查看全部请求历史。").TextColor(t.TextMuted).Wrap()
			return
		}
		for i := len(filtered) - 1; i >= 0; i-- {
			entry := filtered[i]
			if i != len(filtered)-1 {
				ui.Box(c).FillWidth().Height(1).Background(t.Border)
			}
			ui.Row(c).FillWidth().Wrap().AlignItems(ui.Center).Gap(t.Space(1.5)).Children(func() {
				outcomeColor := t.TextMuted
				switch entry.Outcome {
				case "approved":
					outcomeColor = t.Success
				case "refused", "unavailable", "failed":
					outcomeColor = t.Warning
				}
				oneui.Text(c, cliOutcomeLabel(entry.Outcome)).Bold().TextColor(outcomeColor)
				oneui.Text(c, entry.Process).FontSize(t.Rem(.84)).Bold()
				oneui.Text(c, "PID "+uintString(entry.PID)).FontSize(t.Rem(.74)).TextColor(t.TextMuted)
				oneui.Text(c, entry.UTC).FontSize(t.Rem(.72)).TextColor(t.TextMuted)
			})
			detail := "金库 " + entry.Vault + " · " + intString(len(entry.Targets)) + " 个字段"
			oneui.Text(c, detail).FontSize(t.Rem(.76)).TextColor(t.TextMuted).Wrap()
			for _, target := range entry.Targets {
				shortID := target.ID
				if len(shortID) > 8 {
					shortID = shortID[:8]
				}
				oneui.Text(c, target.Slot+" ← "+target.Field+" · "+shortID).FontSize(t.Rem(.74)).TextColor(t.TextMuted)
			}
		}
	})

	ui.Column(c).FillWidth().Border(1, t.Border).Radius(t.Radius).Background(t.Surface).
		Padding(t.Space(3)).Gap(t.Space(1.5)).Children(func() {
		ui.Row(c).FillWidth().AlignItems(ui.Center).Gap(t.Space(1.5)).Children(func() {
			oneui.Text(c, "当前金库的 CLI 执行").Bold().Grow(1)
			oneui.Button(c, "刷新 CLI 审计", oneui.ButtonOutline).Disabled(a.busy || a.session == nil).OnClick(func() {
				session := a.session
				if session == nil {
					return
				}
				a.run(func() outcome {
					events, err := session.Audit()
					return outcome{err: err, apply: func() {
						a.audit = events
						a.status = "CLI 审计已刷新"
					}}
				})
			})
		})
		oneui.Text(c, "来自金库签名审计账本；这里只筛选受控 CLI 执行意图，不显示凭据、程序路径或命令参数。").FontSize(t.Rem(.76)).TextColor(t.TextMuted).Wrap()
		count := 0
		for i := len(a.audit) - 1; i >= 0; i-- {
			event := a.audit[i]
			if !cliRunAuditAction(event.Action) {
				continue
			}
			count++
			ui.Row(c).FillWidth().Wrap().AlignItems(ui.Center).Gap(t.Space(1.5)).Children(func() {
				oneui.Text(c, "CLI 执行").Bold().TextColor(t.Accent)
				oneui.Text(c, event.Action).FontSize(t.Rem(.78))
				oneui.Text(c, event.Result).FontSize(t.Rem(.76)).TextColor(t.TextMuted)
				oneui.Text(c, event.UTC).FontSize(t.Rem(.72)).TextColor(t.TextMuted)
			})
			item := event.Item
			if len(item) > 8 {
				item = item[:8]
			}
			if item != "" {
				oneui.Text(c, "条目 "+item).FontSize(t.Rem(.72)).TextColor(t.TextMuted)
			}
			if count == 50 {
				break
			}
		}
		if count == 0 {
			oneui.Text(c, "暂无已加载的 CLI 执行事件；运行 locklark cli run 后刷新这里。").TextColor(t.TextMuted).Wrap()
		}
	})
}

func cliRunAuditAction(action string) bool {
	return action == "item.run.bundle" || action == "item.run.username" || action == "item.run.password"
}
