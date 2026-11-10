// Package desktop is the native MyGo user interface. It exports no web bindings.
package desktop

import (
	"bytes"
	"context"
	"crypto/subtle"
	"errors"
	"fmt"
	"image"
	"image/color"
	"image/png"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"sync/atomic"
	"time"
	"unicode"

	"github.com/egoist/mygo"
	"github.com/egoist/mygo/transfer"
	"github.com/egoist/mygo/ui"
	"github.com/jihuayu/locklark/internal/browserhost"
	"github.com/jihuayu/locklark/internal/nativeclipboard"
	"github.com/jihuayu/locklark/internal/osunlock"
	"github.com/jihuayu/locklark/internal/personal"
	"github.com/jihuayu/locklark/internal/sshagent"
	"github.com/oneo-me/onevra/source/shells/plain"
	"github.com/oneo-me/onevra/source/theme"
)

type outcome struct {
	apply, drop func()
	err         error
}
type App struct {
	sshHost                                                *sshNativeHost
	sshService                                             *sshagent.Service
	sshApproval                                            *sshNativeRequest
	sshStarting, sshStopping                               bool
	sshStopSequence                                        uint64
	sshTitle, sshImportPath                                string
	sshRows                                                []personal.SSHKeyRow
	sshScope                                               string
	sshSelected                                            *personal.SSHKeyRow
	sshRetired                                             []*sshNativeHost
	notesEditor                                            *nativeNotesDraft
	quick                                                  quickSearchPanel
	quickShortcut                                          string
	operationSequence                                      uint64
	operation                                              *nativeOperation
	mutationUnknown                                        bool
	website, generationLength                              string
	regenerate                                             *personal.NativeLoginView
	exposureGeneration, displaySequence, clipboardSequence uint64
	otpDisplay                                             string
	otpDisplayBounds, otpClipboard                         *personal.OTPBounds
	otpDisplayTarget, otpClipboardTarget                   personal.NativeOTPTarget
	otpDisplayTimer, otpClipboardTimer                     *time.Timer
	fieldDisplaySequence                                   uint64
	displayTimer                                           *time.Timer
	clipboardTimer                                         *time.Timer
	idleSequence                                           uint64
	idleTimer                                              *time.Timer
	queryGeneration                                        uint64

	brokerMu       sync.Mutex
	broker         *browserhost.Broker
	brokerEndpoint string
	brokerSession  *personal.Session
	brokerEpoch    uint64
	cliApprover    func(context.Context, browserhost.Peer, browserhost.BrokerCLIRequest) (bool, error)
	cliPending     *cliRunPending
	// browserPairs are explicit OS-peer pairing reviews. browserPairApprover
	// is a test-only hook used by the direct IPC regression; production always
	// waits for the native buttons below.
	browserPairs        []*browserPairPending
	browserPairApprover func(context.Context, browserhost.BrowserPairRequest) (browserhost.BrowserPairDecision, error)

	browserPasskeyID                               string
	browserSaveID, browserSaveTitle                string
	browser                                        *browserhost.Connection
	browserLabel                                   string
	cancel                                         context.CancelFunc
	systemStore                                    osunlock.Store
	win                                            *mygo.Window
	dispatch                                       func(func())
	launch                                         func(func())
	generation                                     uint64
	session                                        *personal.Session
	busy                                           bool
	path, password, secret, confirmation, issued   string
	create                                         bool
	status, page, query, scope                     string
	rows                                           []personal.Row
	selected                                       *personal.Row
	title, username, value, editField              string
	display                                        string
	displayUntil                                   time.Time
	clipboardUntil                                 time.Time
	clipboardLease, clipboardPending               *nativeclipboard.Lease
	clipboardRetry                                 *time.Timer
	clipboardWarning                               bool
	clipboardManual                                bool
	clipboardWrite                                 func([]byte) (*nativeclipboard.Lease, error)
	clipboardClear                                 func(*nativeclipboard.Lease) nativeclipboard.Result
	audit                                          []personal.Event
	report                                         string
	source, planDigest, exportPath, exportPassword string
	importFull                                     bool

	// M2.4 desktop v2 state. It is reset on lock and never survives a
	// session boundary; settings are non-secret and survive lock.
	v2             v2State
	v2Mode         bool
	onevra         onevraUI
	settings       Settings
	settingsPath   string
	settingsLoaded bool
	lastActivity   time.Time
	// clipboardClearSeconds mirrors security.clipboard.clearAfterSeconds for
	// broker connection goroutines. Only settings mutations and UI start write
	// it; the IPC factory and lease getter read it without touching a.settings.
	clipboardClearSeconds atomic.Int64
	backgroundStop        chan struct{}
	backgroundRunningFlag uint32
}

func New() *App {
	a := &App{generationLength: "24", systemStore: osunlock.New(), scope: "active", sshScope: "active", page: "vault", editField: "password", dispatch: func(fn func()) { fn() }, launch: func(fn func()) { go fn() }}
	a.settings = DefaultSettings()
	a.settingsPath = SettingsPath()
	a.settingsLoaded = true
	a.v2 = newV2State()
	a.refreshClipboardClearSeconds(a.settings)
	a.onevra = newOnevraUI()
	a.importFull = true
	return a
}
func (a *App) run(work func() outcome) { a.runContext(func(context.Context) outcome { return work() }) }
func (a *App) runContext(work func(context.Context) outcome) {
	if a.busy {
		return
	}
	a.beginOperation()
	a.busy = true
	a.status = "处理中…"
	generation := a.generation
	ctx, cancel := context.WithCancel(context.Background())
	a.cancel = cancel
	a.launch(func() {
		r := work(ctx)
		cancel()
		a.dispatch(func() {
			if generation != a.generation {
				if r.drop != nil {
					r.drop()
				}
				return
			}
			a.busy = false
			if r.err != nil {
				a.status = message(r.err)
				if a.session != nil && !a.session.Unlocked() {
					a.Lock()
				} else if a.session != nil && a.idleTimer != nil {
					a.armIdleTimer()
				}
				return
			}
			a.status = "操作完成"
			if r.apply != nil {
				r.apply()
			}
			if a.session != nil && a.idleTimer != nil {
				a.armIdleTimer()
			}
		})
	})
}
func message(e error) string {
	switch {
	case errors.Is(e, personal.ErrSSHKey):
		return "SSH 密钥不可用；仅支持有效的未加密 OpenSSH Ed25519 私钥"
	case errors.Is(e, personal.ErrSSHSign):
		return "本次 SSH 签名已拒绝、撤销或过期；不会自动重试"
	case errors.Is(e, personal.ErrMutationUnknown):
		return mutationUnknownStatus
	case errors.Is(e, personal.ErrMutationCancelled):
		return "操作已取消，未开始写入"
	case errors.Is(e, personal.ErrMutationRefused):
		return "输入不符合保存要求；未保存"
	case errors.Is(e, personal.ErrOTPNotConfigured):
		return "此登录未配置验证码"
	case errors.Is(e, personal.ErrOTPTime):
		return "验证码已失效或时钟变化；本次未交付，请明确重新获取"
	case errors.Is(e, nativeclipboard.ErrUnsupported):
		return "此环境暂不支持安全复制；可使用按次显示"
	case errors.Is(e, nativeclipboard.ErrUnavailable):
		return "系统剪贴板暂不可用；本次未确认复制，不会自动重试"
	case errors.Is(e, nativeclipboard.ErrWrite):
		return "复制结果未确认，请检查系统剪贴板；不会自动重试"
	case errors.Is(e, personal.ErrDesktopDelivery):
		return "本次原生交付未完成；不会自动重试"
	case errors.Is(e, personal.ErrConflict):
		return "条目已在其他操作中变更，请刷新后重试"
	case errors.Is(e, personal.ErrTrashed):
		return "条目在回收站中，请先恢复"
	case errors.Is(e, personal.ErrSystemUnlockExpired):
		return "系统快捷解锁已过期；请重新完整解锁后主动启用"
	case errors.Is(e, osunlock.ErrNotFound):
		return "尚未启用系统快捷解锁；请先完整解锁并在安全设置启用"
	case errors.Is(e, osunlock.ErrMissingEntitlement):
		return "系统钥匙串缺少签名权限；此构建无法使用 Touch ID，请使用主密码与 Secret Key"
	case errors.Is(e, osunlock.ErrCancelled):
		return "系统验证已取消；可继续使用主密码与 Secret Key"
	case errors.Is(e, osunlock.ErrAuthFailed):
		return "系统验证未通过；可重试，或使用主密码与 Secret Key"
	case errors.Is(e, osunlock.ErrNotAvailable):
		return "系统钥匙串暂不可用；请稍后重试，必要时重启 Mac，或使用主密码与 Secret Key"
	case errors.Is(e, osunlock.ErrInteractionNotAllowed):
		return "当前无法显示系统验证（如屏幕已锁定）；解锁 Mac 后重试，或使用主密码与 Secret Key"
	case errors.Is(e, personal.ErrSystemUnlockUnavailable):
		return "系统快捷解锁不可用；需要系统密钥服务与正确权限，请使用主密码与 Secret Key"
	case errors.Is(e, personal.ErrSessionLocked):
		return "金库已锁定，请重新解锁"
	default:
		return "操作未完成。请检查输入、文件权限和当前版本后重试。"
	}
}
func visible(s string) string {
	var out strings.Builder
	for _, r := range s {
		if unicode.IsControl(r) || unicode.Is(unicode.Cf, r) {
			fmt.Fprintf(&out, "\\u{%X}", r)
		} else {
			out.WriteRune(r)
		}
	}
	return out.String()
}

type listFilter struct {
	query      string
	scope      string
	generation uint64
}

func (a *App) captureFilter() listFilter {
	scope := a.scope
	if scope == "" {
		scope = "active"
	}
	return listFilter{query: a.query, scope: scope, generation: a.queryGeneration}
}

func (a *App) filterCurrent(f listFilter) bool {
	scope := a.scope
	if scope == "" {
		scope = "active"
	}
	return a.query == f.query && scope == f.scope && a.queryGeneration == f.generation
}

func queryRows(s *personal.Session, f listFilter) ([]personal.Row, error) {
	if f.query == "" {
		return s.List(f.scope)
	}
	return s.Search(f.query, f.scope)
}

func (a *App) applyMutationRefresh(r nativeResult, filter listFilter) bool {
	a.selected = nil
	a.hideDisplay()
	if r.refreshErr != nil || !a.filterCurrent(filter) {
		a.rows = nil
		return false
	}
	a.rows = loginProjection(r.rows)
	return true
}

func (a *App) hideDisplay() {
	a.fieldDisplaySequence++
	if a.displayTimer != nil {
		a.displayTimer.Stop()
		a.displayTimer = nil
	}
	a.display = ""
	a.displayUntil = time.Time{}
}

func (a *App) showFieldDisplay(value string, until time.Time) {
	a.hideDisplay()
	a.display = value
	a.displayUntil = until
	sequence := a.fieldDisplaySequence
	generation := a.generation
	exposure := a.exposureGeneration
	if d := time.Until(until); !until.IsZero() && d > 0 {
		a.displayTimer = time.AfterFunc(d, func() {
			a.dispatch(func() {
				if a.generation == generation && a.exposureGeneration == exposure && a.fieldDisplaySequence == sequence {
					a.hideDisplay()
				}
			})
		})
	}
}

func (a *App) stopIdleTimer() {
	a.idleSequence++
	if a.idleTimer != nil {
		a.idleTimer.Stop()
		a.idleTimer = nil
	}
}

func (a *App) armIdleTimer() {
	a.stopIdleTimer()
	s := a.session
	if s == nil {
		return
	}
	deadline, ok := s.IdleDeadline()
	if !ok {
		a.Lock()
		return
	}
	generation := a.generation
	sequence := a.idleSequence
	d := max(time.Until(deadline), time.Millisecond)
	a.idleTimer = time.AfterFunc(d, func() {
		a.dispatch(func() {
			if a.session != s || a.generation != generation || a.idleSequence != sequence {
				return
			}
			a.idleTimer = nil
			if !s.Unlocked() {
				a.Lock()
				return
			}
			a.armIdleTimer()
		})
	})
}
func (a *App) Lock() {
	a.stopSSHAgent()
	a.sshRows = nil
	a.sshSelected = nil
	a.sshTitle = ""
	a.sshImportPath = ""
	if a.operation != nil {
		a.operation.gate.Cancel()
		if a.operation.gate.CommitWon() {
			a.mutationUnknown = true
		}
	}
	a.operation = nil
	// Revoke all session/UI authority before native clipboard metadata calls.
	a.generation++
	a.stopIdleTimer()
	a.clearNotesEditor()
	a.closeQuickSearch()
	s := a.session
	a.session = nil
	if s != nil {
		s.RequestLock()
	}
	a.cancelPendingCLIRun()
	a.cancelPendingBrowserPairs()
	a.notifyBrowserBrokerLocked()
	if s != nil {
		a.launch(s.Lock)
	}
	a.regenerate = nil
	if a.browser != nil {
		a.browser.Invalidate()
	}
	if a.cancel != nil {
		a.cancel()
		a.cancel = nil
	}
	a.password = ""
	a.secret = ""
	a.confirmation = ""
	a.issued = ""
	a.value = ""
	a.username = ""
	a.title = ""
	a.website = ""
	a.display = ""
	a.exportPassword = ""
	a.rows = nil
	a.selected = nil
	a.audit = nil
	a.report = ""
	a.planDigest = ""
	a.query = ""
	a.queryGeneration++
	a.browserSaveID = ""
	a.browserSaveTitle = ""
	a.busy = false
	a.status = "金库已锁定"
	if a.mutationUnknown {
		a.status += " · " + mutationUnknownStatus
	}
	if a.browser != nil && a.browser.OTPUnknown() {
		a.status += " · 验证码交付结果未确认；不会自动重试"
	}
	if a.browser != nil && a.browser.SaveUnknown() {
		a.status += " · 结果未确认，请在金库核实，勿重复保存"
	}
	a.clearDailyExposure()
	a.resetV2()
	a.onevra.resetOnevra()
	a.v2Mode = false
	a.lastActivity = time.Time{}
}
func (a *App) unlock() {
	path := a.path
	pw := []byte(a.password)
	key, e := personal.ParseSecret(a.secret)
	a.password = ""
	a.secret = ""
	if e != nil {
		clear(pw)
		a.status = "Secret Key 格式不正确"
		return
	}
	a.runContext(func(ctx context.Context) outcome {
		defer clear(pw)
		defer clear(key)
		s, e := personal.UnlockSession(path, pw, key, 5*time.Minute)
		if e != nil {
			return outcome{err: e}
		}
		if ctx.Err() != nil {
			s.Lock()
			return outcome{err: personal.ErrSessionLocked}
		}
		rows, e := s.List("active")
		if e != nil {
			s.Lock()
			return outcome{err: e}
		}
		return outcome{drop: s.Lock, apply: func() {
			a.session = s
			a.armIdleTimer()
			a.rows = loginProjection(rows)
			a.scope = "active"
			a.page = "vault"
			a.v2Mode = !classicLayoutRequested()
			a.touchActivity()
			a.loadV2Metadata()
			a.status = "已解锁 · " + idleLockLabel(a.settingsSnapshot().AutoLockDuration())
			a.startBrowserBroker()
			a.notifyBrowserBrokerUnlocked()
		}}
	})
}
func (a *App) createVaultFile() {
	if a.password == "" || a.password != a.confirmation || subtle.ConstantTimeCompare([]byte(a.issued), []byte(a.secret)) != 1 {
		a.status = "请确认主密码，并重新输入离线保存的 Secret Key"
		return
	}
	path := a.path
	pw := []byte(a.password)
	key, e := personal.ParseSecret(a.secret)
	if e != nil {
		a.status = "密钥确认不正确"
		return
	}
	a.password = ""
	a.secret = ""
	a.confirmation = ""
	a.issued = ""
	a.run(func() outcome {
		defer clear(pw)
		defer clear(key)
		if e := personal.Create(path, string(pw), key); e != nil {
			return outcome{err: e}
		}
		s, e := personal.UnlockSession(path, pw, key, 5*time.Minute)
		if e != nil {
			return outcome{err: e}
		}
		return outcome{drop: s.Lock, apply: func() {
			a.session = s
			a.armIdleTimer()
			a.rows = nil
			a.scope = "active"
			a.page = "vault"
			a.create = false
			a.v2Mode = !classicLayoutRequested()
			a.touchActivity()
			a.loadV2Metadata()
			a.status = "金库已创建，Secret Key 请继续离线保管"
			a.startBrowserBroker()
			a.notifyBrowserBrokerUnlocked()
		}}
	})
}
func (a *App) refresh() {
	a.clearNotesEditor()
	a.clearDailyExposure()
	a.regenerate = nil
	s := a.session
	if s == nil {
		return
	}
	filter := a.captureFilter()
	a.run(func() outcome {
		rows, e := queryRows(s, filter)
		return outcome{err: e, apply: func() {
			if !a.filterCurrent(filter) {
				a.rows = nil
				a.selected = nil
				a.hideDisplay()
				a.status = "搜索条件已变更，请重新刷新"
				return
			}
			a.rows = loginProjection(rows)
			a.selected = nil
			a.hideDisplay()
			a.status = fmt.Sprintf("%d 个条目", len(a.rows))
		}}
	})
}
func (a *App) add() { a.saveNative(false) }
func (a *App) edit() {
	if a.session == nil || a.selected == nil || a.busy {
		return
	}
	s := a.session
	target := *a.selected
	field, value := a.editField, []byte(a.value)
	a.value = ""
	filter := a.captureFilter()
	generation := a.generation
	exposure, operation := a.exposureGeneration, a.operationSequence
	a.clearNotesEditor()
	a.clearDailyExposure()
	if a.session != s || a.generation != generation || a.exposureGeneration != exposure+1 || a.operationSequence != operation || a.selected == nil || a.selected.ID != target.ID || a.selected.Revision != target.Revision || a.busy {
		clear(value)
		return
	}
	started := a.runNative(func(g *personal.MutationGate) nativeResult {
		defer clear(value)
		rev, e := s.EditNativeField(target.ID, target.Revision, field, value, g)
		out := nativeResult{receipt: personal.GenerationReceipt{ID: target.ID, Revision: rev}, err: e}
		if e == nil {
			out.rows, out.refreshErr = queryRows(s, filter)
		}
		return out
	}, func(r nativeResult) {
		ok := a.applyMutationRefresh(r, filter)
		a.status = "字段已更新"
		if !ok {
			a.status += "；列表未刷新，请手动刷新"
		}
	})
	if !started {
		clear(value)
	}
}
func (a *App) state(action string) {
	if a.session == nil || a.selected == nil || a.busy {
		return
	}
	s := a.session
	target := *a.selected
	filter := a.captureFilter()
	generation := a.generation
	exposure, operation := a.exposureGeneration, a.operationSequence
	a.clearNotesEditor()
	a.clearDailyExposure()
	if a.session != s || a.generation != generation || a.exposureGeneration != exposure+1 || a.operationSequence != operation || a.selected == nil || a.selected.ID != target.ID || a.selected.Revision != target.Revision || a.busy {
		return
	}
	a.runNative(func(g *personal.MutationGate) nativeResult {
		rev, e := s.SetNativeState(target.ID, target.Revision, action, g)
		out := nativeResult{receipt: personal.GenerationReceipt{ID: target.ID, Revision: rev}, err: e}
		if e == nil {
			out.rows, out.refreshErr = queryRows(s, filter)
		}
		return out
	}, func(r nativeResult) {
		ok := a.applyMutationRefresh(r, filter)
		a.status = "操作完成"
		if !ok {
			a.status += "；列表未刷新，请手动刷新"
		}
	})
}
func (a *App) disclose(field, purpose string) {
	if a.selected == nil || a.session == nil {
		return
	}
	s := a.session
	target := personal.RevealTarget{ID: a.selected.ID, Revision: a.selected.Revision, Field: field}
	exposure, generation := a.exposureGeneration, a.generation
	a.run(func() outcome {
		f, e := s.PrepareField(target, purpose)
		return outcome{err: e, drop: func() { s.Discard(f) }, apply: func() {
			if !a.exposureCurrent(s, personal.NativeOTPTarget{ID: target.ID, Revision: target.Revision}, generation, exposure) {
				s.Discard(f)
				return
			}
			valid := func() bool {
				return a.exposureCurrent(s, personal.NativeOTPTarget{ID: target.ID, Revision: target.Revision}, generation, exposure)
			}
			e := s.Consume(f, func(value []byte) error {
				if purpose == "copy" {
					if e := a.writeClipboard(value, time.Now().Add(30*time.Second), valid); e != nil {
						return e
					}
					a.status = clipboardStatus(30 * time.Second)
				} else {
					shown := visible(string(value))
					if field == "notes" {
						shown = visibleNotes(string(value))
					}
					a.showFieldDisplay(shown, time.Now().Add(15*time.Second))
					a.status = "字段显示 15 秒"
				}
				return nil
			})
			if e != nil && valid() && !errors.Is(e, errClipboardSuperseded) {
				a.status = message(e)
			}

		}}
	})
}
func (a *App) View(c *ui.Context) {
	now := time.Now()
	a.checkOTPExposure(now)
	if !a.displayUntil.IsZero() && !now.Before(a.displayUntil) {
		a.hideDisplay()
	}
	if !a.clipboardUntil.IsZero() && !now.Before(a.clipboardUntil) {
		a.clearClipboard()
	}
	if a.session != nil && !a.session.Unlocked() {
		a.Lock()
	}
	// backgroundTick drives the v2 reveal/large-type timers and configurable
	// idle lock without requiring a render; the legacy idle timer remains for
	// the unconfigured/default path.
	a.backgroundTick(now)
	if a.session != nil && a.idleTimer == nil {
		a.armIdleTimer()
	}
	c.After(time.Second)
	t := c.Theme()
	a.brokerMu.Lock()
	cliPending := a.cliPending != nil
	pairPending := len(a.browserPairs) != 0
	a.brokerMu.Unlock()
	if cliPending {
		ui.Column(c.Key(a.generation)).Fill().Background(t.Background).Padding(24).Gap(16).Children(func() { a.cliApprovalView(c) })
		return
	}
	if pairPending {
		ui.Column(c.Key(a.generation)).Fill().Background(t.Background).Padding(24).Gap(16).Children(func() { a.browserPairView(c) })
		return
	}
	if a.session != nil && a.sshApproval == nil && a.browser == nil && !a.quick.open && a.v2Mode && a.page == "vault" {
		a.v2View(c)
		return
	}
	ui.Column(c.Key(a.generation)).Fill().Background(t.Background).Padding(24).Gap(14).Children(func() {
		if !a.onevra.shellActive {
			ui.Row(c).FillWidth().AlignItems(ui.Center).Gap(12).Children(func() {
				ui.Text(c, "LOCKLARK").FontSize(22).Bold().TextColor(t.Text)
				ui.Text(c, "本地金库").TextColor(t.TextMuted).Grow(1)
				if a.browser == nil {
					ui.Button(c, "快捷搜索").OnClick(a.showQuickSearch)
				}
				if a.session != nil {
					ui.Button(c, "立即锁定").OnClick(a.Lock)
				}
			})
		}
		if a.session == nil {
			a.lockView(c)
		} else if a.sshApproval != nil {
			a.sshApprovalView(c)
		} else if a.browser != nil {
			a.browserView(c)
		} else if a.quick.open {
			a.quickSearchView(c)
		} else {
			a.vaultView(c)
		}
		if a.mutationUnknown {
			ui.Text(c, mutationUnknownStatus).Bold().TextColor(t.Warning)
		}
		if a.clipboardWarning {
			ui.Text(c, "系统剪贴板清理未确认；会仅对原所有权重试").Bold().TextColor(t.Warning)
		}
		if a.clipboardManual {
			ui.Text(c, clipboardManualCleanupNotice()).Bold().TextColor(t.Warning)
		}
		ui.Text(c, a.status).FontSize(13).TextColor(t.TextMuted)
	})
}
func (a *App) lockView(c *ui.Context) {
	t := c.Theme()
	ui.Column(c).Width(560).Border(1, t.Border).Radius(t.Radius).Background(t.Surface).Padding(t.Space(4)).Gap(12).Children(func() {
		heading := "解锁金库"
		if a.create {
			heading = "创建离线金库"
		}
		ui.Text(c, heading).FontSize(26).Bold().TextColor(t.Text)
		ui.Text(c, "主密码与 Secret Key 仅在本机原生窗口输入，全程离线完成派生与加解密。").FontSize(13).TextColor(t.TextMuted)
		ui.Row(c).FillWidth().AlignItems(ui.End).Gap(8).Children(func() {
			ui.TextInput(c, &a.path).Label("金库文件").Placeholder("金库文件的完整路径").Disabled(a.busy).Grow(1)
			ui.Button(c, "选择金库位置…").Disabled(a.busy).OnClick(a.chooseVault)
		})
		ui.TextInput(c, &a.password).Label("主密码").Placeholder("主密码").Password().Disabled(a.busy)
		if a.create {
			ui.TextInput(c, &a.confirmation).Label("确认主密码").Placeholder("再次输入主密码").Password().Disabled(a.busy)
			if a.issued == "" {
				ui.Button(c, "生成 Secret Key").Disabled(a.busy).OnClick(func() {
					key, e := personal.NewSecret()
					if e != nil {
						a.status = "密钥生成失败"
						return
					}
					a.issued = personal.FormatSecret(key)
					clear(key)
				})
			} else {
				ui.Column(c).FillWidth().Border(1, t.Warning).Radius(t.Radius).Background(t.Background).Padding(t.Space(3)).Gap(6).Children(func() {
					ui.Text(c, "请立即离线备份此 Secret Key；一旦遗失，无法仅凭主密码恢复金库：").FontSize(12).TextColor(t.Warning)
					ui.Text(c, a.issued).FontSize(17).Bold().TextColor(t.Text)
				})
			}
		}
		ui.TextInput(c, &a.secret).Label("Secret Key").Placeholder("LL1-…（创建时重新输入已保存密钥）").Password().Disabled(a.busy)
		if a.create {
			ui.Row(c).Gap(8).Children(func() {
				ui.PrimaryButton(c, "确认密钥已离线保存并创建").Disabled(a.busy || a.issued == "").OnClick(a.createVaultFile)
				ui.Button(c, "返回解锁").Disabled(a.busy).OnClick(func() { a.Lock(); a.create = false; a.status = "" })
			})
		} else {
			ui.Row(c).Gap(8).Wrap().Children(func() {
				ui.PrimaryButton(c, "解锁").Disabled(a.busy).OnClick(a.unlock)
				ui.Button(c, "使用"+osunlock.Label()+"解锁").Disabled(a.busy || a.path == "").OnClick(a.systemUnlock)
				ui.Button(c, "创建新金库").Disabled(a.busy).OnClick(func() { a.Lock(); a.create = true; a.status = "" })
			})
			ui.Text(c, "首次或过期后需先完整解锁并在「安全设置」中启用快捷解锁；验证失败时可随时使用主密码与 Secret Key。").FontSize(12).TextColor(t.TextMuted)
			ui.Text(c, osunlock.Requirement()).FontSize(12).TextColor(t.TextMuted)
		}
	})
}
func (a *App) vaultView(c *ui.Context) {
	t := c.Theme()
	ui.Row(c).FillWidth().Padding(0, 0, 8, 0).Gap(8).Children(func() {
		tabs := []struct{ id, label string }{{"vault", "金库"}, {"ssh", "SSH 密钥"}, {"activity", "活动"}, {"health", "体检"}, {"transfer", "导入与导出"}}
		if classicLayoutRequested() {
			// Keep the classic tab as the only "安全设置" control there; the
			// Onevra shell hides its gear in this mode.
			tabs = append(tabs, struct{ id, label string }{"security", "安全设置"})
		}
		for _, tab := range tabs {
			tab := tab
			ui.Button(c, tab.label).OnClick(func() {
				a.clearNotesEditor()
				a.clearDailyExposure()
				a.regenerate = nil
				a.page = tab.id
				a.display = ""
				if tab.id == "ssh" {
					a.refreshSSHKeys()
				}
			})
		}
	})
	ui.Box(c).FillWidth().Height(1).Background(t.Border)
	switch a.page {
	case "ssh":
		a.sshKeysView(c)
	case "security":
		a.securityView(c)
	case "activity":
		a.activityView(c)
	case "health":
		a.healthView(c)
	case "transfer":
		a.transferView(c)
	default:
		a.itemsView(c)
	}
}
func (a *App) itemsView(c *ui.Context) {
	if a.notesEditor != nil {
		a.notesEditorView(c)
		return
	}
	if a.regenerate != nil {
		ui.Scroll(c).Fill().Children(func() { ui.Column(c).Gap(12).Children(func() { a.regenerationView(c) }) })
		return
	}
	ui.Row(c).Gap(8).Children(func() {
		input := ui.TextInput(c, &a.query).Label("搜索标题").Placeholder("搜索标题").Grow(1)
		if input.Changed() {
			a.queryGeneration++
		}
		ui.Button(c, "搜索 / 刷新").Disabled(a.busy).OnClick(a.refresh)
		ui.Button(c, "新建登录").Disabled(a.busy).OnClick(func() {
			a.clearNotesEditor()
			a.clearDailyExposure()
			a.selected = nil
			a.regenerate = nil
			a.value = ""
			a.username = ""
			a.title = ""
			a.website = ""
		})
	})
	ui.Row(c).Gap(8).Children(func() {
		for _, scope := range []struct{ id, label string }{{"active", "活动"}, {"archived", "归档"}, {"trashed", "回收站"}, {"all", "全部"}} {
			scope := scope
			ui.Button(c, scope.label).Disabled(a.busy).OnClick(func() { a.scope = scope.id; a.queryGeneration++; a.refresh() })
		}
	})
	ui.Row(c).Gap(24).Grow(1).Children(func() {
		ui.Scroll(c).Width(350).FillHeight().Children(func() {
			ui.Column(c).Gap(8).Children(func() {
				if len(a.rows) == 0 {
					ui.Text(c, "此范围没有条目")
				}
				for _, row := range a.rows {
					row := row
					ui.Button(c.Key(row.ID), visible(row.Title)+" · "+row.State).FillWidth().Disabled(a.busy).OnClick(func() {
						a.clearNotesEditor()
						a.clearDailyExposure()
						a.regenerate = nil
						a.selected = &row
						a.display = ""
						a.value = ""
					})
				}
			})
		})
		ui.Scroll(c).Grow(1).FillHeight().Children(func() {
			ui.Column(c).Gap(12).Children(func() {
				if a.selected == nil {
					a.addView(c)
					return
				}
				row := a.selected
				ui.Text(c, visible(row.Title)).FontSize(22).Bold()
				ui.Text(c, "ID: "+row.ID).FontSize(12)
				if row.State == "trashed" {
					ui.Text(c, "恢复后才能查看或使用字段")
					ui.Button(c, "恢复条目").Disabled(a.busy).OnClick(func() { a.state("item.untrash") })
					return
				}
				ui.Text(c, "所有显示与复制操作均记录本地审计；复制内容可能被系统剪贴板历史保留。").FontSize(12)
				ui.Row(c).Gap(8).Children(func() {
					ui.Button(c, "显示备注").Disabled(a.busy).OnClick(func() { a.disclose("notes", "show") })
					ui.Button(c, "复制备注").Disabled(a.busy).OnClick(func() { a.disclose("notes", "copy") })
					ui.Button(c, "编辑备注").Disabled(a.busy).OnClick(a.editNotes)
				})
				ui.Button(c, "重新生成本地密码").Disabled(a.busy).OnClick(a.reviewRegeneration)
				ui.Row(c).Gap(8).Children(func() {
					ui.Button(c, "显示验证码").Disabled(a.busy).OnClick(func() { a.requestOTP("show") })
					ui.Button(c, "复制验证码").Disabled(a.busy).OnClick(func() { a.requestOTP("copy") })
				})
				a.otpView(c)
				ui.Row(c).Gap(8).Children(func() {
					ui.Button(c, "显示用户名").Disabled(a.busy).OnClick(func() { a.disclose("username", "show") })
					ui.Button(c, "显示密码").Disabled(a.busy).OnClick(func() { a.disclose("password", "show") })
				})
				ui.Row(c).Gap(8).Children(func() {
					ui.Button(c, "复制用户名").Disabled(a.busy).OnClick(func() { a.disclose("username", "copy") })
					ui.Button(c, "复制密码").Disabled(a.busy).OnClick(func() { a.disclose("password", "copy") })
				})
				if a.display != "" {
					ui.Column(c).Role(ui.RoleGroup).Label("已授权显示的字段").Children(func() { ui.Text(c, a.display) })
					ui.Button(c, "立即隐藏").OnClick(func() { a.exposureGeneration++; a.hideDisplay() })
				}
				ui.Text(c, "更新单个字段（不预填原值，保存后旧值归入修订历史）：").Bold()
				ui.Row(c).Gap(6).Children(func() {
					for _, field := range []string{"title", "username", "password", "otp", "url"} {
						field := field
						ui.Button(c, field).OnClick(func() { a.editField = field; a.value = "" })
					}
				})
				ui.Text(c, "当前字段："+a.editField)
				ui.TextInput(c, &a.value).Label("新字段值").Placeholder("新值").Password().Disabled(a.busy)
				ui.Button(c, "确认保存字段").Disabled(a.busy).OnClick(a.edit)
				ui.Row(c).Gap(8).Children(func() {
					if row.State == "archived" {
						ui.Button(c, "取消归档").Disabled(a.busy).OnClick(func() { a.state("item.unarchive") })
					} else {
						ui.Button(c, "归档条目").Disabled(a.busy).OnClick(func() { a.state("item.archive") })
					}
					ui.Button(c, "移入回收站").Disabled(a.busy).OnClick(func() { a.state("item.trash") })
				})
			})
		})
	})
}
func (a *App) addView(c *ui.Context) {
	ui.Text(c, "新建登录").FontSize(22).Bold()
	ui.TextInput(c, &a.title).Label("登录标题").Placeholder("标题").Disabled(a.busy)
	ui.TextInput(c, &a.website).Label("网站（可选）").Placeholder("https://example.com").Disabled(a.busy)
	ui.TextInput(c, &a.username).Label("新登录用户名").Placeholder("用户名").Password().Disabled(a.busy)
	ui.TextInput(c, &a.value).Label("新登录密码").Placeholder("密码").Password().Disabled(a.busy)
	ui.PrimaryButton(c, "保存登录").Disabled(a.busy || strings.TrimSpace(a.title) == "").OnClick(a.add)
	ui.TextInput(c, &a.generationLength).Label("密码长度（22–256）").Disabled(a.busy)
	ui.Button(c, "生成强密码并保存").Disabled(a.busy || strings.TrimSpace(a.title) == "").OnClick(func() { a.saveNative(true) })
}
func (a *App) activityView(c *ui.Context) {
	t := c.Theme()
	ui.Row(c).FillWidth().AlignItems(ui.Center).Gap(12).Children(func() {
		ui.Column(c).Grow(1).Gap(2).Children(func() {
			ui.Text(c, "安全审计日志").FontSize(20).Bold().TextColor(t.Text)
			ui.Text(c, "记录所有解锁、显示、复制、自动填充、SSH 签名与 CLI 授权事件。").FontSize(12).TextColor(t.TextMuted)
		})
		ui.Button(c, "刷新活动").Disabled(a.busy).OnClick(func() {
			s := a.session
			a.run(func() outcome { events, e := s.Audit(); return outcome{err: e, apply: func() { a.audit = events }} })
		})
	})
	ui.Scroll(c).Grow(1).FillWidth().Border(1, t.Border).Radius(t.Radius).Background(t.Surface).Padding(t.Space(3)).Children(func() {
		ui.Column(c).FillWidth().Gap(6).Children(func() {
			if len(a.audit) == 0 {
				ui.Text(c, "暂无已加载的审计事件，请点击「刷新活动」查看最新记录。").FontSize(13).TextColor(t.TextMuted)
			}
			for _, e := range a.audit {
				ui.Column(c).FillWidth().Gap(4).Children(func() {
					ui.Text(c, fmt.Sprintf("%s · %s · %s", e.Action, e.Result, e.Item)).FontSize(13).TextColor(t.Text)
					ui.Box(c).FillWidth().Height(1).Background(t.Border)
				})
			}
		})
	})
}
func (a *App) healthView(c *ui.Context) {
	t := c.Theme()
	ui.Column(c).FillWidth().Border(1, t.Border).Radius(t.Radius).Background(t.Surface).Padding(t.Space(4)).Gap(12).Children(func() {
		ui.Row(c).FillWidth().AlignItems(ui.Center).Gap(12).Children(func() {
			ui.Column(c).Grow(1).Gap(4).Children(func() {
				ui.Text(c, "本地安全体检").FontSize(20).Bold().TextColor(t.Text)
				ui.Text(c, "基于本地离线规则检测弱密码、重复密码与未启用 2FA 的登录条目，不发起任何联网查询。").FontSize(13).TextColor(t.TextMuted)
			})
			ui.Button(c, "确认扫描活动登录").Disabled(a.busy).OnClick(func() {
				s := a.session
				a.run(func() outcome {
					report, e := s.Health()
					return outcome{err: e, apply: func() { a.report = fmt.Sprintf("%+v", report) }}
				})
			})
		})
		ui.Column(c).FillWidth().Border(1, t.Border).Radius(t.Radius).Background(t.Background).Padding(t.Space(3)).Children(func() {
			ui.Text(c, a.report).FontSize(13).TextColor(t.Text)
		})
	})
}
func importDirectory() string {
	home, err := os.UserHomeDir()
	if err != nil {
		return ""
	}
	return filepath.Join(home, "Downloads")
}

func (a *App) transferView(c *ui.Context) {
	t := c.Theme()
	ui.Row(c).FillWidth().Gap(16).Children(func() {
		// Left card: 1Password 1PUX Import
		ui.Column(c).Grow(1).MinWidth(0).Border(1, t.Border).Radius(t.Radius).Background(t.Surface).Padding(14).Gap(8).Children(func() {
			ui.Text(c, "1Password 1PUX 导入：默认导入登录与纯文本备注，可选完整类别（实验）；不支持的数据将整批原子拒绝，来源记录加密保留。").FontSize(13).Bold().TextColor(t.Text)
			ui.Row(c).FillWidth().AlignItems(ui.End).Gap(8).Children(func() {
				ui.TextInput(c, &a.source).Label("1PUX 文件").Placeholder("1PUX 归档完整路径").Disabled(a.busy).Grow(1)
				ui.Button(c, "选择 1PUX 文件…").Disabled(a.busy).OnClick(func() {
					win := a.win
					a.run(func() outcome {
						paths, e := mygo.Dialog.Open(mygo.OpenDialogOptions{Parent: win, Title: "选择 1Password 1PUX", DefaultPath: importDirectory(), Filters: []mygo.FileFilter{{Name: "1Password 1PUX", Extensions: []string{"1pux"}}}})
						return outcome{err: e, apply: func() {
							if len(paths) == 1 {
								a.source = paths[0]
								a.planDigest = ""
								a.report = ""
							}
						}}
					})
				})
			})
			drop := ui.Column(c).FillWidth().Border(1, t.Border).Radius(t.Radius).Background(t.Background).Gap(2).Padding(8).Children(func() {
				ui.Text(c, "或把 .1pux 文件拖到这里").FontSize(13).Bold().TextColor(t.Accent)
			})
			if !a.busy {
				if d, ok := ui.DropData(drop, transfer.DropOptions{Formats: []transfer.Format{transfer.FileList, transfer.URIList}, Operations: transfer.Copy}); ok {
					files, e := d.Data.Files()
					switch {
					case e != nil:
						a.status = "无法读取拖入的文件"
					case len(files) != 1:
						a.status = "一次只能拖入一个 .1pux 文件"
					case !strings.EqualFold(filepath.Ext(files[0]), ".1pux"):
						a.status = "请拖入 1Password 导出的 .1pux 文件"
					default:
						a.source, a.planDigest, a.report = files[0], "", ""
						a.status = "已选择 1PUX，请生成导入计划"
					}
				}
			}
			ui.Row(c).Gap(8).Wrap().AlignItems(ui.Center).Children(func() {
				ui.Checkbox(c, &a.importFull, "完整类别（含卡片/身份/笔记，实验）").Disabled(a.busy).OnChange(func() {
					a.planDigest = ""
					a.report = ""
				})
				ui.Button(c, "打开 1Password 导出…").Disabled(a.busy).OnClick(func() {
					c.OpenURLThen("onepassword://", func(err error) {
						a.dispatch(func() {
							if err != nil {
								a.status = "无法自动打开 1Password，请手动启动并导出 .1pux"
								return
							}
							a.status = "已打开 1Password；请选择金库 → 导出 → 1PUX，再把文件拖回此页"
						})
					})
				})
			})
			ui.Text(c, "1Password 8：选择金库 → 导出 → 1PUX；Locklark 不接收 1Password 主密码或 Secret Key。").FontSize(12).TextColor(t.TextMuted)
			ui.Text(c, "1Password 7 的 .opvault 目录不能直接导入；请先导出为 .1pux。").FontSize(12).TextColor(t.TextMuted)
			ui.Text(c, "1PUX 是未加密导出文件；导入完成后请安全删除。").FontSize(12).TextColor(t.Warning)
			if a.report != "" {
				ui.Text(c, a.report).FontSize(12).Bold().TextColor(t.Text)
			}
			ui.Row(c).Gap(8).Wrap().Children(func() {
				ui.Button(c, "生成导入计划").Disabled(a.busy || strings.TrimSpace(a.source) == "").OnClick(func() {
					s, source, full := a.session, a.source, a.importFull
					a.planDigest = ""
					a.run(func() outcome {
						var r personal.ImportReceipt
						var e error
						if full {
							r, e = s.PlanImportV2(source)
						} else {
							r, e = s.PlanImport(source)
						}
						return outcome{err: e, apply: func() {
							a.planDigest = r.Report.SourceDigest
							mode := "登录与备注"
							if full {
								mode = "完整类别"
							}
							a.report = fmt.Sprintf("%s：待导入 %d 条，归档 %d 条", mode, r.Report.Items, r.Report.Archived)
						}}
					})
				})
				ui.PrimaryButton(c, "确认整批导入").Disabled(a.busy || a.planDigest == "").OnClick(func() {
					s, source, digest, full := a.session, a.source, a.planDigest, a.importFull
					a.planDigest = ""
					a.run(func() outcome {
						var e error
						if full {
							_, e = s.ImportV2(source, digest)
						} else {
							_, e = s.Import(source, digest)
						}
						return outcome{err: e, apply: func() { a.status = "导入完成，请到金库刷新" }}
					})
				})
			})
		})

		// Right card: KDBX Encrypted Export
		ui.Column(c).Width(360).Border(1, t.Border).Radius(t.Radius).Background(t.Surface).Padding(14).Gap(10).Children(func() {
			ui.Text(c, "KDBX 加密导出：导出所有状态条目及来源元数据，使用独立导出密码加密。").FontSize(13).Bold().TextColor(t.Text)
			ui.TextInput(c, &a.exportPath).Label("导出路径").Placeholder("新的 .kdbx 完整路径")
			ui.TextInput(c, &a.exportPassword).Label("独立导出密码").Placeholder("至少 12 字符的独立导出密码").Password()
			ui.Button(c, "确认加密导出").Disabled(a.busy).OnClick(func() {
				s, path, password := a.session, a.exportPath, a.exportPassword
				a.exportPassword = ""
				a.run(func() outcome { return outcome{err: s.Export(password, path)} })
			})
		})
	})
}
func Run() error {
	a := New()
	if e := a.LoadSettings(); e != nil {
		a.status = "安全设置文件无法读取；已使用默认值"
	}
	a.startBackgroundLoop()
	a.refreshClipboardClearSeconds(a.settingsSnapshot())
	mygo.App.SetName("Locklark")
	mygo.App.WhenReady(func() {
		if classicLayoutRequested() {
			// Keep the classic layout on its original window and header. The
			// Onevra shell header would duplicate its "快捷搜索", "立即锁定" and
			// "安全设置" controls, which breaks accessibility and the native
			// acceptance driver's unique-label requirement.
			a.win = mygo.NewWindow(mygo.WindowOptions{
				Title:     "Locklark · 本地金库",
				Width:     1100,
				Height:    820,
				MinWidth:  900,
				MinHeight: 680,
				Content:   ui.View(a.View),
			})
		} else {
			a.onevra.shellActive = true
			shell := plain.NewShell(plain.ShellOptions{
				Title:         "Locklark · 本地金库",
				Width:         1240,
				Height:        820,
				MinWidth:      980,
				MinHeight:     680,
				StateKey:      "locklark.main",
				Theme:         theme.Onevra,
				HeaderLeading: a.onevraHeaderLeading,
				HeaderActions: a.onevraHeaderActions,
				Content:       a.View,
			})
			a.win = shell.Window()
		}
		a.dispatch = a.win.Update
		a.win.OnClose(func(*mygo.CloseEvent) { a.Lock() })
		a.clipboardWrite = nativeclipboard.Write
		a.clipboardClear = nativeclipboard.ClearOwned
		// The broker may have started before the UI thread existed; publish the
		// settings snapshot again so every connection factory reads live values.
		a.refreshClipboardClearSeconds(a.settingsSnapshot())
		mygo.Power.OnSuspend(a.Lock)
		mygo.Power.OnLockScreen(a.Lock)
		mygo.App.OnQuit(a.Lock)
		a.startBrowserBroker()
		a.registerQuickSearch(mygo.GlobalShortcut.Register)
		icon := image.NewNRGBA(image.Rect(0, 0, 32, 32))
		for y := 4; y < 28; y++ {
			for x := 6; x < 26; x++ {
				icon.SetNRGBA(x, y, color.NRGBA{R: 33, G: 130, B: 110, A: 255})
			}
		}
		var pngIcon bytes.Buffer
		_ = png.Encode(&pngIcon, icon)
		_, _ = mygo.NewTray(mygo.TrayOptions{ID: "locklark", Icon: pngIcon.Bytes(), ToolTip: "Locklark", Menu: mygo.NewMenu([]*mygo.MenuItem{{Label: "打开金库", Click: func(*mygo.MenuItem, *mygo.Window) { a.win.Show(); a.win.Focus() }}, {Label: "快捷搜索", Click: func(*mygo.MenuItem, *mygo.Window) { a.showQuickSearch() }}, {Label: "立即锁定", Click: func(*mygo.MenuItem, *mygo.Window) { a.Lock(); a.win.Invalidate() }}, {Label: "退出", Click: func(*mygo.MenuItem, *mygo.Window) { a.Lock(); mygo.App.Quit() }}})})
	})
	err := mygo.App.Run()
	a.stopBackgroundLoop()
	a.Lock()
	a.stopBrowserBroker()
	if !a.waitSSHShutdown(5*time.Second) && err == nil {
		return sshagent.ErrUnavailable
	}
	return err
}

func (a *App) systemUnlock() {
	path, store := a.path, a.systemStore
	a.password = ""
	a.secret = ""
	a.runContext(func(ctx context.Context) outcome {
		s, e := personal.UnlockWithSystemContext(ctx, path, store, 5*time.Minute)
		if e != nil {
			return outcome{err: e}
		}
		rows, e := s.List("active")
		if e != nil {
			s.Lock()
			return outcome{err: e}
		}
		return outcome{drop: s.Lock, apply: func() {
			a.session = s
			a.armIdleTimer()
			a.rows = loginProjection(rows)
			a.scope = "active"
			a.page = "vault"
			a.v2Mode = !classicLayoutRequested()
			a.touchActivity()
			a.loadV2Metadata()
			a.status = "已通过系统解锁"
			a.startBrowserBroker()
			a.notifyBrowserBrokerUnlocked()
		}}
	})
}
func (a *App) securityView(c *ui.Context) {
	t := c.Theme()
	ui.Column(c).FillWidth().Gap(10).Children(func() {
		ui.Text(c, "安全设置").FontSize(22).Bold().TextColor(t.Text)
		ui.Column(c).FillWidth().Border(1, t.Border).Radius(t.Radius).Background(t.Surface).Padding(12).Gap(4).Children(func() {
			ui.Text(c, "快捷搜索："+quickSearchAcceleratorLabel()).Bold().TextColor(t.Text)
			shortcut := a.quickShortcut
			if shortcut == "" {
				shortcut = "全局快捷键尚未提交注册；可使用窗口顶部的「快捷搜索」按钮。"
			}
			ui.Text(c, shortcut).FontSize(13).TextColor(t.TextMuted)
		})
		ui.Column(c).FillWidth().Border(1, t.Border).Radius(t.Radius).Background(t.Surface).Padding(12).Gap(6).Children(func() {
			ui.Text(c, "快捷解锁："+osunlock.Label()).Bold().TextColor(t.Text)
			ui.Text(c, osunlock.Description()).FontSize(13).TextColor(t.Text)
			ui.Text(c, osunlock.Requirement()).FontSize(12).TextColor(t.TextMuted)
			ui.Text(c, "首次或授权到期后需使用主密码与 Secret Key 完整解锁，再主动启用；系统验证失败时仍可通过完整凭据解锁。").FontSize(12).TextColor(t.TextMuted)
			ui.Row(c).Gap(8).Wrap().Children(func() {
				ui.PrimaryButton(c, "启用系统快捷解锁（有效期 24 小时）").Disabled(a.busy).OnClick(func() {
					s, store := a.session, a.systemStore
					a.run(func() outcome {
						return outcome{err: s.EnableSystemUnlock(store), apply: func() { a.status = "系统快捷解锁已启用；现在可锁定并试用" }}
					})
				})
				ui.Button(c, "停用系统快捷解锁").Disabled(a.busy).OnClick(func() {
					path, store := a.path, a.systemStore
					a.run(func() outcome {
						return outcome{err: personal.DisableSystemUnlock(path, store), apply: func() { a.status = "系统快捷解锁已停用" }}
					})
				})
			})
		})
		ui.Column(c).FillWidth().Border(1, t.Border).Radius(t.Radius).Background(t.Surface).Padding(12).Children(func() {
			ui.Text(c, "自动锁定策略：默认 5 分钟无操作、系统锁屏或休眠时自动锁定；退出应用时立即清除内存会话。").FontSize(12).TextColor(t.TextMuted)
		})
	})
}

func (a *App) chooseVault() {
	win, create := a.win, a.create
	a.run(func() outcome {
		var path string
		var e error
		if create {
			path, e = mygo.Dialog.Save(mygo.SaveDialogOptions{Parent: win, Title: "创建金库", DefaultPath: "personal.ll", Filters: []mygo.FileFilter{{Name: "Locklark 金库", Extensions: []string{"ll"}}}})
		} else {
			var paths []string
			paths, e = mygo.Dialog.Open(mygo.OpenDialogOptions{Parent: win, Title: "选择金库", Filters: []mygo.FileFilter{{Name: "Locklark 金库", Extensions: []string{"ll"}}}})
			if len(paths) == 1 {
				path = paths[0]
			}
		}
		return outcome{err: e, apply: func() {
			if path != "" {
				a.path = path
			}
			a.status = ""
		}}
	})
}
