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
	"strings"
	"time"
	"unicode"

	"github.com/egoist/mygo"
	"github.com/egoist/mygo/ui"
	"github.com/jihuayu/locklark/internal/browserhost"
	"github.com/jihuayu/locklark/internal/nativeclipboard"
	"github.com/jihuayu/locklark/internal/osunlock"
	"github.com/jihuayu/locklark/internal/personal"
	"github.com/jihuayu/locklark/internal/sshagent"
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
	clipboardWrite                                 func([]byte) (*nativeclipboard.Lease, error)
	clipboardClear                                 func(*nativeclipboard.Lease) nativeclipboard.Result
	audit                                          []personal.Event
	report                                         string
	source, planDigest, exportPath, exportPassword string
}

func New() *App {
	return &App{generationLength: "24", systemStore: osunlock.New(), scope: "active", sshScope: "active", page: "vault", editField: "password", dispatch: func(fn func()) { fn() }, launch: func(fn func()) { go fn() }}
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
				}
				return
			}
			a.status = "操作完成"
			if r.apply != nil {
				r.apply()
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
	// Revoke all session/UI authority before native clipboard metadata calls.
	a.generation++
	a.clearNotesEditor()
	a.closeQuickSearch()
	s := a.session
	a.session = nil
	if s != nil {
		s.RequestLock()
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
	a.display = ""
	a.exportPassword = ""
	a.rows = nil
	a.selected = nil
	a.audit = nil
	a.report = ""
	a.planDigest = ""
	a.query = ""
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
			a.rows = loginProjection(rows)
			a.scope = "active"
			a.page = "vault"
			a.status = "已解锁 · 5 分钟未操作自动锁定"
		}}
	})
}
func (a *App) createVault() {
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
			a.rows = nil
			a.create = false
			a.status = "金库已创建，Secret Key 请继续离线保管"
		}}
	})
}
func (a *App) refresh() {
	a.clearNotesEditor()
	a.clearDailyExposure()
	a.regenerate = nil
	s, query, scope := a.session, a.query, a.scope
	if s == nil {
		return
	}
	a.run(func() outcome {
		var rows []personal.Row
		var e error
		if query == "" {
			rows, e = s.List(scope)
		} else {
			rows, e = s.Search(query, scope)
		}
		return outcome{err: e, apply: func() {
			a.rows = loginProjection(rows)
			a.selected = nil
			a.display = ""
			a.status = fmt.Sprintf("%d 个条目", len(a.rows))
		}}
	})
}
func (a *App) add() { a.saveNative(false) }
func (a *App) edit() {
	a.clearNotesEditor()
	a.clearDailyExposure()
	if a.selected == nil {
		return
	}
	s := a.session
	target := *a.selected
	field, value := a.editField, a.value
	a.value = ""
	scope := a.scope
	a.run(func() outcome {
		_, e := s.Edit(personal.Edit{ID: target.ID, Revision: target.Revision, Field: field, Value: value})
		if e != nil {
			return outcome{err: e}
		}
		rows, e := s.List(scope)
		return outcome{err: e, apply: func() { a.rows = loginProjection(rows); a.selected = nil; a.display = ""; a.status = "字段已更新" }}
	})
}
func (a *App) state(action string) {
	a.clearNotesEditor()
	a.clearDailyExposure()
	if a.selected == nil {
		return
	}
	s := a.session
	target := *a.selected
	scope := a.scope
	a.run(func() outcome {
		_, e := s.SetState(target.ID, target.Revision, action)
		if e != nil {
			return outcome{err: e}
		}
		rows, e := s.List(scope)
		return outcome{err: e, apply: func() { a.rows = loginProjection(rows); a.selected = nil; a.display = "" }}
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
					a.status = "已复制到系统剪贴板 · 30 秒后尝试清理"
				} else {
					if field == "notes" {
						a.display = visibleNotes(string(value))
					} else {
						a.display = visible(string(value))
					}
					a.displayUntil = time.Now().Add(15 * time.Second)
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
		a.display = ""
		a.displayUntil = time.Time{}
	}
	if !a.clipboardUntil.IsZero() && !now.Before(a.clipboardUntil) {
		a.clearClipboard()
	}
	if a.session != nil && !a.session.Unlocked() {
		a.Lock()
	}
	c.After(time.Second)
	ui.Column(c.Key(a.generation)).Fill().Padding(24).Gap(16).Children(func() {
		ui.Row(c).Gap(12).Children(func() {
			ui.Text(c, "LOCKLARK").FontSize(24).Bold()
			ui.Text(c, "本地金库").Grow(1)
			if a.browser == nil {
				ui.Button(c, "快捷搜索").OnClick(a.showQuickSearch)
			}
			if a.session != nil {
				ui.Button(c, "立即锁定").OnClick(a.Lock)
			}
		})
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
			ui.Text(c, mutationUnknownStatus).Bold()
		}
		if a.clipboardWarning {
			ui.Text(c, "系统剪贴板清理未确认；会仅对原所有权重试").Bold()
		}
		ui.Text(c, a.status).FontSize(13)
	})
}
func (a *App) lockView(c *ui.Context) {
	ui.Column(c).Width(540).Gap(12).Children(func() {
		heading := "解锁金库"
		if a.create {
			heading = "创建离线金库"
		}
		ui.Text(c, heading).FontSize(28).Bold()
		ui.Text(c, "主密码与 Secret Key 仅在本机原生窗口输入。")
		ui.TextInput(c, &a.path).Label("金库文件").Placeholder("金库文件的完整路径").Disabled(a.busy)
		ui.Button(c, "选择金库位置…").Disabled(a.busy).OnClick(a.chooseVault)
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
				ui.Text(c, "请离线抄写这份密钥，遗失后无法仅凭主密码恢复：")
				ui.Text(c, a.issued).FontSize(17)
			}
		}
		ui.TextInput(c, &a.secret).Label("Secret Key").Placeholder("LL1-…（创建时重新输入已保存密钥）").Password().Disabled(a.busy)
		if a.create {
			ui.PrimaryButton(c, "确认密钥已离线保存并创建").Disabled(a.busy || a.issued == "").OnClick(a.createVault)
		} else {
			ui.PrimaryButton(c, "解锁").Disabled(a.busy).OnClick(a.unlock)
			ui.Button(c, "使用"+osunlock.Label()+"解锁").Disabled(a.busy || a.path == "").OnClick(a.systemUnlock)
			ui.Text(c, "需先完整解锁并在安全设置启用；失败时可继续使用主密码与 Secret Key。")
		}
		label := "创建新金库"
		if a.create {
			label = "返回解锁"
		}
		ui.Button(c, label).Disabled(a.busy).OnClick(func() { a.Lock(); a.create = !a.create; a.status = "" })
	})
}
func (a *App) vaultView(c *ui.Context) {
	ui.Row(c).Gap(8).Children(func() {
		for _, tab := range []struct{ id, label string }{{"vault", "金库"}, {"ssh", "SSH 密钥"}, {"activity", "活动"}, {"health", "体检"}, {"transfer", "导入与导出"}, {"security", "安全设置"}} {
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
		ui.TextInput(c, &a.query).Label("搜索标题").Placeholder("搜索标题").Grow(1)
		ui.Button(c, "搜索 / 刷新").Disabled(a.busy).OnClick(a.refresh)
		ui.Button(c, "新建登录").Disabled(a.busy).OnClick(func() {
			a.clearNotesEditor()
			a.clearDailyExposure()
			a.selected = nil
			a.regenerate = nil
			a.value = ""
			a.username = ""
		})
	})
	ui.Row(c).Gap(8).Children(func() {
		for _, scope := range []struct{ id, label string }{{"active", "活动"}, {"archived", "归档"}, {"trashed", "回收站"}, {"all", "全部"}} {
			scope := scope
			ui.Button(c, scope.label).Disabled(a.busy).OnClick(func() { a.scope = scope.id; a.refresh() })
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
				ui.Text(c, "以下操作会记录审计。复制内容可能被系统剪贴板历史保留。")
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
					ui.Button(c, "立即隐藏").OnClick(func() { a.exposureGeneration++; a.display = ""; a.displayUntil = time.Time{} })
				}
				ui.Text(c, "更新一个字段（原值不预填）：")
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
	ui.TextInput(c, &a.website).Label("网站（可选）").Disabled(a.busy)
	ui.TextInput(c, &a.username).Label("新登录用户名").Placeholder("用户名").Password().Disabled(a.busy)
	ui.TextInput(c, &a.value).Label("新登录密码").Placeholder("密码").Password().Disabled(a.busy)
	ui.PrimaryButton(c, "保存登录").Disabled(a.busy || strings.TrimSpace(a.title) == "").OnClick(a.add)
	ui.TextInput(c, &a.generationLength).Label("密码长度（22–256）").Disabled(a.busy)
	ui.Button(c, "生成强密码并保存").Disabled(a.busy || strings.TrimSpace(a.title) == "").OnClick(func() { a.saveNative(true) })
}
func (a *App) activityView(c *ui.Context) {
	ui.Button(c, "刷新活动").Disabled(a.busy).OnClick(func() {
		s := a.session
		a.run(func() outcome { events, e := s.Audit(); return outcome{err: e, apply: func() { a.audit = events }} })
	})
	ui.Scroll(c).Grow(1).Children(func() {
		ui.Column(c).Gap(6).Children(func() {
			for _, e := range a.audit {
				ui.Text(c, fmt.Sprintf("%s · %s · %s", e.Action, e.Result, e.Item)).FontSize(13)
			}
		})
	})
}
func (a *App) healthView(c *ui.Context) {
	ui.Text(c, "本地规则体检，不查询泄露库；没有发现问题不表示密码安全。")
	ui.Button(c, "确认扫描活动登录").Disabled(a.busy).OnClick(func() {
		s := a.session
		a.run(func() outcome {
			report, e := s.Health()
			return outcome{err: e, apply: func() { a.report = fmt.Sprintf("%+v", report) }}
		})
	})
	ui.Text(c, a.report)
}
func (a *App) transferView(c *ui.Context) {
	ui.Text(c, "1PUX 登录及纯文本备注导入：不支持的数据整批拒绝；来源记录保留旧值。").Bold()
	ui.TextInput(c, &a.source).Label("1PUX 文件").Placeholder("1PUX 归档完整路径").Disabled(a.busy)
	ui.Button(c, "生成导入计划").Disabled(a.busy).OnClick(func() {
		s, source := a.session, a.source
		a.planDigest = ""
		a.run(func() outcome {
			r, e := s.PlanImport(source)
			return outcome{err: e, apply: func() {
				a.planDigest = r.Report.SourceDigest
				a.report = fmt.Sprintf("待导入 %d 条，归档 %d 条", r.Report.Items, r.Report.Archived)
			}}
		})
	})
	ui.Text(c, a.report)
	ui.Button(c, "确认整批导入").Disabled(a.busy || a.planDigest == "").OnClick(func() {
		s, source, digest := a.session, a.source, a.planDigest
		a.planDigest = ""
		a.run(func() outcome {
			_, e := s.Import(source, digest)
			return outcome{err: e, apply: func() { a.status = "导入完成，请到金库刷新" }}
		})
	})
	ui.Text(c, "导出所有状态的条目与来源旧值，使用独立密码加密为 KDBX。").Bold()
	ui.TextInput(c, &a.exportPath).Label("导出路径").Placeholder("新的 .kdbx 完整路径")
	ui.TextInput(c, &a.exportPassword).Label("独立导出密码").Placeholder("至少 12 字符的独立导出密码").Password()
	ui.Button(c, "确认加密导出").Disabled(a.busy).OnClick(func() {
		s, path, password := a.session, a.exportPath, a.exportPassword
		a.exportPassword = ""
		a.run(func() outcome { return outcome{err: s.Export(password, path)} })
	})
}
func Run() error {
	a := New()
	mygo.App.SetName("Locklark")
	mygo.App.WhenReady(func() {
		a.win = mygo.NewWindow(mygo.WindowOptions{Title: "Locklark · 本地金库", Width: 1100, Height: 820, MinWidth: 900, MinHeight: 680, Content: ui.View(a.View)})
		a.dispatch = a.win.Update
		a.win.OnClose(func(*mygo.CloseEvent) { a.Lock() })
		a.clipboardWrite = nativeclipboard.Write
		a.clipboardClear = nativeclipboard.ClearOwned
		mygo.Power.OnSuspend(a.Lock)
		mygo.Power.OnLockScreen(a.Lock)
		mygo.App.OnQuit(a.Lock)
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
	a.Lock()
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
			a.rows = loginProjection(rows)
			a.scope = "active"
			a.page = "vault"
			a.status = "已通过系统解锁"
		}}
	})
}
func (a *App) securityView(c *ui.Context) {
	ui.Text(c, "安全设置").FontSize(24).Bold()
	ui.Text(c, "快捷搜索："+quickSearchAcceleratorLabel()).Bold()
	shortcut := a.quickShortcut
	if shortcut == "" {
		shortcut = "全局快捷键尚未提交注册；可使用窗口的快捷搜索按钮。"
	}
	ui.Text(c, shortcut)
	ui.Text(c, "快捷解锁："+osunlock.Label()).Bold()
	ui.Text(c, osunlock.Description())
	ui.Text(c, "首次或到期后使用主密码与 Secret Key 完整解锁，再主动启用。系统验证失败时保留完整解锁入口。")
	ui.Button(c, "启用系统快捷解锁（有效期 24 小时）").Disabled(a.busy).OnClick(func() {
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
	ui.Text(c, "自动锁定：5 分钟未操作、锁屏、睡眠；退出时清除当前会话。")
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
