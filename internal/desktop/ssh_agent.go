package desktop

import (
	"bytes"
	"context"
	"io"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/egoist/mygo"
	"github.com/egoist/mygo/transfer"
	"github.com/egoist/mygo/ui"
	"github.com/jihuayu/locklark/internal/personal"
	"github.com/jihuayu/locklark/internal/sshagent"
	oneui "github.com/oneo-me/onevra/source/components"
	"github.com/oneo-me/onevra/source/icons/lucide"
	"golang.org/x/crypto/ssh"
)

type sshNativeRequest struct {
	host     *sshNativeHost
	ctx      context.Context
	cancel   context.CancelFunc
	intent   *personal.SSHSignIntent
	view     personal.SSHSignView
	decision chan bool
	once     sync.Once
	decided  bool // native UI thread only
}

func (r *sshNativeRequest) choose(approved bool) {
	// A user may revoke an approved request until the core's final grant wins.
	// The one-shot decision channel must not swallow that later cancellation.
	if !approved {
		r.cancel()
		if r.intent != nil {
			r.intent.Cancel()
		}
	}
	r.once.Do(func() {
		r.decision <- approved
	})
}

type sshNativeHost struct {
	session          *personal.Session
	ctx              context.Context
	cancel           context.CancelFunc
	mu               sync.Mutex
	pending          *sshNativeRequest
	present          func(*sshNativeRequest)
	finished         func(*sshNativeRequest, bool)
	service          *sshagent.Service
	started, stopped chan struct{}
	stopError        error
}

// Track endpoint cleanup independently of UI dispatch: the window loop may
// already be closed when a cancelled startup worker finally creates a socket.
func (h *sshNativeHost) trackServiceStart() {
	h.started = make(chan struct{})
	h.stopped = make(chan struct{})
	go func() {
		<-h.ctx.Done()
		<-h.started
		h.mu.Lock()
		service := h.service
		h.mu.Unlock()
		var e error
		if service != nil {
			e = service.Close()
		}
		h.mu.Lock()
		h.stopError = e
		h.mu.Unlock()
		close(h.stopped)
	}()
}
func (h *sshNativeHost) finishServiceStart(service *sshagent.Service) {
	h.mu.Lock()
	h.service = service
	h.mu.Unlock()
	close(h.started)
}
func (a *App) waitSSHShutdown(timeout time.Duration) bool {
	deadline := time.NewTimer(timeout)
	defer deadline.Stop()
	for _, h := range a.sshRetired {
		if h.stopped == nil {
			continue
		}
		select {
		case <-h.stopped:
			h.mu.Lock()
			e := h.stopError
			h.mu.Unlock()
			if e != nil {
				return false
			}
		case <-deadline.C:
			return false
		}
	}
	return true
}

func newSSHNativeHost(s *personal.Session, present func(*sshNativeRequest), finished func(*sshNativeRequest, bool)) *sshNativeHost {
	ctx, cancel := context.WithCancel(context.Background())
	return &sshNativeHost{session: s, ctx: ctx, cancel: cancel, present: present, finished: finished}
}
func (h *sshNativeHost) close() {
	h.cancel()
	h.mu.Lock()
	r := h.pending
	if r != nil {
		r.cancel()
		if r.intent != nil {
			r.intent.Cancel()
		}
	}
	h.mu.Unlock()
}
func (h *sshNativeHost) Identities(ctx context.Context, _ sshagent.Peer) ([]sshagent.Identity, error) {
	if ctx.Err() != nil || h.ctx.Err() != nil || !h.session.Unlocked() {
		return nil, nil
	}
	rows, e := h.session.ListSSHKeys()
	if e != nil {
		return nil, sshagent.ErrRefused
	}
	if ctx.Err() != nil || h.ctx.Err() != nil || !h.session.Unlocked() {
		return nil, nil
	}
	if len(rows) > sshagent.MaxIdentities {
		return nil, sshagent.ErrRefused
	}
	keys := make([]sshagent.Identity, 0, len(rows))
	for _, row := range rows {
		pub, e := canonicalSSHPublic(row.PublicKey)
		if e != nil {
			return nil, sshagent.ErrRefused
		}
		keys = append(keys, sshagent.Identity{Blob: pub.Marshal(), Comment: "Locklark " + row.Fingerprint + " " + row.ID})
	}
	return keys, nil
}
func (h *sshNativeHost) Sign(parent context.Context, wire sshagent.SignRequest) (signature []byte, err error) {
	ctx, cancel := context.WithCancel(parent)
	defer cancel()
	stop := context.AfterFunc(h.ctx, cancel)
	defer stop()
	r := &sshNativeRequest{host: h, ctx: ctx, cancel: cancel, decision: make(chan bool, 1)}
	h.mu.Lock()
	if h.ctx.Err() != nil || h.pending != nil || ctx.Err() != nil {
		h.mu.Unlock()
		return nil, sshagent.ErrRefused
	}
	h.pending = r
	h.mu.Unlock()
	delivered := false
	defer func() {
		cancel()
		h.mu.Lock()
		if h.pending == r {
			h.pending = nil
		}
		intent := r.intent
		h.mu.Unlock()
		if intent != nil {
			h.session.DiscardSSHSign(intent)
		}
		if h.finished != nil {
			h.finished(r, delivered)
		}
	}()
	if !h.session.Unlocked() {
		return nil, sshagent.ErrRefused
	}
	rows, e := h.session.ListSSHKeys()
	if e != nil {
		return nil, sshagent.ErrRefused
	}
	var selected *personal.SSHKeyRow
	for i := range rows {
		pub, e := canonicalSSHPublic(rows[i].PublicKey)
		if e != nil {
			return nil, sshagent.ErrRefused
		}
		if bytes.Equal(pub.Marshal(), wire.PublicKey) {
			if selected != nil {
				return nil, sshagent.ErrRefused
			}
			selected = &rows[i]
		}
	}
	if selected == nil || ctx.Err() != nil {
		return nil, sshagent.ErrRefused
	}
	intent, e := h.session.PrepareSSHSign(personal.SSHKeyTarget{ID: selected.ID, Revision: selected.Revision}, personal.SSHSignRequest{RequestID: wire.RequestID, ConnectionID: wire.ConnectionID, Peer: wire.Peer.Label(), PublicKey: wire.PublicKey, Data: wire.Data}, wire.Until)
	if e != nil {
		return nil, sshagent.ErrRefused
	}
	h.mu.Lock()
	r.intent = intent
	valid := h.pending == r && h.ctx.Err() == nil && ctx.Err() == nil
	h.mu.Unlock()
	if !valid {
		intent.Cancel()
		return nil, sshagent.ErrRefused
	}
	r.view = intent.View()
	if h.present == nil {
		return nil, sshagent.ErrRefused
	}
	h.present(r)
	select {
	case <-ctx.Done():
		return nil, sshagent.ErrRefused
	case approved := <-r.decision:
		if !approved {
			return nil, sshagent.ErrRefused
		}
	}
	if ctx.Err() != nil || h.ctx.Err() != nil {
		return nil, sshagent.ErrRefused
	}
	output, e := h.session.ApproveSSHSign(intent)
	if e != nil {
		return nil, sshagent.ErrRefused
	}
	defer h.session.DiscardSSHSignature(output)
	if ctx.Err() != nil || h.ctx.Err() != nil {
		return nil, sshagent.ErrRefused
	}
	signature, e = h.session.ConsumeSSHSignature(output)
	if e != nil || ctx.Err() != nil || h.ctx.Err() != nil {
		clear(signature)
		return nil, sshagent.ErrRefused
	}
	delivered = true
	return signature, nil
}
func canonicalSSHPublic(value string) (ssh.PublicKey, error) {
	pub, comment, options, rest, e := ssh.ParseAuthorizedKey([]byte(value))
	if e != nil || pub.Type() != ssh.KeyAlgoED25519 || comment != "" || len(options) != 0 || len(bytes.TrimSpace(rest)) != 0 {
		return nil, personal.ErrSSHKey
	}
	return pub, nil
}

func (a *App) startSSHAgent() {
	if a.session == nil || a.busy || a.sshService != nil || a.sshStarting || a.sshStopping {
		return
	}
	endpoint, e := sshagent.DefaultEndpoint()
	if e != nil {
		a.status = "当前平台无法创建本地 SSH agent"
		return
	}
	s := a.session
	generation := a.generation
	h := newSSHNativeHost(s, func(r *sshNativeRequest) {
		a.dispatch(func() {
			if a.sshHost != r.host || a.session != s || a.generation != generation || a.busy || a.sshApproval != nil || r.ctx.Err() != nil {
				r.choose(false)
				return
			}
			a.closeQuickSearch()
			a.clearNotesEditor()
			a.clearDailyExposure()
			a.sshApproval = r
			a.busy = true
			a.status = "请核对本次 SSH 签名请求"
			if a.win != nil {
				a.win.Show()
				a.win.Focus()
			}
		})
	}, func(r *sshNativeRequest, granted bool) {
		a.dispatch(func() {
			if a.sshApproval == r {
				a.sshApproval = nil
				a.busy = false
				if granted {
					a.status = "本次 SSH 签名已授权；本地交付及远端登录结果未确认"
				} else {
					a.status = "本次 SSH 签名未交付"
				}
			}
		})
	})
	a.sshHost = h
	a.sshStarting = true
	h.trackServiceStart()
	retired := a.sshRetired[:0]
	for _, old := range a.sshRetired {
		select {
		case <-old.stopped:
		default:
			retired = append(retired, old)
		}
	}
	a.sshRetired = append(retired, h)
	a.run(func() outcome {
		service, e := sshagent.Start(endpoint, h)
		h.finishServiceStart(service)
		if e != nil {
			h.close()
		}
		return outcome{drop: func() {
			h.close()
			if service != nil {
				service.RequestStop()
			}
		}, apply: func() {
			a.sshStarting = false
			if e != nil {
				a.sshHost = nil
				a.status = "本地 SSH agent 无法启动：端点已存在、权限或平台条件不满足"
				return
			}
			a.sshService = service
			a.status = "本地 SSH agent 已开启；每次签名都需原生批准"
		}}
	})
}
func (a *App) stopSSHAgent() {
	h, service := a.sshHost, a.sshService
	a.sshHost = nil
	a.sshService = nil
	a.sshStarting = false
	if h != nil {
		h.close()
	}
	if a.sshApproval != nil {
		a.sshApproval.choose(false)
		a.sshApproval = nil
		a.busy = false
	}
	if service != nil {
		service.RequestStop()
		a.sshStopping = true
		a.sshStopSequence++
		sequence := a.sshStopSequence
		a.launch(func() {
			e := service.Close()
			a.dispatch(func() {
				if sequence == a.sshStopSequence {
					a.sshStopping = false
					if e != nil {
						a.status = "SSH agent 已撤销，端点清理结果未确认"
					}
				}
			})
		})
	}
}
func (a *App) applySSHScopeFilter() {
	scope := a.sshScope
	if scope == "" {
		scope = "active"
	}
	var filtered []personal.SSHKeyRow
	for _, r := range a.sshAllRows {
		state := r.State
		if state == "" {
			state = "active"
		}
		if scope == "all" || state == scope {
			filtered = append(filtered, r)
		}
	}
	a.sshRows = filtered
	if a.sshSelected != nil {
		found := false
		for i := range filtered {
			if filtered[i].ID == a.sshSelected.ID {
				row := filtered[i]
				a.sshSelected = &row
				found = true
				break
			}
		}
		if !found {
			a.sshSelected = nil
		}
	}
}

func (a *App) ensureSSHKeysLoaded() {
	if a.sshLoaded {
		a.applySSHScopeFilter()
		return
	}
	if a.sshLoading || a.session == nil {
		return
	}
	s := a.session
	if a.win == nil {
		rows, e := s.ListSSHKeysState("all")
		if e != nil {
			return
		}
		a.sshAllRows = rows
		a.sshLoaded = true
		a.applySSHScopeFilter()
		return
	}
	gen := a.generation
	a.sshLoading = true
	a.launch(func() {
		rows, e := s.ListSSHKeysState("all")
		a.dispatch(func() {
			if a.session != s || a.generation != gen {
				return
			}
			a.sshLoading = false
			if e != nil {
				a.status = message(e)
				return
			}
			a.sshAllRows = rows
			a.sshLoaded = true
			a.applySSHScopeFilter()
		})
	})
}

func (a *App) refreshSSHKeys() {
	if a.session == nil || a.busy {
		return
	}
	s := a.session
	a.run(func() outcome {
		rows, e := s.ListSSHKeysState("all")
		return outcome{err: e, apply: func() {
			a.sshAllRows = rows
			a.sshLoaded = true
			a.sshLoading = false
			a.applySSHScopeFilter()
			a.sshSelected = nil
			a.status = "SSH 公钥列表已刷新"
		}}
	})
}
func (a *App) saveSSHKey(imported bool) {
	if a.session == nil || a.busy || strings.TrimSpace(a.sshTitle) == "" {
		return
	}
	s, title, path := a.session, a.sshTitle, a.sshImportPath
	var row personal.SSHKeyRow
	var rows []personal.SSHKeyRow
	a.runNative(func(g *personal.MutationGate) nativeResult {
		defer g.Cancel()
		defer s.ReleaseMutation(g)
		var e error
		if imported {
			encoded, err := readSSHImport(path)
			if err != nil {
				return nativeResult{err: personal.ErrSSHKey}
			}
			defer clear(encoded)
			row, e = s.ImportSSHKey(title, encoded, g)
		} else {
			row, e = s.GenerateSSHKey(title, g)
		}
		if e != nil {
			return nativeResult{err: e}
		}
		rows, e = s.ListSSHKeysState("all")
		return nativeResult{err: e}
	}, func(nativeResult) {
		a.sshScope = "active"
		a.sshAllRows = rows
		a.sshLoaded = true
		a.sshLoading = false
		a.applySSHScopeFilter()
		a.sshSelected = &row
		a.sshTitle = ""
		a.sshImportPath = ""
		a.status = "SSH 密钥已加密保存；私钥不会提供给 agent 客户端"
	})
}
func (a *App) sshKeyState(action string) {
	if a.session == nil || a.sshSelected == nil || a.busy {
		return
	}
	s, row := a.session, *a.sshSelected
	var rows []personal.SSHKeyRow
	a.runNative(func(g *personal.MutationGate) nativeResult {
		defer g.Cancel()
		defer s.ReleaseMutation(g)
		if _, e := s.SetSSHKeyState(row.ID, row.Revision, action, g); e != nil {
			return nativeResult{err: e}
		}
		var e error
		rows, e = s.ListSSHKeysState("all")
		return nativeResult{err: e}
	}, func(nativeResult) {
		a.sshAllRows = rows
		a.sshLoaded = true
		a.sshLoading = false
		a.applySSHScopeFilter()
		a.sshSelected = nil
		a.status = "SSH 密钥状态已更新；旧签名请求已撤销"
	})
}
func readSSHImport(path string) ([]byte, error) {
	f, e := openSSHImport(path)
	if e != nil {
		return nil, personal.ErrSSHKey
	}
	defer f.Close()
	info, e := f.Stat()
	if e != nil || !info.Mode().IsRegular() || info.Size() <= 0 || info.Size() > personal.MaxSSHImport {
		return nil, personal.ErrSSHKey
	}
	value, e := io.ReadAll(io.LimitReader(f, personal.MaxSSHImport+1))
	if e != nil || len(value) == 0 || len(value) > personal.MaxSSHImport {
		clear(value)
		return nil, personal.ErrSSHKey
	}
	return value, nil
}
func (a *App) chooseSSHImport() {
	if a.busy {
		return
	}
	win := a.win
	a.run(func() outcome {
		paths, e := mygo.Dialog.Open(mygo.OpenDialogOptions{Parent: win, Title: "选择未加密 OpenSSH Ed25519 私钥"})
		return outcome{err: e, apply: func() {
			if len(paths) == 1 {
				a.sshImportPath = paths[0]
				a.status = "已选择私钥文件；请输入标题并明确确认导入。不会显示文件内容。"
			}
		}}
	})
}
func (a *App) copySSHPublic() {
	if a.sshSelected == nil {
		return
	}
	pub, e := canonicalSSHPublic(a.sshSelected.PublicKey)
	if e != nil {
		a.status = "公钥不可用"
		return
	}
	if mygo.Clipboard.Write(transfer.TextData(string(ssh.MarshalAuthorizedKey(pub)))) != nil {
		a.status = "系统剪贴板写入未确认"
		return
	}
	a.status = "公钥已复制；不包含私钥、选项或自定义注释"
}
func (a *App) sshKeysView(c *ui.Context) {
	ui.Scroll(c).Fill().Children(func() {
		a.sshKeysContentView(c)
	})
}

func (a *App) sshKeysContentView(c *ui.Context) {
	t := c.Theme()
	ui.Column(c).FillWidth().Gap(t.Space(2.5)).Children(func() {
		ui.Column(c).FillWidth().Gap(t.Space(1.5)).Children(func() {
			oneui.Text(c, "SSH 密钥 · Ed25519：SSH agent 只交付公钥和本机逐次批准的签名；不会向客户端提供私钥。").
				FontSize(t.Rem(.80)).TextColor(t.TextMuted).Wrap()
			onevraBanner(c, lucide.ShieldAlert(), "目的地未验证：普通 SSH agent 消息不含可信主机名；此服务不能识别或阻止所有 ssh -A 转发。", t.Warning, nil)
		})

		onevraGroup(c, "新建或导入密钥 · Ed25519", func(row func(func())) {
			row(func() {
				ui.Column(c).FillWidth().Gap(t.Space(1.5)).Children(func() {
					oneui.TextBox(c, &a.sshTitle, oneui.TextBoxOptions{}).
						Label("SSH 密钥标题").Placeholder("例如：GitHub 生产密钥").Disabled(a.uiBusy(c)).FillWidth()
					ui.Row(c).FillWidth().Wrap().Gap(t.Space(1.5)).Children(func() {
						oneui.Button(c, "生成 Ed25519 密钥", oneui.ButtonPrimary).
							Disabled(a.uiBusy(c) || strings.TrimSpace(a.sshTitle) == "").
							OnClick(func() { a.saveSSHKey(false) })
						oneui.Button(c, "选择未加密 OpenSSH 私钥…", oneui.ButtonOutline).
							Disabled(a.uiBusy(c)).
							OnClick(a.chooseSSHImport)
						oneui.Button(c, "确认导入未加密 Ed25519 私钥", oneui.ButtonSecondary).
							Disabled(a.uiBusy(c) || a.sshImportPath == "" || strings.TrimSpace(a.sshTitle) == "").
							OnClick(func() { a.saveSSHKey(true) })
					})
					if a.sshImportPath != "" {
						oneui.Text(c, "所选文件："+visible(a.sshImportPath)).FontSize(t.Rem(.76)).TextColor(t.Accent).Wrap()
					}
					oneui.Text(c, "仅接受有界的未加密 OpenSSH Ed25519 私钥；加密私钥与其他算法明确拒绝。").
						FontSize(t.Rem(.74)).TextColor(t.TextMuted).Wrap()
				})
			})
		})

		onevraGroup(c, "已保存密钥", func(row func(func())) {
			row(func() {
				scopeVal := a.sshScope
				if scopeVal == "" {
					scopeVal = "active"
				}
				ui.Row(c).FillWidth().Wrap().AlignItems(ui.Center).Gap(t.Space(1.5)).Children(func() {
					if next, changed := onevraSegmented(c, scopeVal, [][2]string{
						{"active", "活动 SSH 密钥"},
						{"archived", "已归档 SSH 密钥"},
						{"trashed", "SSH 回收站"},
						{"all", "全部 SSH 密钥"},
					}); changed {
						a.sshScope = next
						if a.sshLoaded {
							a.applySSHScopeFilter()
						} else {
							a.ensureSSHKeysLoaded()
						}
					}
					ui.Box(c).Grow(1)
					oneui.Button(c, "刷新 SSH 密钥", oneui.ButtonOutline).Disabled(a.uiBusy(c)).OnClick(a.refreshSSHKeys)
				})
			})
			if len(a.sshRows) == 0 {
				row(func() {
					if a.sshLoading {
						oneui.Text(c, "正在加载 SSH 密钥…").FontSize(t.Rem(.78)).TextColor(t.TextMuted)
					} else {
						oneui.Text(c, "当前范围没有 SSH 密钥。").FontSize(t.Rem(.78)).TextColor(t.TextMuted)
					}
				})
			} else {
				for _, r := range a.sshRows {
					r := r
					selected := a.sshSelected != nil && a.sshSelected.ID == r.ID
					row(func() {
						bg := ui.Transparent
						if selected {
							bg = t.Accent.Alpha(.08)
						}
						btn := ui.ButtonBase(c.Key("ssh-key-"+r.ID)).FillWidth().Radius(t.Radius).Background(bg).
							Padding(t.Space(1), t.Space(1.5)).
							Label("选择 SSH 密钥：" + browserTitle(r.Title)).
							Disabled(a.uiBusy(c)).
							OnClick(func() { a.sshSelected = &r })
						btn.Children(func() {
							ui.Row(c).FillWidth().AlignItems(ui.Center).Gap(t.Space(2)).Children(func() {
								oneui.Icon(c, lucide.KeyRound()).Size(t.Space(3.5), t.Space(3.5)).TextColor(t.Accent)
								ui.Column(c).Grow(1).MinWidth(0).Gap(t.Space(.2)).Children(func() {
									oneui.Text(c, browserTitle(r.Title)).FontSize(t.Rem(.84)).Bold().SingleLine().Ellipsis("…")
									if r.Fingerprint != "" {
										oneui.Text(c, r.Fingerprint).FontSize(t.Rem(.72)).TextColor(t.TextMuted).SingleLine().Ellipsis("…")
									}
								})
								onevraPill(c, r.State, t.TextMuted)
							})
						})
					})
				}
			}
		})

		if sel := a.sshSelected; sel != nil {
			onevraGroup(c, "密钥详情", func(row func(func())) {
				row(func() {
					ui.Column(c).FillWidth().Gap(t.Space(1)).Children(func() {
						oneui.Text(c, "标题："+browserTitle(sel.Title)).FontSize(t.Rem(.92)).Bold()
						oneui.Text(c, "指纹："+sel.Fingerprint).FontSize(t.Rem(.78)).TextColor(t.Accent).Selectable().Wrap()
						oneui.Text(c, "ID："+sel.ID+" · 修订："+sel.Revision+" · 状态："+sel.State).FontSize(t.Rem(.74)).TextColor(t.TextMuted).Wrap()
						oneui.Text(c, strings.TrimSpace(sel.PublicKey)).FontSize(t.Rem(.74)).TextColor(t.Text).Selectable().Wrap()
					})
				})
				row(func() {
					ui.Row(c).FillWidth().Wrap().Gap(t.Space(1.5)).Children(func() {
						if sel.State == "trashed" {
							oneui.Button(c, "恢复 SSH 密钥", oneui.ButtonPrimary).Disabled(a.uiBusy(c)).OnClick(func() { a.sshKeyState("item.untrash") })
						} else {
							oneui.Button(c, "复制 SSH 公钥", oneui.ButtonPrimary).Disabled(a.uiBusy(c)).OnClick(a.copySSHPublic)
							if sel.State == "archived" {
								oneui.Button(c, "取消归档 SSH 密钥", oneui.ButtonOutline).Disabled(a.uiBusy(c)).OnClick(func() { a.sshKeyState("item.unarchive") })
							} else {
								oneui.Button(c, "归档 SSH 密钥", oneui.ButtonOutline).Disabled(a.uiBusy(c)).OnClick(func() { a.sshKeyState("item.archive") })
							}
							oneui.Button(c, "将 SSH 密钥移入回收站", oneui.ButtonOutline).TextColor(t.Danger).Disabled(a.uiBusy(c)).OnClick(func() { a.sshKeyState("item.trash") })
						}
					})
				})
			})
		}

		onevraGroup(c, "本地 SSH agent", func(row func(func())) {
			row(func() {
				ui.Column(c).FillWidth().Gap(t.Space(1.5)).Children(func() {
					if a.sshService == nil {
						ui.Row(c).FillWidth().Children(func() {
							oneui.Button(c, "开启本地 SSH agent", oneui.ButtonPrimary).
								Disabled(a.uiBusy(c) || a.sshStarting || a.sshStopping).
								OnClick(a.startSSHAgent)
						})
					} else {
						endpoint := a.sshService.Endpoint()
						oneui.Text(c, "SSH_AUTH_SOCK："+endpoint).FontSize(t.Rem(.76)).Selectable().Wrap()
						oneui.Text(c, "IdentityAgent："+endpoint).FontSize(t.Rem(.74)).TextColor(t.TextMuted).Selectable().Wrap()
						ui.Row(c).FillWidth().Wrap().Gap(t.Space(1.5)).Children(func() {
							oneui.Button(c, "复制 SSH_AUTH_SOCK 端点", oneui.ButtonOutline).Disabled(a.uiBusy(c)).OnClick(func() {
								if mygo.Clipboard.Write(transfer.TextData(endpoint)) != nil {
									a.status = "端点复制未确认"
								} else {
									a.status = "已复制非秘密端点；请自行为本次命令或 SSH 配置设置，不会改动系统 agent"
								}
							})
							oneui.Button(c, "停止本地 SSH agent", oneui.ButtonOutline).TextColor(t.Danger).OnClick(func() {
								a.stopSSHAgent()
								a.status = "SSH agent 已撤销，正在关闭本地端点"
							})
						})
					}
					oneui.Text(c, "服务不会接管系统 ssh-agent 或修改 shell 配置。锁库会停止本服务；解锁后需手动重新开启。").
						FontSize(t.Rem(.74)).TextColor(t.TextMuted).Wrap()
				})
			})
		})
	})
}

func (a *App) sshApprovalView(c *ui.Context) {
	t := c.Theme()
	r := a.sshApproval
	v := r.view
	approvalCentered(c, func() {
		approvalCard(c, lucide.KeyRound(), t.Warning, "批准本次 SSH 签名？", func() {
			approvalNotice(c, "目的地未验证：以下为系统取得的本机来源；PID/进程路径不构成程序可信证明，也不能证明远端 SSH 主机。", t.Warning)
			approvalOrigin(c, "本机来源："+visible(v.Peer))
			approvalFacts(c, func() {
				approvalFact(c, "密钥："+browserTitle(v.Key.Title))
				approvalFact(c, "公钥指纹："+v.Key.Fingerprint)
				approvalFact(c, "算法："+v.Algorithm+" · flags="+strconv.FormatUint(uint64(v.Flags), 10))
				approvalFact(c, "签名数据："+strconv.Itoa(v.DataBytes)+" 字节")
				approvalFact(c, "载荷 SHA256："+v.PayloadDigest)
				approvalFact(c, "密钥 ID："+v.Key.ID)
				approvalFact(c, "精确修订："+v.Key.Revision)
				approvalFact(c, "请求 ID："+v.RequestID)
				approvalFact(c, "连接 ID："+v.ConnectionID)
				approvalFact(c, "批准期限："+v.Deadline.Local().Format("15:04:05"))
			})
			approvalActions(c, func() {
				oneui.Button(c, "仅批准本次 SSH 签名", oneui.ButtonPrimary).
					Disabled(r.decided || !time.Now().Before(v.Deadline)).
					OnClick(func() {
						r.decided = true
						r.choose(true)
						a.status = "本次签名正在重新验证；不会记住批准"
					})
				oneui.Button(c, "拒绝本次 SSH 签名", oneui.ButtonOutline).OnClick(func() {
					r.decided = true
					r.choose(false)
				})
				oneui.Button(c, "停止 agent 并拒绝本次", oneui.ButtonGhost).TextColor(t.Danger).OnClick(func() {
					a.stopSSHAgent()
					a.status = "本次 SSH 请求与服务已撤销"
				})
			})
		})
	})
}
