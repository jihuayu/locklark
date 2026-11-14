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
func (a *App) refreshSSHKeys() {
	if a.session == nil || a.busy {
		return
	}
	s := a.session
	scope := a.sshScope
	if scope == "" {
		scope = "active"
	}
	a.run(func() outcome {
		rows, e := s.ListSSHKeysState(scope)
		return outcome{err: e, apply: func() { a.sshRows = rows; a.sshSelected = nil; a.status = "SSH 公钥列表已刷新" }}
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
		rows, e = s.ListSSHKeys()
		return nativeResult{err: e}
	}, func(nativeResult) {
		a.sshScope = "active"
		a.sshRows = rows
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
	s, row, scope := a.session, *a.sshSelected, a.sshScope
	if scope == "" {
		scope = "active"
	}
	var rows []personal.SSHKeyRow
	a.runNative(func(g *personal.MutationGate) nativeResult {
		defer g.Cancel()
		defer s.ReleaseMutation(g)
		if _, e := s.SetSSHKeyState(row.ID, row.Revision, action, g); e != nil {
			return nativeResult{err: e}
		}
		var e error
		rows, e = s.ListSSHKeysState(scope)
		return nativeResult{err: e}
	}, func(nativeResult) {
		a.sshRows = rows
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
	ui.Column(c).FillWidth().Gap(12).Children(func() {
		ui.Column(c).FillWidth().Gap(4).Children(func() {
			ui.Text(c, "SSH 密钥 · Ed25519").FontSize(22).Bold().TextColor(t.Text)
			ui.Text(c, "SSH agent 只交付公钥和本机逐次批准的签名；不会向客户端提供私钥。").FontSize(13).TextColor(t.TextMuted)
			ui.Text(c, "目的地未验证：普通 SSH agent 消息不含可信主机名；此服务不能识别或阻止所有 ssh -A 转发。").FontSize(12).Bold().TextColor(t.Warning)
		})

		// Card 1: Generate / Import Ed25519 SSH Key
		ui.Column(c).FillWidth().Border(1, t.Border).Radius(t.Radius).Background(t.Surface).Padding(t.Space(3)).Gap(8).Children(func() {
			ui.Text(c, "新建或导入密钥").FontSize(15).Bold().TextColor(t.Text)
			ui.TextInput(c, &a.sshTitle).Label("SSH 密钥标题").Placeholder("例如：GitHub 生产密钥").Disabled(a.busy)
			ui.Row(c).Gap(8).Wrap().Children(func() {
				ui.Button(c, "生成 Ed25519 密钥").Disabled(a.busy || strings.TrimSpace(a.sshTitle) == "").OnClick(func() { a.saveSSHKey(false) })
				ui.Button(c, "选择未加密 OpenSSH 私钥…").Disabled(a.busy).OnClick(a.chooseSSHImport)
				ui.Button(c, "确认导入未加密 Ed25519 私钥").Disabled(a.busy || a.sshImportPath == "" || strings.TrimSpace(a.sshTitle) == "").OnClick(func() { a.saveSSHKey(true) })
			})
			if a.sshImportPath != "" {
				ui.Text(c, "所选文件："+visible(a.sshImportPath)).FontSize(12).TextColor(t.Accent)
			}
			ui.Text(c, "仅接受有界的未加密 OpenSSH Ed25519 私钥；加密私钥与其他算法明确拒绝。").FontSize(12).TextColor(t.TextMuted)
		})

		// Card 2: Key List & Selected Key Detail
		ui.Column(c).FillWidth().Border(1, t.Border).Radius(t.Radius).Background(t.Surface).Padding(t.Space(3)).Gap(8).Children(func() {
			ui.Row(c).FillWidth().AlignItems(ui.Center).Gap(8).Wrap().Children(func() {
				ui.Text(c, "已保存密钥").FontSize(15).Bold().TextColor(t.Text).Grow(1)
				ui.Button(c, "刷新 SSH 密钥").Disabled(a.busy).OnClick(a.refreshSSHKeys)
			})
			ui.Row(c).Gap(8).Wrap().Children(func() {
				for _, scope := range []struct{ id, label string }{{"active", "活动 SSH 密钥"}, {"archived", "已归档 SSH 密钥"}, {"trashed", "SSH 回收站"}, {"all", "全部 SSH 密钥"}} {
					scope := scope
					ui.Button(c, scope.label).Disabled(a.busy).OnClick(func() { a.sshScope = scope.id; a.refreshSSHKeys() })
				}
			})
			for _, row := range a.sshRows {
				row := row
				ui.Button(c.Key("ssh-key-"+row.ID), "选择 SSH 密钥："+browserTitle(row.Title)).Disabled(a.busy).OnClick(func() { a.sshSelected = &row })
			}
			if row := a.sshSelected; row != nil {
				ui.Column(c).FillWidth().Border(1, t.Border).Radius(t.Radius).Background(t.Background).Padding(t.Space(3)).Gap(6).Children(func() {
					ui.Text(c, "标题："+browserTitle(row.Title)).Bold().TextColor(t.Text)
					ui.Text(c, "指纹："+row.Fingerprint).FontSize(13).TextColor(t.Accent)
					ui.Text(c, "ID："+row.ID).FontSize(12).TextColor(t.TextMuted)
					ui.Text(c, "修订："+row.Revision).FontSize(12).TextColor(t.TextMuted)
					ui.Text(c, "状态："+row.State).FontSize(12).TextColor(t.TextMuted)
					ui.Text(c, strings.TrimSpace(row.PublicKey)).FontSize(12).TextColor(t.Text)
					ui.Row(c).Gap(8).Wrap().Children(func() {
						if row.State == "trashed" {
							ui.Button(c, "恢复 SSH 密钥").Disabled(a.busy).OnClick(func() { a.sshKeyState("item.untrash") })
						} else {
							ui.Button(c, "复制 SSH 公钥").Disabled(a.busy).OnClick(a.copySSHPublic)
							if row.State == "archived" {
								ui.Button(c, "取消归档 SSH 密钥").Disabled(a.busy).OnClick(func() { a.sshKeyState("item.unarchive") })
							} else {
								ui.Button(c, "归档 SSH 密钥").Disabled(a.busy).OnClick(func() { a.sshKeyState("item.archive") })
							}
							ui.Button(c, "将 SSH 密钥移入回收站").Disabled(a.busy).OnClick(func() { a.sshKeyState("item.trash") })
						}
					})
				})
			}
		})

		// Card 3: Local SSH Agent Service
		ui.Column(c).FillWidth().Border(1, t.Border).Radius(t.Radius).Background(t.Surface).Padding(t.Space(3)).Gap(8).Children(func() {
			ui.Text(c, "本地 SSH agent").FontSize(16).Bold().TextColor(t.Text)
			if a.sshService == nil {
				ui.Button(c, "开启本地 SSH agent").Disabled(a.busy || a.sshStarting || a.sshStopping).OnClick(a.startSSHAgent)
			} else {
				endpoint := a.sshService.Endpoint()
				ui.Column(c).FillWidth().Border(1, t.Border).Radius(t.Radius).Background(t.Background).Padding(t.Space(2)).Gap(4).Children(func() {
					ui.Text(c, "SSH_AUTH_SOCK："+endpoint).FontSize(12).TextColor(t.Text)
					ui.Text(c, "IdentityAgent："+endpoint).FontSize(12).TextColor(t.TextMuted)
				})
				ui.Row(c).Gap(8).Wrap().Children(func() {
					ui.Button(c, "复制 SSH_AUTH_SOCK 端点").Disabled(a.busy).OnClick(func() {
						if mygo.Clipboard.Write(transfer.TextData(endpoint)) != nil {
							a.status = "端点复制未确认"
						} else {
							a.status = "已复制非秘密端点；请自行为本次命令或 SSH 配置设置，不会改动系统 agent"
						}
					})
					ui.Button(c, "停止本地 SSH agent").OnClick(func() { a.stopSSHAgent(); a.status = "SSH agent 已撤销，正在关闭本地端点" })
				})
			}
			ui.Text(c, "服务不会接管系统 ssh-agent 或修改 shell 配置。锁库会停止本服务；解锁后需手动重新开启。").FontSize(12).TextColor(t.TextMuted)
		})
	})
}
func (a *App) sshApprovalView(c *ui.Context) {
	t := c.Theme()
	r := a.sshApproval
	v := r.view
	ui.Scroll(c).Fill().Children(func() {
		ui.Column(c).Width(640).Border(1, t.Border).Radius(t.Radius).Background(t.Surface).Padding(t.Space(4)).Gap(10).Children(func() {
			ui.Text(c, "批准本次 SSH 签名？").FontSize(24).Bold().TextColor(t.Text)
			ui.Column(c).FillWidth().Border(1, t.Warning).Radius(t.Radius).Background(t.Background).Padding(t.Space(3)).Gap(4).Children(func() {
				ui.Text(c, "目的地未验证").FontSize(18).Bold().TextColor(t.Warning)
				ui.Text(c, "以下为系统取得的本机来源；PID/进程路径不构成程序可信证明，也不能证明远端 SSH 主机。").FontSize(12).TextColor(t.TextMuted)
			})
			ui.Column(c).FillWidth().Border(1, t.Border).Radius(t.Radius).Background(t.Background).Padding(t.Space(3)).Gap(4).Children(func() {
				ui.Text(c, "本机来源："+visible(v.Peer)).TextColor(t.Text)
				ui.Text(c, "密钥："+browserTitle(v.Key.Title)).Bold().TextColor(t.Text)
				ui.Text(c, "公钥指纹："+v.Key.Fingerprint).TextColor(t.Accent)
				ui.Text(c, "算法："+v.Algorithm+" · flags="+strconv.FormatUint(uint64(v.Flags), 10)).FontSize(13).TextColor(t.Text)
				ui.Text(c, "签名数据："+strconv.Itoa(v.DataBytes)+" 字节").FontSize(13).TextColor(t.Text)
				ui.Text(c, "载荷 SHA256："+v.PayloadDigest).FontSize(12).TextColor(t.TextMuted)
				ui.Text(c, "密钥 ID："+v.Key.ID).FontSize(12).TextColor(t.TextMuted)
				ui.Text(c, "精确修订："+v.Key.Revision).FontSize(12).TextColor(t.TextMuted)
				ui.Text(c, "请求 ID："+v.RequestID).FontSize(12).TextColor(t.TextMuted)
				ui.Text(c, "连接 ID："+v.ConnectionID).FontSize(12).TextColor(t.TextMuted)
				ui.Text(c, "批准期限："+v.Deadline.Local().Format("15:04:05")).FontSize(13).Bold().TextColor(t.Warning)
			})
			ui.Row(c).Gap(8).Wrap().Children(func() {
				ui.PrimaryButton(c, "仅批准本次 SSH 签名").Disabled(r.decided || !time.Now().Before(v.Deadline)).OnClick(func() {
					r.decided = true
					r.choose(true)
					a.status = "本次签名正在重新验证；不会记住批准"
				})
				ui.Button(c, "拒绝本次 SSH 签名").OnClick(func() { r.decided = true; r.choose(false) })
				ui.Button(c, "停止 agent 并拒绝本次").OnClick(func() { a.stopSSHAgent(); a.status = "本次 SSH 请求与服务已撤销" })
			})
		})
	})
}
