package desktop

import (
	"errors"
	"fmt"
	"os"
	"strconv"
	"strings"
	"time"

	"github.com/egoist/mygo"
	"github.com/egoist/mygo/ui"
	"github.com/jihuayu/passme/internal/browserhost"
	"github.com/jihuayu/passme/internal/osunlock"
	"github.com/jihuayu/passme/internal/personal"
	oneui "github.com/oneo-me/onevra/source/components"
	"github.com/oneo-me/onevra/source/icons/lucide"
)

func (a *App) browserView(c *ui.Context) { a.browserViewFor(c, a.browser) }

// brokeredBrowserApproval returns the exact broker-owned connection that owns
// a pending interactive approval. The view routes every button through this
// pointer, so two extension windows can never share an approval surface.
func (a *App) brokeredBrowserApproval() *browserhost.Connection {
	a.brokerMu.Lock()
	b := a.broker
	a.brokerMu.Unlock()
	if b == nil {
		return nil
	}
	for _, connection := range b.Connections() {
		view := connection.Snapshot()
		if view.Busy {
			continue
		}
		if view.V2 != nil || view.Passkey != nil || view.Signal != nil || view.Profile != nil ||
			view.Pending != nil || view.OTP != nil || view.Save != nil {
			return connection
		}
	}
	return nil
}

// browserViewFor renders one exact connection. Standalone mode passes
// a.browser; brokered desktop mode passes the originating Broker connection so
// approvals can never be routed to a different extension window.
func (a *App) browserViewFor(c *ui.Context, b *browserhost.Connection) {
	if b == nil {
		return
	}
	t := c.Theme()
	view := b.Snapshot()
	if view.SaveStatus != "" {
		a.status = view.SaveStatus
	}
	if view.OTPStatus != "" {
		a.status = view.OTPStatus
	}
	label := a.browserLabel
	if label == "" {
		label = "经桌面 IPC 的固定扩展"
	}
	approvalCentered(c, func() {
		ui.Row(c).FillWidth().MaxWidth(640).Wrap().AlignItems(ui.Center).Gap(t.Space(1.5)).Children(func() {
			oneui.Icon(c, lucide.Globe()).Size(t.Space(4), t.Space(4)).TextColor(t.Accent)
			oneui.Text(c, "浏览器连接").FontSize(t.Rem(1.05)).Bold()
			onevraPill(c, label, t.TextMuted)
			ui.Box(c).Grow(1)
			if view.Paired && !view.Busy && !view.Closed {
				onevraPill(c, "已连接 · 15 分钟有效", t.Success)
			}
		})
		ui.Column(c).FillWidth().MaxWidth(640).Children(func() {
			oneui.Text(c, "此窗口与浏览器共享已解锁的金库会话；请核对浏览器当前网站，再确认本次操作。").
				FontSize(t.Rem(.78)).TextColor(t.TextMuted).Wrap()
		})
		if view.Busy {
			ui.Column(c).FillWidth().MaxWidth(640).Children(func() {
				onevraBanner(c, lucide.Globe(), "正在核对请求…", t.Accent, nil)
			})
			return
		}
		if view.Closed {
			ui.Column(c).FillWidth().MaxWidth(640).Children(func() {
				onevraBanner(c, lucide.TriangleAlert(), "扩展已断开；请重新从浏览器连接。", t.Warning, nil)
			})
			return
		}
		if view.Pair {
			approvalCard(c, lucide.Globe(), t.Accent, "批准浏览器扩展配对", func() {
				approvalNote(c, "连接后可在浏览器选择账号填充、保存登录或使用验证码。快捷模式允许本次连接中的明确浏览器操作，无需反复切回此窗口；锁库或连接到期后失效。")
				approvalActions(c, func() {
					oneui.Button(c, "连接并启用快捷填充", oneui.ButtonPrimary).Disabled(a.busy).OnClick(func() {
						s := a.session
						a.run(func() outcome { return outcome{err: b.ApproveQuickPair(s)} })
					})
					oneui.Button(c, "确认连接此扩展", oneui.ButtonSecondary).Disabled(a.busy).OnClick(func() {
						s := a.session
						a.run(func() outcome { return outcome{err: b.ApprovePair(s)} })
					})
					oneui.Button(c, "拒绝连接", oneui.ButtonOutline).Disabled(a.busy).OnClick(func() {
						a.run(func() outcome { return outcome{err: b.Reject()} })
					})
				})
			})
			return
		}
		if !view.Paired {
			ui.Column(c).FillWidth().MaxWidth(640).Children(func() {
				onevraBanner(c, lucide.Globe(), "等待扩展发起新连接；重新解锁后必须重新配对。", t.TextMuted, nil)
			})
			return
		}
		if view.QuickFill {
			ui.Column(c).FillWidth().MaxWidth(640).Children(func() {
				approvalMeta(c, "已连接 · 连接最多 15 分钟；5 分钟未明确操作自动锁定。快捷填充已启用：在浏览器选择账号即可继续。自动登录设置由扩展管理。")
			})
		} else {
			ui.Column(c).FillWidth().MaxWidth(640).Children(func() {
				approvalMeta(c, "已连接 · 连接最多 15 分钟；5 分钟未明确操作自动锁定。")
			})
		}
		if view.V2 != nil {
			a.browserV2ApprovalView(c, b, *view.V2)
			return
		}
		if view.Passkey == nil && view.PasskeyStatus != "" {
			ui.Column(c).FillWidth().MaxWidth(640).Children(func() {
				approvalMeta(c, view.PasskeyStatus)
			})
		}
		if view.Passkey != nil {
			a.browserPasskeyView(c, b, *view.Passkey, view.PasskeyStatus)
			return
		}
		if view.OTP != nil {
			a.browserOTPView(c, b, *view.OTP, view.OTPStatus)
			return
		}
		if view.Save != nil {
			a.browserSaveView(c, b, *view.Save, view.SaveStatus)
			return
		}
		if view.Signal != nil {
			a.browserSignalView(c, b, *view.Signal, view.SignalStatus)
			return
		}
		if view.SignalStatus != "" {
			ui.Column(c).FillWidth().MaxWidth(640).Children(func() {
				approvalMeta(c, view.SignalStatus)
			})
		}
		// A reserved sensitive profile review must be rendered before the generic
		// login prompt: the login approval path cannot deliver profile fields.
		if view.Profile != nil {
			a.browserProfileView(c, b, *view.Profile)
			return
		}
		if view.Pending == nil {
			approvalCard(c, lucide.Globe(), t.TextMuted, "等待浏览器选择条目", func() {
				approvalNote(c, "在浏览器弹窗中选择当前网站的登录。此窗口不会自行请求或刷新候选。")
			})
			return
		}
		pending := *view.Pending
		approvalCard(c, lucide.Globe(), t.Accent, "确认本次登录填充", func() {
			approvalOrigin(c, "HTTPS 来源："+pending.Origin)
			approvalFacts(c, func() {
				approvalFact(c, "条目："+browserTitle(pending.Title))
				approvalFact(c, "ID："+pending.ItemID)
				approvalFact(c, "精确修订："+pending.Revision)
			})
			approvalNote(c, "仅交付用户名和密码；扩展可按自动登录设置提交。请求 30 秒后失效。")
			approvalActions(c, func() {
				oneui.Button(c, "批准本次填充", oneui.ButtonPrimary).Disabled(a.busy).OnClick(func() {
					a.run(func() outcome { return outcome{err: b.ApproveFill(pending.ID)} })
				})
				oneui.Button(c, "拒绝本次填充", oneui.ButtonOutline).Disabled(a.busy).OnClick(func() {
					a.run(func() outcome { return outcome{err: b.Reject()} })
				})
			})
		})
	})
}

// browserV2ApprovalView is the owner review for one non-quick-fill V2
// disclosure or mutation. It renders only protocol selectors; secrets and
// mutation payloads remain private to the connection until this click.
func (a *App) browserV2ApprovalView(c *ui.Context, b *browserhost.Connection, p browserhost.V2ApprovalView) {
	t := c.Theme()
	heading := "确认浏览器敏感操作"
	detail := "仅在本窗口批准后，才会执行这次操作。"
	approve, reject := "批准本次操作", "拒绝本次操作"
	switch p.Type {
	case "item-reveal-field", "item-copy-field":
		heading, detail = "确认披露金库字段", "仅在本窗口批准后，才会把这一字段交给当前浏览器页面。"
		approve, reject = "批准本次字段披露", "拒绝本次字段披露"
	case "item-create", "item-edit", "item-save", "item-state", "item-restore-history":
		heading, detail = "确认浏览器修改金库", "仅在本窗口批准后，才会写入这次金库变更。"
		approve, reject = "批准本次金库写入", "拒绝本次金库写入"
	case "stage-save", "commit-staged-save":
		heading, detail = "确认浏览器保存登录", "仅在本窗口批准后，才会暂存或提交这次登录保存。"
		approve, reject = "批准本次保存", "拒绝本次保存"
	case "attachment-read":
		heading, detail = "确认下载金库附件", "仅在本窗口批准后，才会把附件内容交给当前浏览器页面。"
		approve, reject = "批准本次附件读取", "拒绝本次附件读取"
	case "attachment-commit", "attachment-remove":
		heading, detail = "确认浏览器修改附件", "仅在本窗口批准后，才会写入或删除附件。"
		approve, reject = "批准本次附件操作", "拒绝本次附件操作"
	case "passkey-remove":
		heading, detail = "确认浏览器删除 Passkey", "仅在本窗口批准后，才会删除该 Passkey。"
		approve, reject = "批准删除 Passkey", "拒绝删除 Passkey"
	}
	approvalCardWith(c, lucide.ShieldAlert(), t.Accent, heading, true, nil, func() {
		if p.Origin != "" {
			approvalOrigin(c, "HTTPS 来源："+visible(p.Origin))
		}
		if p.ItemID != "" || p.Revision != "" || (p.Title != "" && p.Title != p.Origin) || p.Field != "" || p.Action != "" {
			approvalFacts(c, func() {
				if p.ItemID != "" {
					approvalFact(c, "条目 ID："+p.ItemID)
				}
				if p.Revision != "" {
					approvalFact(c, "精确修订："+p.Revision)
				}
				if p.RevisionPinned {
					approvalMeta(c, "修订已固定：按批准时的当前修订执行；条目若已改变则拒绝。")
				}
				if p.Title != "" && p.Title != p.Origin {
					approvalFact(c, "来源名称："+browserTitle(p.Title))
				}
				if p.Field != "" {
					approvalFact(c, "字段选择器："+visible(p.Field))
				}
				if p.Action != "" {
					approvalFact(c, "操作："+visible(p.Action))
				}
			})
		}
		a.browserV2AnchorView(c, p)
		if p.Summary != "" {
			approvalNote(c, "变更摘要："+visible(p.Summary))
		}
		approvalNote(c, detail)
		approvalMeta(c, "此操作不是快捷填充；请求 30 秒后失效。")
		approvalActions(c, func() {
			oneui.Button(c, approve, oneui.ButtonPrimary).Disabled(a.busy).OnClick(func() { a.browserV2Action(b, p.ID, true) })
			oneui.Button(c, reject, oneui.ButtonOutline).Disabled(a.busy).OnClick(func() { a.browserV2Action(b, p.ID, false) })
		})
	})
}

// browserV2AnchorView renders the bounded public anchors of one review. The
// current item (what the approval would read or edit) and the request (what it
// asks to write) are kept visually separate. Only names appear here: the host
// never puts a value, note, card/CVV/PIN, identity number or passkey material
// into the view. Rows sit in a bounded scroll region so the action buttons stay
// visible for any accepted list length.
func (a *App) browserV2AnchorView(c *ui.Context, p browserhost.V2ApprovalView) {
	if p.StoredTitle == "" && p.RequestedTitle == "" && len(p.StoredFields) == 0 && len(p.RequestedFields) == 0 {
		return
	}
	t := c.Theme()
	ui.Scroll(c).Height(210).FillWidth().Border(1, t.Border).Radius(t.Radius).Background(t.Background).Padding(t.Space(2)).Children(func() {
		ui.Column(c).Gap(t.Space(.75)).Children(func() {
			if p.StoredTitle != "" {
				oneui.Text(c, "当前条目：").FontSize(t.Rem(.78)).Bold().TextColor(t.Text)
				oneui.Text(c, "  当前名称："+browserTitle(p.StoredTitle)).FontSize(t.Rem(.78)).TextColor(t.Text).Wrap()
				oneui.Text(c, "  当前类别："+browserV2Category(p.StoredCategory)).FontSize(t.Rem(.76)).TextColor(t.TextMuted).Wrap()
				oneui.Text(c, "  当前字段名："+browserV2FieldNames(p.StoredFields)).FontSize(t.Rem(.76)).TextColor(t.TextMuted).Wrap()
			}
			if p.RequestedTitle != "" || p.RequestedCategory != "" || len(p.RequestedFields) != 0 {
				oneui.Text(c, "请求：").FontSize(t.Rem(.78)).Bold().TextColor(t.Text)
				if p.RequestedTitle != "" {
					oneui.Text(c, "  请求名称："+browserTitle(p.RequestedTitle)).FontSize(t.Rem(.78)).TextColor(t.Text).Wrap()
				}
				if p.RequestedCategory != "" {
					oneui.Text(c, "  请求类别："+browserV2Category(p.RequestedCategory)).FontSize(t.Rem(.76)).TextColor(t.TextMuted).Wrap()
				}
				if len(p.RequestedFields) != 0 {
					oneui.Text(c, "  请求字段名称："+browserV2FieldNames(p.RequestedFields)).FontSize(t.Rem(.76)).TextColor(t.TextMuted).Wrap()
				}
			}
			oneui.Text(c, "以上仅为字段名称，不包含任何字段值。").FontSize(t.Rem(.72)).TextColor(t.TextMuted).Wrap()
		})
	})
}

func browserV2Category(category string) string {
	switch category {
	case "login":
		return "登录（login）"
	case "password":
		return "密码（password）"
	case "secure_note":
		return "安全笔记（secure_note）"
	case "credit_card":
		return "信用卡（credit_card）"
	case "identity":
		return "身份信息（identity）"
	case "":
		return "（未注明）"
	}
	return visible(category)
}

func browserV2FieldNames(fields []string) string {
	if len(fields) == 0 {
		return "（无）"
	}
	return strings.Join(fields, "、")
}

func (a *App) browserV2Action(b *browserhost.Connection, id string, approve bool) {
	a.run(func() outcome {
		var err error
		if approve {
			err = b.ApproveV2(id)
		} else {
			err = b.RejectV2(id)
		}
		return outcome{err: err, apply: func() {
			if v := b.Snapshot(); v.V2 == nil {
				if err != nil {
					a.status = message(err)
				} else if !approve {
					a.status = "已拒绝本次浏览器敏感操作"
				}
			}
		}}
	})
}

// browserProfileView is the owner review for one sensitive profile fill. The
// page proposed only public selectors; this view never reads a card or identity
// value, and the private projection is prepared only after the approval click.
func (a *App) browserProfileView(c *ui.Context, b *browserhost.Connection, p browserhost.ProfileView) {
	t := c.Theme()
	category := "身份信息（identity）"
	if p.Category == "credit_card" {
		category = "信用卡（credit_card）"
	}
	heading := "本次敏感字段填充"
	tone := t.Accent
	if p.Checkout {
		heading = "跨源结账银行卡"
		tone = t.Warning
	}
	approvalCardWith(c, lucide.ShieldAlert(), tone, heading, true, nil, func() {
		approvalOrigin(c, "HTTPS 来源："+visible(p.Origin))
		approvalFacts(c, func() {
			if p.Checkout {
				// A cross-origin checkout frame always shows both sides: the top
				// document that embedded it and the exact card frame target. The
				// native policy already proved they share one registrable domain.
				approvalFact(c, "顶层页面来源："+visible(p.TopOrigin))
				approvalFact(c, "目标框架来源："+visible(p.FrameOrigin))
				approvalFact(c, "顶层文档："+visible(p.TopDocumentID))
				approvalFact(c, "框架文档："+visible(p.FrameDocumentID))
				approvalFact(c, "框架 ID："+strconv.FormatInt(p.FrameID, 10))
			}
			approvalFact(c, "类别："+category)
			approvalFact(c, "条目："+browserTitle(p.Title))
			approvalFact(c, "ID："+p.ItemID)
			approvalFact(c, "精确修订："+p.Revision)
		})
		approvalNote(c, "仅在本窗口批准后，才读取本条目本次允许填充的字段；卡片 PIN、身份证件号码及未列出的字段永不填入。请求 30 秒后失效。")
		// Fixed action area after the bounded review rows: both buttons stay
		// visible for any accepted title length.
		approve, reject := "批准本次敏感字段填充", "拒绝本次敏感字段填充"
		if p.Checkout {
			approve, reject = "批准本次跨源银行卡填充", "拒绝本次跨源银行卡填充"
		}
		approvalActions(c, func() {
			oneui.Button(c, approve, oneui.ButtonPrimary).Disabled(a.busy).OnClick(func() { a.browserProfileAction(b, p.ID, true) })
			oneui.Button(c, reject, oneui.ButtonOutline).Disabled(a.busy).OnClick(func() { a.browserProfileAction(b, p.ID, false) })
		})
	})
}

func (a *App) browserProfileAction(b *browserhost.Connection, id string, approve bool) {
	a.run(func() outcome {
		var err error
		if approve {
			err = b.ApproveProfile(id)
		} else {
			err = b.RejectProfile(id)
		}
		return outcome{err: err, apply: func() {
			if v := b.Snapshot(); v.Profile == nil {
				if err != nil {
					a.status = message(err)
				} else if !approve {
					a.status = "已拒绝本次敏感字段填充"
				}
			}
		}}
	})
}

func (a *App) browserSaveView(c *ui.Context, b *browserhost.Connection, p browserhost.SaveView, status string) {
	t := c.Theme()
	if a.browserSaveID != p.ID {
		a.browserSaveID = p.ID
		a.browserSaveTitle = p.Title
	}
	heading, approve, reject := "新建登录", "批准保存登录", "拒绝保存登录"
	if p.Mode == "update" {
		heading, approve, reject = "更新登录", "批准更新登录", "拒绝更新登录"
	}
	approvalCard(c, lucide.KeyRound(), t.Accent, heading, func() {
		approvalOrigin(c, "HTTPS 来源："+p.Origin)
		if p.Mode == "new" {
			oneui.TextBox(c, &a.browserSaveTitle, oneui.TextBoxOptions{}).Label("新登录标题").Disabled(a.busy || p.Stage != "pending").FillWidth()
		} else {
			approvalFacts(c, func() {
				approvalFact(c, "条目："+browserTitle(p.Title))
				approvalFact(c, "ID："+p.ItemID)
				approvalFact(c, "精确修订："+p.Revision)
			})
		}
		approvalNote(c, "保存的是点击时捕获的用户名与密码；不会验证网站账号是否正确。")
		if p.Mode == "update" {
			approvalMeta(c, "仅替换用户名和密码；保留标题、网址、OTP、备注及来源记录。")
		}
		if status != "" {
			approvalMeta(c, status)
		}
		if p.Stage != "pending" {
			return
		}
		approvalActions(c, func() {
			oneui.Button(c, approve, oneui.ButtonPrimary).Disabled(a.busy).OnClick(func() {
				id, title := p.ID, a.browserSaveTitle
				a.browserSaveAction(b, id, func() error { return b.ApproveSave(id, title) })
			})
			oneui.Button(c, reject, oneui.ButtonOutline).Disabled(a.busy).OnClick(func() { a.browserSaveAction(b, p.ID, func() error { return b.RejectSave(p.ID) }) })
		})
	})
}
func (a *App) browserSaveAction(b *browserhost.Connection, id string, work func() error) {
	a.run(func() outcome {
		e := work()
		return outcome{apply: func() {
			v := b.Snapshot()
			a.status = v.SaveStatus
			if v.SaveRequestID == id && e != nil && a.status == "" {
				a.status = message(e)
			}
		}}
	})
}

func (a *App) browserOTPView(c *ui.Context, b *browserhost.Connection, p browserhost.OTPView, status string) {
	t := c.Theme()
	approvalCard(c, lucide.KeyRound(), t.Accent, "确认本次验证码填充", func() {
		approvalOrigin(c, "HTTPS 来源："+visible(p.Origin))
		approvalFacts(c, func() {
			approvalFact(c, "条目："+browserTitle(p.Title))
			approvalFact(c, "ID："+p.ItemID)
			approvalFact(c, "精确修订："+p.Revision)
		})
		approvalNote(c, "仅填入当前页面的唯一标准验证码框；不会自动提交，也不会自动生成下一期。")
		if status != "" {
			approvalMeta(c, status)
		}
		if p.Stage != "pending" {
			return
		}
		approvalActions(c, func() {
			oneui.Button(c, "批准填充验证码", oneui.ButtonPrimary).Disabled(a.busy).OnClick(func() { a.browserOTPAction(b, p.ID, func() error { return b.ApproveOTP(p.ID) }) })
			oneui.Button(c, "拒绝填充验证码", oneui.ButtonOutline).Disabled(a.busy).OnClick(func() { a.browserOTPAction(b, p.ID, func() error { return b.RejectOTP(p.ID) }) })
		})
	})
}
func (a *App) browserOTPAction(b *browserhost.Connection, id string, work func() error) {
	a.run(func() outcome {
		err := work()
		return outcome{apply: func() {
			view := b.Snapshot()
			if view.OTPRequestID == id {
				a.status = view.OTPStatus
				if err != nil && a.status == "" {
					a.status = message(err)
				}
			}
		}}
	})
}

// browserSignalView renders the owner review for one WebAuthn signal hint. The
// page only ever receives the fixed acknowledgement; every change is shown
// here with the exact origin, RP, current account and new names, and only an
// explicit confirmation can reserve the mutation slot.
//
// The review rows live in a bounded scroll region and the action row sits
// outside it, so the confirmation controls stay visible for any number of
// reviewed accounts (including 2 or 50 rows) instead of being pushed below the
// viewport by unbounded text. The nested compact column keeps the fixed
// chrome (heading, origin/RP, privacy copy, warning, status) tight.
func (a *App) browserSignalView(c *ui.Context, b *browserhost.Connection, p browserhost.SignalView, status string) {
	t := c.Theme()
	heading := "网站请求更新 Passkey 账号"
	switch p.Kind {
	case "unknown":
		heading = "网站报告未知的 Passkey 凭据"
	case "accepted":
		heading = "网站请求清理不再接受的 Passkey"
	case "user":
		heading = "网站请求更新 Passkey 账号名称"
	}
	// Counted before the UI closure: the destructive warning never depends on
	// what happens to be scrolled into view.
	removals := 0
	for _, change := range p.Changes {
		if change.Action == "remove" {
			removals++
		}
	}
	approvalCardWith(c, lucide.FingerprintPattern(), t.Accent, heading, true, nil, func() {
		approvalOrigin(c, "HTTPS 来源："+visible(p.Origin))
		approvalMeta(c, "Passkey 域名："+visible(p.RPID))
		approvalMeta(c, "仅处理下列已启用的登录 Passkey。网站不会获知本地是否存在凭据，也不会收到处理结果或数量。")
		// Every reviewed account stays reachable by scrolling; nothing is
		// truncated and no row is dropped.
		ui.Scroll(c).Height(165).FillWidth().Border(1, t.Border).Radius(t.Radius).Background(t.Background).Padding(t.Space(2)).Children(func() {
			ui.Column(c).Gap(t.Space(.75)).Children(func() {
				for _, change := range p.Changes {
					if change.Action == "remove" {
						oneui.Text(c, "移除 Passkey："+browserTitle(change.Title)+" · "+visible(change.Username)).FontSize(t.Rem(.78)).TextColor(t.Danger).Wrap()
						continue
					}
					oneui.Text(c, "更新账号名称："+browserTitle(change.Title)+" · "+visible(change.Username)).FontSize(t.Rem(.78)).TextColor(t.Text).Wrap()
					oneui.Text(c, "  新用户名："+visible(change.Name)).FontSize(t.Rem(.76)).TextColor(t.TextMuted).Wrap()
					oneui.Text(c, "  新显示名："+visible(change.DisplayName)).FontSize(t.Rem(.76)).TextColor(t.TextMuted).Wrap()
				}
			})
		})
		if removals > 0 {
			approvalNotice(c, "注意：移除操作会在本地不可撤销地清除这些 Passkey；登录名、密码、验证码、备注与附件都会保留。网站信号本身不代表用户验证。", t.Danger)
		} else {
			approvalMeta(c, "仅修改 Passkey 记录中的用户名和显示名；凭据 ID、用户句柄、私钥及所有登录字段保持不变。")
		}
		if status != "" {
			approvalMeta(c, status)
		}
		if p.Working {
			// The cancel path stays busy-independent and outside the bounded
			// list, so a pending approval can still be revoked.
			approvalActions(c, func() {
				oneui.Button(c, "取消尚未提交的更新", oneui.ButtonOutline).OnClick(func() { a.browserSignalCancel(b, p.ID) })
			})
			return
		}
		// Fixed action area: rendered after the bounded rows, never after
		// unbounded text.
		approvalActions(c, func() {
			oneui.Button(c, "确认应用这些更新", oneui.ButtonPrimary).Disabled(a.busy || len(p.Changes) == 0).OnClick(func() {
				a.browserSignalAction(b, p.ID, func() error { return b.ApprovePasskeySignal(p.ID) })
			})
			oneui.Button(c, "取消（不做任何更改）", oneui.ButtonOutline).Disabled(a.busy).OnClick(func() {
				a.browserSignalAction(b, p.ID, func() error { return b.RejectPasskeySignal(p.ID) })
			})
		})
	})
}

func (a *App) browserSignalAction(b *browserhost.Connection, id string, work func() error) {
	a.run(func() outcome {
		err := work()
		return outcome{apply: func() {
			view := b.Snapshot()
			if view.Signal == nil || view.Signal.ID == id {
				if view.SignalStatus != "" {
					a.status = view.SignalStatus
				} else if err != nil {
					a.status = message(err)
				}
			}
		}}
	})
}

// browserSignalCancel revokes a live signal gate directly on the native host.
// It deliberately bypasses a.run/a.busy: an approval may already be waiting on
// the database, and a cancel must still reach the host to cancel that gate.
// RejectPasskeySignal takes only the short Connection lock and performs no
// database work, so this click handler cannot block on the vault.
func (a *App) browserSignalCancel(b *browserhost.Connection, id string) {
	a.status = "已请求取消；若已提交请核实金库"
	err := b.RejectPasskeySignal(id)
	view := b.Snapshot()
	if view.Busy || (view.Signal != nil && view.Signal.ID == id) {
		return
	}
	if view.SignalStatus != "" {
		a.status = view.SignalStatus
	} else if err != nil {
		a.status = message(err)
	}
}

func browserTitle(title string) string {
	if title == "" {
		return "（无标题）"
	}
	return visible(title)
}

// RunBrowser is a separate native process and session for this pipe. It exports
// no web bindings and accepts no command-line unlock factors or approval flags.
func RunBrowser(browser browserhost.Browser, args []string) error {
	if browserhost.ValidateLaunch(browser, args) != nil {
		return browserhost.ErrProtocol
	}
	if os.Getenv("PASSME_BROWSER_STANDALONE") != "1" {
		err := browserhost.RelayStdio(browser, args, os.Stdin, os.Stdout)
		if err == nil {
			return nil
		}
		if !errors.Is(err, browserhost.ErrBrokerUnavailable) {
			return err
		}
	}
	if e := restoreBrowserAccessibility(browser); e != nil {
		return e
	}
	a := New()
	a.browserLabel = "chrome-extension://" + browserhost.ChromiumID + "/"
	if browser == browserhost.Firefox {
		a.browserLabel = browserhost.FirefoxID
	}
	if browser == browserhost.Safari {
		a.browserLabel = browserhost.SafariID
	}
	writer := browserhost.NewNativeWriter(os.Stdout, 250*time.Millisecond, func() { os.Exit(74) })
	mygo.App.SetName("Passme Browser")
	mygo.App.WhenReady(func() {
		a.win = mygo.NewWindow(mygo.WindowOptions{
			Title:     "Passme · 浏览器原生确认",
			Width:     1000,
			Height:    780,
			MinWidth:  900,
			MinHeight: 680,
			Content: ui.View(func(c *ui.Context) {
				c.SetTheme(a.onevraTheme(c))
				a.View(c)
			}),
		})
		a.dispatch = a.win.Update
		a.browser = browserhost.NewConnection(writer, func() { a.win.Invalidate() })
		a.win.OnClose(func(*mygo.CloseEvent) { a.Lock(); a.browser.Close(); mygo.App.Quit() })
		mygo.Power.OnSuspend(a.Lock)
		mygo.Power.OnLockScreen(a.Lock)
		mygo.App.OnQuit(a.Lock)
		go func() {
			for {
				request, e := browserhost.ReadRequest(os.Stdin)
				if e != nil {
					break
				}
				e = a.browser.Handle(request)
				request.Clear()
				if e != nil {
					break
				}
			}
			a.browser.Close()
			a.dispatch(func() { a.Lock(); mygo.App.Quit() })
		}()
	})
	return mygo.App.Run()
}

// passkeySystemStore reports the trusted native OS adapter that can perform a
// fresh per-operation user verification. It is a structural check only: the
// Linux Secret Service adapter deliberately does not implement it, and no
// renderer or protocol value can supply one.
func (a *App) passkeySystemStore() (personal.SystemPasskeyVerificationStore, bool) {
	store, ok := a.systemStore.(personal.SystemPasskeyVerificationStore)
	if !ok || store == nil {
		return nil, false
	}
	return store, true
}

// shortPasskeyCredential renders a safe, non-secret hint that distinguishes two
// credentials of the same login in the native selector. The full selector is
// still bound on click; this text is display only.
func shortPasskeyCredential(id string) string {
	if len(id) <= 8 {
		return visible(id)
	}
	return visible(id[:8]) + "…"
}

// passkeyChoiceLabel keeps every reviewed choice distinguishable: the request
// RP, the account and a short credential hint. Two credentials of one parent
// must never render as two identical buttons.
func passkeyChoiceLabel(p browserhost.PasskeyView, choice personal.PasskeyChoice, create bool, existing int) string {
	prefix := "登录："
	if create {
		prefix = "保存到："
	}
	label := prefix + visible(p.RPID) + " · " + browserTitle(choice.Title) + " · " + visible(choice.Username)
	if choice.CredentialID != "" {
		label += " · 凭据 " + shortPasskeyCredential(choice.CredentialID)
	}
	if create {
		label += fmt.Sprintf("（已有 %d 个 Passkey）", existing)
		if existing > 0 {
			label += " · 升级加密格式，旧客户端将拒绝该金库"
		}
	}
	return label
}

func (a *App) browserPasskeyView(c *ui.Context, b *browserhost.Connection, p browserhost.PasskeyView, status string) {
	t := c.Theme()
	if a.browserPasskeyID != p.ID {
		a.browserPasskeyID = p.ID
		a.password = ""
		a.secret = ""
	}
	heading := "使用 Passkey 登录"
	if p.Create {
		heading = "保存 Passkey"
	}
	var trailing func()
	if !p.Working {
		trailing = func() {
			oneui.Button(c, "取消 / 使用其他验证器", oneui.ButtonOutline).Disabled(a.busy).OnClick(func() {
				a.password = ""
				a.secret = ""
				a.run(func() outcome { return outcome{err: b.RejectPasskey(p.ID)} })
			})
		}
	}
	approvalCardWith(c, lucide.FingerprintPattern(), t.Accent, heading, true, trailing, func() {
		approvalOrigin(c, "网站："+visible(p.Origin))
		approvalFacts(c, func() {
			approvalFact(c, "Passkey 域名："+visible(p.RPID))
			if p.Create {
				approvalFact(c, "账号："+visible(p.Username))
			}
		})
		if status != "" {
			approvalMeta(c, status)
		}
		if p.Working {
			return
		}
		approvalMeta(c, "需要用户验证时，请在此重新输入主密码和 Secret Key。网站不会获得这些解锁因素。")
		ui.Row(c).FillWidth().Gap(t.Space(2)).Children(func() {
			ui.Column(c).Grow(1).MinWidth(0).Children(func() {
				oneui.TextBox(c, &a.password, oneui.TextBoxOptions{}).Label("验证主密码").Password().Disabled(a.busy).FillWidth()
			})
			ui.Column(c).Grow(1).MinWidth(0).Children(func() {
				oneui.TextBox(c, &a.secret, oneui.TextBoxOptions{}).Label("验证 Secret Key").Password().Disabled(a.busy).FillWidth()
			})
		})
		approve := func(item, credential string) {
			pw := []byte(a.password)
			var key []byte
			var err error
			if a.secret != "" {
				key, err = personal.ParseSecret(a.secret)
			}
			a.password = ""
			a.secret = ""
			if err != nil {
				clear(pw)
				a.status = "Secret Key 格式不正确"
				return
			}
			a.run(func() outcome {
				defer clear(pw)
				defer clear(key)
				return outcome{err: b.ApprovePasskeyCredential(p.ID, item, credential, pw, key)}
			})
		}
		if p.VerificationRequired {
			approvalNotice(c, "此网站要求用户验证；必须填写两个解锁因素。", t.Warning)
		}
		factorsReady := a.password != "" && a.secret != "" || !p.VerificationRequired && a.password == "" && a.secret == ""
		// Keep reviewed choices reachable while factors and cancel remain visible.
		if p.Create {
			approvalNotice(c, "添加第二个 Passkey 会升级该登录的加密格式；旧客户端将拒绝打开金库。请仅在核对账号后明确批准。", t.Warning)
			ui.Row(c).FillWidth().Children(func() {
				oneui.Button(c, "创建新登录并保存 Passkey", oneui.ButtonPrimary).Disabled(a.busy || !factorsReady).OnClick(func() { approve("", "") })
			})
		}
		ui.Scroll(c).Height(160).FillWidth().Border(1, t.Border).Radius(t.Radius).Background(t.Background).Padding(t.Space(2)).Children(func() {
			ui.Column(c).FillWidth().Gap(t.Space(.75)).Children(func() {
				for index, choice := range p.Choices {
					choice := choice
					existing := 0
					if index < len(p.ChoicePasskeys) {
						existing = p.ChoicePasskeys[index]
					}
					label := passkeyChoiceLabel(p, choice, p.Create, existing)
					ui.Button(c, label).Key("passkey-knowledge:" + choice.ID + ":" + choice.CredentialID).FillWidth().Disabled(a.busy || !factorsReady).OnClick(func() { approve(choice.ID, choice.CredentialID) })
				}
				// A per-account (or new-credential) system factor button appears only when
				// the trusted native adapter can perform a fresh user verification. The
				// adapter is never called while rendering, listing candidates or before a
				// target is selected; each click asks the OS again and no earlier unlock
				// result is reused. Enrollment in "安全设置" must already exist.
				if store, ok := a.passkeySystemStore(); ok {
					systemLabel := osunlock.Label()
					approveSystem := func(item, credential string) {
						// Stale knowledge-factor inputs never travel with an OS approval.
						a.password = ""
						a.secret = ""
						a.run(func() outcome {
							e := b.ApprovePasskeyCredentialWithSystem(p.ID, item, credential, store)
							return outcome{err: e, apply: func() {
								if v := b.Snapshot(); v.PasskeyStatus != "" {
									a.status = v.PasskeyStatus
								}
							}}
						})
					}
					oneui.Text(c, "系统验证（"+systemLabel+"）：需先在“安全设置”启用系统快捷解锁；每次操作都会重新由系统验证，网站不会获得解锁因素。").
						FontSize(t.Rem(.74)).TextColor(t.TextMuted).Wrap()
					if p.Create {
						ui.Button(c, "使用"+systemLabel+"创建并保存 Passkey").FillWidth().Disabled(a.busy).OnClick(func() { approveSystem("", "") })
					}
					for index, choice := range p.Choices {
						choice := choice
						existing := 0
						if index < len(p.ChoicePasskeys) {
							existing = p.ChoicePasskeys[index]
						}
						label := "使用" + systemLabel + passkeyChoiceLabel(p, choice, p.Create, existing)
						ui.Button(c, label).Key("passkey-system:" + choice.ID + ":" + choice.CredentialID).FillWidth().Disabled(a.busy).OnClick(func() { approveSystem(choice.ID, choice.CredentialID) })
					}
					oneui.Text(c, "系统验证失败或被取消时，请继续使用主密码与 Secret Key。").FontSize(t.Rem(.74)).TextColor(t.TextMuted).Wrap()
				}
			})
		})
	})
}
