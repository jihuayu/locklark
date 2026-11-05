package desktop

import (
	"errors"
	"fmt"
	"strconv"
	"time"

	"github.com/egoist/mygo/ui"
	"github.com/jihuayu/locklark/internal/personal"
)

const mutationUnknownStatus = "有一项操作结果未确认，请在金库核实，勿重复该操作"

type nativeOperation struct {
	gate       *personal.MutationGate
	generation uint64
}
type nativeResult struct {
	receipt         personal.GenerationReceipt
	rows            []personal.Row
	refreshErr, err error
	delivery        *personal.NativeOTPDelivery
}

func (a *App) runNative(work func(*personal.MutationGate) nativeResult, apply func(nativeResult)) bool {
	if a.busy || a.session == nil {
		return false
	}
	s := a.session
	g := personal.NewMutationGate(time.Now().Add(30 * time.Second))
	if e := s.RegisterMutation(g); e != nil {
		a.status = message(e)
		return false
	}
	op := &nativeOperation{g, a.generation}
	a.operation = op
	a.busy = true
	a.status = "处理中…"
	a.launch(func() {
		r := work(g)
		a.dispatch(func() {
			if a.operation != op || op.generation != a.generation {
				if r.delivery != nil {
					a.launch(func() { s.DiscardOTPDelivery(r.delivery) })
				}
				return
			}
			a.busy = false
			if r.err != nil && r.delivery != nil {
				a.launch(func() { s.DiscardOTPDelivery(r.delivery) })
			}
			if errors.Is(r.err, personal.ErrMutationUnknown) {
				a.mutationUnknown = true
				a.status = mutationUnknownStatus
				return
			}
			a.operation = nil
			if r.err != nil {
				a.status = message(r.err)
				if !s.Unlocked() {
					a.Lock()
				}
				return
			}
			apply(r)
		})
	})
	return true
}

func (a *App) passwordLength() (int, bool) {
	n, e := strconv.Atoi(a.generationLength)
	if e != nil || strconv.Itoa(n) != a.generationLength || n < 22 || n > 256 {
		a.status = "密码长度须为22至256的整数"
		return 0, false
	}
	return n, true
}
func (a *App) saveNative(generate bool) {
	if a.session == nil || a.busy {
		return
	}
	length := 24
	if generate {
		var ok bool
		length, ok = a.passwordLength()
		if !ok {
			return
		}
	}
	meta, user, value, scope := personal.NativeLoginMetadata{Title: a.title, URL: a.website}, []byte(a.username), []byte(a.value), a.scope
	a.username = ""
	a.value = ""
	a.clearDailyExposure()
	a.saveNativeCaptured(meta, user, value, scope, generate, length)
}
func (a *App) saveNativeCaptured(meta personal.NativeLoginMetadata, user, value []byte, scope string, generate bool, length int) {
	s := a.session
	started := a.runNative(func(g *personal.MutationGate) nativeResult {
		defer clear(user)
		defer clear(value)
		var r personal.GenerationReceipt
		var e error
		if generate {
			r, e = s.GenerateNativeLogin(meta, user, length, g)
		} else {
			r, e = s.SaveNativeLogin(meta, user, value, g)
		}
		out := nativeResult{receipt: r, err: e}
		if e == nil {
			out.rows, out.refreshErr = s.List(scope)
		}
		return out
	}, func(r nativeResult) {
		a.rows = r.rows
		a.selected = nil
		a.title = ""
		a.website = ""
		a.status = "登录已保存"
		if generate {
			a.status = fmt.Sprintf("已生成并保存 · %d字符 · 策略熵至少%d位", r.receipt.Profile.Length, r.receipt.Profile.EntropyBits)
		}
		if r.refreshErr != nil {
			a.status += "；列表未刷新，请手动刷新"
		}
	})
	if !started {
		clear(user)
		clear(value)
	}
}
func (a *App) reviewRegeneration() {
	if a.selected == nil || a.session == nil {
		return
	}
	s, id, revision := a.session, a.selected.ID, a.selected.Revision
	a.clearDailyExposure()
	exposure := a.exposureGeneration
	a.run(func() outcome {
		v, e := s.ReviewNativeLogin(id, revision)
		return outcome{err: e, apply: func() {
			if a.page != "vault" || a.selected == nil || a.selected.ID != id || a.selected.Revision != revision || a.exposureGeneration != exposure {
				return
			}
			a.regenerate = &v
			a.status = "请核对目标后确认；不会修改网站账号"
		}}
	})
}
func (a *App) confirmRegeneration() {
	if a.regenerate == nil || a.session == nil {
		return
	}
	length, ok := a.passwordLength()
	if !ok {
		return
	}
	s, target, scope := a.session, *a.regenerate, a.scope
	a.clearDailyExposure()
	a.runNative(func(g *personal.MutationGate) nativeResult {
		r, e := s.RegenerateNativePassword(target.ID, target.Revision, length, g)
		out := nativeResult{receipt: r, err: e}
		if e == nil {
			out.rows, out.refreshErr = s.List(scope)
		}
		return out
	}, func(r nativeResult) {
		a.regenerate = nil
		a.rows = r.rows
		a.selected = nil
		a.status = "本地密码已重新生成；网站密码尚未修改"
		if r.refreshErr != nil {
			a.status += "；列表未刷新，请手动刷新"
		}
	})
}
func (a *App) regenerationView(c *ui.Context) {
	target := *a.regenerate
	ui.Text(c, "确认重新生成本地密码").FontSize(22).Bold()
	ui.Text(c, "仅替换本地金库密码，不会替你修改网站密码。").Bold()
	ui.Text(c, "条目："+browserTitle(target.Title))
	ui.Text(c, "网站："+visible(target.URL))
	ui.Text(c, "状态："+target.State)
	ui.Text(c, "ID："+target.ID).FontSize(12)
	ui.Text(c, "修订："+target.Revision).FontSize(12)
	ui.TextInput(c, &a.generationLength).Label("密码长度（22–256）").Disabled(a.busy)
	ui.PrimaryButton(c, "确认生成并替换").Disabled(a.busy).OnClick(a.confirmRegeneration)
	ui.Button(c, "取消重新生成").Disabled(a.busy).OnClick(func() { a.regenerate = nil; a.status = "未重新生成" })
}

// UI state only: never reenter a Session mutex from a granted callback.
func (a *App) exposureCurrent(s *personal.Session, target personal.NativeOTPTarget, generation, exposure uint64) bool {
	return a.session == s && a.generation == generation && a.exposureGeneration == exposure && a.page == "vault" && a.selected != nil && a.selected.ID == target.ID && a.selected.Revision == target.Revision
}
func (a *App) requestOTP(purpose string) {
	if a.selected == nil || a.session == nil || a.busy {
		return
	}
	s, target, exposure := a.session, personal.NativeOTPTarget{ID: a.selected.ID, Revision: a.selected.Revision}, a.exposureGeneration
	generation := a.generation
	a.runNative(func(g *personal.MutationGate) nativeResult {
		p, e := s.PrepareOTP(target, purpose, g)
		if e != nil {
			return nativeResult{err: e}
		}
		d, e := s.AuthorizeOTP(p)
		return nativeResult{delivery: d, err: e}
	}, func(r nativeResult) {
		if !a.exposureCurrent(s, target, generation, exposure) {
			a.launch(func() { s.DiscardOTPDelivery(r.delivery) })
			a.status = "验证码交付已撤销"
			return
		}
		valid := func() bool { return a.exposureCurrent(s, target, generation, exposure) }
		e := s.DeliverOTP(r.delivery, target, func(code []byte, b personal.OTPBounds) error {
			if purpose == "copy" {
				if e := a.writeClipboard(code, b.Deadline, func() bool { return valid() && b.Check(time.Now()) }); e != nil {
					return e
				}
				sequence := a.clipboardSequence
				a.otpClipboard = &b
				a.otpClipboardTarget = target
				a.otpClipboardTimer = time.AfterFunc(time.Until(b.Deadline), func() {
					a.dispatch(func() {
						if a.clipboardSequence == sequence {
							a.clearClipboard()
						}
					})
				})
				a.status = "已复制验证码；到期尝试清理，系统剪贴板历史可能保留"
			} else {
				a.hideOTP()
				a.otpDisplay = string(code)
				a.otpDisplayBounds = &b
				a.otpDisplayTarget = target
				a.displaySequence++
				sequence := a.displaySequence
				a.otpDisplayTimer = time.AfterFunc(time.Until(b.Deadline), func() {
					a.dispatch(func() {
						if a.displaySequence == sequence {
							a.hideOTP()
						}
					})
				})
				a.status = "本次验证码已显示；到期后请明确重新获取"
			}
			return nil
		})
		if e != nil && a.exposureCurrent(s, target, generation, exposure) && !errors.Is(e, errClipboardSuperseded) {
			a.status = message(e)
		}
	})
}
func (a *App) hideOTP() {
	a.displaySequence++
	if a.otpDisplayTimer != nil {
		a.otpDisplayTimer.Stop()
		a.otpDisplayTimer = nil
	}
	a.otpDisplay = ""
	a.otpDisplayBounds = nil
}
func (a *App) clearDailyExposure() {
	a.exposureGeneration++
	a.hideOTP()
	a.display = ""
	a.displayUntil = time.Time{}
	a.clearClipboard()
}
func (a *App) checkOTPExposure(now time.Time) {
	target := personal.NativeOTPTarget{}
	if a.selected != nil && a.page == "vault" {
		target = personal.NativeOTPTarget{ID: a.selected.ID, Revision: a.selected.Revision}
	}
	if a.otpDisplayBounds != nil && (a.otpDisplayTarget != target || !a.otpDisplayBounds.Check(now)) {
		a.hideOTP()
	}
	if a.otpClipboard != nil && (a.otpClipboardTarget != target || !a.otpClipboard.Check(now)) {
		a.clearClipboard()
	}
}
func (a *App) otpView(c *ui.Context) {
	if a.otpDisplay != "" {
		ui.Column(c).Role(ui.RoleGroup).Label("已授权显示的验证码").Children(func() { ui.Text(c, a.otpDisplay).FontSize(24).Bold() })
		ui.Button(c, "隐藏验证码").OnClick(func() { a.exposureGeneration++; a.hideOTP() })
	}
}
