package desktop

import (
	"fmt"
	"strings"
	"unicode"

	"github.com/egoist/mygo/ui"
	"github.com/jihuayu/locklark/internal/personal"
)

type nativeNotesDraft struct {
	target personal.RevealTarget
	title  string
	value  string
}

func (nativeNotesDraft) String() string               { return "[native notes draft]" }
func (nativeNotesDraft) GoString() string             { return "[native notes draft]" }
func (nativeNotesDraft) MarshalJSON() ([]byte, error) { return nil, personal.ErrDesktopDelivery }

func visibleNotes(s string) string {
	var out strings.Builder
	for _, r := range s {
		if r != '\n' && r != '\t' && (unicode.IsControl(r) || unicode.Is(unicode.Cf, r)) {
			fmt.Fprintf(&out, "\\u{%X}", r)
		} else {
			out.WriteRune(r)
		}
	}
	return out.String()
}

// This is separate from clearDailyExposure: temporarily opening quick search
// must hide delivered values while preserving an intentional editor draft.
func (a *App) clearNotesEditor() {
	if a.notesEditor != nil {
		a.notesEditor.value = ""
		a.notesEditor = nil
	}
}

func (a *App) editNotes() {
	if a.session == nil || a.selected == nil || a.busy || a.page != "vault" {
		return
	}
	s := a.session
	target := personal.RevealTarget{ID: a.selected.ID, Revision: a.selected.Revision, Field: "notes"}
	title := a.selected.Title
	generation := a.generation
	previousExposure, operation := a.exposureGeneration, a.operationSequence
	a.clearNotesEditor()
	a.clearDailyExposure()
	if a.session != s || a.generation != generation || a.exposureGeneration != previousExposure+1 || a.operationSequence != operation || a.page != "vault" || a.selected == nil || a.selected.ID != target.ID || a.selected.Revision != target.Revision || a.busy {
		return
	}
	exposure := a.exposureGeneration
	a.run(func() outcome {
		field, e := s.PrepareField(target, "edit")
		return outcome{err: e, drop: func() { s.Discard(field) }, apply: func() {
			if !a.exposureCurrent(s, personal.NativeOTPTarget{ID: target.ID, Revision: target.Revision}, generation, exposure) {
				s.Discard(field)
				return
			}
			e := s.Consume(field, func(value []byte) error {
				a.value = ""
				a.notesEditor = &nativeNotesDraft{target: target, title: title, value: string(value)}
				a.status = "备注编辑器包含可见秘密；保存前可以取消。"
				return nil
			})
			if e != nil {
				a.status = message(e)
			}
		}}
	})
}

func (a *App) saveNotes(draft *nativeNotesDraft) {
	if draft == nil || a.notesEditor != draft || a.session == nil || a.selected == nil || a.busy || a.page != "vault" || a.selected.ID != draft.target.ID || a.selected.Revision != draft.target.Revision {
		return
	}
	s, target, scope := a.session, draft.target, a.scope
	generation := a.generation
	exposure, operation := a.exposureGeneration, a.operationSequence
	value := []byte(draft.value)
	a.clearNotesEditor()
	a.clearDailyExposure()
	if a.session != s || a.generation != generation || a.exposureGeneration != exposure+1 || a.operationSequence != operation || a.page != "vault" || a.selected == nil || a.selected.ID != target.ID || a.selected.Revision != target.Revision || a.busy {
		clear(value)
		return
	}
	a.saveNotesCaptured(s, target, value, scope)
}

func (a *App) saveNotesCaptured(s *personal.Session, target personal.RevealTarget, value []byte, scope string) {
	started := a.runNative(func(g *personal.MutationGate) nativeResult {
		defer clear(value)
		revision, e := s.SaveNativeNotes(target.ID, target.Revision, value, g)
		r := nativeResult{err: e, receipt: personal.GenerationReceipt{ID: target.ID, Revision: revision}}
		if e == nil {
			r.rows, r.refreshErr = s.List(scope)
		}
		return r
	}, func(r nativeResult) {
		a.rows, a.selected = r.rows, nil
		a.status = "备注已保存；需要查看时请重新明确读取。"
		if r.refreshErr != nil {
			a.status += "列表未刷新，请手动刷新。"
		}
	})
	if !started {
		clear(value)
	}
}

func (a *App) notesEditorView(c *ui.Context) {
	draft := a.notesEditor
	ui.Scroll(c).Fill().Children(func() {
		ui.Column(c).Gap(12).Children(func() {
			ui.Text(c, "编辑登录备注").FontSize(24).Bold()
			ui.Text(c, "登录："+browserTitle(draft.title)).Bold()
			ui.Text(c, "这是可见的秘密正文。仅按保存按钮提交，Enter 只换行；取消不修改金库。")
			ui.Text(c, "ID: "+draft.target.ID).FontSize(12)
			ui.Text(c, "修订: "+draft.target.Revision).FontSize(12)
			ui.TextArea(c, &draft.value).Label("备注正文（可见多行）").Height(300).Disabled(a.busy)
			ui.PrimaryButton(c, "保存备注").Disabled(a.busy).OnClick(func() { a.saveNotes(draft) })
			ui.Button(c, "取消编辑备注").Disabled(a.busy).OnClick(func() {
				if a.notesEditor == draft {
					a.clearNotesEditor()
					a.clearDailyExposure()
					a.status = "备注编辑已取消；未保存。"
				}
			})
		})
	})
}
