package desktop

import (
	"github.com/egoist/mygo/ui"
	oneui "github.com/oneo-me/onevra/source/components"
	"github.com/oneo-me/onevra/source/icons/lucide"
)

// editorFieldSpec is one editable value inside an item field group.
type editorFieldSpec struct {
	Key         string
	Label       string
	Placeholder string
	Value       *string
	LabelValue  *string
	Concealed   bool
	Multiline   bool
	Busy        bool
	MenuLabel   string
	BuildMenu   func(*oneui.Menu)
	Trailing    func(*ui.Context)
}

// editorFieldGroupSpec is a titled collection of related item fields.
type editorFieldGroupSpec struct {
	Key               string
	Title             string
	Badge             string
	Fields            []editorFieldSpec
	ExtraRows         []func(*ui.Context)
	AddLabel          string
	BuildAddMenu      func(*oneui.Menu)
	SecondaryAddLabel string
	OnSecondaryAdd    func()
	HeaderAction      func()
}

// editorFieldRow is the reusable input component. Its label is visible rather
// than hidden in a placeholder, and the row menu keeps field actions in one
// stable place as the item editor grows.
func editorFieldRow(c *ui.Context, spec editorFieldSpec) {
	if spec.Value == nil {
		return
	}
	t := c.Theme()
	ui.Row(c.Key("editor-field:"+spec.Key)).FillWidth().MinWidth(0).
		AlignItems(ui.Start).Gap(t.Space(1.5)).
		Padding(t.Space(2), t.Space(3)).Children(func() {
		ui.Column(c).Grow(1).MinWidth(0).Gap(t.Space(.5)).Children(func() {
			if spec.LabelValue != nil {
				ui.Row(c).FillWidth().AlignItems(ui.End).Gap(t.Space(1.5)).Children(func() {
					oneui.TextBox(c, spec.LabelValue, oneui.TextBoxOptions{}).
						Label("字段名").
						Placeholder(spec.Label).
						Grow(1).
						Disabled(spec.Busy)
					if spec.Trailing != nil {
						spec.Trailing(c)
					}
				})
			} else {
				ui.Row(c).FillWidth().AlignItems(ui.Center).Gap(t.Space(1)).Children(func() {
					oneui.Text(c, spec.Label).FontSize(t.Rem(.74)).TextColor(t.TextMuted).SingleLine().Grow(1)
					if spec.Trailing != nil {
						spec.Trailing(c)
					}
				})
			}
			input := oneui.TextBox(c, spec.Value, oneui.TextBoxOptions{Multiline: spec.Multiline}).
				Label(spec.Label).
				FillWidth().
				Disabled(spec.Busy)
			if spec.Placeholder != "" {
				input.Placeholder(spec.Placeholder)
			}
			if spec.Concealed {
				input.Password()
			}
			if spec.Multiline {
				input.Lines(2, 6)
			}
		})
		if spec.BuildMenu != nil {
			menuButton := oneui.IconButton(c, lucide.Ellipsis(), spec.MenuLabel, oneui.IconButtonCompact).
				Disabled(spec.Busy)
			oneui.MenuButton(c, menuButton, spec.BuildMenu)
		}
	})
}

// editorFieldGroup composes field rows into one calm document surface with
// hairline dividers and a single add action.
func editorFieldGroup(c *ui.Context, spec editorFieldGroupSpec) {
	t := c.Theme()
	ui.Column(c.Key("editor-field-group:"+spec.Key)).FillWidth().MinWidth(0).Gap(t.Space(1.5)).Children(func() {
		if spec.Title != "" || spec.Badge != "" || spec.HeaderAction != nil {
			ui.Row(c).FillWidth().Wrap().AlignItems(ui.Center).Gap(t.Space(1.5)).Padding(0, t.Space(1)).Children(func() {
				if spec.Title != "" {
					oneui.Text(c, spec.Title).FontSize(t.Rem(.76)).Bold().TextColor(t.TextMuted).Grow(1)
				} else {
					ui.Spacer(c)
				}
				if spec.Badge != "" {
					onevraPill(c, spec.Badge, t.TextMuted)
				}
				if spec.HeaderAction != nil {
					spec.HeaderAction()
				}
			})
		}

		ui.Column(c).FillWidth().MinWidth(0).
			Border(1, t.Border).Radius(t.Radius*1.25).Background(t.Surface).Children(func() {
			shown := false
			for i := range spec.Fields {
				if shown {
					ui.Box(c).FillWidth().Height(1).Background(t.Border.Alpha(.7))
				}
				editorFieldRow(c, spec.Fields[i])
				shown = true
			}
			for _, row := range spec.ExtraRows {
				if shown {
					ui.Box(c).FillWidth().Height(1).Background(t.Border.Alpha(.7))
				}
				row(c)
				shown = true
			}

			if (spec.AddLabel != "" && spec.BuildAddMenu != nil) || (spec.SecondaryAddLabel != "" && spec.OnSecondaryAdd != nil) {
				if shown {
					ui.Box(c).FillWidth().Height(1).Background(t.Border.Alpha(.7))
				}
				ui.Row(c).FillWidth().Gap(t.Space(1.5)).Padding(t.Space(1.5), t.Space(3)).Children(func() {
					if spec.SecondaryAddLabel != "" && spec.OnSecondaryAdd != nil {
						if oneui.Button(c, spec.SecondaryAddLabel, oneui.ButtonOutline).Clicked() {
							spec.OnSecondaryAdd()
						}
					}
					if spec.AddLabel != "" && spec.BuildAddMenu != nil {
						addButton := oneui.Button(c, spec.AddLabel, oneui.ButtonGhost)
						oneui.MenuButton(c, addButton, spec.BuildAddMenu)
					}
				})
			}
		})
	})
}
