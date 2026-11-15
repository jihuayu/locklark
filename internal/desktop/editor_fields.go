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
		Radius(t.Space(1.25)).
		Background(t.Background.Alpha(.55)).
		Padding(t.Space(1.5), t.Space(1.75)).Children(func() {
		if spec.BuildMenu != nil {
			menuButton := ui.ButtonBase(c).Size(t.Space(5), t.Space(5)).
				Radius(t.Radius).Label(spec.MenuLabel).TextColor(t.Accent).
				Disabled(spec.Busy)
			menuButton.Children(func() {
				oneui.Icon(c, lucide.Menu()).Size(t.Space(3.5), t.Space(3.5))
			})
			oneui.MenuButton(c, menuButton, spec.BuildMenu)
		} else {
			ui.Box(c).Size(t.Space(5), t.Space(5)).Shrink(0)
		}

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
					oneui.Text(c, spec.Label).FontSize(t.Rem(.74)).Bold().
						TextColor(t.Accent).SingleLine().Grow(1)
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
	})
}

// editorFieldGroup composes field rows into one product surface with shared
// separators and a single add action.
func editorFieldGroup(c *ui.Context, spec editorFieldGroupSpec) {
	t := c.Theme()
	ui.Column(c.Key("editor-field-group:"+spec.Key)).FillWidth().MinWidth(0).
		Border(1, t.Border).Radius(t.Radius).Background(t.Surface).
		Padding(t.Space(2), t.Space(2)).Gap(0).Children(func() {
		ui.Row(c).FillWidth().Wrap().AlignItems(ui.Center).Gap(t.Space(2)).
			Padding(t.Space(1), t.Space(1.5), t.Space(1.5), t.Space(1.5)).
			Children(func() {
				oneui.Text(c, spec.Title).FontSize(t.Rem(1.02)).Bold().Grow(1)
				if spec.Badge != "" {
					oneui.Badge(c, spec.Badge, oneui.BadgeOptions{Tone: oneui.BadgeAccent})
				}
				if spec.HeaderAction != nil {
					spec.HeaderAction()
				}
			})

		shown := false
		for i := range spec.Fields {
			if shown {
				ui.Box(c).FillWidth().Height(1).Background(t.Border)
			}
			editorFieldRow(c, spec.Fields[i])
			shown = true
		}
		for _, row := range spec.ExtraRows {
			if shown {
				ui.Box(c).FillWidth().Height(1).Background(t.Border)
			}
			row(c)
			shown = true
		}

		if (spec.AddLabel != "" && spec.BuildAddMenu != nil) || (spec.SecondaryAddLabel != "" && spec.OnSecondaryAdd != nil) {
			ui.Box(c).FillWidth().Height(1).Background(t.Border)
			ui.Row(c).FillWidth().Gap(t.Space(1.5)).Padding(t.Space(1.25), t.Space(1.5)).Children(func() {
				if spec.SecondaryAddLabel != "" && spec.OnSecondaryAdd != nil {
					if oneui.Button(c, spec.SecondaryAddLabel, oneui.ButtonOutline).Grow(1).Clicked() {
						spec.OnSecondaryAdd()
					}
				}
				if spec.AddLabel != "" && spec.BuildAddMenu != nil {
					addButton := oneui.Button(c, spec.AddLabel, oneui.ButtonGhost).Grow(1)
					oneui.MenuButton(c, addButton, spec.BuildAddMenu)
				}
			})
		}
	})
}
