package desktop

import (
	"time"

	"github.com/egoist/mygo/ui"
	"github.com/oneo-me/onevra/source/components"
)

const (
	onevraSidebarDefaultWidth float32 = 216
	onevraListDefaultWidth    float32 = 320
)

// onevraToast is a deferred toast: mutations finish asynchronously without a
// ui.Context, so the next frame emits it.
type onevraToast struct {
	message string
	action  string
	undo    func()
}

// onevraPending runs an action once the detail for itemID has loaded, so row
// context-menu actions that need the selected detail (copy, edit, duplicate)
// work on a row that was not selected yet.
type onevraPending struct {
	itemID string
	run    func()
}

// onevraUI owns presentation-only state for the native Onevra shell. Business
// state stays in v2State and the existing session-facing methods. Nothing here
// holds a secret value.
type onevraUI struct {
	sidebarWidth      float32
	listWidth         float32
	rowCursor         int
	list              *components.ListState
	shellActive       bool
	showAllCategories bool
	moveDialogOpen    bool
	moveCopyMode      bool
	moveTargetVaultID string

	copyIntent     string
	copiedItem     string
	copiedKey      string
	copiedAt       time.Time
	copiedUntil    time.Time
	toast          *onevraToast
	pending        *onevraPending
	quickQuery     string
	quickCursor    int
	editor         onevraEditorState
	iconBitmaps    map[string]*ui.Bitmap
	iconPickerOpen bool
	iconPickerTint string
}

func newOnevraUI() onevraUI {
	return onevraUI{
		sidebarWidth: onevraSidebarDefaultWidth,
		listWidth:    onevraListDefaultWidth,
		rowCursor:    -1,
		list:         &components.ListState{},
	}
}

// resetOnevra drops row selection and every transient interaction without
// discarding the user's non-secret column widths.
func (u *onevraUI) resetOnevra() {
	u.rowCursor = -1
	u.list = &components.ListState{}
	u.moveDialogOpen = false
	u.moveCopyMode = false
	u.moveTargetVaultID = ""
	u.copyIntent, u.copiedItem, u.copiedKey = "", "", ""
	u.copiedAt, u.copiedUntil = time.Time{}, time.Time{}
	u.toast = nil
	u.pending = nil
	u.quickQuery = ""
	u.quickCursor = 0
	u.editor = onevraEditorState{}
	for _, bmp := range u.iconBitmaps {
		if bmp != nil {
			bmp.ReleasePixels()
		}
	}
	u.iconBitmaps = nil
	u.iconPickerOpen = false
	u.iconPickerTint = ""
}
