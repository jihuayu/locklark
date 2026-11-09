package desktop

import "github.com/oneo-me/onevra/source/components"

const (
	onevraSidebarDefaultWidth float32 = 220
	onevraListDefaultWidth    float32 = 340
)

// onevraUI owns presentation-only state for the native Onevra shell. Business
// state stays in v2State and the existing session-facing methods.
type onevraUI struct {
	sidebarWidth float32
	listWidth    float32
	rowCursor    int
	list         *components.ListState
}

func newOnevraUI() onevraUI {
	return onevraUI{
		sidebarWidth: onevraSidebarDefaultWidth,
		listWidth:    onevraListDefaultWidth,
		rowCursor:    -1,
		list:         &components.ListState{},
	}
}

// resetOnevra drops row selection without discarding the user's non-secret
// column widths.
func (u *onevraUI) resetOnevra() {
	u.rowCursor = -1
	u.list = &components.ListState{}
}
