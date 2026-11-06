package desktop

import "github.com/jihuayu/locklark/internal/personal"

// SSH keys have their own management surface and must not acquire legacy
// login field disclosure/edit controls through a generic metadata list.
func loginProjection(rows []personal.Row) []personal.Row {
	filtered := make([]personal.Row, 0, len(rows))
	for _, row := range rows {
		if row.Kind != "ssh-key" {
			filtered = append(filtered, row)
		}
	}
	return filtered
}
