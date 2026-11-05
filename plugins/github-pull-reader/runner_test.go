package pullreader

import (
	"io"
	"strings"
	"testing"
)

func TestProcessCopyCannotBypassOutputLimit(t *testing.T) {
	// os/exec copies child stdout via io.Copy, whose ReaderFrom optimization
	// must not bypass the frame cap.
	var out output
	_, err := io.Copy(&out, struct{ io.Reader }{strings.NewReader(strings.Repeat("a", 8192))})
	if err == nil || out.Len() > 4096 {
		t.Fatal("child output bypassed 4096 byte cap")
	}
}
