package browserhost

import (
	"runtime"
	"strings"
	"testing"
	"time"
)

func TestFillQueuedForWriterRefusesAfterLock(t *testing.T) {
	c, s, out, r := paired(t)
	r = matchAndFill(t, c, out, r)
	// Reserve the serializer slot, as another in-flight response would.
	release, e := c.writer.acquire(time.Now().Add(time.Second), nil)
	if e != nil {
		t.Fatal(e)
	}
	done := make(chan error, 1)
	go func() { done <- c.ApproveFill(r.ID) }()
	deadline := time.Now().Add(time.Second)
	waiting := false
	for time.Now().Before(deadline) {
		stack := make([]byte, 1<<18)
		n := runtime.Stack(stack, true)
		for _, g := range strings.Split(string(stack[:n]), "\n\n") {
			if strings.Contains(g, "(*Connection).ApproveFill") && strings.Contains(g, "(*Writer).acquire") {
				waiting = true
			}
		}
		if waiting {
			break
		}
		time.Sleep(time.Millisecond)
	}
	if !waiting {
		release()
		t.Fatal("approval did not reach writer acquisition")
	}
	c.Invalidate()
	if s.Unlocked() {
		release()
		t.Fatal("session still unlocked")
	}
	before := len(out.responses(t))
	release()
	err := <-done
	for _, response := range out.responses(t)[before:] {
		if response.Type == "fill" {
			t.Fatalf("fill containing credentials emitted after native lock while no fill bytes had previously been written; approval error=%v", err)
		}
	}
}
