package browserhost

import (
	"bytes"
	"context"
	"errors"
	"os"
	"os/exec"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/jihuayu/locklark/internal/personal"
)

type markedStdout struct{ once sync.Once }

func (p *markedStdout) Write(value []byte) (int, error) {
	p.once.Do(func() { _, _ = os.Stderr.Write([]byte("stdout-write-entered\n")) })
	return os.Stdout.Write(value)
}
func (*markedStdout) Close() error { return os.Stdout.Close() }

type stubbornTransport struct {
	writeEntered, closeEntered chan struct{}
	writeRelease, closeRelease chan struct{}
	writeOnce, closeOnce       sync.Once
	failWrite                  bool
}

func (p *stubbornTransport) Write([]byte) (int, error) {
	p.writeOnce.Do(func() { close(p.writeEntered) })
	if !p.failWrite {
		<-p.writeRelease
	}
	return 0, errors.New("fixed transport failure")
}
func (p *stubbornTransport) Close() error {
	p.closeOnce.Do(func() { close(p.closeEntered) })
	<-p.closeRelease
	return nil
}
func TestNativeWriterWatchdogDoesNotWaitForWriteOrClose(t *testing.T) {
	for _, closeBlocked := range []bool{false, true} {
		p := &stubbornTransport{make(chan struct{}), make(chan struct{}), make(chan struct{}), make(chan struct{}), sync.Once{}, sync.Once{}, closeBlocked}
		fired, done := make(chan struct{}), make(chan struct{})
		w := NewNativeWriter(p, 20*time.Millisecond, func() { close(fired) })
		go func() { _ = w.Write(Response{V: 1, Type: "error", Error: "refused"}); close(done) }()
		if closeBlocked {
			select {
			case <-p.closeEntered:
			case <-time.After(time.Second):
				t.Fatal("close failure path not reached")
			}
		}
		select {
		case <-fired:
		case <-time.After(time.Second):
			t.Fatal("watchdog waited for blocked transport")
		}
		if !w.failed.Load() {
			t.Fatal("watchdog did not mark terminal before fatal")
		}
		close(p.writeRelease)
		close(p.closeRelease)
		select {
		case <-done:
		case <-time.After(time.Second):
			t.Fatal("test transport did not release")
		}
		if w.Write(Response{Type: "error"}) == nil {
			t.Fatal("terminal writer was reused")
		}
	}
}
func TestOTPWaitingForWriterSlotIsCancellableWithoutGrant(t *testing.T) {
	w := NewWriter(&memoryPipe{}, time.Second)
	release, err := w.acquire(time.Now().Add(time.Second), nil)
	if err != nil {
		t.Fatal(err)
	}
	control := personal.NewBrowserOTPControl(time.Now().Add(time.Second))
	done := make(chan error, 1)
	go func() {
		done <- w.WriteOTP(reqID(40), control, func() (*personal.BrowserOTPOutput, error) {
			t.Error("grant ran before slot acquisition")
			return nil, ErrProtocol
		})
	}()
	control.Cancel()
	select {
	case err := <-done:
		if err == nil {
			t.Fatal("cancelled slot succeeded")
		}
	case <-time.After(time.Second):
		release()
		t.Fatal("slot acquisition ignored cancellation")
	}
	release()
}

func TestNativeWriterBlockingStdoutExit(t *testing.T) {
	if os.Getenv("LOCKLARK_TEST_BLOCKING_STDOUT") == "1" {
		if forceBlockingStdout() != nil {
			os.Exit(75)
		}
		w := NewNativeWriter(&markedStdout{}, 40*time.Millisecond, func() { os.Exit(74) })
		rows := make([]personal.Row, 100)
		for i := range rows {
			rows[i] = personal.Row{ID: reqID(i + 1), Revision: strings.Repeat("a", 64), Title: strings.Repeat("s", 1024), State: "active"}
		}
		for {
			if w.Write(Response{V: 1, ID: reqID(1), Type: "candidates", Candidates: rows}) != nil {
				os.Exit(76)
			}
		}
	}
	reader, writer, err := os.Pipe()
	if err != nil {
		t.Fatal(err)
	}
	defer reader.Close() // kept open and deliberately never read
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	command := exec.CommandContext(ctx, os.Args[0], "-test.run=^TestNativeWriterBlockingStdoutExit$", "-test.count=1")
	command.Env = append(os.Environ(), "LOCKLARK_TEST_BLOCKING_STDOUT=1")
	command.Stdout = writer
	var diagnostic bytes.Buffer
	command.Stderr = &diagnostic // fixed marker only; stdout is never read
	if err = command.Start(); err != nil {
		writer.Close()
		t.Fatal("child start failed")
	}
	writer.Close()
	err = command.Wait()
	var exit *exec.ExitError
	if ctx.Err() != nil || !errors.As(err, &exit) || exit.ExitCode() != 74 || !bytes.Contains(diagnostic.Bytes(), []byte("stdout-write-entered\n")) {
		t.Fatal("child did not exit through its own fatal watchdog")
	}
}
