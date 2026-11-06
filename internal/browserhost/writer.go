package browserhost

import (
	"encoding/binary"
	"encoding/json"
	"io"
	"sync/atomic"
	"time"

	"github.com/jihuayu/locklark/internal/personal"
)

// A writer slot has bounded, cancellable acquisition. No state mutex is held
// during encoding or native I/O. Production native hosts use a fatal watchdog:
// Close alone cannot reliably interrupt inherited nonpollable stdout writes.
type Writer struct {
	out     io.WriteCloser
	timeout time.Duration
	failed  atomic.Bool
	slot    chan struct{}
	fatal   func()
}

func NewWriter(out io.WriteCloser, timeout time.Duration) *Writer {
	return newWriter(out, timeout, nil)
}
func NewNativeWriter(out io.WriteCloser, timeout time.Duration, fatal func()) *Writer {
	return newWriter(out, timeout, fatal)
}
func newWriter(out io.WriteCloser, timeout time.Duration, fatal func()) *Writer {
	w := &Writer{out: out, timeout: timeout, fatal: fatal, slot: make(chan struct{}, 1)}
	w.slot <- struct{}{}
	return w
}
func (w *Writer) acquire(until time.Time, cancel <-chan struct{}) (func(), error) {
	if w.failed.Load() || w.timeout <= 0 || w.timeout > time.Second || !time.Now().Before(until) {
		return nil, ErrProtocol
	}
	timer := time.NewTimer(time.Until(until))
	defer timer.Stop()
	select {
	case <-w.slot:
		if w.failed.Load() || !time.Now().Before(until) {
			w.slot <- struct{}{}
			return nil, ErrProtocol
		}
		select {
		case <-cancel:
			w.slot <- struct{}{}
			return nil, ErrProtocol
		default:
		}
		return func() { w.slot <- struct{}{} }, nil
	case <-cancel:
		return nil, ErrProtocol
	case <-timer.C:
		return nil, ErrProtocol
	}
}

type writeWatch struct {
	state  atomic.Uint32 // active, finished, timed out
	timers []*time.Timer
	w      *Writer
}

func (w *Writer) watch(until time.Time) *writeWatch {
	watch := &writeWatch{w: w}
	watch.shorten(until)
	return watch
}
func (x *writeWatch) shorten(until time.Time) {
	x.timers = append(x.timers, time.AfterFunc(time.Until(until), func() {
		if !x.state.CompareAndSwap(0, 2) {
			return
		}
		x.w.failed.Store(true)
		// No Writer/Session/Connection/control lock or Close precedes fatal.
		// Production injects os.Exit(74), which deliberately does not return.
		if x.w.fatal != nil {
			x.w.fatal()
			return
		}
		_ = x.w.out.Close()
	}))
}
func (x *writeWatch) finish() bool {
	finished := x.state.CompareAndSwap(0, 1)
	for _, timer := range x.timers {
		timer.Stop()
	}
	return finished
}
func (w *Writer) writeFrame(raw []byte) error {
	if len(raw) == 0 || len(raw) > MaxOutput || w.failed.Load() {
		return ErrProtocol
	}
	data := binary.NativeEndian.AppendUint32(make([]byte, 0, len(raw)+4), uint32(len(raw)))
	data = append(data, raw...)
	defer clear(data)
	for len(data) > 0 {
		n, err := w.out.Write(data)
		if err != nil || n <= 0 || n > len(data) {
			w.failed.Store(true)
			// The watchdog remains armed while Close itself may be blocked.
			_ = w.out.Close()
			return ErrProtocol
		}
		data = data[n:]
	}
	if w.failed.Load() {
		return ErrProtocol
	}
	return nil
}
func (w *Writer) Write(response Response) error {
	return w.WriteGranted(time.Now().Add(w.timeout), nil, func() (Response, error) { return response, nil })
}

// WriteGranted acquires the serializer before granting disclosure. The grant
// must revalidate its authority; no secret response is retained while queued.
func (w *Writer) WriteGranted(until time.Time, cancel <-chan struct{}, grant func() (Response, error)) error {
	until = minTime(until, time.Now().Add(w.timeout))
	release, err := w.acquire(until, cancel)
	if err != nil {
		return err
	}
	defer release()
	watch := w.watch(until)
	defer watch.finish()
	response, err := grant()
	if err != nil {
		return err
	}
	raw, err := json.Marshal(response)
	if err != nil || len(raw) > MaxOutput {
		clear(raw)
		return ErrProtocol
	}
	defer clear(raw)
	if err = w.writeFrame(raw); err != nil {
		return err
	}
	if !watch.finish() {
		return ErrProtocol
	}
	return nil
}

// WriteOTP owns a slot before calling grant. No code is copied or encoded while
// waiting. Every error after control.Granted is an unknown delivery outcome.
func (w *Writer) WriteOTP(id string, control *personal.BrowserOTPControl, grant func() (*personal.BrowserOTPOutput, error)) error {
	if !token.MatchString(id) || control == nil || grant == nil {
		return ErrProtocol
	}
	until := minTime(control.Deadline(), time.Now().Add(w.timeout))
	release, err := w.acquire(until, control.Done())
	if err != nil {
		return err
	}
	defer release()
	if !control.Pending() {
		return ErrProtocol
	}
	control.Shorten(until)
	watch := w.watch(until)
	defer watch.finish()
	output, err := grant()
	if err != nil || output == nil {
		return ErrProtocol
	}
	defer output.Clear()
	watch.shorten(output.Deadline())
	err = output.Consume(func(code []byte, bounds personal.OTPBounds) error {
		if !bounds.Check(time.Now()) || w.failed.Load() {
			return ErrProtocol
		}
		// The fixed validated hex ID and ASCII digits need no JSON escaping.
		// This is the only path allowed to serialize a code; no Go string copy.
		raw := make([]byte, 0, 128)
		raw = append(raw, `{"v":1,"id":"`...)
		raw = append(raw, id...)
		raw = append(raw, `","type":"otp-fill","code":"`...)
		raw = append(raw, code...)
		raw = append(raw, '"', '}')
		defer clear(raw)
		return w.writeFrame(raw)
	})
	if err != nil || !watch.finish() {
		return ErrProtocol
	}
	return nil
}
func (w *Writer) Close() error { w.failed.Store(true); return w.out.Close() }
