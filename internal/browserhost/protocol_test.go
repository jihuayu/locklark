package browserhost

import (
	"bytes"
	"encoding/binary"
	"errors"
	"io"
	"path/filepath"
	"runtime"
	"testing"
	"time"
)

func frame(s string) []byte {
	return append(binary.NativeEndian.AppendUint32(nil, uint32(len(s))), []byte(s)...)
}
func TestFramesStrictAndBounded(t *testing.T) {
	valid := `{"v":1,"id":"11111111111111111111111111111111","type":"hello"}`
	if _, e := ReadRequest(bytes.NewReader(frame(valid))); e != nil {
		t.Fatal(e)
	}
	for _, s := range []string{`{}`, valid + `{}`, `{"v":1,"v":1,"id":"11111111111111111111111111111111","type":"hello"}`, `{"v":1,"id":"11111111111111111111111111111111","type":"hello","x":{}}`, `{"v":1,"id":"11111111111111111111111111111111","type":"hello","capability":"x"}`} {
		if _, e := ReadRequest(bytes.NewReader(frame(s))); e == nil {
			t.Fatal("accepted malformed DTO")
		}
	}
	for _, raw := range [][]byte{{1}, binary.NativeEndian.AppendUint32(nil, MaxInput+1), frame(valid)[:10]} {
		if _, e := ReadRequest(bytes.NewReader(raw)); e == nil {
			t.Fatal("accepted bad frame")
		}
	}
}
func TestStartupIdentity(t *testing.T) {
	if ValidateLaunch(Chromium, []string{"chrome-extension://" + ChromiumID + "/"}) != nil {
		t.Fatal("Chrome")
	}
	for _, args := range [][]string{{}, {"chrome-extension://aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa/"}, {"chrome-extension://" + ChromiumID + "/", "--parent-window=garbage"}, {"chrome-extension://" + ChromiumID + "/", "extra"}} {
		if ValidateLaunch(Chromium, args) == nil {
			t.Fatal("untrusted launch")
		}
	}
	if ValidateLaunch(Firefox, []string{filepath.Join(t.TempDir(), HostName+".json"), FirefoxID}) != nil {
		t.Fatal("Firefox")
	}
	if runtime.GOOS == "windows" && ValidateLaunch(Firefox, []string{`C:org.locklark.browser.json`, FirefoxID}) == nil {
		t.Fatal("drive-relative Firefox manifest")
	}
}
func TestWriterTimeoutAndBrokenPipe(t *testing.T) {
	r, w := io.Pipe()
	defer r.Close()
	writer := NewWriter(w, 20*time.Millisecond)
	start := time.Now()
	if writer.Write(Response{V: 1, Type: "error", Error: "refused"}) == nil || time.Since(start) > time.Second {
		t.Fatal("write not bounded")
	}
	if writer.Write(Response{V: 1, Type: "error"}) == nil {
		t.Fatal("failed writer reused")
	}
	writer = NewWriter(failingWriter{}, time.Second)
	if writer.Write(Response{V: 1, Type: "error"}) == nil {
		t.Fatal("broken pipe")
	}
}

func TestEmptyLoginFieldsAndErrorsHaveFixedShape(t *testing.T) {
	var raw bytes.Buffer
	writer := NewWriter(bufferCloser{&raw}, time.Second)
	if writer.Write(Response{Type: "fill"}) != nil {
		t.Fatal("empty fill")
	}
	if !bytes.Contains(raw.Bytes(), []byte(`"username":""`)) || !bytes.Contains(raw.Bytes(), []byte(`"password":""`)) {
		t.Fatal("omitted fixed field")
	}
	raw.Reset()
	if writer.Write(Response{Type: "error", Error: "refused", Username: "must-not-serialize", Password: "must-not-serialize"}) != nil || bytes.Contains(raw.Bytes(), []byte("must-not-serialize")) {
		t.Fatal("error leaked field")
	}
}

type bufferCloser struct{ *bytes.Buffer }

func (bufferCloser) Close() error { return nil }

type failingWriter struct{}

func (failingWriter) Write([]byte) (int, error) { return 0, errors.New("pipe") }
func (failingWriter) Close() error              { return nil }
