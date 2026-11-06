//go:build linux

package main

import (
	"bytes"
	"encoding/json"
	"fmt"
	"os"
	"os/exec"
	"strings"
	"testing"

	"golang.org/x/sys/unix"
)

type promptEchoCheck struct {
	f             *os.File
	observed      bool
	safe          bool
	closeOnReturn bool
}

func (w *promptEchoCheck) Write(p []byte) (int, error) {
	if w.closeOnReturn && bytes.Equal(p, []byte("\r\n")) {
		_ = w.f.Close()
		return 0, errCommand
	}
	if bytes.Contains(p, []byte("Sequencer signing seed")) {
		mode, e := unix.IoctlGetTermios(int(w.f.Fd()), unix.TCGETS)
		w.observed = true
		w.safe = e == nil && mode.Lflag&unix.ECHO == 0 && mode.Lflag&unix.ICANON == 0
		if !w.safe {
			return 0, errCommand
		}
	}
	return w.f.Write(p)
}

// This runs only in the test executable under an actual controlling PTY. The
// prompt writer checks ECHO synchronously before forwarding any visible byte,
// making prompt-before-hide a deterministic failure rather than a paste race.
func TestSequencerTTYChild(t *testing.T) {
	if os.Getenv("LOCKLARK_TEST_SEQUENCER_TTY_CHILD") != "1" {
		t.Skip("subprocess-only terminal probe")
	}
	f, e := os.OpenFile("/dev/tty", os.O_RDWR, 0)
	if e != nil {
		t.Fatal("missing controlling terminal")
	}
	defer f.Close()
	before, e := unix.IoctlGetTermios(int(f.Fd()), unix.TCGETS)
	if e != nil {
		t.Fatal("terminal mode unavailable")
	}
	w := &promptEchoCheck{f: f, closeOnReturn: os.Getenv("LOCKLARK_TEST_CLOSE_TERMINAL_ON_RETURN") == "1"}
	key, e := readSequencerTerminal(f, w)
	valid := e == nil && len(key) == 64
	clear(key)
	inspect := f
	if w.closeOnReturn {
		inspect, e = os.OpenFile("/dev/tty", os.O_RDWR, 0)
		if e != nil {
			t.Fatal("fallback terminal unavailable")
		}
		defer inspect.Close()
	}
	after, modeErr := unix.IoctlGetTermios(int(inspect.Fd()), unix.TCGETS)
	restored := modeErr == nil && *before == *after
	fmt.Fprintf(inspect, "\r\nTTY_RESULT valid=%t echo=%t restored=%t\r\n", valid, w.observed && w.safe, restored)
	if !w.observed || !w.safe || !restored {
		t.Fatal("terminal disclosure ordering/restoration failed")
	}
}

func TestSequencerTTYHidesBeforePromptAndRestoresEveryPath(t *testing.T) {
	python, e := exec.LookPath("python3")
	if e != nil {
		t.Skip("python3 required for real controlling-PTY test")
	}
	executable, e := os.Executable()
	if e != nil {
		t.Fatal(e)
	}
	script := `
import fcntl,json,os,pty,select,signal,subprocess,sys,termios,time
cfg=json.load(sys.stdin)
master,slave=pty.openpty()
before=termios.tcgetattr(slave)
def setup():
 os.setsid();fcntl.ioctl(0,termios.TIOCSCTTY,0)
env=dict(os.environ);env['LOCKLARK_TEST_SEQUENCER_TTY_CHILD']='1'
if cfg.get('restore_failure'):env['LOCKLARK_TEST_CLOSE_TERMINAL_ON_RETURN']='1'
p=subprocess.Popen([sys.argv[1],'-test.run=^TestSequencerTTYChild$','-test.count=1'],stdin=slave,stdout=slave,stderr=slave,env=env,preexec_fn=setup,close_fds=True)
data=b'';sent=False;echo=False;deadline=time.monotonic()+8
while time.monotonic()<deadline:
 ready,_,_=select.select([master],[],[],0.05)
 if ready:
  try: block=os.read(master,65536)
  except OSError: break
  data+=block
  if not sent and b'hidden): ' in data:
   echo=not bool(termios.tcgetattr(slave)[3]&termios.ECHO)
   if cfg.get('signal'):p.send_signal(getattr(signal,cfg['signal']))
   else:os.write(master,bytes.fromhex(cfg['input']))
   sent=True
 if p.poll() is not None:
  while select.select([master],[],[],0)[0]:
   try: data+=os.read(master,65536)
   except OSError: break
  break
if p.poll() is None:p.kill();p.wait()
restored=termios.tcgetattr(slave)==before
marker=('TTY_RESULT valid='+str(cfg['valid']).lower()+' echo=true restored=true').encode()
private=all(value.encode() not in data for value in cfg['canaries'])
print(json.dumps({'ok':p.returncode==0 and sent and echo and restored and marker in data and private}))
os.close(master);os.close(slave)
`
	seed := strings.Repeat("ab", 32)
	for _, tc := range []struct {
		name, input, signal   string
		valid, restoreFailure bool
	}{
		{name: "valid", input: seed + "\r", valid: true},
		{name: "cancel", input: seed[:32] + "\x03"},
		{name: "escape", input: seed[:32] + "\x1b"},
		{name: "short", input: seed[:32] + "\r"},
		{name: "too-long", input: seed + "a\r"},
		{name: "invalid", input: seed[:32] + "z\r"},
		{name: "backspace", input: seed + "\x7fb\r", valid: true},
		{name: "sigterm", signal: "SIGTERM"},
		{name: "sighup", signal: "SIGHUP"},
		{name: "restore-failure", input: seed + "\r", restoreFailure: true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			payload, _ := json.Marshal(map[string]any{"input": fmt.Sprintf("%x", []byte(tc.input)), "valid": tc.valid, "signal": tc.signal, "restore_failure": tc.restoreFailure, "canaries": []string{seed, seed[:32]}})
			cmd := exec.Command(python, "-c", script, executable)
			cmd.Stdin = bytes.NewReader(payload)
			raw, e := cmd.CombinedOutput()
			if e != nil {
				t.Fatal("controlling-PTY probe failed")
			}
			var result struct {
				OK bool `json:"ok"`
			}
			if json.Unmarshal(raw, &result) != nil || !result.OK {
				t.Fatal("secret terminal ordering, privacy or restoration contract failed")
			}
		})
	}
}
