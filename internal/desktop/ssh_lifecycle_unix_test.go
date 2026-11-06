//go:build linux || darwin

package desktop

import (
	"github.com/jihuayu/locklark/internal/localpath"
	"github.com/jihuayu/locklark/internal/sshagent"
	"os"
	"path/filepath"
	"testing"
	"time"
)

func TestNativeSSHCancelledStartupCleansEndpointWithoutUIDispatch(t *testing.T) {
	parent, e := localpath.TrustedTemporaryParent("/tmp")
	if e != nil {
		t.Fatal("trusted lifecycle fixture unavailable")
	}
	dir, e := os.MkdirTemp(parent, "llssh-exit-")
	if e != nil {
		t.Fatal("lifecycle fixture unavailable")
	}
	defer os.RemoveAll(dir)
	h := newSSHNativeHost(nil, nil, nil)
	h.trackServiceStart()
	h.close()
	path := filepath.Join(dir, "agent.sock")
	service, e := sshagent.Start(path, h)
	if e != nil {
		t.Fatal("late endpoint fixture failed")
	}
	h.finishServiceStart(service)
	select {
	case <-h.stopped:
	case <-time.After(time.Second):
		t.Fatal("cancelled startup relied on a dead UI dispatcher")
	}
	if _, e = os.Lstat(path); !os.IsNotExist(e) {
		t.Fatal("cancelled startup left an owned socket behind")
	}
}
