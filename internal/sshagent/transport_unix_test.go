//go:build linux || darwin

package sshagent

import (
	"errors"
	"github.com/jihuayu/locklark/internal/localpath"
	"net"
	"os"
	"path/filepath"
	"testing"

	clientagent "golang.org/x/crypto/ssh/agent"
)

func shortSocketDirectory(t *testing.T) string {
	t.Helper()
	parent, e := localpath.TrustedTemporaryParent("/tmp")
	if e != nil {
		t.Fatal("trusted test temp unavailable")
	}
	dir, e := os.MkdirTemp(parent, "llssh-")
	if e != nil {
		t.Fatal("short socket fixture unavailable")
	}
	t.Cleanup(func() { _ = os.RemoveAll(dir) })
	return dir
}
func nativeTestEndpoint(t *testing.T) string {
	return filepath.Join(shortSocketDirectory(t), "agent.sock")
}

func TestPrivateSocketPeerAndEndpointOwnership(t *testing.T) {
	path := nativeTestEndpoint(t)
	h := newTestHandler(t)
	s, e := Start(path, h)
	if e != nil {
		t.Fatal("private agent start failed")
	}
	defer s.Close()
	info, e := os.Lstat(path)
	if e != nil || info.Mode().Perm() != 0600 {
		t.Fatal("socket permissions not private")
	}
	c, e := net.Dial("unix", path)
	if e != nil {
		t.Fatal("connect private agent failed")
	}
	defer c.Close()
	keys, e := clientagent.NewClient(c).List()
	if e != nil || len(keys) != 1 {
		t.Fatal("authenticated identities failed")
	}
	if _, e = Start(path, h); e == nil {
		t.Fatal("existing endpoint was taken over")
	}
	if e = s.Close(); e != nil {
		t.Fatal("agent close failed")
	}
	if _, e = os.Lstat(path); !os.IsNotExist(e) {
		t.Fatal("owned endpoint was not removed")
	}
}

func TestUnixCleanupFailureIsPersistent(t *testing.T) {
	for _, stage := range []string{"stat", "unlink"} {
		t.Run(stage, func(t *testing.T) {
			path := nativeTestEndpoint(t)
			s, e := Start(path, newTestHandler(t))
			if e != nil {
				t.Fatal("agent start failed")
			}
			l := s.listener.(*unixListener)
			if stage == "stat" {
				l.lstat = func(string) (os.FileInfo, error) { return nil, os.ErrPermission }
			} else {
				l.remove = func(string) error { return os.ErrPermission }
			}
			if e := s.Close(); e != ErrUnavailable {
				t.Error("failed socket cleanup was incorrectly confirmed")
			}
			if e := l.Close(); e != ErrUnavailable {
				t.Error("repeated listener close lost its fixed cleanup failure")
			}
			if _, e := os.Lstat(path); e != nil {
				t.Error("failure fixture unexpectedly removed endpoint")
			}
		})
	}
}

func TestUnixMissingEndpointCleanupIsConfirmed(t *testing.T) {
	path := nativeTestEndpoint(t)
	s, e := Start(path, newTestHandler(t))
	if e != nil {
		t.Fatal("agent start failed")
	}
	if os.Remove(path) != nil {
		t.Fatal("socket fixture removal failed")
	}
	if s.Close() != nil || s.listener.Close() != nil {
		t.Fatal("confirmed missing endpoint close was not idempotent")
	}
}

func TestUnixEndpointReportsCanonicalListenerAddress(t *testing.T) {
	root := shortSocketDirectory(t)
	realParent := filepath.Join(root, "real")
	alias := filepath.Join(root, "alias")
	if os.Mkdir(realParent, 0700) != nil || os.Symlink(realParent, alias) != nil {
		t.Fatal("canonical endpoint fixture failed")
	}
	s, e := Start(filepath.Join(alias, "private", "agent.sock"), newTestHandler(t))
	if e != nil {
		t.Fatal("agent start through canonical alias failed")
	}
	defer s.Close()
	expected := filepath.Join(realParent, "private", "agent.sock")
	if s.Endpoint() != expected || s.Endpoint() != s.listener.Addr().String() {
		t.Fatal("reported endpoint retained a replaceable alias")
	}
}
func TestEndpointReplacementIsNeverRemoved(t *testing.T) {
	path := nativeTestEndpoint(t)
	s, e := Start(path, newTestHandler(t))
	if e != nil {
		t.Fatal("agent start failed")
	}
	if e = os.Rename(path, path+".old"); e != nil {
		t.Fatal("rename own socket fixture failed")
	}
	replacement, e := net.ListenUnix("unix", &net.UnixAddr{Name: path, Net: "unix"})
	if e != nil {
		t.Fatal("replacement fixture failed")
	}
	replacement.SetUnlinkOnClose(false)
	defer replacement.Close()
	if e = s.Close(); !errors.Is(e, ErrUnavailable) {
		t.Fatal("replacement cleanup was incorrectly confirmed")
	}
	if _, e = os.Lstat(path); e != nil {
		t.Fatal("unowned replacement endpoint was removed")
	}
}
func TestUnsafeSocketDirectoryAndExistingFileAreRejected(t *testing.T) {
	dir := shortSocketDirectory(t)
	if os.Chmod(dir, 0755) != nil {
		t.Fatal("directory fixture failed")
	}
	if _, e := Start(filepath.Join(dir, "agent.sock"), newTestHandler(t)); e == nil {
		t.Fatal("public directory accepted")
	}
	if os.Chmod(dir, 0700) != nil {
		t.Fatal("directory fixture failed")
	}
	path := filepath.Join(dir, "agent.sock")
	if os.WriteFile(path, []byte("owned fixture"), 0600) != nil {
		t.Fatal("existing file fixture failed")
	}
	if _, e := Start(path, newTestHandler(t)); e == nil {
		t.Fatal("existing file was replaced")
	}
}

func TestPrivateLeafDoesNotAuthorizeUntrustedAncestor(t *testing.T) {
	root := shortSocketDirectory(t)
	unsafe := filepath.Join(root, "unsafe")
	leaf := filepath.Join(unsafe, "private")
	if os.Mkdir(unsafe, 0777) != nil || os.Chmod(unsafe, 0777) != nil || os.Mkdir(leaf, 0700) != nil {
		t.Fatal("unsafe ancestor fixture failed")
	}
	s, e := Start(filepath.Join(leaf, "agent.sock"), newTestHandler(t))
	if e == nil {
		_ = s.Close()
		t.Fatal("0700 leaf masked a replaceable socket ancestor")
	}
}
