//go:build linux

package main

import (
	"context"
	"fmt"
	"io"
	"os"
	"os/exec"
	"strings"
	"syscall"
	"testing"
	"time"

	"golang.org/x/sys/unix"
)

const readerCTTYChildEnv = "LOCKLARK_READER_CTTY_CHILD"

func TestReadRegularLinuxCharDeviceNoCTTY(t *testing.T) {
	master, err := os.OpenFile("/dev/ptmx", os.O_RDWR|unix.O_NOCTTY, 0)
	if err != nil {
		t.Fatal("PTY allocation failed")
	}
	defer master.Close()
	if err := unix.IoctlSetPointerInt(int(master.Fd()), unix.TIOCSPTLCK, 0); err != nil {
		t.Fatal("PTY unlock failed")
	}
	n, err := unix.IoctlGetInt(int(master.Fd()), unix.TIOCGPTN)
	if err != nil {
		t.Fatal("PTY number failed")
	}
	slavePath := fmt.Sprintf("/dev/pts/%d", n)

	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	cmd := exec.CommandContext(ctx, os.Args[0], "-test.run=^TestReadRegularLinuxCharDeviceNoCTTYChild$", "-test.count=1")
	cmd.Env = append(os.Environ(), readerCTTYChildEnv+"=1", "LOCKLARK_READER_CTTY_PATH="+slavePath)
	cmd.Stdin = strings.NewReader("")
	cmd.Stdout = io.Discard
	cmd.Stderr = io.Discard
	cmd.SysProcAttr = &syscall.SysProcAttr{Setsid: true}
	if err := cmd.Start(); err != nil {
		t.Fatal("PTY child start failed")
	}
	if err := cmd.Wait(); err != nil {
		t.Fatal("PTY child failed")
	}
}

func TestReadRegularLinuxCharDeviceNoCTTYChild(t *testing.T) {
	if os.Getenv(readerCTTYChildEnv) != "1" {
		return
	}
	path := os.Getenv("LOCKLARK_READER_CTTY_PATH")
	if path == "" || noCTTY() == false {
		t.Fatal("child did not start without a controlling terminal")
	}
	if _, err := readRegular(path, 64); err == nil {
		t.Fatal("character device input was accepted")
	}
	if !noCTTY() {
		t.Fatal("character device read acquired a controlling terminal")
	}
}

func noCTTY() bool {
	f, err := os.Open("/dev/tty")
	if err != nil {
		return true
	}
	_ = f.Close()
	return false
}
