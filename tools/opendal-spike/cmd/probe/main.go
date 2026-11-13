//go:build linux

// Command probe exercises failure and cancellation boundaries of the official
// OpenDAL Go binding (v0.1.16) against synthetic in-memory data only. Every
// case is meant to run in its own process, because some cases intentionally
// provoke panics, crashes, or hangs.
package main

import (
	"errors"
	"flag"
	"fmt"
	"os"
	"path/filepath"
	"sync"
	"time"

	"github.com/apache/opendal-go-services/memory"
	opendal "github.com/apache/opendal/bindings/go"
)

func logf(format string, args ...any) {
	fmt.Printf("[probe] "+format+"\n", args...)
}

func isPrintable(s string) bool {
	for _, r := range s {
		if r < 0x20 || r > 0x7e {
			return false
		}
	}
	return true
}

func codeOf(err error) string {
	if err == nil {
		return "<nil>"
	}
	var oerr *opendal.Error
	if errors.As(err, &oerr) {
		return fmt.Sprintf("Code(%d)", oerr.Code())
	}
	return "non-opendal-error"
}

func newMem(opts opendal.OperatorOptions, layers ...opendal.OperatorOption) *opendal.Operator {
	if err := memory.Scheme.LoadOnce(); err != nil {
		logf("native load FAILED: %v", err)
		os.Exit(1)
	}
	op, err := opendal.NewOperator(memory.Scheme, opts, layers...)
	if err != nil {
		logf("NewOperator FAILED: %v", err)
		os.Exit(1)
	}
	return op
}

type staticScheme struct {
	name string
	path string
}

func (s staticScheme) Name() string    { return s.name }
func (s staticScheme) Path() string    { return s.path }
func (s staticScheme) LoadOnce() error { return nil }

func main() {
	c := flag.String("case", "", "case to run")
	flag.Parse()

	switch *c {
	case "load-missing":
		_, err := opendal.NewOperator(staticScheme{"memory", "/tmp/definitely-missing-opendal/libopendal_c.so"}, nil)
		logf("load missing path err=%v code=%s", err, codeOf(err))
	case "load-corrupt":
		p := filepath.Join(os.TempDir(), "corrupt-libopendal.so")
		if err := os.WriteFile(p, []byte("this is not an ELF shared object"), 0o755); err != nil {
			logf("setup error: %v", err)
			os.Exit(1)
		}
		_, err := opendal.NewOperator(staticScheme{"memory", p}, nil)
		logf("load corrupt file err=%v code=%s", err, codeOf(err))
	case "load-tmpdir":
		err := memory.Scheme.LoadOnce()
		logf("load with unwritable TMPDIR err=%v", err)
	case "capabilities":
		op := newMem(nil)
		defer op.Close()
		full, native := op.Info().GetFullCapability(), op.Info().GetNativeCapability()
		logf("full: stat=%t read=%t write=%t list=%t delete=%t copy=%t rename=%t presign=%t create_dir=%t list_recursive=%t",
			full.Stat(), full.Read(), full.Write(), full.List(), full.Delete(), full.Copy(), full.Rename(), full.Presign(), full.CreateDir(), full.ListWithRecursive())
		logf("native: stat=%t read=%t write=%t list=%t delete=%t copy=%t rename=%t presign=%t create_dir=%t list_recursive=%t",
			native.Stat(), native.Read(), native.Write(), native.List(), native.Delete(), native.Copy(), native.Rename(), native.Presign(), native.CreateDir(), native.ListWithRecursive())
		if err := op.Write("a.txt", []byte("a")); err != nil {
			logf("write err=%v", err)
		}
		errCopy := op.Rename("a.txt", "b.txt")
		logf("rename claimed=%t actual err=%v code=%s", full.Rename(), errCopy, codeOf(errCopy))
		_, errPresign := op.PresignRead("a.txt", time.Minute)
		logf("presign claimed=%t actual err=%v code=%s", full.Presign(), errPresign, codeOf(errPresign))
		if full.Copy() {
			errCopy = op.Copy("a.txt", "c.txt")
			logf("copy claimed=true actual err=%v code=%s", errCopy, codeOf(errCopy))
		}
	case "error-matrix":
		op := newMem(nil)
		defer op.Close()
		if err := op.Write("f.txt", []byte("data")); err != nil {
			logf("write f.txt err=%v", err)
		}
		if err := op.Write("dir/x.txt", []byte("x")); err != nil {
			logf("write dir/x.txt err=%v", err)
		}
		_, err := op.Read("missing.txt")
		logf("read missing: err=%v code=%s", err, codeOf(err))
		_, err = op.Stat("missing.txt")
		logf("stat missing: err=%v code=%s", err, codeOf(err))
		_, err = op.Read("dir/")
		logf("read directory: err=%v code=%s", err, codeOf(err))
		// v0.1.16 has no ranged Read option (Reader has Seek instead), so the
		// range-error boundary is not reachable through this API.
		err = op.Delete("missing.txt")
		logf("delete missing (documented idempotent): err=%v code=%s", err, codeOf(err))
		err = op.Rename("missing.txt", "x.txt")
		logf("rename missing: err=%v code=%s", err, codeOf(err))
		lister, err := op.List("missing-dir/")
		if err != nil {
			logf("list missing dir: err=%v code=%s", err, codeOf(err))
		} else {
			n := 0
			for lister.Next() {
				n++
			}
			logf("list missing dir: entries=%d iterErr=%v code=%s", n, lister.Error(), codeOf(lister.Error()))
			lister.Close()
		}
	case "timeout-io":
		op := newMem(nil, opendal.WithTimeout(time.Second, time.Nanosecond))
		defer op.Close()
		start := time.Now()
		err := op.Write("t.txt", []byte("timeout probe"))
		logf("write with 1ns IO timeout: err=%v code=%s elapsed=%s", err, codeOf(err), time.Since(start))
		start = time.Now()
		data, err := op.Read("t.txt")
		logf("read with 1ns IO timeout: err=%v code=%s data_len=%d elapsed=%s", err, codeOf(err), len(data), time.Since(start))
		big := make([]byte, 8<<20)
		start = time.Now()
		err = op.Write("big.bin", big)
		logf("write 8MiB with 1ns IO timeout: err=%v code=%s elapsed=%s", err, codeOf(err), time.Since(start))
		start = time.Now()
		data, err = op.Read("big.bin")
		logf("read 8MiB with 1ns IO timeout: err=%v code=%s data_len=%d elapsed=%s", err, codeOf(err), len(data), time.Since(start))
		start = time.Now()
		_, err = op.Stat("t.txt")
		logf("stat with 1s non-IO timeout: err=%v code=%s elapsed=%s", err, codeOf(err), time.Since(start))
	case "timeout-invalid":
		_, err := opendal.NewOperator(memory.Scheme, nil, opendal.WithTimeout(0, 0))
		logf("WithTimeout(0,0) err=%v", err)
	case "info-name":
		op := newMem(nil)
		defer op.Close()
		seen := map[string]int{}
		for i := 0; i < 50; i++ {
			seen[op.Info().GetName()]++
		}
		for name, n := range seen {
			full := name
			if len(name) > 40 {
				name = name[:40] + "..."
			}
			logf("GetName value len=%d count=%d printable=%t prefix=%q", len(full), n, isPrintable(full), name[:min(8, len(name))])
		}
	case "close-then-use":
		op := newMem(nil)
		if err := op.Write("x.txt", []byte("x")); err != nil {
			logf("write err=%v", err)
		}
		op.Close()
		logf("operator closed; now reading through closed operator")
		_, err := op.Read("x.txt")
		logf("read after Close returned err=%v", err)
	case "close-during-list":
		op := newMem(nil)
		for i := 0; i < 2000; i++ {
			if err := op.Write(fmt.Sprintf("bulk/%04d.txt", i), []byte("x")); err != nil {
				logf("seed write %d err=%v", i, err)
				break
			}
		}
		var wg sync.WaitGroup
		wg.Add(1)
		go func() {
			defer wg.Done()
			defer func() {
				if r := recover(); r != nil {
					logf("list goroutine panic: %v", r)
				}
			}()
			for round := 0; round < 200; round++ {
				lister, err := op.List("bulk/")
				if err != nil {
					logf("list err=%v", err)
					return
				}
				for lister.Next() {
				}
				if err := lister.Error(); err != nil {
					logf("lister err=%v", err)
				}
				lister.Close()
			}
			logf("list goroutine finished cleanly")
		}()
		time.Sleep(10 * time.Millisecond)
		op.Close()
		logf("operator closed while listing")
		wg.Wait()
		logf("survived close-during-list")
	case "slow-uncancellable":
		op := newMem(nil)
		defer op.Close()
		for i := 0; ; i++ {
			key := fmt.Sprintf("slow/%06d.bin", i)
			if err := op.Write(key, make([]byte, 1<<20)); err != nil {
				logf("write %d err=%v code=%s", i, err, codeOf(err))
				return
			}
			if i%50 == 0 {
				logf("still writing, i=%d (no per-call context to cancel)", i)
			}
		}
	default:
		logf("unknown case %q", *c)
		os.Exit(2)
	}
}
