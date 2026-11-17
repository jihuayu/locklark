//go:build linux

// Command memory is a minimal real round-trip against the official OpenDAL Go
// binding with the official memory service companion module. It only keeps
// synthetic in-memory data; it never reads cloud credentials or performs any
// network I/O.
package main

import (
	"errors"
	"flag"
	"fmt"
	"os"
	"runtime"
	"sort"
	"strings"
	"time"

	"github.com/apache/opendal-go-services/memory"
	opendal "github.com/apache/opendal/bindings/go"
)

func logf(format string, args ...any) {
	fmt.Printf("[%s] "+format+"\n", append([]any{time.Now().UTC().Format("15:04:05.000")}, args...)...)
}

func main() {
	timeout := flag.Duration("timeout", 30*time.Second, "hard wall-clock budget for the whole run")
	flag.Parse()

	done := make(chan int, 1)
	go func() { done <- run() }()
	select {
	case code := <-done:
		os.Exit(code)
	case <-time.After(*timeout):
		logf("FAIL: hard timeout %s elapsed", *timeout)
		os.Exit(4)
	}
}

func run() int {
	failures := 0
	check := func(name string, ok bool, detail string) {
		status := "PASS"
		if !ok {
			status = "FAIL"
			failures++
		}
		logf("%s %s: %s", status, name, detail)
	}

	logf("go=%s os=%s arch=%s", runtime.Version(), runtime.GOOS, runtime.GOARCH)
	logf("binding=github.com/apache/opendal/bindings/go v0.1.16 companion=github.com/apache/opendal-go-services/memory v0.1.16")

	if err := memory.Scheme.LoadOnce(); err != nil {
		logf("FAIL native load: %v", err)
		return 1
	}
	logf("native lib path=%s", memory.Scheme.Path())

	op, err := opendal.NewOperator(memory.Scheme, opendal.OperatorOptions{})
	if err != nil {
		logf("FAIL NewOperator: %v", err)
		return 1
	}
	defer func() {
		op.Close()
		logf("PASS Close")
	}()

	info := op.Info()
	logf("info scheme=%s root=%q read=%t write=%t list=%t",
		info.GetScheme(), info.GetRoot(),
		info.GetFullCapability().Read(), info.GetFullCapability().Write(), info.GetFullCapability().List())

	// Write synthetic data.
	payloads := map[string]string{
		"spike/hello.txt":    "hello from opendal memory spike\n",
		"spike/nested/a.txt": "synthetic-alpha",
		"spike/nested/b.txt": "synthetic-beta",
	}
	keys := make([]string, 0, len(payloads))
	for k := range payloads {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	writeOK := true
	for _, k := range keys {
		if err := op.Write(k, []byte(payloads[k])); err != nil {
			writeOK = false
			logf("write %s: %v", k, err)
		}
	}
	check("Write", writeOK, fmt.Sprintf("%d synthetic objects", len(keys)))

	// Read back and compare.
	readOK := writeOK
	for _, k := range keys {
		data, err := op.Read(k)
		if err != nil {
			readOK = false
			logf("read %s: %v", k, err)
			continue
		}
		if string(data) != payloads[k] {
			readOK = false
			logf("read %s mismatch: got %q", k, data)
		}
	}
	check("Read", readOK, "byte-for-byte match")

	// Stat one object.
	if st, err := op.Stat("spike/hello.txt"); err != nil {
		check("Stat", false, err.Error())
	} else {
		check("Stat", st.IsFile() && st.ContentLength() == uint64(len(payloads["spike/hello.txt"])),
			fmt.Sprintf("len=%d", st.ContentLength()))
	}

	// List recursively and compare names.
	lister, err := op.List("spike/")
	if err != nil {
		check("List", false, err.Error())
	} else {
		got := []string{}
		for lister.Next() {
			got = append(got, lister.Entry().Path())
		}
		listerErr := lister.Error()
		if cerr := lister.Close(); cerr != nil {
			listerErr = errors.Join(listerErr, cerr)
		}
		sort.Strings(got)
		// Single-level listing of "spike/" returns the direct object and the
		// "nested/" prefix (no recursion in binding v0.1.16).
		want := []string{"spike/hello.txt", "spike/nested/"}
		check("List(non-recursive)", listerErr == nil && strings.Join(got, ",") == strings.Join(want, ","),
			fmt.Sprintf("got=%v err=%v", got, listerErr))
	}

	// Missing object yields a typed CodeNotFound error.
	_, err = op.Read("spike/does-not-exist")
	var oerr *opendal.Error
	check("Read-missing=CodeNotFound", errors.As(err, &oerr) && oerr.Code() == opendal.CodeNotFound, fmt.Sprintf("err=%v", err))

	if failures > 0 {
		logf("RESULT: FAIL (%d)", failures)
		return 1
	}
	logf("RESULT: PASS")
	return 0
}
