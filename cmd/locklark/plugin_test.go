package main

import (
	"bytes"
	"encoding/json"
	"errors"
	"path/filepath"
	"testing"

	"github.com/jihuayu/locklark/internal/pluginstore"
)

type pluginBrokenWriter struct{}

func (pluginBrokenWriter) Write([]byte) (int, error) {
	return 0, errors.New("untrusted output failure")
}
func TestPluginCLIOutputFailureAndDisabledExecution(t *testing.T) {
	path := filepath.Join(t.TempDir(), "catalog.db")
	if e := runPlugin([]string{"init", "--file", path}, pluginBrokenWriter{}); e != pluginOutputFailure {
		t.Fatal("output error", e)
	}
	if _, e := pluginstore.Create(path); e != pluginstore.ErrExists {
		t.Fatal("lost receipt overwrote initialized file", e)
	}
	for _, args := range [][]string{{"run", "--file", path}, {"install", "--file", path}, {"init", "--file", path, "--file", path}, {"init", "--file", path, "--backend", "bun"}} {
		if e := runPlugin(args, &bytes.Buffer{}); e != pluginUsage {
			t.Fatal("unsupported plugin command", e)
		}
	}
	var out bytes.Buffer
	if e := run([]string{"plugin", "init", "--file", filepath.Join(t.TempDir(), "new.db")}, &out, &bytes.Buffer{}); e != nil {
		t.Fatal(e)
	}
	var status pluginstore.Status
	if json.Unmarshal(out.Bytes(), &status) != nil || status.Execution != "disabled" || status.Sequence != 1 {
		t.Fatal("CLI route")
	}
}
