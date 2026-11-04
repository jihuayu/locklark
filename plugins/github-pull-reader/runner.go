package pullreader

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"time"
)

type output struct{ bytes.Buffer }

func (w *output) Write(p []byte) (int, error) {
	if w.Len()+len(p) > 4096 {
		return 0, io.ErrShortBuffer
	}
	return w.Buffer.Write(p)
}
func Propose(ctx context.Context, bun, repo string, number int) ([]byte, error) {
	bad := errors.New("built-in proposal unavailable")
	if !filepath.IsAbs(bun) {
		return nil, bad
	}
	dir, e := os.MkdirTemp("", "locklark-builtin-")
	if e != nil {
		return nil, bad
	}
	defer os.Remove(dir)
	src := filepath.Join(dir, "index.ts")
	conf := filepath.Join(dir, "bunfig.toml")
	if e = os.WriteFile(src, module, 0600); e != nil {
		return nil, bad
	}
	defer os.Remove(src)
	if e = os.WriteFile(conf, nil, 0600); e != nil {
		return nil, bad
	}
	defer os.Remove(conf)
	input, _ := json.Marshal(struct {
		Repo   string `json:"repo"`
		Number int    `json:"number"`
	}{repo, number})
	ctx, cancel := context.WithTimeout(ctx, 4*time.Second)
	defer cancel()
	cmd := exec.CommandContext(ctx, bun, "run", "--no-install", "--no-addons", "--no-env-file", "--config="+conf, src)
	cmd.Dir = dir
	cmd.Env = []string{"SystemRoot=" + os.Getenv("SystemRoot")}
	cmd.Stdin = bytes.NewReader(input)
	var out output
	cmd.Stdout = &out
	cmd.Stderr = io.Discard
	if e = cmd.Run(); e != nil {
		return nil, bad
	}
	return out.Bytes(), nil
}
