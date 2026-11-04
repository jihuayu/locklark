package agentmcp

import (
	"os"
	"path/filepath"
	"testing"
)

func TestStateCannotShareWritableRelay(t *testing.T) {
	root := t.TempDir()
	var c Config
	mk := func(name string) string {
		p := filepath.Join(root, name)
		if err := os.Mkdir(p, 0700); err != nil {
			t.Fatal(err)
		}
		return p
	}
	c.Inbox = mk("requests")
	c.Poll.Private = mk("private")
	c.Poll.Exchange = mk("exchange")
	for i, p := range []*string{&c.Poll.Key, &c.Poll.Host, &c.Poll.Recipient} {
		*p = filepath.Join(c.Poll.Private, []string{"key", "host", "recipient"}[i])
		if err := os.WriteFile(*p, nil, 0600); err != nil {
			t.Fatal(err)
		}
	}
	if !isolated(c) {
		t.Fatal("isolated layout refused")
	}
	bad := c
	bad.Poll.Private = root
	if isolated(bad) {
		t.Fatal("private parent of public relay accepted")
	}
	bad = c
	bad.Poll.Key = filepath.Join(c.Inbox, "key")
	if err := os.WriteFile(bad.Poll.Key, nil, 0600); err != nil {
		t.Fatal(err)
	}
	if isolated(bad) {
		t.Fatal("key exposed to relay")
	}
}
