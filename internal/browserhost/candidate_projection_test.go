package browserhost

import (
	"bytes"
	"encoding/json"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"

	"github.com/jihuayu/locklark/internal/personal"
)

func TestCandidateProjectionPreservesStrictBrowserDTO(t *testing.T) {
	raw, e := json.Marshal(Response{V: 1, ID: strings.Repeat("a", 32), Type: "candidates", Candidates: []personal.Row{{Kind: "login", ID: strings.Repeat("b", 32), Revision: strings.Repeat("c", 64), Title: "title", State: "active"}}})
	if e != nil {
		t.Fatal("candidate encode")
	}
	var response struct {
		Candidates []map[string]json.RawMessage `json:"candidates"`
	}
	if json.Unmarshal(raw, &response) != nil || len(response.Candidates) != 1 {
		t.Fatal("candidate shape")
	}
	row := response.Candidates[0]
	if len(row) != 4 {
		t.Fatal("browser candidate gained a field outside its strict DTO")
	}
	for _, key := range []string{"id", "revision", "title", "state"} {
		if _, ok := row[key]; !ok {
			t.Fatal("browser candidate lost a fixed field")
		}
	}
	t.Run("actual-extension-validator", func(t *testing.T) {
		node, e := exec.LookPath("node")
		if e != nil {
			t.Skip("Node unavailable; fixed Go DTO assertions still run")
		}
		core, e := filepath.Abs("../../browser-extension/core.js")
		if e != nil {
			t.Fatal("extension path")
		}
		command := exec.Command(node, "-e", `const core=require(process.argv[1]); let raw=''; process.stdin.on('data',b=>raw+=b); process.stdin.on('end',()=>{const m=JSON.parse(raw); if(!core.validResponse(m))process.exit(1);m.candidates[0].kind='login';if(core.validResponse(m))process.exit(2)});`, core)
		command.Stdin = bytes.NewReader(raw)
		if command.Run() != nil {
			t.Fatal("actual extension rejected Go projection or accepted extra kind")
		}
	})
	if _, e = json.Marshal(Response{V: 1, Type: "matches", Candidates: []personal.Row{{Kind: "ssh-key", ID: "key", State: "active"}}}); e == nil {
		t.Fatal("non-login candidate reached browser")
	}
}
