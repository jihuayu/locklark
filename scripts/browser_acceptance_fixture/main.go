// Creates disposable synthetic data for external browser/native UI acceptance.
// This is test tooling, not a product unlock or approval bypass.
package main

import (
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"flag"
	"fmt"
	"os"
	"path/filepath"

	"github.com/jihuayu/locklark/internal/origin"
	"github.com/jihuayu/locklark/internal/personal"
)

type fixture struct {
	Path, Password, Secret, Username, Value, Title, Origin string
	SeedID                                                 string
	SaveUsername, SaveValue, UpdateUsername, UpdateValue   string
	RejectedUsername, RejectedValue                        string
}

func run() error {
	out := flag.String("out", "", "new private directory containing synthetic data only")
	site := flag.String("origin", "", "controlled HTTPS test origin")
	observe := flag.String("observe", "", "read a generated private fixture and observe a consistent vault copy")
	flag.Parse()
	if *observe != "" {
		if *out != "" || *site != "" || flag.NArg() != 0 {
			return fmt.Errorf("one fixture operation required")
		}
		return observeFixture(*observe)
	}
	canonical, err := origin.Parse(*site)
	if err != nil || *out == "" || !filepath.IsAbs(*out) {
		return fmt.Errorf("absolute output and supported HTTPS origin required")
	}
	if err = os.Mkdir(*out, 0700); err != nil {
		return err
	}
	key, err := personal.NewSecret()
	if err != nil {
		return err
	}
	defer clear(key)
	var entropy [72]byte
	if _, err = rand.Read(entropy[:]); err != nil {
		return err
	}
	f := fixture{
		Path:     filepath.Join(*out, "synthetic.ll"),
		Password: "Acceptance-" + hex.EncodeToString(entropy[:8]),
		Secret:   personal.FormatSecret(key),
		Username: "synthetic-browser-user",
		Value:    "Synthetic-" + hex.EncodeToString(entropy[8:24]),
		Title:    "Browser acceptance login", Origin: canonical,
		SaveUsername: "合成浏览器用户", SaveValue: "Synthetic-new-🔐-" + hex.EncodeToString(entropy[24:40]),
		UpdateUsername: "synthetic-updated-browser-user", UpdateValue: "Synthetic-updated-" + hex.EncodeToString(entropy[40:56]),
		RejectedUsername: "synthetic-rejected-browser-user", RejectedValue: "Synthetic-rejected-" + hex.EncodeToString(entropy[56:72]),
	}
	clear(entropy[:])
	if err = personal.Create(f.Path, f.Password, key); err != nil {
		return err
	}
	id, err := personal.AddLogin(f.Path, f.Password, key, f.Title, f.Username, f.Value)
	if err != nil {
		return err
	}
	f.SeedID = id
	rows, err := personal.List(f.Path, f.Password, key)
	if err != nil {
		return err
	}
	for _, row := range rows {
		if row.ID == id {
			if _, err = personal.EditLogin(f.Path, f.Password, key, personal.Edit{ID: id, Revision: row.Revision, Field: "url", Value: canonical + "/login"}); err != nil {
				return err
			}
		}
	}
	data, err := json.Marshal(f)
	if err != nil {
		return err
	}
	defer clear(data)
	return os.WriteFile(filepath.Join(*out, "fixture.json"), data, 0600)
}

func main() {
	if run() != nil {
		fmt.Fprintln(os.Stderr, "Synthetic browser fixture operation failed")
		os.Exit(1)
	}
}
