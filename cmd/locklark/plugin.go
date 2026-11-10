package main

import (
	"encoding/json"
	"errors"
	"io"

	"github.com/jihuayu/locklark/internal/pluginstore"
)

const pluginHelpText = `usage: locklark plugin <command> [flags]

COMMANDS
  init        --file NEW_DB
  inspect     --package FILE --id ID --publisher HEX_KEY
  install     --file DB --parent CHECKPOINT --pins TRUSTED_JSON --package FILE --id ID --publisher HEX_KEY --digest PACKAGE_DIGEST
  list|audit  --file DB --anchor CHECKPOINT --pins TRUSTED_JSON
  revoke      --file DB --parent CHECKPOINT --pins TRUSTED_JSON --id ID

NOTES
  - Every catalog read or mutation verifies the trusted checkpoint and publisher pins.
  - Third-party plugin execution is disabled.
`

var pluginUsage = errors.New(pluginHelpText)
var pluginOutputFailure = errors.New("plugin output failed; a catalog mutation may already be committed")

func runPlugin(args []string, out io.Writer) error {
	if len(args) == 1 && (args[0] == "help" || args[0] == "--help" || args[0] == "-h") {
		_, err := io.WriteString(out, pluginHelpText)
		return err
	}
	if len(args) < 3 || len(args)%2 != 1 {
		return pluginUsage
	}
	opts := map[string]string{}
	for i := 1; i < len(args); i += 2 {
		if args[i+1] == "" || opts[args[i]] != "" {
			return pluginUsage
		}
		opts[args[i]] = args[i+1]
	}
	required := func(names ...string) bool {
		if len(opts) != len(names) {
			return false
		}
		for _, name := range names {
			if opts[name] == "" {
				return false
			}
		}
		return true
	}
	var response any
	var err error
	switch args[0] {
	case "init":
		if !required("--file") {
			return pluginUsage
		}
		response, err = pluginstore.Create(opts["--file"])
	case "inspect":
		if !required("--package", "--id", "--publisher") {
			return pluginUsage
		}
		raw, e := pluginstore.ReadPackage(opts["--package"])
		if e != nil {
			return e
		}
		p, e := pluginstore.Verify(raw, opts["--id"], opts["--publisher"])
		if e != nil {
			return e
		}
		response = struct {
			Info         pluginstore.Info         `json:"plugin"`
			Runtime      string                   `json:"runtime"`
			Capabilities []string                 `json:"declared_capabilities"`
			Dependencies []pluginstore.Dependency `json:"dependency_lock"`
			Bytes        int                      `json:"bundle_bytes"`
			Execution    string                   `json:"execution"`
		}{pluginstore.Info{ID: p.ID, Publisher: p.Publisher, Version: p.Version, Digest: pluginstore.Digest(raw)}, p.Runtime, p.Capabilities, p.Dependencies, len(p.Bundle), "disabled"}
	case "install":
		if !required("--file", "--parent", "--pins", "--package", "--id", "--publisher", "--digest") {
			return pluginUsage
		}
		pins, e := pluginstore.ReadPins(opts["--pins"])
		if e != nil {
			return e
		}
		raw, e := pluginstore.ReadPackage(opts["--package"])
		if e != nil {
			return e
		}
		response, err = pluginstore.Install(opts["--file"], opts["--parent"], opts["--id"], opts["--publisher"], opts["--digest"], raw, pins)
	case "list", "audit":
		if !required("--file", "--anchor", "--pins") {
			return pluginUsage
		}
		pins, e := pluginstore.ReadPins(opts["--pins"])
		if e != nil {
			return e
		}
		if args[0] == "list" {
			response, err = pluginstore.Read(opts["--file"], opts["--anchor"], pins)
		} else {
			response, err = pluginstore.Audit(opts["--file"], opts["--anchor"], pins)
		}
	case "revoke":
		if !required("--file", "--parent", "--pins", "--id") {
			return pluginUsage
		}
		pins, e := pluginstore.ReadPins(opts["--pins"])
		if e != nil {
			return e
		}
		response, err = pluginstore.Revoke(opts["--file"], opts["--parent"], opts["--id"], pins)
	default:
		return pluginUsage
	}
	if err != nil {
		return err
	}
	if json.NewEncoder(out).Encode(response) != nil {
		return pluginOutputFailure
	}
	return nil
}
