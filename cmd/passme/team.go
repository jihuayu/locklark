package main

import (
	"github.com/jihuayu/passme/internal/teambootstrapcli"
	"io"
)

func runTeam(args []string, out io.Writer) error { return teambootstrapcli.RunOwner(args, out) }
