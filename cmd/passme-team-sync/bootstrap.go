package main

import (
	"github.com/jihuayu/passme/internal/teambootstrapcli"
	"io"
)

func runBootstrap(args []string, out io.Writer) error { return teambootstrapcli.RunService(args, out) }
