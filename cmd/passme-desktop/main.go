package main

import (
	"errors"
	"fmt"
	"github.com/jihuayu/passme/internal/desktop"
	"os"
)

func main() {
	err := desktop.RunDesktopArgs(os.Args[1:])
	if err == nil {
		return
	}
	var usage *desktop.UsageError
	if errors.As(err, &usage) {
		fmt.Fprintln(os.Stderr, usage.Error())
		os.Exit(2)
	}
	if errors.Is(err, desktop.ErrSettingsPath) {
		fmt.Fprintln(os.Stderr, err.Error())
		os.Exit(2)
	}
	fmt.Fprintln(os.Stderr, "Passme desktop could not start; check native platform dependencies")
	os.Exit(1)
}
