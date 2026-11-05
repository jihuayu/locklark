package main

import (
	"fmt"
	"github.com/jihuayu/locklark/internal/browserhost"
	"github.com/jihuayu/locklark/internal/desktop"
	"os"
)

func main() {
	if desktop.RunBrowser(browserhost.Chromium, os.Args[1:]) != nil {
		fmt.Fprintln(os.Stderr, "Locklark native browser host could not start")
		os.Exit(1)
	}
}
