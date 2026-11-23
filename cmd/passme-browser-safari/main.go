package main

import (
	"fmt"
	"github.com/jihuayu/passme/internal/browserhost"
	"github.com/jihuayu/passme/internal/desktop"
	"os"
)

func main() {
	if desktop.RunBrowser(browserhost.Safari, os.Args[1:]) != nil {
		fmt.Fprintln(os.Stderr, "Passme native browser host could not start")
		os.Exit(1)
	}
}
