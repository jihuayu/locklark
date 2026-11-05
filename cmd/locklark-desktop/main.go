package main

import (
	"fmt"
	"github.com/jihuayu/locklark/internal/desktop"
	"os"
)

func main() {
	if desktop.Run() != nil {
		fmt.Fprintln(os.Stderr, "Locklark desktop could not start; check native platform dependencies")
		os.Exit(1)
	}
}
