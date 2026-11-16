package main

import (
	"fmt"
	"github.com/jihuayu/passme/internal/desktop"
	"os"
)

func main() {
	if desktop.Run() != nil {
		fmt.Fprintln(os.Stderr, "Passme desktop could not start; check native platform dependencies")
		os.Exit(1)
	}
}
