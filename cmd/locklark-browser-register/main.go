package main

import (
	"flag"
	"fmt"
	"github.com/jihuayu/locklark/internal/browserhost"
	"os"
	"runtime"
)

func main() {
	browser := flag.String("browser", "", "chrome, edge or firefox")
	host := flag.String("host", "", "absolute path to the corresponding Chromium or Firefox native binary")
	output := flag.String("output", "", "absolute manifest path ending in org.locklark.browser.json; default is the browser per-user NativeMessagingHosts directory")
	user := flag.Bool("register-user", false, "Windows only: register the manifest in HKCU; never elevates")
	replace := flag.Bool("replace", false, "explicitly replace an existing manifest")
	flag.Parse()
	if *output == "" {
		*output, _ = browserhost.DefaultManifestPath(*browser)
	}
	if flag.NArg() != 0 || *user && runtime.GOOS != "windows" || browserhost.Register(*browser, *host, *output, *replace) != nil {
		fmt.Fprintln(os.Stderr, "Native host registration failed; check browser, binary and manifest paths")
		os.Exit(1)
	}
	if *user && browserhost.RegisterUser(*browser, *output, *replace) != nil {
		fmt.Fprintln(os.Stderr, "Manifest created but Windows user registry registration failed")
		os.Exit(1)
	}
	if runtime.GOOS == "windows" && !*user {
		fmt.Println("Manifest created. Run with --register-user and explicit --replace to register its path in Windows HKCU.")
	} else {
		fmt.Println("Native host manifest registered for this user.")
	}
}
