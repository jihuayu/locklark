//go:build !linux

package main

// Actual terminal/exec acceptance is Linux-only until separately implemented
// and exercised on another platform; cross compilation is not a runtime claim.
func terminalEcho() bool                                    { return false }
func execGH(string, []string, []string)                     { panic("unsupported fixture platform") }
func execControllingTTY(string, string, []string, []string) { panic("unsupported fixture platform") }
