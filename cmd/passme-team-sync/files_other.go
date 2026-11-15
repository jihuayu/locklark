//go:build !unix && !windows

package main

func readLocalFile(string, int64, bool) ([]byte, error) { return nil, errCommand }
