package main

import (
	_ "embed"
	"strings"
)

//go:embed version.txt
var sourceVersion string

// version can be overridden by release packaging with -X main.version.
var version string

func init() {
	if version == "" {
		version = strings.TrimSpace(sourceVersion)
	}
}
