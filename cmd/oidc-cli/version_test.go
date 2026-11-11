package main

import (
	"strings"
	"testing"
)

func TestEmbeddedVersion(t *testing.T) {
	if strings.TrimSpace(sourceVersion) == "" || version != strings.TrimSpace(sourceVersion) {
		t.Fatal("source builds must report the canonical embedded version")
	}
}
