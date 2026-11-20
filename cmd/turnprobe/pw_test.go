package main

import (
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
)

func TestReadPasswordBounds(t *testing.T) {
	dir := t.TempDir()
	write := func(name string, n int, mode os.FileMode) string {
		p := filepath.Join(dir, name)
		if err := os.WriteFile(p, []byte(strings.Repeat("a", n)), mode); err != nil {
			t.Fatal(err)
		}
		return p
	}
	if pw, err := readPassword(write("edge", 4096, 0o600)); err != nil || len(pw) != 4096 {
		t.Errorf("4096 bytes: len=%d err=%v", len(pw), err)
	}
	if _, err := readPassword(write("big", 4097, 0o600)); err == nil || !strings.Contains(err.Error(), "too large") {
		t.Errorf("4097 bytes: err=%v", err)
	}
	if runtime.GOOS != "windows" && os.Geteuid() != 0 {
		if _, err := readPassword(write("wo", 5, 0o200)); err == nil {
			t.Error("an unreadable file was read")
		}
	}
}
