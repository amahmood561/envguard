package gitdiff

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

const sample = `diff --git a/config.js b/config.js
index 1111111..2222222 100644
--- a/config.js
+++ b/config.js
@@ -3,0 +4,2 @@ module.exports = {
+  region: "us-east-1",
+++ starts with plus signs
@@ -10 +12 @@ function x() {
-  old
+  new line twelve
diff --git a/gone.txt b/gone.txt
deleted file mode 100644
--- a/gone.txt
+++ /dev/null
@@ -1 +0,0 @@
-bye
`

func TestParse(t *testing.T) {
	s := Parse(sample)
	want := []Added{
		{"config.js", 4, `  region: "us-east-1",`},
		{"config.js", 5, "++ starts with plus signs"},
		{"config.js", 12, "  new line twelve"},
	}
	if len(s.Lines) != len(want) {
		t.Fatalf("got %d lines: %+v", len(s.Lines), s.Lines)
	}
	for i := range want {
		if s.Lines[i] != want[i] {
			t.Errorf("line %d: got %+v want %+v", i, s.Lines[i], want[i])
		}
	}
}

func TestInstallHookRespectsExistingHook(t *testing.T) {
	dir := gitRepo(t)
	hook := filepath.Join(dir, ".git", "hooks", "pre-commit")
	if err := os.WriteFile(hook, []byte("#!/bin/sh\nnpm test\n"), 0o755); err != nil {
		t.Fatal(err)
	}
	if _, err := InstallHook(dir, "/usr/local/bin/envguard", false); err == nil {
		t.Fatal("overwrote someone else's hook")
	}
	path, err := InstallHook(dir, "/usr/local/bin/envguard", true)
	if err != nil {
		t.Fatal(err)
	}
	data, _ := os.ReadFile(path)
	if !strings.Contains(string(data), HookMarker) || !strings.Contains(string(data), "'/usr/local/bin/envguard' staged") {
		t.Fatalf("unexpected hook:\n%s", data)
	}
	// Reinstalling over our own hook needs no --force.
	if _, err := InstallHook(dir, "envguard", false); err != nil {
		t.Fatal(err)
	}
}

func gitRepo(t *testing.T) string {
	t.Helper()
	dir := t.TempDir()
	if _, err := git(dir, "init", "-q"); err != nil {
		t.Skip("git not available:", err)
	}
	return dir
}
