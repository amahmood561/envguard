// Package gitdiff reads what is about to be committed, and installs the hook.
package gitdiff

import (
	"bytes"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"strconv"
	"strings"
)

// Added is one line added by the staged change.
type Added struct {
	Path string
	Line int
	Text string
}

// Staged is everything a commit would add: new lines and new or renamed files.
type Staged struct {
	Lines []Added
	Files []string
}

func git(dir string, args ...string) ([]byte, error) {
	cmd := exec.Command("git", append([]string{"-C", dir, "-c", "core.quotePath=false"}, args...)...)
	var stderr bytes.Buffer
	cmd.Stderr = &stderr
	out, err := cmd.Output()
	if err != nil {
		return nil, fmt.Errorf("git %s: %v: %s", args[0], err, strings.TrimSpace(stderr.String()))
	}
	return out, nil
}

// TopLevel returns the root of the repository containing dir.
func TopLevel(dir string) (string, error) {
	out, err := git(dir, "rev-parse", "--show-toplevel")
	return strings.TrimSpace(string(out)), err
}

// ReadStaged returns the staged change of the repository at dir.
// Only added lines are returned, so secrets already in history don't block
// every commit; `envguard scan` finds those.
func ReadStaged(dir string) (*Staged, error) {
	diff, err := git(dir, "diff", "--cached", "--no-color", "--no-ext-diff", "-U0", "--diff-filter=ACMR")
	if err != nil {
		return nil, err
	}
	s := Parse(string(diff))
	names, err := git(dir, "diff", "--cached", "--name-only", "--diff-filter=ACR", "-z")
	if err != nil {
		return nil, err
	}
	for _, n := range strings.Split(string(names), "\x00") {
		if n != "" {
			s.Files = append(s.Files, n)
		}
	}
	return s, nil
}

var hunk = regexp.MustCompile(`^@@ -\d+(?:,\d+)? \+(\d+)`)

// Parse extracts added lines from `git diff -U0` output.
func Parse(diff string) *Staged {
	s := &Staged{}
	var path string
	var line int
	inHeader := false
	for _, l := range strings.Split(diff, "\n") {
		switch {
		case strings.HasPrefix(l, "diff --git "):
			inHeader, path = true, ""
		case inHeader && strings.HasPrefix(l, "+++ "):
			p := strings.TrimRight(strings.TrimPrefix(l, "+++ "), "\t")
			if p == "/dev/null" {
				path = ""
			} else {
				path = strings.TrimPrefix(p, "b/")
			}
		case strings.HasPrefix(l, "@@"):
			inHeader = false
			if m := hunk.FindStringSubmatch(l); m != nil {
				line, _ = strconv.Atoi(m[1])
			}
		case !inHeader && path != "" && strings.HasPrefix(l, "+"):
			s.Lines = append(s.Lines, Added{Path: path, Line: line, Text: strings.TrimSuffix(l[1:], "\r")})
			line++
		}
	}
	return s
}

// HookMarker identifies a pre-commit hook written by envguard.
const HookMarker = "# Installed by envguard."

// InstallHook writes the pre-commit hook for the repository at dir and returns
// its path. An existing hook that envguard did not write is left alone unless
// force is set.
func InstallHook(dir, exe string, force bool) (string, error) {
	out, err := git(dir, "rev-parse", "--git-path", "hooks")
	if err != nil {
		return "", err
	}
	hooks := strings.TrimSpace(string(out))
	if !filepath.IsAbs(hooks) {
		hooks = filepath.Join(dir, hooks)
	}
	path := filepath.Join(hooks, "pre-commit")
	if old, err := os.ReadFile(path); err == nil && !bytes.Contains(old, []byte(HookMarker)) && !force {
		return "", fmt.Errorf("%s already exists and was not written by envguard; rerun with --force to replace it, or add `envguard staged` to it yourself", path)
	}
	if exe == "" {
		exe = "envguard"
	}
	script := "#!/bin/sh\n" + HookMarker + " Blocks commits that add secrets.\n" +
		"# Bypass once, only if you are sure: git commit --no-verify\n" +
		"exec '" + strings.ReplaceAll(exe, "'", `'\''`) + "' staged\n"
	if err := os.MkdirAll(hooks, 0o755); err != nil {
		return "", err
	}
	return path, os.WriteFile(path, []byte(script), 0o755)
}
