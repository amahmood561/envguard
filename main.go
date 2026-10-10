// Command envguard stops secrets before they are committed.
package main

import (
	"flag"
	"fmt"
	"io"
	"os"
	"strings"

	"github.com/amahmood561/envguard/internal/gitdiff"
	"github.com/amahmood561/envguard/internal/rules"
	"github.com/amahmood561/envguard/internal/scan"
)

const version = "0.1.0"

const usage = `envguard: stop secrets before they are committed.

Usage:
  envguard install [--force]        install the git pre-commit hook in this repository
  envguard staged [--json]          scan lines added in the staged change (what the hook runs)
  envguard scan [--json] [path...]  scan files (default: the current directory)
  envguard rules                    list what envguard looks for

Exit status: 0 nothing found, 1 secrets found, 2 error.
Silence a line with an "envguard:allow" comment. Skip paths by listing globs in .envguardignore.
`

func main() {
	os.Exit(run(os.Args[1:], os.Stdout, os.Stderr))
}

func run(args []string, stdout, stderr io.Writer) int {
	if len(args) == 0 {
		fmt.Fprint(stderr, usage)
		return 2
	}
	fail := func(err error) int {
		fmt.Fprintf(stderr, "envguard: %v\n", err)
		return 2
	}
	fset := flag.NewFlagSet(args[0], flag.ContinueOnError)
	fset.SetOutput(stderr)
	asJSON := fset.Bool("json", false, "print findings as JSON")
	force := fset.Bool("force", false, "replace an existing pre-commit hook")

	switch args[0] {
	case "scan":
		if fset.Parse(args[1:]) != nil {
			return 2
		}
		paths := fset.Args()
		if len(paths) == 0 {
			paths = []string{"."}
		}
		ig, err := scan.LoadIgnore(".")
		if err != nil {
			return fail(err)
		}
		found, n, warnings, err := scan.Paths(paths, ig)
		if err != nil {
			return fail(err)
		}
		for _, w := range warnings {
			fmt.Fprintf(stderr, "envguard: warning: %s\n", w)
		}
		if *asJSON {
			return report(scan.WriteJSON(stdout, found), found, stderr)
		}
		if len(found) == 0 {
			fmt.Fprintf(stdout, "envguard: no secrets found in %d files\n", n)
			return 0
		}
		scan.WriteText(stdout, found, fmt.Sprintf("in %d files", n))
		return 1

	case "staged":
		if fset.Parse(args[1:]) != nil {
			return 2
		}
		top, err := gitdiff.TopLevel(".")
		if err != nil {
			return fail(err)
		}
		ig, err := scan.LoadIgnore(top)
		if err != nil {
			return fail(err)
		}
		staged, err := gitdiff.ReadStaged(top)
		if err != nil {
			return fail(err)
		}
		found := scan.Staged(staged, ig)
		if *asJSON {
			return report(scan.WriteJSON(stdout, found), found, stderr)
		}
		if len(found) == 0 {
			return 0 // a hook that passes stays quiet
		}
		// stderr: git shows a hook's stderr when it blocks the commit.
		scan.WriteText(stderr, found, "in staged changes; commit blocked")
		fmt.Fprint(stderr, "Unstage a file with: git restore --staged <file>\n")
		return 1

	case "install":
		if fset.Parse(args[1:]) != nil {
			return 2
		}
		top, err := gitdiff.TopLevel(".")
		if err != nil {
			return fail(err)
		}
		path, err := gitdiff.InstallHook(top, executable(), *force)
		if err != nil {
			return fail(err)
		}
		fmt.Fprintf(stdout, "envguard: pre-commit hook installed at %s\n", path)
		return 0

	case "rules":
		for _, r := range rules.All {
			fmt.Fprintf(stdout, "%-22s %s\n", r.ID, r.Description)
		}
		fmt.Fprintf(stdout, "%-22s %s\n", "sensitive-file", ".env, .dev.vars, SSH keys, .pem/.key/.p12 files")
		return 0

	case "version", "--version":
		fmt.Fprintln(stdout, "envguard", version)
		return 0

	case "help", "-h", "--help":
		fmt.Fprint(stdout, usage)
		return 0
	}
	fmt.Fprintf(stderr, "envguard: unknown command %q\n\n%s", args[0], usage)
	return 2
}

func report(err error, found []scan.Finding, stderr io.Writer) int {
	if err != nil {
		fmt.Fprintf(stderr, "envguard: %v\n", err)
		return 2
	}
	if len(found) > 0 {
		return 1
	}
	return 0
}

// executable returns the path the hook should call. A `go run` binary lives in
// a temporary build directory, so fall back to finding envguard on PATH.
func executable() string {
	exe, err := os.Executable()
	if err != nil || strings.Contains(exe, "go-build") {
		return "envguard"
	}
	return exe
}
