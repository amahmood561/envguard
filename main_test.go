package main

import (
	"bytes"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
)

func j(parts ...string) string { return strings.Join(parts, "") }

var stripeKey = j("sk_", "live_", "51Hq8ZtLm2Vx9Rk4Pn7Wb3Jd")

func repo(t *testing.T) string {
	t.Helper()
	dir := t.TempDir()
	for _, args := range [][]string{{"init", "-q"}, {"config", "user.email", "t@example.com"}, {"config", "user.name", "t"}} {
		if out, err := exec.Command("git", append([]string{"-C", dir}, args...)...).CombinedOutput(); err != nil {
			t.Skipf("git: %v %s", err, out)
		}
	}
	t.Chdir(dir)
	return dir
}

func write(t *testing.T, dir, name, body string) {
	t.Helper()
	p := filepath.Join(dir, name)
	if err := os.MkdirAll(filepath.Dir(p), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(p, []byte(body), 0o644); err != nil {
		t.Fatal(err)
	}
}

func gitDo(t *testing.T, dir string, args ...string) {
	t.Helper()
	if out, err := exec.Command("git", append([]string{"-C", dir}, args...)...).CombinedOutput(); err != nil {
		t.Fatalf("git %v: %v %s", args, err, out)
	}
}

func TestStagedBlocksSecretWithoutPrintingIt(t *testing.T) {
	dir := repo(t)
	write(t, dir, "config.js", "module.exports = { key: \""+stripeKey+"\" };\n")
	write(t, dir, ".dev.vars", "X=1\n")
	gitDo(t, dir, "add", ".")

	var out, errOut bytes.Buffer
	if code := run([]string{"staged"}, &out, &errOut); code != 1 {
		t.Fatalf("exit %d, stderr:\n%s", code, errOut.String())
	}
	msg := errOut.String()
	for _, want := range []string{"config.js:1:", "stripe-secret-key", "sk_l********", ".dev.vars", "sensitive-file"} {
		if !strings.Contains(msg, want) {
			t.Errorf("missing %q in:\n%s", want, msg)
		}
	}
	if strings.Contains(msg+out.String(), stripeKey) {
		t.Fatal("printed the full secret")
	}
}

func TestStagedOnlyLooksAtAddedLines(t *testing.T) {
	dir := repo(t)
	write(t, dir, "old.txt", "token = \""+stripeKey+"\"\n")
	gitDo(t, dir, "add", ".")
	gitDo(t, dir, "commit", "-q", "--no-verify", "-m", "old")
	write(t, dir, "old.txt", "token = \""+stripeKey+"\"\nharmless = 1\n")
	gitDo(t, dir, "add", ".")

	var out, errOut bytes.Buffer
	if code := run([]string{"staged"}, &out, &errOut); code != 0 {
		t.Fatalf("exit %d: an old secret should not block an unrelated change\n%s", code, errOut.String())
	}
}

func TestAllowMarkerAndIgnoreFile(t *testing.T) {
	dir := repo(t)
	write(t, dir, "a.js", "k = \""+stripeKey+"\" // envguard:allow\n")
	write(t, dir, "testdata/fixture.txt", stripeKey+"\n")
	write(t, dir, ".envguardignore", "# fixtures\ntestdata/\n")
	gitDo(t, dir, "add", ".")

	var out, errOut bytes.Buffer
	if code := run([]string{"staged"}, &out, &errOut); code != 0 {
		t.Fatalf("exit %d:\n%s", code, errOut.String())
	}
}

func TestScanRespectsGitignoreAndReportsJSON(t *testing.T) {
	dir := repo(t)
	write(t, dir, ".gitignore", ".env\n")
	write(t, dir, ".env", "STRIPE_SECRET_KEY="+stripeKey+"\n")  // ignored by git: fine
	write(t, dir, "src/app.py", "STRIPE = '"+stripeKey+"'\n")   // not ignored: reported
	write(t, dir, "logo.png", "\x89PNG\x00\x00"+stripeKey+"\n") // binary: skipped

	var out, errOut bytes.Buffer
	if code := run([]string{"scan", "--json"}, &out, &errOut); code != 1 {
		t.Fatalf("exit %d:\n%s%s", code, out.String(), errOut.String())
	}
	got := out.String()
	if !strings.Contains(got, `"file": "src/app.py"`) || strings.Contains(got, ".env") || strings.Contains(got, "logo.png") {
		t.Fatalf("unexpected findings:\n%s", got)
	}
}

func TestInstall(t *testing.T) {
	dir := repo(t)
	var out, errOut bytes.Buffer
	if code := run([]string{"install"}, &out, &errOut); code != 0 {
		t.Fatalf("exit %d: %s", code, errOut.String())
	}
	if _, err := os.Stat(filepath.Join(dir, ".git", "hooks", "pre-commit")); err != nil {
		t.Fatal(err)
	}
}
