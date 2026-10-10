// Package scan applies the rules to files, staged changes and single lines,
// and prints findings without ever printing a whole secret.
package scan

import (
	"bufio"
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"io/fs"
	"os"
	"os/exec"
	"path"
	"path/filepath"
	"runtime"
	"sort"
	"strings"
	"sync"

	"github.com/amahmood561/envguard/internal/gitdiff"
	"github.com/amahmood561/envguard/internal/rules"
)

// AllowMarker silences findings on the line that contains it.
const AllowMarker = "envguard:allow"

// MaxFileSize skips large files (bundles, data dumps) that aren't hand-written config.
const MaxFileSize = 5 << 20

type Finding struct {
	File        string `json:"file"`
	Line        int    `json:"line,omitempty"`
	Column      int    `json:"column,omitempty"`
	Rule        string `json:"rule"`
	Description string `json:"description"`
	Redacted    string `json:"redacted,omitempty"`
}

// Redact keeps just enough of a secret to recognise which one it is. The mask
// has a fixed width so it doesn't reveal the length either.
func Redact(secret string) string {
	if len(secret) <= 8 {
		return "********"
	}
	return secret[:4] + "********"
}

// Line returns the findings for one line of text.
func Line(file string, n int, text string) []Finding {
	if strings.Contains(text, AllowMarker) {
		return nil
	}
	var out []Finding
	for _, m := range rules.Find(text) {
		out = append(out, Finding{
			File: file, Line: n, Column: m.Start + 1,
			Rule: m.Rule.ID, Description: m.Rule.Description, Redacted: Redact(m.Secret),
		})
	}
	return out
}

func fileFinding(file string) []Finding {
	if why, bad := rules.SensitiveFile(file); bad {
		return []Finding{{File: file, Rule: "sensitive-file", Description: why}}
	}
	return nil
}

// Reader scans r line by line. Binary content is skipped.
func Reader(file string, r io.Reader) ([]Finding, error) {
	br := bufio.NewReader(r)
	head, _ := br.Peek(8000)
	if bytes.IndexByte(head, 0) >= 0 {
		return nil, nil
	}
	sc := bufio.NewScanner(br)
	sc.Buffer(make([]byte, 64*1024), MaxFileSize)
	var out []Finding
	for n := 1; sc.Scan(); n++ {
		out = append(out, Line(file, n, strings.TrimSuffix(sc.Text(), "\r"))...)
	}
	return out, sc.Err()
}

// Ignore is the set of path globs from .envguardignore.
type Ignore []string

func LoadIgnore(dir string) (Ignore, error) {
	data, err := os.ReadFile(filepath.Join(dir, ".envguardignore"))
	if os.IsNotExist(err) {
		return nil, nil
	}
	if err != nil {
		return nil, err
	}
	var ig Ignore
	for _, l := range strings.Split(string(data), "\n") {
		if l = strings.TrimSpace(l); l != "" && !strings.HasPrefix(l, "#") {
			ig = append(ig, strings.TrimPrefix(l, "/"))
		}
	}
	return ig, nil
}

// Match reports whether a slash-separated path is ignored. A pattern matches
// the whole path, the file name, or a directory prefix ("testdata/").
func (ig Ignore) Match(p string) bool {
	p = filepath.ToSlash(p)
	for _, pat := range ig {
		dir := strings.TrimSuffix(pat, "/")
		if strings.HasPrefix(p, dir+"/") {
			return true
		}
		if ok, _ := path.Match(pat, p); ok {
			return true
		}
		if ok, _ := path.Match(pat, path.Base(p)); ok {
			return true
		}
	}
	return false
}

var skipDirs = map[string]bool{".git": true, "node_modules": true, ".venv": true, "venv": true, "__pycache__": true, ".wrangler": true}

// listFiles returns the files under root that could be committed: inside a git
// repository that is tracked plus untracked-but-not-ignored files, so a .env
// that .gitignore already covers is not reported. Elsewhere it walks the tree.
func listFiles(root string) ([]string, error) {
	if info, err := os.Stat(root); err != nil {
		return nil, err
	} else if !info.IsDir() {
		return []string{root}, nil
	}
	cmd := exec.Command("git", "-C", root, "ls-files", "-co", "--exclude-standard", "-z")
	if out, err := cmd.Output(); err == nil {
		var files []string
		for _, f := range strings.Split(string(out), "\x00") {
			if f != "" {
				files = append(files, filepath.Join(root, f))
			}
		}
		return files, nil
	}
	var files []string
	err := filepath.WalkDir(root, func(p string, d fs.DirEntry, err error) error {
		if err != nil {
			return err
		}
		if d.IsDir() && p != root && skipDirs[d.Name()] {
			return filepath.SkipDir
		}
		if d.Type().IsRegular() {
			files = append(files, p)
		}
		return nil
	})
	return files, err
}

// Paths scans every file under the given roots in parallel. It returns the
// findings, how many files were read, and warnings for files it could not read.
func Paths(roots []string, ig Ignore) (findings []Finding, scanned int, warnings []string, err error) {
	var files []string
	for _, root := range roots {
		fs, err := listFiles(root)
		if err != nil {
			return nil, 0, nil, err
		}
		files = append(files, fs...)
	}

	jobs := make(chan string)
	var mu sync.Mutex
	var wg sync.WaitGroup
	for range runtime.NumCPU() {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for f := range jobs {
				found, warn := scanFile(f)
				mu.Lock()
				findings = append(findings, found...)
				scanned++
				if warn != "" {
					warnings = append(warnings, warn)
				}
				mu.Unlock()
			}
		}()
	}
	for _, f := range files {
		if !ig.Match(filepath.ToSlash(filepath.Clean(f))) {
			jobs <- f
		}
	}
	close(jobs)
	wg.Wait()
	Sort(findings)
	sort.Strings(warnings)
	return findings, scanned, warnings, nil
}

func scanFile(f string) ([]Finding, string) {
	name := filepath.ToSlash(filepath.Clean(f))
	found := fileFinding(name)
	info, err := os.Stat(f)
	if err != nil || !info.Mode().IsRegular() {
		return found, "" // deleted from the work tree, or a symlink
	}
	if info.Size() > MaxFileSize {
		return found, fmt.Sprintf("%s: skipped, larger than %d MB", name, MaxFileSize>>20)
	}
	fh, err := os.Open(f)
	if err != nil {
		return found, fmt.Sprintf("%s: %v", name, err)
	}
	defer fh.Close()
	more, err := Reader(name, fh)
	if err != nil {
		return append(found, more...), fmt.Sprintf("%s: %v", name, err)
	}
	return append(found, more...), ""
}

// Staged scans what a commit would add.
func Staged(s *gitdiff.Staged, ig Ignore) []Finding {
	var out []Finding
	for _, f := range s.Files {
		if !ig.Match(f) {
			out = append(out, fileFinding(f)...)
		}
	}
	for _, a := range s.Lines {
		if !ig.Match(a.Path) {
			out = append(out, Line(a.Path, a.Line, a.Text)...)
		}
	}
	Sort(out)
	return out
}

func Sort(fs []Finding) {
	sort.Slice(fs, func(i, j int) bool {
		a, b := fs[i], fs[j]
		if a.File != b.File {
			return a.File < b.File
		}
		if a.Line != b.Line {
			return a.Line < b.Line
		}
		return a.Column < b.Column
	})
}

// WriteText prints findings for a person. where is "in staged changes" or similar.
func WriteText(w io.Writer, fs []Finding, where string) {
	noun := "possible secrets"
	if len(fs) == 1 {
		noun = "possible secret"
	}
	fmt.Fprintf(w, "envguard: %d %s %s\n\n", len(fs), noun, where)
	width := 0
	locs := make([]string, len(fs))
	for i, f := range fs {
		locs[i] = f.File
		if f.Line > 0 {
			locs[i] = fmt.Sprintf("%s:%d:%d", f.File, f.Line, f.Column)
		}
		width = max(width, len(locs[i]))
	}
	for i, f := range fs {
		fmt.Fprintf(w, "  %-*s  %-22s %s", width, locs[i], f.Rule, f.Description)
		if f.Redacted != "" {
			fmt.Fprintf(w, "  %s", f.Redacted)
		}
		fmt.Fprintln(w)
	}
	fmt.Fprint(w, "\nMove secrets into a secret store (for example `wrangler secret put NAME`) and reference them by name.\n"+
		"False positive? Add \"envguard:allow\" to the line, or the path to .envguardignore.\n")
}

func WriteJSON(w io.Writer, fs []Finding) error {
	if fs == nil {
		fs = []Finding{}
	}
	enc := json.NewEncoder(w)
	enc.SetIndent("", "  ")
	return enc.Encode(fs)
}
