package scan

import (
	"strings"
	"testing"
)

func TestRedactHidesSecretAndLength(t *testing.T) {
	a, b := Redact("sk_live_short_one_1234"), Redact("sk_live_a_much_longer_secret_value_5678")
	if a != "sk_l********" || len(a) != len(b) {
		t.Fatalf("got %q and %q", a, b)
	}
	if Redact("abc") != "********" {
		t.Fatal("short secrets must be fully masked")
	}
}

func TestIgnoreMatch(t *testing.T) {
	ig := Ignore{"testdata/", "*.snap", "docs/example.md"}
	for _, p := range []string{"testdata/a.txt", "pkg/x.snap", "docs/example.md"} {
		if !ig.Match(p) {
			t.Errorf("%s should be ignored", p)
		}
	}
	for _, p := range []string{"src/testdata.go", "docs/other.md"} {
		if ig.Match(p) {
			t.Errorf("%s should not be ignored", p)
		}
	}
}

func TestReaderSkipsBinaryAndHonoursAllow(t *testing.T) {
	key := strings.Join([]string{"sk_", "live_", "51Hq8ZtLm2Vx9Rk4Pn7Wb3Jd"}, "")
	if f, _ := Reader("bin", strings.NewReader("\x00\x01"+key)); len(f) != 0 {
		t.Fatal("scanned binary content")
	}
	f, _ := Reader("a.txt", strings.NewReader("ok\nk="+key+" # envguard:allow\nk2="+key+"\r\n"))
	if len(f) != 1 || f[0].Line != 3 {
		t.Fatalf("got %+v", f)
	}
}
