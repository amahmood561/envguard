// Package rules holds the secret patterns envguard looks for.
//
// Specific rules (a provider's key format) are checked first. The generic
// "something named like a secret is assigned a random-looking value" rule only
// runs when no specific rule matched the line, so a Stripe key in
// STRIPE_SECRET_KEY=... is reported once, as a Stripe key.
package rules

import (
	"math"
	"regexp"
	"strings"
)

type Rule struct {
	ID          string
	Description string
	re          *regexp.Regexp
	group       int               // capture group holding the secret; 0 = whole match
	check       func(string) bool // optional extra test on the secret
	generic     bool
}

type Match struct {
	Rule       *Rule
	Start, End int // byte offsets of the secret within the line
	Secret     string
}

func rule(id, desc, pattern string) *Rule {
	return &Rule{ID: id, Description: desc, re: regexp.MustCompile(pattern)}
}

var All = []*Rule{
	rule("aws-access-key", "AWS access key ID", `\b(?:AKIA|ASIA)[0-9A-Z]{16}\b`),
	rule("stripe-secret-key", "Stripe live secret or restricted key", `\b[rs]k_live_[0-9A-Za-z]{20,}\b`),
	rule("stripe-webhook-secret", "Stripe webhook signing secret", `\bwhsec_[0-9A-Za-z]{24,}\b`),
	rule("anthropic-api-key", "Anthropic API key", `\bsk-ant-[A-Za-z0-9_\-]{32,}`),
	rule("openai-api-key", "OpenAI API key", `\bsk-(?:proj|svcacct|admin)-[A-Za-z0-9_\-]{20,}|\bsk-[A-Za-z0-9]{48}\b`),
	rule("github-token", "GitHub token", `\b(?:ghp|gho|ghu|ghs|ghr)_[A-Za-z0-9]{36}\b|\bgithub_pat_[A-Za-z0-9_]{22,}`),
	rule("slack-token", "Slack token", `\bxox[abprs]-[A-Za-z0-9-]{10,}`),
	rule("google-api-key", "Google API key", `\bAIza[0-9A-Za-z_\-]{35}\b`),
	rule("resend-api-key", "Resend API key", `\bre_[A-Za-z0-9]{8,}_[A-Za-z0-9]{16,}\b`),
	rule("private-key", "Private key block", `-----BEGIN (?:(?:RSA|EC|DSA|OPENSSH|PGP|ENCRYPTED) )?PRIVATE KEY(?: BLOCK)?-----`),
	{
		ID:          "database-url-password",
		Description: "Password inside a database connection string",
		re:          regexp.MustCompile(`\b(?:postgres(?:ql)?|mysql|mongodb(?:\+srv)?|rediss?|amqps?)://[^\s:/@'"]+:([^\s@/'"]+)@`),
		group:       1,
		check:       func(s string) bool { return len(s) >= 6 && !Placeholder(s) },
	},
	{
		ID:          "generic-secret",
		Description: "Random-looking value assigned to a secret-named variable",
		re: regexp.MustCompile(`(?i)\b([a-z0-9_.\-]*(?:secret|token|api[_-]?key|passw(?:or)?d|private[_-]?key|auth[_-]?key|access[_-]?key)[a-z0-9_.\-]*)["']?\s*(?::=|=>|=|:)\s*["']?` +
			"([^\\s\"'`,;()]{16,})"),
		group:   2,
		check:   looksRandom,
		generic: true,
	},
}

// Find returns every secret in one line of text.
func Find(line string) []Match {
	var out []Match
	for _, generic := range []bool{false, true} {
		if generic && len(out) > 0 {
			break
		}
		for _, r := range All {
			if r.generic != generic {
				continue
			}
			for _, loc := range r.re.FindAllStringSubmatchIndex(line, -1) {
				s, e := loc[2*r.group], loc[2*r.group+1]
				if s < 0 {
					continue
				}
				secret := line[s:e]
				if r.check != nil && !r.check(secret) {
					continue
				}
				out = append(out, Match{Rule: r, Start: s, End: e, Secret: secret})
			}
		}
	}
	return out
}

var placeholders = []string{
	"your", "example", "sample", "changeme", "change_me", "change-me", "placeholder",
	"xxxx", "dummy", "fake", "redacted", "password", "<", ">", "${", "{{", "%(",
	"process.env", "env.", "getenv", "environ", "****", "...",
}

// Placeholder reports whether a value is a template stand-in rather than a real secret.
func Placeholder(s string) bool {
	l := strings.ToLower(s)
	for _, p := range placeholders {
		if strings.Contains(l, p) {
			return true
		}
	}
	return false
}

// looksRandom keeps the generic rule quiet on code like `token = makeToken()`:
// real secrets mix letters and digits and have high character entropy.
func looksRandom(s string) bool {
	if Placeholder(s) || strings.HasPrefix(s, "$") {
		return false
	}
	// Stripe test keys and publishable keys are safe to commit.
	for _, p := range []string{"sk_test_", "rk_test_", "pk_test_", "pk_live_"} {
		if strings.HasPrefix(s, p) {
			return false
		}
	}
	hasDigit := strings.ContainsAny(s, "0123456789")
	hasLetter := strings.IndexFunc(s, func(r rune) bool { return (r|0x20) >= 'a' && (r|0x20) <= 'z' }) >= 0
	return hasDigit && hasLetter && Entropy(s) >= 3.5
}

// Entropy is the Shannon entropy of s in bits per character.
func Entropy(s string) float64 {
	if s == "" {
		return 0
	}
	counts := map[rune]int{}
	for _, r := range s {
		counts[r]++
	}
	n := float64(len([]rune(s)))
	var h float64
	for _, c := range counts {
		p := float64(c) / n
		h -= p * math.Log2(p)
	}
	return h
}

// SensitiveFile reports whether a file should never be committed at all,
// whatever it contains, and why.
func SensitiveFile(path string) (string, bool) {
	base := path
	if i := strings.LastIndexAny(path, `/\`); i >= 0 {
		base = path[i+1:]
	}
	lower := strings.ToLower(base)
	switch {
	case lower == ".env" || strings.HasPrefix(lower, ".env."):
		for _, ok := range []string{".example", ".sample", ".template", ".dist"} {
			if strings.HasSuffix(lower, ok) {
				return "", false
			}
		}
		return "dotenv file (keep it out of git; commit a .env.example instead)", true
	case lower == ".dev.vars":
		return "Wrangler local secrets file", true
	case lower == "id_rsa" || lower == "id_ed25519" || lower == "id_ecdsa" || lower == "id_dsa":
		return "SSH private key", true
	case strings.HasSuffix(lower, ".pem") || strings.HasSuffix(lower, ".p12") || strings.HasSuffix(lower, ".pfx") || strings.HasSuffix(lower, ".key"):
		return "key or certificate file", true
	}
	return "", false
}
