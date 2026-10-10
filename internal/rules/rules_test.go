package rules

import (
	"strings"
	"testing"
)

// Test secrets are assembled at runtime so this file never contains a string
// that looks like a real key to envguard, GitHub push protection, or anyone else.
func j(parts ...string) string { return strings.Join(parts, "") }

func TestFindsKnownFormats(t *testing.T) {
	cases := map[string]string{
		"aws-access-key":        j("aws_id = AKIA", "Z7Q2M4K8P1X6C3V9"),
		"stripe-secret-key":     j("STRIPE_SECRET_KEY=sk_", "live_", "51Hq8ZtLm2Vx9Rk4Pn7Wb3Jd"),
		"stripe-webhook-secret": j(`secret: "whsec_`, "q8Zt2LmV9xR4pK7sW1nB5cHd", `"`),
		"anthropic-api-key":     j("ANTHROPIC_API_KEY=sk-ant-", "api03-", strings.Repeat("Ab9_xY2-", 6)),
		"openai-api-key":        j("key = 'sk-proj-", strings.Repeat("Qw3Er5Ty", 5), "'"),
		"github-token":          j("token: gh", "p_", strings.Repeat("aB3dE6gH9k", 3), "Lm2Np5"),
		"slack-token":           j("SLACK=xox", "b-", "1234567890-AbCdEfGhIj"),
		"google-api-key":        j("maps_key: AI", "za", "SyD8z", strings.Repeat("Kq3Vx", 6)),
		"resend-api-key":        j("RESEND_API_KEY=re_", "Ab3dE6gH_", "Jk9LmN2pQr5StU8vWx1Yz4Ab"),
		"private-key":           j("-----BEGIN ", "RSA PRIVATE KEY-----"),
		"database-url-password": j("DATABASE_URL=postgres://app:", "Hk29dLq8vZ", "@db.internal:5432/main"),
		"generic-secret":        j(`const JWT_SECRET = "`, "q8Zt2LmV9xR4pK7sW1nB", `";`),
	}
	for want, line := range cases {
		got := Find(line)
		if len(got) != 1 || got[0].Rule.ID != want {
			t.Errorf("%s: got %v from %q", want, ids(got), line)
		}
	}
}

func TestSpecificRuleWinsOverGeneric(t *testing.T) {
	got := Find(j("STRIPE_SECRET_KEY=sk_", "live_", "51Hq8ZtLm2Vx9Rk4Pn7Wb3Jd"))
	if len(got) != 1 || got[0].Rule.ID != "stripe-secret-key" {
		t.Fatalf("got %v", ids(got))
	}
	if !strings.HasPrefix(got[0].Secret, "sk_live_") {
		t.Fatalf("secret span wrong: %q", got[0].Secret)
	}
}

func TestIgnoresPlaceholdersAndCode(t *testing.T) {
	for _, line := range []string{
		"STRIPE_SECRET_KEY=",
		j("STRIPE_SECRET_KEY=sk_", "test_", "51Hq8ZtLm2Vx9Rk4Pn7Wb3Jd"),
		"API_KEY=your-api-key-goes-here-123",
		"const token = process.env.API_TOKEN_VALUE_123",
		`password: "${DB_PASSWORD_FROM_VAULT_1}"`,
		"tokenizer := newTokenizer(cfg)",
		"DATABASE_URL=postgres://user:password@localhost:5432/db",
		"DATABASE_URL=postgres://user:${PGPASS}@localhost:5432/db",
		"secret_name = STRIPE_SECRET_KEY",
		"api_key: xxxxxxxxxxxxxxxxxxxxxxxx",
		"// see https://example.com/docs/api-keys",
		"accessToken: aaaaaaaaaaaaaaaa1111",
	} {
		if got := Find(line); len(got) != 0 {
			t.Errorf("false positive %v on %q", ids(got), line)
		}
	}
}

func TestSensitiveFile(t *testing.T) {
	for _, p := range []string{".env", "app/.env.production", ".dev.vars", "keys/id_rsa", "certs/server.pem", "tls.key"} {
		if _, bad := SensitiveFile(p); !bad {
			t.Errorf("%s should be sensitive", p)
		}
	}
	for _, p := range []string{".env.example", "config/.env.sample", "id_rsa.pub", "src/env.go", "README.md"} {
		if _, bad := SensitiveFile(p); bad {
			t.Errorf("%s should not be sensitive", p)
		}
	}
}

func TestEntropy(t *testing.T) {
	if Entropy("aaaaaaaa") != 0 {
		t.Error("constant string should have zero entropy")
	}
	if Entropy("q8Zt2LmV9xR4pK7sW1nB") < 4 {
		t.Error("random string should have high entropy")
	}
}

func ids(ms []Match) []string {
	var out []string
	for _, m := range ms {
		out = append(out, m.Rule.ID)
	}
	return out
}
