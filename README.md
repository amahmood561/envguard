# envguard

Stop secrets before they're committed.

envguard is a single Go binary that runs as a git pre-commit hook. It looks at
the lines a commit would **add**, and blocks the commit if one of them is an API
key, a private key, a database password, or a file like `.env` that should never
be in git. It prints where the secret is, never the secret itself.

```
$ git commit -m "wire up billing"
envguard: 2 possible secrets in staged changes; commit blocked

  src/billing.js:14:22  stripe-secret-key      Stripe live secret or restricted key  sk_l********
  .dev.vars             sensitive-file         Wrangler local secrets file

Move secrets into a secret store (for example `wrangler secret put NAME`) and reference them by name.
False positive? Add "envguard:allow" to the line, or the path to .envguardignore.
Unstage a file with: git restore --staged <file>
```

## Install

```sh
go install github.com/amahmood561/envguard@latest
cd your-repo
envguard install          # writes .git/hooks/pre-commit
```

`install` won't replace a pre-commit hook it didn't write. Use `--force`, or add
`envguard staged` to your existing hook.

## Commands

| Command | What it does |
|---|---|
| `envguard install [--force]` | Install the pre-commit hook in the current repository |
| `envguard staged [--json]` | Scan the lines added in the staged change (what the hook runs) |
| `envguard scan [--json] [path...]` | Scan files that could be committed. Inside a repo that means tracked files plus untracked files `.gitignore` doesn't cover |
| `envguard rules` | List what envguard looks for |

Exit status is `0` when nothing is found, `1` when secrets are found and `2` on
an error, so `envguard scan` drops straight into CI.

## What it finds

- **Known key formats:** AWS, Stripe (live secret, restricted and webhook keys), Anthropic,
  OpenAI, GitHub, Slack, Google, Resend, and PEM/OpenSSH private keys
- **Passwords in connection strings** (`postgres://user:pass@host`)
- **Generic secrets:** a variable named like a secret (`*_SECRET`, `*_TOKEN`,
  `api_key`, `password`…) assigned a value that looks random (mixed letters and
  digits, high entropy). Placeholders such as `your-key-here`, `${VAR}` and
  `process.env.X` are ignored, and so are Stripe test and publishable keys.
- **Files that shouldn't be committed:** `.env` and `.env.*` (but not
  `.env.example`), `.dev.vars`, SSH private keys, `.pem`/`.key`/`.p12` files

## Design choices

- **Only added lines block a commit.** A secret already in history shouldn't stop
  every unrelated commit. Run `envguard scan` to find those, then rotate them.
  Removing a secret from history doesn't make it safe again.
- **Output never contains the secret.** Findings show the first four characters
  and a fixed-width mask, so the length isn't revealed either, and CI logs stay clean.
- **No network, no config needed.** Rules are compiled in. Files are scanned in
  parallel, and binary and very large (>5 MB) files are skipped.

## Silencing false positives

```js
const exampleKey = "AKIA..."; // envguard:allow
```

```
# .envguardignore: one glob per line, relative to the repo root
testdata/
*.snap
```

## Develop

```sh
go test ./...
```

Test secrets are assembled at runtime from pieces, so the repository itself
contains nothing that looks like a key.
