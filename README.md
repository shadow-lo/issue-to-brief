# issue-to-brief

A Claude Code skill that turns a GitHub issue into a compact, agent-ready task
brief before any code is written: acceptance criteria, files to touch, the
test command, and per-step model-tier hints. The agent reads one short brief
instead of exploring the repo, so it spends fewer tokens.

It is built to work with two sibling tools:

- **quota-pilot** reads the tier hints (`tier-hint: haiku|sonnet|opus` lines in
  the Markdown, or `steps[].tier_hint` in the JSON) to route each step to the
  cheapest model that can do it.
- **subagent-verify** reads `.claude/briefs/current.json` (`files.likely`,
  `files.must_not_touch`, `acceptance_criteria`) to check that a subagent's
  claimed changes really happened and stayed in scope.

## Install

```bash
mkdir -p ~/.claude/skills
cp -r skill/issue-to-brief ~/.claude/skills/
```

Requires Python 3.9+ (stdlib only, no dependencies). `gh` is optional.

## Use

In Claude Code: "work on acme/demo#42" or "brief this issue: <url>". The skill
runs, for example:

```bash
gh issue view 42 --repo acme/demo --json number,title,body,labels,url \
  | python3 ~/.claude/skills/issue-to-brief/scripts/issue_to_brief.py \
      generate --repo acme/demo --number 42 --stdin
```

or, without `gh`:

```bash
python3 ~/.claude/skills/issue-to-brief/scripts/issue_to_brief.py generate acme/demo#42 --fetch
```

Output in the current repo: `.claude/briefs/issue-42.json`, `issue-42.md`,
`current.json` (and a `.gitignore` so they are not committed). Other commands:
`validate <brief.json>`, `render <brief.json>`, `finalize <brief.json>` (after
editing a brief by hand).

## Security

| Risk | Defence |
|---|---|
| Prompt injection in issue text | Text is sanitized (HTML comments, `<script>`, zero-width, bidi, Unicode tag characters, control chars removed), scanned for 10 injection pattern families plus hidden content, flagged in `untrusted.injection_flags`, and labelled as untrusted data in every brief. Raw text is piped straight to the script so the agent never reads it. Injection flags prevent a `haiku` tier. |
| Smuggling into parsed lines | Tier reasons come from a fixed vocabulary (no parentheses, so the strict `tier-hint` line format always parses). Any `tier-hint` / `quota-pilot` token in issue text is neutralized anywhere in a line, and Unicode line separators (U+2028/2029/0085, VT, FF) are turned into real newlines first so they cannot fake a line. Untrusted inline text is rendered as code spans (no links, autolinks, images or HTML, so no exfiltration via image URLs); the summary is fenced with a fence longer than any in the text. |
| Secret leakage | GitHub/GitLab/AWS/Anthropic/OpenAI/Google/Slack/Discord/Stripe/npm/PyPI/Hugging Face tokens, JWTs, Bearer/Basic headers, private keys (incl. PGP), URL credentials and `password=...` style assignments (quoted or not) are redacted on the raw text, again after sanitizing, and only then truncated, so a length cap can never leave half a token behind. `source.url` is rebuilt from the validated repo and number, never copied. Secrets files (`.env*`, `*.pem`, `id_rsa*`, `.npmrc`, credentials, tfstate, ...) are never put in a brief as files to read or change; a mention adds them to `must_not_touch`, sets `sensitive=true` and raises `secret_file_mention`. Repo scans skip them. The token is read only from `GITHUB_TOKEN`/`GH_TOKEN` (never argv), format-checked, never logged, and scrubbed from errors. |
| Token sent elsewhere | Requests go only to `https://api.github.com`, redirects are refused (they could forward `Authorization`), and the response origin is re-checked. |
| Write access to GitHub | Only HTTP GET is used. |
| Shell injection | No `subprocess`, no shell, no `eval`. Issue refs are validated with strict regexes. The test command is a fixed argv picked from repo config files, never from the issue and never copied from a `package.json` script body, and `validate` accepts only an allow-list of argv shapes (plus up to 5 existing test files for pytest). |
| Path traversal / symlinks | All paths are checked to be repo-relative (no `/`, `..`, `\`, `:`, `~`, leading `-`). Repo scanning never follows symlinks. Output refuses symlinked directories and target files and writes atomically; `finalize` is the only supported way to rewrite a brief after editing. `validate`/`finalize` refuse symlinks and non-regular files and read with a size cap. |
| Agent editing its own guard rails | `.git/`, `.github/`, `.claude/` (settings, hooks, agents, commands, skills and the briefs themselves), `CLAUDE.md`, `CLAUDE.local.md`, `.mcp.json`, `.husky/`, `.githooks/`, `.pre-commit-config.yaml` and `.gitmodules` are always in `must_not_touch`. They can never be expected changes, context or step files, and `allowed_globs` never covers them (`validate` rejects a glob that could). Matching is case-insensitive, so `.Claude/` on macOS/Windows is caught too. |
| Resource exhaustion / ReDoS | Caps on response size, body length, line length, criteria, paths, labels, files scanned, bytes per file and total bytes per scan (one pass for all symbols). Raw text is cut to the GitHub body limit (+4 KB) before any regex runs, dropping the trailing partial line so no secret fragment survives. Line-oriented regexes are linear; tests feed known worst-case inputs at the full 1 MB input cap and require each to finish in under 3 seconds. |

`validate` re-checks all of this, so a brief that was edited by hand (or by a
compromised step) can be rejected before another tool trusts it.

## Tests

```bash
python3 -m unittest discover -s tests -v
```

## Format

See [docs/SCHEMA.md](docs/SCHEMA.md).

## Known limitations

- Secret redaction is pattern-based. A bare high-entropy value with no
  recognizable prefix or `key=` label (for example a bare AWS secret access
  key) is not redacted, and compound names like `mypassword=` with no separator
  or case change are missed.
- `keys/` and `private/` directories are treated as secret locations
  everywhere. This fails safe but hides, for example, i18n `keys/en.json`.
- Bare multi-dot filenames in prose (`webpack.config.js` without a slash or
  backticks) are not extracted.
- All of `.github/` and `.claude/` are guard rails on purpose, so issues about
  CI or Claude config get no file hints for those paths.
- Injection detection is advisory. The real defences are that issue text never
  becomes instructions, commands or parsed lines.
