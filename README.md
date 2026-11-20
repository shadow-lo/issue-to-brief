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
`current.json`. Other commands: `validate <brief.json>`, `render <brief.json>`.

## Security

| Risk | Defence |
|---|---|
| Prompt injection in issue text | Text is sanitized (HTML comments, `<script>`, zero-width, bidi, Unicode tag characters, control chars removed), scanned for 10 injection pattern families plus hidden content, flagged in `untrusted.injection_flags`, and labelled as untrusted data in every brief. Raw text is piped straight to the script so the agent never reads it. Injection flags prevent a `haiku` tier. |
| Smuggling into parsed lines | Tier reasons come from a fixed vocabulary. Issue lines that look like `tier-hint:` or `<!-- quota-pilot` are neutralized. Untrusted Markdown is escaped (no live links or images, so no exfiltration via image URLs) or fenced with a fence longer than any in the text. |
| Secret leakage | GitHub/AWS/Anthropic/OpenAI/Google/Slack/Stripe/npm tokens, JWTs, private keys, URL credentials and `password=...` style assignments are redacted before anything is written. The token is read only from `GITHUB_TOKEN`/`GH_TOKEN` (never argv), format-checked, never logged, and scrubbed from errors. |
| Token sent elsewhere | Requests go only to `https://api.github.com`, redirects are refused (they could forward `Authorization`), and the response origin is re-checked. |
| Write access to GitHub | Only HTTP GET is used. |
| Shell injection | No `subprocess`, no shell, no `eval`. Issue refs are validated with strict regexes. The test command is a fixed argv picked from repo config files, never from the issue and never copied from a `package.json` script body. |
| Path traversal / symlinks | All paths are checked to be repo-relative (no `/`, `..`, `\`, `:`, `~`, leading `-`). Repo scanning never follows symlinks. Output refuses symlinked directories and target files and writes atomically. |
| Agent editing its own guard rails | `.git/`, `.github/workflows/`, `.claude/settings*.json` and `.claude/hooks/` are always in `must_not_touch` and can never be listed as expected changes. |
| Resource exhaustion | Caps on response size, body length, criteria, paths, labels, files scanned and bytes read per file. |

`validate` re-checks all of this, so a brief that was edited by hand (or by a
compromised step) can be rejected before another tool trusts it.

## Tests

```bash
python3 -m unittest discover -s tests -v
```

## Format

See [docs/SCHEMA.md](docs/SCHEMA.md).
