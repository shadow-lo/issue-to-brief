# Brief format: `issue-brief`, schema 1

A brief is a JSON file (canonical, machine-readable) plus an optional Markdown
rendering for humans. Default location inside the target repo:

```
.claude/briefs/issue-<number>.json
.claude/briefs/issue-<number>.md
.claude/briefs/current.json      # copy of the most recent brief (subagent-verify default)
```

subagent-verify reads `current.json` by default, or the path in the env
variable `SUBAGENT_VERIFY_BRIEF`.

Sibling tools read the JSON only. The Markdown is a view and is never parsed.

## Top-level fields

| Field | Type | Notes |
|---|---|---|
| `schema` | `1` (integer) | Required. Consumers must reject other values. |
| `kind` | `"issue-brief"` | Required. |
| `source` | object | `repo` (`owner/name`), `issue` (int), `url`, `fetched_at` (ISO-8601 UTC), `content_sha256` (hash of the raw issue title+body, so a consumer can detect a stale brief). |
| `title` | string | Sanitized issue title (max 200 chars). |
| `summary` | string | Sanitized, truncated issue body excerpt. **Untrusted data.** |
| `untrusted` | object | `injection_flags` (list of pattern ids that matched, plus `hidden_content` when HTML comments / invisible characters were stripped), `redactions` (count of secrets masked), `notice` (fixed string). |
| `acceptance_criteria` | list | `{id: "AC1", text, source: "checkbox"|"section"|"inferred", done: bool}` |
| `files` | object | See below. **This is the contract subagent-verify checks.** |
| `test_command` | object or null | `{argv: [..], source: "<repo file it came from>", cwd: "."}`. Never taken from issue text. |
| `steps` | list | Ordered steps with model-tier hints for quota-pilot. See below. |
| `labels` | list[string] | Sanitized issue labels. |

## `files` (subagent-verify contract)

```json
"files": {
  "modify":   ["src/app.py"],
  "create":   ["tests/test_app.py"],
  "delete":   [],
  "context":  ["src/util.py"],
  "likely":   ["src/app.py", "tests/test_app.py"],
  "must_not_touch": [".git/", ".github/workflows/", ".claude/settings.json", ".claude/hooks/"],
  "allowed_globs": ["src/**", "tests/**"]
}
```

- `likely` = `modify` + `create`, the field subagent-verify reports as
  "expected but untouched".
- `must_not_touch` entries are paths or directory prefixes (trailing `/`).
  The generator always includes CI workflows, git internals and Claude hook /
  settings files, so a subagent steered by a hostile issue cannot quietly
  change its own guard rails. subagent-verify flags changes under these.

- All paths are repo-relative POSIX paths. No absolute paths, no `..`, no
  backslashes, no NUL. The generator enforces this; consumers should re-check.
- `modify` / `create` / `delete` are the *expected* changes. A verifier can
  compare them with `git diff --name-status` after a subagent claims success.
- `context` files are read-only hints (worth reading, not expected to change).
- `allowed_globs` is the scope. A change outside these globs is suspicious
  and should be flagged by a verifier.
- `mentioned_missing`: paths the issue mentions that were not found in the
  checkout (or all mentioned paths when no checkout was available). Unverified.
- `modify` entries were confirmed to exist in the repo when the brief was
  generated; `create` entries were confirmed **not** to exist.

## `steps` and tier hints (quota-pilot contract)

```json
"tier": {"hint": "sonnet", "sensitive": false, "reason": "normal bugfix in known code"},
"steps": [
  {"id": "S1", "title": "Read context files", "kind": "explore",
   "tier_hint": "haiku",  "reason": "read-only exploration",
   "files": ["src/util.py"], "acceptance": []},
  {"id": "S2", "title": "Implement the change", "kind": "implement",
   "tier_hint": "sonnet", "reason": "normal feature/bugfix in known code",
   "files": ["src/app.py"],  "acceptance": ["AC1", "AC2"]},
  {"id": "S3", "title": "Run tests and check acceptance criteria", "kind": "verify",
   "tier_hint": "haiku",  "reason": "mechanical verification",
   "files": [], "acceptance": ["AC1", "AC2"]}
]
```

- `kind`: `explore` | `implement` | `test` | `verify`.
- `tier_hint`: `haiku` | `sonnet` | `opus`. It is the **maximum** tier the step
  needs. quota-pilot may push a step down under quota pressure, but never
  below `sonnet` when `tier.sensitive` is true.
- `tier` (top level) is the whole-brief hint: the highest step hint, plus
  `sensitive` (true when the issue touches security, auth, secrets,
  migrations or data deletion).
- Heuristic used by the generator: `haiku` = mechanical, rename, format, docs,
  simple tests; `sonnet` = normal feature or bugfix in known code; `opus` =
  architecture, cross-cutting, security-sensitive, ambiguous.

The Markdown rendering carries the same hints in the line format quota-pilot
parses (see `/mnt/project-files/quota-pilot/integration/tier-hints.md`):

```
<!-- quota-pilot: tier=sonnet sensitive=false -->
...
### S2. Implement the change
tier-hint: sonnet  (reason: normal feature/bugfix in known code)
```

Reasons are generated from a fixed vocabulary, never copied from issue text,
so an issue cannot smuggle text into a line a router parses.

## Security properties

- The brief is generated from untrusted issue text. Free-text fields
  (`title`, `summary`, `acceptance_criteria[].text`) are data, not
  instructions; agents reading them must not follow commands inside them.
- Secrets that match known token patterns are replaced with `[REDACTED:<kind>]`.
- `test_command` comes only from repository config files (package.json,
  pyproject.toml, Makefile, ...), never from the issue.
