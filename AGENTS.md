# AGENTS.md

This file tells a coding agent how work is done in this repository. It says what
is not visible in the code, and does not restate the code.

## Project at a glance

Two standalone scripts that run one skill of the
[appsec-advisor](https://github.com/appsec-foundry/appsec-advisor) plugin without
an interactive Claude Code session. No package, no build step, no test suite.

- `create-threat-model.sh` — the headless launcher: provision the plugin,
  provision the target, profile it, run the scan through the plugin's own
  runner, publish the report. Everything else in this repository serves it.
- `repo_profile.py` — what a scan would read, before it costs anything.
- `README.md` — the user-facing documentation. A change to a flag, a default or
  a configuration variable is not finished until it is in there.

The plugin itself is not vendored here; the launcher clones or reads it at
runtime (`ADVISOR_SOURCE`, `ADVISOR_REF`, `ADVISOR_LOCAL_PATH`).

## Branch flow

Development happens on `main`. There are no feature branches and no `dev`
branch — commit to `main` directly. Do not open branches for review, and do not
create a pull request unless the operator asks for one.

This differs from the plugin repository next door, which releases from `main`
and develops on `dev`. Do not carry its flow over here.

## Rules that always apply

### `repo_profile.py` is a copy, not a source

It is maintained and tested in the plugin as `scripts/repo_profile.py` and kept
here so the profile still works against an older pinned `ADVISOR_REF`. Fix it
upstream and copy the result; a fix that exists only here will be overwritten
and was never tested.

### The launcher is read from disk while it runs

Bash reads a script by byte offset as it executes it, so a rewrite mid-run makes
the next read land in the middle of another line. The whole body therefore sits
in one brace group: bash parses the file before the first command of it runs.
Keep the closing `}` as the last line, keep the `exit "$RC"` in front of it —
without that exit, bash reads on past the group — and leave the body
unindented; the group is a parsing device, not a block anyone reads.

### One place per decision

- Every setting lives in the `CONFIGURATION` block at the top and reads as
  `VAR="${VAR:-default}"`, so the environment can override it. A new variable
  belongs in `--help config` in the same change.
- A new flag touches three places: the argument parser, `usage()`, and the
  README.
- Output goes through `step` / `info` / `detail` / `ok` / `warn` / `die`.
  The preflight block collects `pf_pass` / `pf_warn` rows and prints them before
  the scan; state there what a run will do, including what it will not do — an
  absence nobody sees is what makes a mistyped command line cost an hour.
- Questions go through `ask_choice`, whose default answer neither destroys nor
  creates anything, and which is only asked where someone can answer it. A
  non-interactive run takes the default and says so.

### Credentials

- No key, token or password is ever written into this repository, into an
  example, or into any output. The scripts name a source (`KEY_SOURCE`,
  `*_TOKEN_FILE`, `ANTHROPIC_API_KEY_CMD`), never a value.
- Tokens reach git through the credential helper in `git_auth`, so they stay out
  of the process list, the URL and the clone's `.git/config`. Keep every new git
  call on `git_auth` / `git_output` for that reason.
- Reading the target and writing the report repository use separate credentials,
  because writing is a different privilege. Do not collapse them.

### Do not weaken what the launcher guarantees

- `TRUST_MODE=untrusted` is the default and keeps the files that steer an
  assistant out of the scanned copy. The list is `REPO_OWNED_PATHS`, and it
  mirrors `_REPO_OWNED_CLAUDE_PATHS` in the plugin's `preflight_untrusted.py`,
  which aborts a run over any of them — so it is kept in sync with the plugin,
  not edited on its own.
- A failed scan publishes nothing: nothing in a file says which run wrote it, so
  the exit code decides before the first file is staged.
- Runtime files pass the plugin's secret scanner before they are published, and
  no scanner means nothing is published.

## Verify a change

There is no test suite, so verification is manual and belongs in every change to
the launcher:

```bash
bash -n create-threat-model.sh
./create-threat-model.sh --help >/dev/null
sh create-threat-model.sh --help >/dev/null        # the re-exec path
APPSEC_ADVISOR_CACHE=/tmp/ctm-cache ADVISOR_SOURCE=local \
    ./create-threat-model.sh --target-dir . --profile-only --output-dir /tmp/ctm-out
```

The last one runs steps 1–5 — no model, no credential, no cost — and proves that
the steps, the traps and the preflight still work. A change to the scan or the
publish path needs a real run against a small target; the report of a finished
run stays in the output directory, so a second run does not have to pay for the
first one's mistake.

`appsec-reports/` is git-ignored. An assessment is never committed here.

## Commit messages

`type: lowercase summary` (`feat`, `fix`, `docs`, `chore`) and a body that says
what went wrong and why the fix has the shape it has. Write for someone who
finds the commit in a year with no memory of the session it came from.
