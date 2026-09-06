# appsec-advisor-tools

Two companion scripts for [appsec-foundry/appsec-advisor](https://github.com/appsec-foundry/appsec-advisor), the Claude Code plugin that builds threat models from source code. The plugin is normally driven from an interactive Claude Code session. These scripts run one of its skills without a session, from a terminal, a cron job or a CI pipeline.

## create-threat-model.sh

A headless launcher for the plugin's `create-threat-model` skill. It provisions the plugin (from GitHub at a configurable ref, or from a local checkout), provisions the target (a local directory or a fresh clone), profiles it, and then runs the scan through the plugin's own runner. The plugin's other skills are not reachable from here.

```bash
# a local checkout
./create-threat-model.sh --target-dir ~/myapp

# a repository, cloned fresh at a given ref
./create-threat-model.sh --target-repo https://github.com/example/app.git --target-ref main

# scan and publish the finished report into a git repository
./create-threat-model.sh --target-dir ~/myapp --output-repo git@github.com:example/appsec-reports.git

# also build Strix pentest tasks against the running instance
./create-threat-model.sh --target-dir ~/myapp --url http://localhost:3000

# a thorough run with SARIF output, failing the build on high findings
ASSESSMENT_DEPTH=thorough WITH_SARIF=1 FAIL_ON=high ./create-threat-model.sh --target-dir ~/myapp
```

The report lands in `./appsec-reports/<target-slug>/` unless `--output-dir` says otherwise: `threat-model.md` and `threat-model.yaml`, the SARIF, Threat Dragon, PDF and HTML variants where the run was asked for them, `pentest-tasks.yaml` when `--url` named a running instance, and `run.log`. That directory is git-ignored in this repository.

A run with `--output-repo` reads its report from that repository, so the local directory is only where the scan works and the publish step copies from. It moves to `$TMPDIR/appsec-advisor/<target-slug>` for that reason, and the current directory stays clean. That directory is cleared at the start of every publishing run, without asking — what it held was published, and keeping one per run would leave the intermediates of every run ever started behind. The flip side is that such a run starts from nothing every time: no earlier model, no changelog against the last assessment, new finding IDs. `--output-dir` or `OUTPUT_DIR_BASE` names a stable directory instead, publishing or not, and nothing there is ever cleared.

`--help` lists the options, `--help config` every configuration variable.

### A run with everything spelled out

```bash
ADVISOR_REPO_URL=https://github.com/appsec-foundry/appsec-advisor \
ADVISOR_REF=dev \
ASSESSMENT_DEPTH=quick \
WITH_REQUIREMENTS=1 \
./create-threat-model.sh --target-repo https://github.com/juice-shop/juice-shop \
    --url http://localhost:3000 \
    --output-repo https://github.com/example/juice-shop-report \
    --create-output-repo --console-log --max-budget 30
```

- `ADVISOR_REPO_URL` — where the plugin is cloned from; the value above is the default, set it for a fork or a mirror.
- `ADVISOR_REF=dev` — plugin ref to run: branch, tag or commit. Default `latest` = newest release tag.
- `ASSESSMENT_DEPTH=quick` — shallowest of `quick`, `standard` (default), `thorough`.
- `WITH_REQUIREMENTS=1` — grade the findings against the requirements catalog the plugin is configured with; there is no launcher flag for it, the variable is what passes `--requirements` to the run.
- `--target-repo <url>` — clone and scan that repository, here at its default branch.
- `--url http://localhost:3000` — where that repository is running. The scan stays static; the URL only ends up in `pentest-tasks.yaml`, as the target of the Strix tasks.
- `--output-repo <url>` — publish the artifacts there, under `reports/<target-slug>`.
- `--create-output-repo` — create it, private, when it is missing. Needs `OUTPUT_GIT_TOKEN` with creation rights.
- `--console-log` — keep the script's own output as `console.log` and publish it too.
- `--max-budget 30` — stop above $30 estimated cost. API billing only.

## repo_profile.py

Answers what a scan would read, before it costs anything. One directory walk, no agents, no model, no network, no credential, and no file content is read, so it is safe to point at code you have not looked at yet. It says nothing about security; that is what the threat model is for.

```bash
python3 repo_profile.py --repo ~/myapp
python3 repo_profile.py --repo ~/myapp --json
```

```
Repository profile — /home/mrohr/myapp
  working tree at 9a290c1 · 2 of 155 files tracked by git

  size            1.5 MB  155 files
  vendored           0 B  0 files
  source          1.5 MB  155 files

  languages (share of source bytes)
    JSON       78.7%      1.2 MB  110 files
    ...
```

The launcher runs this as its fifth step and writes the JSON to `.target-profile.json` in the output directory. `./create-threat-model.sh --target-dir ~/myapp --profile-only` stops there, which is the cheapest way to size up an unfamiliar repository.

This file is a copy of the plugin's `scripts/repo_profile.py`, kept next to the launcher so the profile also works with an older pinned plugin ref. The plugin is where it is maintained and tested.

## Requirements

`git` and `python3` with `pyyaml` and `jsonschema`, the [Claude Code CLI](https://claude.ai/download) on `PATH` as `claude`, and a Claude subscription or an Anthropic API key. `--profile-only` gets by with `git` and `python3` alone, and `repo_profile.py` on its own needs only `python3`.

## Configuration

Everything sits in the `CONFIGURATION` block at the top of `create-threat-model.sh`, and every value there can be overridden from the environment. The block covers which plugin ref to run (`ADVISOR_SOURCE`, `ADVISOR_REF`, or `ADVISOR_LOCAL_PATH` for a local checkout or packaged build), the scan itself (`ASSESSMENT_DEPTH`, `TRUST_MODE`, `SESSION_MODEL`, `REASONING_MODEL`, `SCAN_MODE`, the `WITH_*` output formats, `RUN_QA`), and the limits (`FAIL_ON`, `MAX_DURATION`, `MAX_BUDGET`).

### Credentials

The scripts hold no key, only the name of a source. `KEY_SOURCE` picks between AWS Secrets Manager (`aws`), any command that prints the key (`cmd`), a `chmod 600` file (`file`), an exported `ANTHROPIC_API_KEY` (`env`), or the first source that is configured (`auto`). `AUTH_MODE=subscription` ignores API keys and bills the Claude subscription instead.

```bash
KEY_SOURCE=aws AWS_SECRET_ID=appsec-advisor/anthropic-api-key \
    ./create-threat-model.sh --target-repo https://gitlab.example.com/team/app.git
```

Reading a private target repository and writing a report repository take separate credentials, because they are separate privileges: `TARGET_GIT_TOKEN` or `TARGET_GIT_TOKEN_FILE` for `--target-repo`, `OUTPUT_GIT_TOKEN` or `OUTPUT_GIT_TOKEN_FILE` for `--output-repo`. Tokens reach git through a credential helper, so they show up neither in the process list nor in the clone's `.git/config`.

Where both repositories live in the same place, one credential does: `GIT_TOKEN` (or `GIT_TOKEN_FILE`, and `GIT_USER` for the account name) is what both pairs fall back to, and the specific variable still wins wherever it is set. One credential for two hosts is the case to think about — the helper answers whatever git asks it about, so the same secret is offered to both — and a run that does that says so in its preflight.

Creating the report repository with `--create-output-repo` is the one thing a git credential cannot do: the repository is made through the host's API, so it needs `OUTPUT_GIT_TOKEN` (or `GIT_TOKEN`) with `repo` on GitHub or `api` on GitLab, which is more than pushing needs. Publishing into a repository that already exists needs no token at all when the URL is an ssh one — that push travels on your key.

### Publishing

`--output-repo <url>` copies the finished artifacts into a clone of that repository and commits them under `reports/<target-slug>`, which `OUTPUT_REPO_PATH` can change. The scan itself always runs into the local output directory, so transient run files stay out of the published report. `OUTPUT_REPO_PUSH=0` commits without pushing.

## Trust mode

Under the default `TRUST_MODE=untrusted`, files that steer an assistant before the plugin can establish its own trust boundary never reach the run: `CLAUDE.md`, `.claude/`, `.vscode/tasks.json` and `.devcontainer/` are dropped from a clone, and a local `--target-dir` that carries them is scanned as a sanitized copy while the original stays untouched. Both cases are reported on stderr. Scanning code you do not control is what that mode is for, so switch it off only for a repository whose instruction files you have read.
