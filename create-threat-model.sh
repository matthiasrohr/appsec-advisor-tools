#!/usr/bin/env bash
# ─────────────────────────────────────────────────────────────────────────────
# create-threat-model.sh — headless launcher for the AppSec Advisor skill of
# the same name. It runs that one skill; the plugin's other skills are not
# reachable from here.
#
#   create-threat-model.sh --target-dir  <path> [--output-dir <dir>]
#   create-threat-model.sh --target-repo <url>  [--output-dir <dir>] [--target-ref <ref>]
#
# What it does: provision the plugin (official GitHub repo at a configurable
# ref, or a local checkout / self-packaged build), provision the target (local
# directory or a fresh clone), then run the scan through the plugin's own
# headless runner (scripts/run-headless.sh → claude -p).
#
# Every value in the CONFIGURATION block can be overridden from the
# environment:  ADVISOR_REF=dev ASSESSMENT_DEPTH=quick create-threat-model.sh …
# ─────────────────────────────────────────────────────────────────────────────

# This script uses bash features (arrays, pipefail). Started as `sh script.sh`
# it would otherwise die on the next line with "Illegal option -o pipefail".
if [ -z "${BASH_VERSION:-}" ]; then
    if command -v bash >/dev/null 2>&1; then
        exec bash "$0" "$@"
    fi
    echo "create-threat-model.sh needs bash — install it, or run: bash $0" >&2
    exit 1
fi

set -Eeuo pipefail

# Where this script lives, so an optional companion next to it is found without
# configuration, wherever the pair was copied to.
SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"

# This launcher was called appsec-scan.sh until it was renamed after the skill
# it runs, and machines that ran it still hold its cache and key files under
# that name. A default path therefore points at the new location but keeps the
# old one while that is the one that exists — a rename must not send the next
# run looking for the API key where it is not.
path_or_legacy() {
    if [ -e "$1" ] || [ ! -e "$2" ]; then printf '%s' "$1"; else printf '%s' "$2"; fi
}

# ══════════════════════════ CONFIGURATION ═══════════════════════════════════

# ── Which appsec-advisor to run ──────────────────────────────────────────────
# official = clone appsec-foundry/appsec-advisor from GitHub
# local    = use a local checkout, a packaged build directory, or a .tgz package
ADVISOR_SOURCE="${ADVISOR_SOURCE:-official}"

ADVISOR_REPO_URL="${ADVISOR_REPO_URL:-https://github.com/appsec-foundry/appsec-advisor.git}"

# latest | main | dev | v0.6.0-beta.2 | <commit-sha>
#   latest = newest release tag; falls back to the newest pre-release tag when
#            the repository carries no stable tag yet.
ADVISOR_REF="${ADVISOR_REF:-latest}"

# Used when ADVISOR_SOURCE=local. Accepts
#   • a checkout root             (~/appsec-advisor)
#   • a packaged build directory  (~/appsec-advisor/build/<internal-name>)
#   • a package tarball           (~/appsec-advisor/dist/<internal-name>-x.y.z.tgz)
ADVISOR_LOCAL_PATH="${ADVISOR_LOCAL_PATH:-$HOME/appsec-advisor}"

# Clones, unpacked packages and sanitized target copies live here. The cache
# belongs to the tool family, not to this one script, so it is not named after
# it. APPSEC_SCAN_CACHE is the earlier name of the variable and still works.
CACHE_DIR="${APPSEC_ADVISOR_CACHE:-${APPSEC_SCAN_CACHE:-$(path_or_legacy "$HOME/.cache/appsec-advisor" "$HOME/.cache/appsec-scan")}}"

# ── Scan options (forwarded to run-headless.sh) ──────────────────────────────
ASSESSMENT_DEPTH="${ASSESSMENT_DEPTH:-standard}"  # quick | standard | thorough
TRUST_MODE="${TRUST_MODE:-untrusted}"             # untrusted | trusted
SESSION_MODEL="${SESSION_MODEL:-}"                # e.g. claude-sonnet-4-6 (empty = plugin default)
REASONING_MODEL="${REASONING_MODEL:-}"            # opus | opus-cheap | sonnet | sonnet-economy
WITH_SARIF="${WITH_SARIF:-0}"                     # 1 → threat-model.sarif.json
WITH_THREATDRAGON="${WITH_THREATDRAGON:-0}"       # 1 → threat-model.threatdragon.json (alpha)
WITH_REQUIREMENTS="${WITH_REQUIREMENTS:-0}"       # 1 → run the requirements check
RUN_QA="${RUN_QA:-1}"                             # 0 → --no-qa (faster, less checked)

# What the run does. Also settable per run with --mode. The compact runtime has
# no incremental mode; a standard run always reassesses the repository.
#   standard = full assessment, report history preserved
#   rebuild  = clear the prior model, cache and history first; finding IDs may change
#   rerender = rebuild the report from the existing Stage-1 fragments, no analysis
# Whether the mode was chosen deliberately. Evaluated before the default lands,
# because an output directory holding a previous run asks for the mode — and it
# must not ask someone who has already answered.
[ -n "${SCAN_MODE:-}" ] && MODE_EXPLICIT=1 || MODE_EXPLICIT=0
SCAN_MODE="${SCAN_MODE:-standard}"
FAIL_ON="${FAIL_ON:-}"                            # critical | high | medium → non-zero exit
MAX_DURATION="${MAX_DURATION:-}"                  # seconds; empty = no wall-clock limit
# Spend cap in USD, also settable per run with --max-budget. It only bites under
# API billing; a subscription run is not metered in dollars.
MAX_BUDGET="${MAX_BUDGET:-}"

# ── Authentication ───────────────────────────────────────────────────────────
# auto         = use a service key when one is configured, else the subscription
# api-key      = require a service key; abort when none can be obtained
# subscription = ignore any API key and bill against the Claude subscription
AUTH_MODE="${AUTH_MODE:-auto}"

# Where the service key comes from. NEVER put a key value in this file; these
# settings only name a source.
#
#   aws    — AWS Secrets Manager through the AWS CLI (AWS_SECRET_ID below)
#   cmd    — any command that prints the key on stdout (ANTHROPIC_API_KEY_CMD)
#   file   — a file holding the key (ANTHROPIC_API_KEY_FILE), chmod 600
#   env    — ANTHROPIC_API_KEY already exported, e.g. a masked GitLab CI variable
#   auto   — first configured source wins, in the order: cmd, aws, file, env
KEY_SOURCE="${KEY_SOURCE:-auto}"

# KEY_SOURCE=aws. Region and credentials come from the AWS CLI's own settings
# (AWS_REGION / AWS_PROFILE / SSO session / instance role).
AWS_SECRET_ID="${AWS_SECRET_ID:-}"          # name or ARN of the secret
AWS_SECRET_FIELD="${AWS_SECRET_FIELD:-}"    # JSON field; empty = secret holds the bare key

# KEY_SOURCE=cmd / file
ANTHROPIC_API_KEY_CMD="${ANTHROPIC_API_KEY_CMD:-}"
ANTHROPIC_API_KEY_FILE="${ANTHROPIC_API_KEY_FILE:-$(path_or_legacy "$HOME/.config/appsec-advisor/api-key" "$HOME/.config/appsec-scan/api-key")}"

KEY_FETCH_TIMEOUT="${KEY_FETCH_TIMEOUT:-60}"  # seconds allowed for fetching the key

# Spend one tiny request to find out whether Anthropic accepts the credential,
# instead of discovering it minutes into the scan.
#   auto = only when a service key is used (run-headless.sh already checks the
#          stored subscription credentials itself) | 1 = always | 0 = never
VERIFY_AUTH="${VERIFY_AUTH:-auto}"
VERBOSITY="${VERBOSITY:-normal}"                  # quiet | normal | verbose
EXTRA_ARGS=()                                     # extra run-headless.sh flags

# Business context for this run: an http(s) URL or a file path. Also settable
# per run with --context. It weights impact ratings; it never creates findings.
CONTEXT_SRC="${CONTEXT_SRC:-}"

# ── Target handling ──────────────────────────────────────────────────────────
CLONE_DEPTH="${CLONE_DEPTH:-1}"                   # 0 → full history (needed for a sha ref)

# Credentials for a private --target-repo over https. Without these, git uses
# whatever it already has: a credential helper, or a key for an ssh URL. The
# token reaches git through a credential helper, so it appears neither in the
# process list nor in the clone's .git/config. It is NOT the same token as
# OUTPUT_GIT_TOKEN below, which writes the report repository.
TARGET_GIT_TOKEN="${TARGET_GIT_TOKEN:-}"
TARGET_GIT_TOKEN_FILE="${TARGET_GIT_TOKEN_FILE:-}"   # file holding it, chmod 600
TARGET_GIT_USER="${TARGET_GIT_USER:-oauth2}"         # GitLab: oauth2, GitHub: x-access-token

# ── Publishing the report to a git repository ────────────────────────────────
# Also settable per run with --output-repo. The scan itself always runs into the
# local output directory; only the finished artifacts are copied into a clone of
# this repository and committed there, so no transient run files are published.
OUTPUT_REPO="${OUTPUT_REPO:-}"                       # git URL, https or ssh
OUTPUT_REPO_BRANCH="${OUTPUT_REPO_BRANCH:-}"         # empty = the repo's default branch
OUTPUT_REPO_PATH="${OUTPUT_REPO_PATH:-}"             # empty = reports/<target-slug>
OUTPUT_REPO_PUSH="${OUTPUT_REPO_PUSH:-1}"            # 0 = commit locally, do not push
OUTPUT_REPO_FILES="${OUTPUT_REPO_FILES:-threat-model.md threat-model.yaml threat-model.sarif.json threat-model.threatdragon.json threat-model.pdf threat-model.html}"

# Write credentials for OUTPUT_REPO. Deliberately separate from the target ones:
# reading a repository and writing to one are different privileges.
OUTPUT_GIT_TOKEN="${OUTPUT_GIT_TOKEN:-}"
OUTPUT_GIT_TOKEN_FILE="${OUTPUT_GIT_TOKEN_FILE:-}"   # file holding it, chmod 600
OUTPUT_GIT_USER="${OUTPUT_GIT_USER:-oauth2}"
OUTPUT_GIT_NAME="${OUTPUT_GIT_NAME:-appsec-advisor}"
OUTPUT_GIT_EMAIL="${OUTPUT_GIT_EMAIL:-appsec-advisor@localhost}"
# Parent directory for the report when --output-dir is omitted. OUTPUT_BASE is
# the earlier name for this and still works.
OUTPUT_DIR_BASE="${OUTPUT_DIR_BASE:-${OUTPUT_BASE:-$PWD/appsec-reports}}"

# ════════════════════════ end of configuration ══════════════════════════════

# Instruction-bearing files the host loads before the plugin can establish its
# own trust boundary. Mirrors _REPO_OWNED_CLAUDE_PATHS in preflight_untrusted.py;
# an untrusted run aborts when the target carries any of them.
REPO_OWNED_PATHS=(
    "CLAUDE.md"
    "CLAUDE.local.md"
    ".claude/settings.json"
    ".claude/settings.local.json"
    ".claude/hooks.json"
    ".claude/hooks"
    ".claude/.mcp.json"
    ".claude/agents"
    ".claude/skills"
    ".claude/commands"
    ".claude/CLAUDE.md"
    ".vscode/tasks.json"
    ".devcontainer/devcontainer.json"
)

# ── Output helpers ───────────────────────────────────────────────────────────
if [ -t 1 ]; then
    C_RED=$'\033[0;31m'; C_GREEN=$'\033[0;32m'; C_YELLOW=$'\033[1;33m'
    C_CYAN=$'\033[0;36m'; C_DIM=$'\033[2m'; C_NC=$'\033[0m'
else
    C_RED=""; C_GREEN=""; C_YELLOW=""; C_CYAN=""; C_DIM=""; C_NC=""
fi

STEP=0
TOTAL_STEPS=7
step()  { STEP=$((STEP + 1)); printf '\n%s▶ [%d/%d] %s%s\n' "$C_CYAN" "$STEP" "$TOTAL_STEPS" "$*" "$C_NC"; }
info()  { printf '      %s\n' "$*"; }
detail(){ printf '      %s%s%s\n' "$C_DIM" "$*" "$C_NC"; }
ok()    { printf '      %s✓%s %s\n' "$C_GREEN" "$C_NC" "$*"; }
warn()  { printf '      %s⚠%s %s\n' "$C_YELLOW" "$C_NC" "$*" >&2; }
die()   { printf '\n%s✗%s %s\n' "$C_RED" "$C_NC" "$*" >&2; exit 1; }

# One shape for every question this script asks: what it found, then both ways
# out with what each one costs, so the two are read side by side instead of one
# after the answer. Returns 0 for the default and 1 for the keyed option.
#   ask_choice <state> <default option> <[r] option> [<dim note>]
# Anything but the key takes the default, and the default is always the option
# that destroys nothing — a typo at this prompt cannot clear an assessment.
ask_choice() {
    local reply
    printf '\n      %s?%s %s\n' "$C_YELLOW" "$C_NC" "$1"
    [ -n "${4:-}" ] && printf '        %s%s%s\n' "$C_DIM" "$4" "$C_NC"
    printf '        %s[Enter]%s  %s\n' "$C_GREEN" "$C_NC" "$2"
    printf '        %s[r]%s      %s\n' "$C_YELLOW" "$C_NC" "$3"
    printf '        choice: '
    read -r reply || reply=""
    printf '\n'
    case "$reply" in r|R|rebuild) return 1 ;; *) return 0 ;; esac
}

# Ctrl-C reaches the whole process group, so the scan dies with it — but the
# runner then exits with SIGPIPE (141), not SIGINT, and bash walks on into the
# result and publish steps and pushes a report the user just aborted. Stop the
# launcher with the run instead.
on_interrupt() {
    trap - INT TERM
    printf '\n%s✗%s interrupted at step %d/%d\n' "$C_RED" "$C_NC" "$STEP" "$TOTAL_STEPS" >&2
    exit 130
}
trap on_interrupt INT TERM

usage() {
    cat <<'HELP'
create-threat-model.sh — run the AppSec Advisor skill create-threat-model
headlessly against a repository, and optionally publish the report.

Usage:
  create-threat-model.sh --target-dir  <path> [options]
  create-threat-model.sh --target-repo <url>  [options]

Options:
  --target-dir  <path>   Local directory to scan
  --target-repo <url>    Git repository to clone and scan (https://, ssh:// or git@)
  --target-ref  <ref>    Branch, tag or commit for --target-repo
  --output-dir  <dir>    Report directory (default: ./appsec-reports/<target-slug>)
  --output-repo <url>    Publish the finished report into this git repository
  --context     <src>    Business context for this run: http(s) URL or file path
  --mode        <mode>   standard (default) = full assessment, history preserved
                         rebuild            = clear model, cache and history first
                         rerender           = re-render from existing Stage-1 data
                         Without --mode, the output directory decides: a
                         finished report asks whether to keep it, a finished
                         analysis that was never rendered offers the render,
                         and what an interrupted analysis left is rebuilt.
                         Unattended, each of the three takes the first option.
  --max-budget  <usd>    Stop the run when the estimated cost exceeds this
                         amount. API billing only (MAX_BUDGET sets a default).
  --profile-only         Print the target's size, language split and build
                         manifests, then stop. No model, no credential, no cost.
  -h, --help             This help
  --help config          Every configuration variable and its values

Examples:
  create-threat-model.sh --target-dir ~/myapp
  KEY_SOURCE=aws AWS_SECRET_ID=appsec-advisor/anthropic-api-key \
      create-threat-model.sh --target-repo https://gitlab.example.com/team/app.git

Configuration comes from the CONFIGURATION block at the top of this file; every
value there can be overridden from the environment.
HELP
}

usage_config() {
    cat <<'HELP'
Configuration variables. Every one can be set in the environment or edited in
the CONFIGURATION block at the top of the script.

Plugin and scan:
  ADVISOR_SOURCE=official|local   ADVISOR_REF=latest|main|dev|<tag>|<sha>
  ADVISOR_LOCAL_PATH=<checkout|build-dir|.tgz>
  TARGET_GIT_TOKEN=…   TARGET_GIT_TOKEN_FILE=<chmod 600>   TARGET_GIT_USER=oauth2
      credentials for a private --target-repo over https (GitLab PAT, project or
      group token; GitHub: TARGET_GIT_USER=x-access-token). ssh URLs use your key.
  OUTPUT_DIR_BASE=<dir>  parent of the report directory when --output-dir is omitted
  OUTPUT_REPO=<url>  OUTPUT_REPO_BRANCH=<branch>  OUTPUT_REPO_PATH=reports/<slug>
  OUTPUT_REPO_PUSH=1|0   OUTPUT_REPO_FILES="threat-model.md threat-model.yaml …"
  OUTPUT_GIT_TOKEN=…  OUTPUT_GIT_TOKEN_FILE=<chmod 600>  OUTPUT_GIT_USER=oauth2
  OUTPUT_GIT_NAME=appsec-advisor   OUTPUT_GIT_EMAIL=appsec-advisor@localhost
      write credentials and commit identity for the report repository; kept
      separate from the target ones because writing is a different privilege
  ASSESSMENT_DEPTH=quick|standard|thorough        TRUST_MODE=untrusted|trusted
  SESSION_MODEL=<model>   REASONING_MODEL=<tier>  VERBOSITY=quiet|normal|verbose
  SCAN_MODE=standard|rebuild|rerender             (same as --mode)
  WITH_SARIF=1  WITH_THREATDRAGON=1  WITH_REQUIREMENTS=1  RUN_QA=0
  FAIL_ON=critical|high|medium      MAX_DURATION=<seconds>   MAX_BUDGET=<usd>

Service key (the key value never belongs in this file, only its source):
  AUTH_MODE=auto|api-key|subscription
  KEY_SOURCE=auto|aws|cmd|file|env              KEY_FETCH_TIMEOUT=<seconds>
          auto takes the first configured source, in this order:
          cmd, aws, file, env — name a source explicitly to override it
  VERIFY_AUTH=auto|1|0     one tiny request that proves the credential is accepted

  aws     AWS_SECRET_ID=<name|arn>  AWS_SECRET_FIELD=<json field, optional>
          region and credentials come from the AWS CLI (AWS_REGION, AWS_PROFILE, SSO,
          instance role)
  cmd     ANTHROPIC_API_KEY_CMD="…"              any command printing the key
  file    ANTHROPIC_API_KEY_FILE=~/.config/appsec-advisor/api-key   (chmod 600)
  env     ANTHROPIC_API_KEY=…                    e.g. a masked GitLab CI variable
HELP
}

# ── Arguments ────────────────────────────────────────────────────────────────
TARGET_DIR=""; TARGET_REPO=""; TARGET_REF=""; OUTPUT_DIR=""; PROFILE_ONLY=0
while [ $# -gt 0 ]; do
    case "$1" in
        --profile-only) PROFILE_ONLY=1; shift ;;
        --target-dir)  TARGET_DIR="${2:?--target-dir needs a path}";  shift 2 ;;
        --target-repo) TARGET_REPO="${2:?--target-repo needs a URL}"; shift 2 ;;
        --target-ref)  TARGET_REF="${2:?--target-ref needs a ref}";   shift 2 ;;
        --output-dir|--output|-o)
                       OUTPUT_DIR="${2:?--output-dir needs a path}";  shift 2 ;;
        --context)     CONTEXT_SRC="${2:?--context needs a URL or a file path}"; shift 2 ;;
        --output-repo) OUTPUT_REPO="${2:?--output-repo needs a git URL}"; shift 2 ;;
        --mode)        SCAN_MODE="${2:?--mode needs standard, rebuild or rerender}"; MODE_EXPLICIT=1; shift 2 ;;
        --max-budget)  MAX_BUDGET="${2:?--max-budget needs an amount in USD}"; shift 2 ;;
        -h|--help)
            case "${2:-}" in
                config|all|env) usage_config ;;
                *)              usage ;;
            esac
            exit 0 ;;
        *)             usage >&2; die "unknown option: $1" ;;
    esac
done

[ -n "$TARGET_DIR" ] || [ -n "$TARGET_REPO" ] || { usage >&2; die "give --target-dir or --target-repo"; }
[ -n "$TARGET_DIR" ] && [ -n "$TARGET_REPO" ] && die "--target-dir and --target-repo are mutually exclusive"
[ -z "$TARGET_REF" ] || [ -n "$TARGET_REPO" ] || die "--target-ref applies to --target-repo only"
[ "$PROFILE_ONLY" = "0" ] || [ -z "$OUTPUT_REPO" ] || die "--profile-only produces no report, so there is nothing to publish to --output-repo"

case "$ADVISOR_SOURCE"   in official|local) ;; *) die "ADVISOR_SOURCE must be 'official' or 'local' (got: $ADVISOR_SOURCE)" ;; esac
case "$TRUST_MODE"       in untrusted|trusted) ;; *) die "TRUST_MODE must be 'untrusted' or 'trusted' (got: $TRUST_MODE)" ;; esac
case "$ASSESSMENT_DEPTH" in quick|standard|thorough) ;; *) die "ASSESSMENT_DEPTH must be quick, standard or thorough (got: $ASSESSMENT_DEPTH)" ;; esac
case "$VERBOSITY"        in quiet|normal|verbose) ;; *) die "VERBOSITY must be quiet, normal or verbose (got: $VERBOSITY)" ;; esac
case "$SCAN_MODE" in
    standard|rebuild|rerender) ;;
    incremental) die "the compact runtime has no incremental mode — use --mode standard (it reassesses the repository and keeps the report history)" ;;
    *) die "--mode must be standard, rebuild or rerender (got: $SCAN_MODE)" ;;
esac
case "$AUTH_MODE"        in auto|api-key|subscription) ;; *) die "AUTH_MODE must be auto, api-key or subscription (got: $AUTH_MODE)" ;; esac
case "$KEY_SOURCE"       in auto|aws|cmd|file|env) ;; *) die "KEY_SOURCE must be auto, aws, cmd, file or env (got: $KEY_SOURCE)" ;; esac
case "$KEY_FETCH_TIMEOUT" in ''|*[!0-9]*) die "KEY_FETCH_TIMEOUT must be a whole number of seconds (got: $KEY_FETCH_TIMEOUT)" ;; esac
[ -z "$MAX_BUDGET" ] || case "$MAX_BUDGET" in
    *[!0-9.]*|.*|*.*.*|0|0.0|0.00) die "--max-budget must be a positive amount in USD (got: $MAX_BUDGET)" ;;
esac
[ -z "$MAX_DURATION" ] || case "$MAX_DURATION" in *[!0-9]*) die "MAX_DURATION must be a whole number of seconds (got: $MAX_DURATION)" ;; esac
[ -z "$FAIL_ON" ] || case "$FAIL_ON" in critical|high|medium) ;; *) die "FAIL_ON must be critical, high or medium (got: $FAIL_ON)" ;; esac

if [ -z "$TARGET_GIT_TOKEN" ] && [ -n "$TARGET_GIT_TOKEN_FILE" ]; then
    [ -f "$TARGET_GIT_TOKEN_FILE" ] || die "TARGET_GIT_TOKEN_FILE does not exist: $TARGET_GIT_TOKEN_FILE"
    [ -r "$TARGET_GIT_TOKEN_FILE" ] || die "TARGET_GIT_TOKEN_FILE is not readable: $TARGET_GIT_TOKEN_FILE"
    tg_perm="$(stat -c '%a' "$TARGET_GIT_TOKEN_FILE" 2>/dev/null || stat -f '%Lp' "$TARGET_GIT_TOKEN_FILE" 2>/dev/null || true)"
    case "$tg_perm" in
        *00) : ;;
        "")  warn "cannot determine the permissions of $TARGET_GIT_TOKEN_FILE" ;;
        *)   die "$TARGET_GIT_TOKEN_FILE is readable beyond its owner (mode $tg_perm) — run: chmod 600 $TARGET_GIT_TOKEN_FILE" ;;
    esac
    TARGET_GIT_TOKEN="$(cat -- "$TARGET_GIT_TOKEN_FILE")"
fi
TARGET_GIT_TOKEN="$(printf '%s' "$TARGET_GIT_TOKEN" | tr -d '[:space:]')"

if [ -z "$OUTPUT_GIT_TOKEN" ] && [ -n "$OUTPUT_GIT_TOKEN_FILE" ]; then
    [ -f "$OUTPUT_GIT_TOKEN_FILE" ] || die "OUTPUT_GIT_TOKEN_FILE does not exist: $OUTPUT_GIT_TOKEN_FILE"
    [ -r "$OUTPUT_GIT_TOKEN_FILE" ] || die "OUTPUT_GIT_TOKEN_FILE is not readable: $OUTPUT_GIT_TOKEN_FILE"
    og_perm="$(stat -c '%a' "$OUTPUT_GIT_TOKEN_FILE" 2>/dev/null || stat -f '%Lp' "$OUTPUT_GIT_TOKEN_FILE" 2>/dev/null || true)"
    case "$og_perm" in
        *00) : ;;
        "")  warn "cannot determine the permissions of $OUTPUT_GIT_TOKEN_FILE" ;;
        *)   die "$OUTPUT_GIT_TOKEN_FILE is readable beyond its owner (mode $og_perm) — run: chmod 600 $OUTPUT_GIT_TOKEN_FILE" ;;
    esac
    OUTPUT_GIT_TOKEN="$(cat -- "$OUTPUT_GIT_TOKEN_FILE")"
fi
OUTPUT_GIT_TOKEN="$(printf '%s' "$OUTPUT_GIT_TOKEN" | tr -d '[:space:]')"

if [ -n "$OUTPUT_REPO" ]; then
    case "$OUTPUT_REPO_PUSH" in 0|1) ;; *) die "OUTPUT_REPO_PUSH must be 0 or 1 (got: $OUTPUT_REPO_PUSH)" ;; esac
    # The path is joined onto a clone's working tree; keep it inside it.
    case "$OUTPUT_REPO_PATH" in
        /*)        die "OUTPUT_REPO_PATH must be relative to the repository root (got: $OUTPUT_REPO_PATH)" ;;
        *..*)      die "OUTPUT_REPO_PATH must not contain '..' (got: $OUTPUT_REPO_PATH)" ;;
        *[[:space:]]*) die "OUTPUT_REPO_PATH must not contain spaces (got: $OUTPUT_REPO_PATH)" ;;
    esac
    [ -n "$OUTPUT_REPO_FILES" ] || die "OUTPUT_REPO_FILES is empty — there would be nothing to publish"
fi

if [ -n "$CONTEXT_SRC" ]; then
    case "$CONTEXT_SRC" in
        *[[:space:]]*)      die "--context takes a URL or a file path without spaces — put pasted text in a file and pass that" ;;
        https://*|http://*) : ;;
        *://*)              die "--context takes an http(s) URL or a file path (got: $CONTEXT_SRC)" ;;
        *)
            [ -e "$CONTEXT_SRC" ] || die "--context file does not exist: $CONTEXT_SRC"
            [ -f "$CONTEXT_SRC" ] || die "--context is not a regular file: $CONTEXT_SRC"
            [ -r "$CONTEXT_SRC" ] || die "--context file is not readable: $CONTEXT_SRC"
            [ -s "$CONTEXT_SRC" ] || die "--context file is empty: $CONTEXT_SRC"
            # The scan runs with the plugin directory as its working directory,
            # so a relative path would be resolved against the wrong place.
            CONTEXT_SRC="$(cd "$(dirname "$CONTEXT_SRC")" && pwd)/$(basename "$CONTEXT_SRC")"
            case "$CONTEXT_SRC" in
                *[[:space:]]*) die "the context file's absolute path contains spaces, which the plugin's --context cannot carry: $CONTEXT_SRC" ;;
            esac ;;
    esac
fi

# Slug for cache and default output paths — never let a repository name reach a
# filesystem path unfiltered.
raw_name="${TARGET_DIR:-$TARGET_REPO}"
raw_name="${raw_name%/}"; raw_name="${raw_name##*/}"; raw_name="${raw_name%.git}"
SLUG="$(printf '%s' "$raw_name" | tr -c 'A-Za-z0-9._-' '-' | sed 's/^-*//; s/-*$//')"
[ -n "$SLUG" ] || SLUG="target"
[ -n "$OUTPUT_REPO_PATH" ] || OUTPUT_REPO_PATH="reports/$SLUG"
[ -n "$OUTPUT_REPO" ] && TOTAL_STEPS=8
# Preflight, plugin, target, output directory, profile — and then nothing.
[ "$PROFILE_ONLY" = "1" ] && TOTAL_STEPS=5

# A git URL is handed to `git clone`; a leading dash would become an option and
# ext:: would make git execute a command from the URL.
validate_git_url() {
    case "$1" in
        -*)                             die "refusing a git URL that starts with '-': $1" ;;
        https://*|http://*|ssh://*|git@*) : ;;
        *)                              die "unsupported git URL: $1 (use https://, ssh:// or git@)" ;;
    esac
}

# Resolve which credential the run bills against, and export it for the child
# process. Only the credential's origin, type and length are ever printed — the
# value goes to the environment and nowhere else, in particular not into run.log.
AUTH_DESC="subscription"
KEY_SOURCE_EFFECTIVE=""

# Which backend actually applies. In auto mode the first configured one wins.
select_key_source() {
    local s="$KEY_SOURCE"
    if [ "$s" = "auto" ]; then
        if   [ -n "$ANTHROPIC_API_KEY_CMD" ]; then s="cmd"
        elif [ -n "$AWS_SECRET_ID" ];         then s="aws"
        elif [ -n "$ANTHROPIC_API_KEY_FILE" ] && [ -f "$ANTHROPIC_API_KEY_FILE" ]; then s="file"
        elif [ -n "${ANTHROPIC_API_KEY:-}" ]; then s="env"
        else s="none"
        fi
    fi
    KEY_SOURCE_EFFECTIVE="$s"
}

# Everything that can be settled without a network call, settled before one.
check_key_source() {
    local perm=""
    case "$KEY_SOURCE_EFFECTIVE" in
        aws)
            command -v aws >/dev/null 2>&1 \
                || die "KEY_SOURCE=aws, but the AWS CLI is not installed — see https://docs.aws.amazon.com/cli/"
            [ -n "$AWS_SECRET_ID" ] || die "KEY_SOURCE=aws, but AWS_SECRET_ID is not set (name or ARN of the secret)"
            if [ -z "${AWS_REGION:-}${AWS_DEFAULT_REGION:-}" ] && [ -z "$(aws configure get region 2>/dev/null)" ]; then
                case "$AWS_SECRET_ID" in
                    arn:aws:secretsmanager:*) : ;;  # the ARN carries the region
                    *) die "no AWS region configured — set AWS_REGION, run 'aws configure', or give AWS_SECRET_ID as a full ARN" ;;
                esac
            fi ;;
        cmd)
            [ -n "$ANTHROPIC_API_KEY_CMD" ] || die "KEY_SOURCE=cmd, but ANTHROPIC_API_KEY_CMD is empty" ;;
        file)
            [ -n "$ANTHROPIC_API_KEY_FILE" ] || die "KEY_SOURCE=file, but ANTHROPIC_API_KEY_FILE is empty"
            [ -f "$ANTHROPIC_API_KEY_FILE" ] || die "key file not found: $ANTHROPIC_API_KEY_FILE"
            [ -r "$ANTHROPIC_API_KEY_FILE" ] || die "key file is not readable: $ANTHROPIC_API_KEY_FILE"
            perm="$(stat -c '%a' "$ANTHROPIC_API_KEY_FILE" 2>/dev/null || stat -f '%Lp' "$ANTHROPIC_API_KEY_FILE" 2>/dev/null || true)"
            case "$perm" in
                *00) : ;;
                "")  warn "cannot determine the permissions of $ANTHROPIC_API_KEY_FILE" ;;
                *)   die "key file $ANTHROPIC_API_KEY_FILE is readable beyond its owner (mode $perm) — run: chmod 600 $ANTHROPIC_API_KEY_FILE" ;;
            esac ;;
        env)
            [ -n "${ANTHROPIC_API_KEY:-}" ] || die "KEY_SOURCE=env, but ANTHROPIC_API_KEY is not set" ;;
    esac
}

# A secret store behind an expired session or a VPN can hang instead of failing.
run_bounded() {
    if command -v timeout >/dev/null 2>&1; then
        timeout "$KEY_FETCH_TIMEOUT" "$@"
    else
        "$@"
    fi
}

fetch_key() {  # prints the raw secret on stdout; the caller captures stderr
    case "$KEY_SOURCE_EFFECTIVE" in
        aws)    run_bounded aws secretsmanager get-secret-value \
                    --secret-id "$AWS_SECRET_ID" --query SecretString --output text ;;
        # The command comes from this launcher's own configuration, never from
        # scanned repository content, so a shell is the right thing to run it in.
        cmd)    run_bounded sh -c "$ANTHROPIC_API_KEY_CMD" ;;
        file)   cat -- "$ANTHROPIC_API_KEY_FILE" ;;
        env)    printf '%s' "${ANTHROPIC_API_KEY:-}" ;;
    esac
}

# Turn a backend's exit code and its own diagnostics into one actionable line.
explain_key_failure() {  # explain_key_failure <exit-code> <backend-stderr>
    local rc="$1" text="$2"
    if [ "$rc" = "124" ]; then
        die "fetching the service key timed out after ${KEY_FETCH_TIMEOUT}s — raise KEY_FETCH_TIMEOUT, or check the secret store"
    fi
    case "$KEY_SOURCE_EFFECTIVE" in
        aws)
            case "$text" in
                *ExpiredToken*|*"has expired"*|*"Error loading SSO Token"*|*"session associated with this profile"*)
                    die "the AWS credentials have expired — run: aws sso login${AWS_PROFILE:+ --profile $AWS_PROFILE}" ;;
                *"Unable to locate credentials"*|*"NoCredentialProviders"*)
                    die "no AWS credentials found — configure an SSO profile, set AWS_PROFILE, or run this on a host with an instance role" ;;
                *AccessDenied*|*UnauthorizedOperation*)
                    die "AWS denied access to secret '$AWS_SECRET_ID' — the identity needs secretsmanager:GetSecretValue on it, plus kms:Decrypt when a customer-managed key encrypts it" ;;
                *ResourceNotFoundException*)
                    die "secret '$AWS_SECRET_ID' does not exist in this account and region — check AWS_SECRET_ID, AWS_REGION and AWS_PROFILE" ;;
                *InvalidRequestException*)
                    die "AWS refused the request for '$AWS_SECRET_ID' — the secret may be scheduled for deletion" ;;
                *)  die "reading '$AWS_SECRET_ID' from AWS Secrets Manager failed (aws exit $rc)" ;;
            esac ;;
        cmd)
            die "ANTHROPIC_API_KEY_CMD failed (exit $rc)" ;;
        *)
            die "could not read the service key (exit $rc)" ;;
    esac
}

# One request with a one-word answer, the cheapest way to learn whether the
# credential is accepted at all.
verify_auth() {
    local out rc=0
    info "auth: checking the credential with a one-word request"
    out="$(run_bounded "$CLAUDE_EXECUTABLE" -p 'Reply with the single word: ok' --output-format text 2>&1)" || rc=$?
    if [ "$rc" -ne 0 ] || printf '%s' "$out" | grep -qiE '401|invalid bearer|not authenticated|authentication_error|invalid.?api.?key'; then
        printf '%s\n' "$out" | head -3 | sed 's/^/      /' >&2
        case "$KEY_SOURCE_EFFECTIVE" in
            ""|none) die "Anthropic did not accept the stored subscription credentials — run 'claude auth login', or set a service key (KEY_SOURCE)" ;;
            *)       die "Anthropic rejected the service key from $1 — it may be revoked, belong to another organization, or have no credit left" ;;
        esac
    fi
    ok "credential accepted"
}

# git with the target credentials, when there are any. The token travels in the
# environment of the credential helper, never on the command line, and never
# into the clone's .git/config.
# GIT_TIMEOUT bounds a probe; a clone gets none, it may legitimately take long.
# The credentials are a command prefix, so they stay out of the launcher's own
# environment and never reach the scanning agent.
git_auth() {  # git_auth <user> <token> <git arguments...>
    local user="$1" token="$2"; shift 2
    local pre=()
    if [ -n "${GIT_TIMEOUT:-}" ] && command -v timeout >/dev/null 2>&1; then
        pre=(timeout "$GIT_TIMEOUT")
    fi
    if [ -n "$token" ]; then
        APPSEC_GIT_USER="$user" APPSEC_GIT_TOKEN="$token" GIT_TERMINAL_PROMPT=0 \
            ${pre[@]+"${pre[@]}"} git -c credential.helper= \
            -c 'credential.helper=!f() { printf "username=%s\npassword=%s\n" "$APPSEC_GIT_USER" "$APPSEC_GIT_TOKEN"; }; f' \
            "$@"
    else
        # Without this, git prompts for a username on a private repository and
        # the launcher hangs instead of failing.
        GIT_TERMINAL_PROMPT=0 ${pre[@]+"${pre[@]}"} git "$@"
    fi
}
git_target() { git_auth "$TARGET_GIT_USER" "$TARGET_GIT_TOKEN" "$@"; }
git_output() { git_auth "$OUTPUT_GIT_USER" "$OUTPUT_GIT_TOKEN" "$@"; }

# Is the remote there, and may we read it? Answered before a clone starts.
check_remote_repo() {  # check_remote_repo <url> <description> [none|target|output] [allow-empty]
    local url="$1" what="$2" creds="${3:-none}" allow_empty="${4:-0}" err rc=0 text
    # Reset per call: the caller reads it to say so in its own words instead of
    # letting git's "cloned an empty repository" warning speak for the launcher.
    REMOTE_EMPTY=0
    err="$(mktemp)"
    case "$creds" in
        target) GIT_TIMEOUT="$KEY_FETCH_TIMEOUT" git_target ls-remote --quiet --exit-code -- "$url" HEAD >/dev/null 2>"$err" || rc=$? ;;
        output) GIT_TIMEOUT="$KEY_FETCH_TIMEOUT" git_output ls-remote --quiet --exit-code -- "$url" HEAD >/dev/null 2>"$err" || rc=$? ;;
        *)      GIT_TERMINAL_PROMPT=0 run_bounded git ls-remote --quiet --exit-code -- "$url" HEAD >/dev/null 2>"$err" || rc=$? ;;
    esac
    text="$(tr -d '\r' <"$err" | tr '\n' ' ')"
    rm -f "$err"
    [ "$rc" -eq 0 ] && return 0
    case "$rc" in
        2)   # An empty repository has nothing to scan, but it is a perfectly
             # good place to publish the first report into.
             if [ "$allow_empty" = "1" ]; then
                 REMOTE_EMPTY=1
                 return 0
             fi
             die "$what is an empty repository: $url" ;;
        124) die "$url did not answer within ${KEY_FETCH_TIMEOUT}s — check the network or the VPN" ;;
    esac
    case "$text" in
        *"not found"*|*"Not Found"*|*"does not appear to be a git repository"*)
            die "$what does not exist, or the credentials in use cannot see it: $url" ;;
        *"could not read Username"*|*"terminal prompts disabled"*)
            # A private and a missing repository look identical over https: the
            # host answers both with an authentication challenge.
            die "$what is not readable without credentials: $url — it either does not exist or it is private. Configure a git credential helper, or use an ssh URL with a loaded key" ;;
        *"Authentication failed"*|*"Invalid username or password"*)
            die "the stored credentials for $url were rejected — check the token in your git credential helper" ;;
        *"Permission denied"*)
            die "the ssh key was rejected for $url — check 'ssh -T' against that host" ;;
        *"Could not resolve host"*)
            die "cannot resolve the host of $url — check the URL and your DNS" ;;
        *"Connection refused"*|*"Connection timed out"*|*"unable to access"*)
            die "cannot reach $url — the host may need a VPN or a proxy" ;;
        *)  die "$what is not readable: $url${text:+ ($text)}" ;;
    esac
}

resolve_auth() {
    if [ "$AUTH_MODE" = "subscription" ]; then
        # An API key exported in the ambient environment would silently take
        # precedence over the subscription — drop it for the child process.
        unset ANTHROPIC_API_KEY
        if [ -n "${CLAUDE_CODE_OAUTH_TOKEN:-}" ]; then
            AUTH_DESC="subscription (CLAUDE_CODE_OAUTH_TOKEN)"
        else
            AUTH_DESC="subscription (stored credentials — run 'claude auth login' if the scan fails to authenticate)"
        fi
        info "auth: $AUTH_DESC"
        return 0
    fi

    select_key_source
    if [ "$KEY_SOURCE_EFFECTIVE" = "none" ]; then
        if [ "$AUTH_MODE" = "api-key" ]; then
            die "AUTH_MODE=api-key, but no key source is configured — set KEY_SOURCE and its settings (AWS_SECRET_ID, ANTHROPIC_API_KEY_CMD, ANTHROPIC_API_KEY_FILE or ANTHROPIC_API_KEY)"
        fi
        unset ANTHROPIC_API_KEY
        AUTH_DESC="subscription (no service key configured)"
        info "auth: $AUTH_DESC"
        return 0
    fi
    check_key_source

    local key="" origin="" err_file="" err_text="" rc=0
    case "$KEY_SOURCE_EFFECTIVE" in
        aws)    origin="AWS Secrets Manager ($AWS_SECRET_ID)" ;;
        cmd)    origin="ANTHROPIC_API_KEY_CMD" ;;
        file)   origin="$ANTHROPIC_API_KEY_FILE" ;;
        env)    origin="the environment" ;;
    esac
    info "auth: fetching the service key from $origin"

    err_file="$(mktemp)"
    key="$(fetch_key 2>"$err_file")" || rc=$?
    err_text="$(tr -d '\r' <"$err_file" | tr '\n' ' ')"
    if [ "$rc" -ne 0 ]; then
        # Show the backend's own diagnostics first, then one line on what to do.
        [ -s "$err_file" ] && sed 's/^/      /' "$err_file" >&2
        rm -f "$err_file"
        explain_key_failure "$rc" "$err_text"
    fi
    rm -f "$err_file"

    # An AWS secret is often a JSON document with several fields.
    if [ "$KEY_SOURCE_EFFECTIVE" = "aws" ] && [ -n "$AWS_SECRET_FIELD" ]; then
        key="$(printf '%s' "$key" | python3 -c '
import json, sys
field = sys.argv[1]
try:
    data = json.loads(sys.stdin.read())
except Exception:
    sys.exit("the secret is not JSON, but AWS_SECRET_FIELD is set")
if not isinstance(data, dict) or field not in data:
    present = ", ".join(sorted(data)) if isinstance(data, dict) else "none"
    sys.exit("the secret has no field %r (present: %s)" % (field, present))
print(str(data[field]))
' "$AWS_SECRET_FIELD")" || die "could not read field '$AWS_SECRET_FIELD' from secret '$AWS_SECRET_ID'"
    fi

    # A trailing newline from a secret store or an editor is invisible here and
    # surfaces minutes into the run as a bare 401.
    key="$(printf '%s' "$key" | tr -d '[:space:]')"

    if [ -z "$key" ]; then
        die "$origin returned an empty value — check the secret's name and content"
    fi

    # A JSON blob instead of a key means the field was not selected.
    case "$key" in
        \{*)
            if [ "$KEY_SOURCE_EFFECTIVE" = "aws" ] && [ -z "$AWS_SECRET_FIELD" ]; then
                die "secret '$AWS_SECRET_ID' holds JSON, not a bare key — set AWS_SECRET_FIELD to the field that carries it"
            fi
            die "$origin returned JSON, not a key value" ;;
    esac

    case "$key" in
        sk-ant-api*) : ;;
        sk-ant-oat*) die "the value from $origin is a subscription OAuth token (sk-ant-oat…), not an API key — set AUTH_MODE=subscription and export CLAUDE_CODE_OAUTH_TOKEN instead" ;;
        sk-ant-*)    warn "the value from $origin is an Anthropic credential of an unexpected type" ;;
        *)           warn "the value from $origin does not look like an Anthropic key (expected sk-ant-…)" ;;
    esac

    export ANTHROPIC_API_KEY="$key"
    # With both present the API key wins; drop the token so billing is unambiguous.
    unset CLAUDE_CODE_OAUTH_TOKEN
    KEY_ORIGIN="$origin"
    AUTH_DESC="API key from $origin (${#key} chars)"
    info "auth: $AUTH_DESC — billed per token, not against the subscription"
    if [ -n "$MAX_BUDGET" ]; then
        info "spend cap: \$$MAX_BUDGET"
    else
        warn "no spend cap for this API-billed run — set --max-budget <usd> or MAX_BUDGET"
    fi
}

# ═════════════════════════════ 1. Preflight ══════════════════════════════════
step "Preflight"

CLAUDE_EXECUTABLE="${APPSEC_CLAUDE_EXECUTABLE:-claude}"
command -v git >/dev/null 2>&1 || die "git not found"
command -v python3 >/dev/null 2>&1 || die "python3 not found"
ok "git $(git --version | awk '{print $3}'), python3 $(python3 -c 'import sys;print("%d.%d.%d"%sys.version_info[:3])')"

# The profile is a directory walk. It needs neither the CLI, nor the pipeline's
# python packages, nor a credential — requiring them would keep the one mode
# that costs nothing out of the places that have no key.
if [ "$PROFILE_ONLY" = "1" ]; then
    AUTH_DESC="not used (--profile-only)"
    ok "profile only — no credential needed, no model will be called"
else
    command -v "$CLAUDE_EXECUTABLE" >/dev/null 2>&1 \
        || die "Claude Code CLI not found ($CLAUDE_EXECUTABLE). Install it: https://claude.ai/download"
    python3 -c 'import yaml, jsonschema' >/dev/null 2>&1 \
        || die "python3 is missing pyyaml/jsonschema — the pipeline needs both: python3 -m pip install pyyaml jsonschema"
    ok "claude $("$CLAUDE_EXECUTABLE" --version 2>/dev/null | head -1)"

    resolve_auth
    if [ -n "$MAX_BUDGET" ] && [ "${KEY_SOURCE_EFFECTIVE:-none}" = "none" ]; then
        warn "a spend cap only limits API-billed runs; this one bills against the subscription, so \$$MAX_BUDGET is ignored"
    fi
    case "$VERIFY_AUTH" in
        1)    verify_auth "${KEY_ORIGIN:-the configured credential}" ;;
        auto) [ "${KEY_SOURCE_EFFECTIVE:-none}" != "none" ] && verify_auth "${KEY_ORIGIN:-the configured credential}" ;;
    esac
fi

# The plugin fetches a context URL through its own URL policy, which rejects
# hosts resolving to private, loopback or reserved addresses. Say so now rather
# than letting the run discover it.
case "${CONTEXT_SRC:-}" in
    http://*|https://*)
        ctx_rc=0
        python3 - "$CONTEXT_SRC" <<'PY' || ctx_rc=$?
import ipaddress, socket, sys, urllib.parse
host = urllib.parse.urlparse(sys.argv[1]).hostname or ""
if not host:
    sys.exit(3)
try:
    infos = socket.getaddrinfo(host, None)
except OSError:
    sys.exit(2)
for info in infos:
    ip = ipaddress.ip_address(info[4][0])
    if ip.is_private or ip.is_loopback or ip.is_link_local or ip.is_reserved:
        sys.exit(1)
PY
        case "$ctx_rc" in
            0) ok "context source reachable by name: $CONTEXT_SRC" ;;
            1) warn "the context URL resolves to a private address — the plugin's URL policy rejects those; pass the document as a file instead" ;;
            2)  # Behind a proxy the name is resolved there, not here, so an
                # unresolvable name says nothing about reachability.
                if [ -n "${https_proxy:-}${HTTPS_PROXY:-}${http_proxy:-}${HTTP_PROXY:-}" ]; then
                    detail "context URL not resolvable locally; a proxy is configured, so this says nothing"
                else
                    warn "cannot resolve the host of the context URL from here: $CONTEXT_SRC"
                fi ;;
            3) die  "--context URL has no host: $CONTEXT_SRC" ;;
        esac ;;
    "") : ;;
    *)  ok "context file: $CONTEXT_SRC" ;;
esac

mkdir -p "$CACHE_DIR" || die "cannot create cache directory: $CACHE_DIR"

# ══════════════════════ 2. Provision the plugin ══════════════════════════════
step "Provision appsec-advisor ($ADVISOR_SOURCE)"

# Newest tag: prefer stable releases, fall back to pre-releases. `sort -V`
# orders v0.6.0 before v0.6.0-beta.2, so pre-releases must be filtered out
# rather than sorted against stable tags.
newest_tag() {
    local dir="$1" all stable
    all="$(git -C "$dir" tag --list 'v[0-9]*')"
    [ -n "$all" ] || return 1
    stable="$(printf '%s\n' "$all" | grep -v -- '-' || true)"
    if [ -n "$stable" ]; then
        printf '%s\n' "$stable" | sort -V | tail -1
    else
        printf '%s\n' "$all" | sort -V | tail -1
    fi
}

provision_official() {
    validate_git_url "$ADVISOR_REPO_URL"
    check_remote_repo "$ADVISOR_REPO_URL" "the appsec-advisor repository"
    PLUGIN_DIR="$CACHE_DIR/appsec-advisor"
    if [ -d "$PLUGIN_DIR/.git" ]; then
        info "updating cached clone: $PLUGIN_DIR"
        git -C "$PLUGIN_DIR" remote set-url origin "$ADVISOR_REPO_URL"
        git -C "$PLUGIN_DIR" fetch --quiet --tags --force --prune origin || die "git fetch failed for $ADVISOR_REPO_URL"
    else
        info "cloning $ADVISOR_REPO_URL"
        git clone --quiet -- "$ADVISOR_REPO_URL" "$PLUGIN_DIR" || die "git clone failed for $ADVISOR_REPO_URL"
    fi

    local want="$ADVISOR_REF" sha=""
    if [ "$want" = "latest" ]; then
        want="$(newest_tag "$PLUGIN_DIR")" || die "ADVISOR_REF=latest, but the repository has no v* tag"
        case "$want" in *-*) warn "no stable release tag yet — using pre-release $want" ;; esac
    fi
    sha="$(git -C "$PLUGIN_DIR" rev-parse -q --verify "refs/tags/$want^{commit}" 2>/dev/null || true)"
    [ -n "$sha" ] || sha="$(git -C "$PLUGIN_DIR" rev-parse -q --verify "refs/remotes/origin/$want^{commit}" 2>/dev/null || true)"
    [ -n "$sha" ] || sha="$(git -C "$PLUGIN_DIR" rev-parse -q --verify "$want^{commit}" 2>/dev/null || true)"
    [ -n "$sha" ] || die "ADVISOR_REF '$ADVISOR_REF' is not a tag, branch or commit in $ADVISOR_REPO_URL"

    git -C "$PLUGIN_DIR" checkout --quiet --detach "$sha"
    git -C "$PLUGIN_DIR" reset --quiet --hard "$sha"
    ADVISOR_VERSION="$want ($(git -C "$PLUGIN_DIR" rev-parse --short HEAD))"
}

provision_local() {
    local p="$ADVISOR_LOCAL_PATH"
    [ -e "$p" ] || die "ADVISOR_LOCAL_PATH does not exist: $p"

    if [ -f "$p" ]; then
        case "$p" in
            *.tgz|*.tar.gz) : ;;
            *) die "ADVISOR_LOCAL_PATH is a file but not a .tgz/.tar.gz package: $p" ;;
        esac
        local digest dest
        digest="$(sha256sum "$p" | cut -c1-12)"
        dest="$CACHE_DIR/packages/$(basename "$p")-$digest"
        if [ ! -d "$dest" ]; then
            info "unpacking package $(basename "$p")"
            mkdir -p "$dest"
            tar -xzf "$p" -C "$dest" || die "cannot unpack $p"
        else
            detail "package already unpacked: $dest"
        fi
        p="$dest"
    fi

    if [ -f "$p/.claude-plugin/plugin.json" ]; then
        PLUGIN_DIR="$p"
    else
        # Packaged builds and unpacked tarballs put the plugin one level down
        # (build/<internal-name>/…), so look exactly one level deep.
        local found=() d
        for d in "$p"/*/; do
            [ -f "$d/.claude-plugin/plugin.json" ] && found+=("${d%/}")
        done
        case ${#found[@]} in
            1) PLUGIN_DIR="${found[0]}" ;;
            0) die "no .claude-plugin/plugin.json in $p or its immediate subdirectories" ;;
            *) die "several plugin roots under $p — point ADVISOR_LOCAL_PATH at one of them" ;;
        esac
    fi
    PLUGIN_DIR="$(cd "$PLUGIN_DIR" && pwd)"
    if git -C "$PLUGIN_DIR" rev-parse --git-dir >/dev/null 2>&1; then
        ADVISOR_VERSION="local checkout ($(git -C "$PLUGIN_DIR" describe --tags --always --dirty 2>/dev/null || echo 'unknown'))"
    else
        ADVISOR_VERSION="local package"
    fi
}

if [ "$ADVISOR_SOURCE" = "official" ]; then provision_official; else provision_local; fi

[ -f "$PLUGIN_DIR/.claude-plugin/plugin.json" ] || die "not a plugin directory: $PLUGIN_DIR"
RUNNER="$PLUGIN_DIR/scripts/run-headless.sh"
# --profile-only never reaches the runner, so a plugin that cannot scan is no
# reason to refuse a directory walk.
[ "$PROFILE_ONLY" = "1" ] || [ -x "$RUNNER" ] || [ -f "$RUNNER" ] || die "headless runner missing: $RUNNER"
PLUGIN_NAME="$(python3 -c 'import json,sys;print(json.load(open(sys.argv[1])).get("name","?"))' "$PLUGIN_DIR/.claude-plugin/plugin.json" 2>/dev/null || echo '?')"
ok "plugin '$PLUGIN_NAME' — $ADVISOR_VERSION"
detail "$PLUGIN_DIR"

# ══════════════════════ 3. Provision the target ══════════════════════════════
step "Provision target"

# Instruction-bearing files present at the target root (untrusted preflight aborts on these).
list_repo_owned() {
    local root="$1" rel
    for rel in "${REPO_OWNED_PATHS[@]}"; do
        [ -e "$root/$rel" ] && printf '%s\n' "$rel"
    done
    return 0
}

strip_repo_owned() {
    local root="$1" rel
    for rel in "${REPO_OWNED_PATHS[@]}"; do
        rm -rf -- "${root:?}/$rel"
    done
}

if [ -n "$TARGET_REPO" ]; then
    validate_git_url "$TARGET_REPO"
    case "$TARGET_REPO" in
        https://*:*@*|http://*:*@*)
            warn "the target URL carries credentials — those land in the clone's .git/config and in the process list; TARGET_GIT_TOKEN does the same job without either" ;;
    esac
    if [ -n "$TARGET_GIT_TOKEN" ]; then
        case "$TARGET_REPO" in
            https://*) info "using TARGET_GIT_TOKEN for the clone (user: $TARGET_GIT_USER)" ;;
            *) warn "TARGET_GIT_TOKEN is set but the target URL is not https — ssh access uses your key, the token is ignored" ;;
        esac
    fi
    check_remote_repo "$TARGET_REPO" "the target repository" target
    if [ -n "$TARGET_REF" ] && ! printf '%s' "$TARGET_REF" | grep -qE '^[0-9a-f]{7,40}$'; then
        GIT_TIMEOUT="$KEY_FETCH_TIMEOUT" git_target ls-remote --exit-code --heads --tags -- "$TARGET_REPO" "$TARGET_REF" >/dev/null 2>&1 \
            || die "branch or tag '$TARGET_REF' does not exist in $TARGET_REPO"
    fi
    TARGET="$CACHE_DIR/targets/$SLUG"
    rm -rf "$TARGET"; mkdir -p "$(dirname "$TARGET")"
    info "cloning $TARGET_REPO${TARGET_REF:+ @ $TARGET_REF}"
    if printf '%s' "$TARGET_REF" | grep -qE '^[0-9a-f]{7,40}$'; then
        # A commit sha cannot be cloned with --branch, and a shallow clone would
        # not contain it.
        git_target clone --quiet -- "$TARGET_REPO" "$TARGET" || die "git clone failed"
        git -C "$TARGET" checkout --quiet --detach "$TARGET_REF" || die "commit $TARGET_REF not found in $TARGET_REPO"
    else
        clone_args=(clone --quiet)
        [ "$CLONE_DEPTH" != "0" ] && clone_args+=(--depth "$CLONE_DEPTH")
        [ -n "$TARGET_REF" ] && clone_args+=(--branch "$TARGET_REF")
        git_target "${clone_args[@]}" -- "$TARGET_REPO" "$TARGET" || die "git clone failed"
    fi
    if [ "$TRUST_MODE" = "untrusted" ]; then
        stripped="$(list_repo_owned "$TARGET")"
        if [ -n "$stripped" ]; then
            strip_repo_owned "$TARGET"
            warn "stripped repo-owned agent configuration from the clone: $(printf '%s ' $stripped)"
        fi
    fi
    ok "target checked out at $(git -C "$TARGET" rev-parse --short HEAD)"
else
    [ -e "$TARGET_DIR" ] || die "--target-dir does not exist: $TARGET_DIR"
    [ -d "$TARGET_DIR" ] || die "--target-dir is not a directory: $TARGET_DIR"
    [ -r "$TARGET_DIR" ] && [ -x "$TARGET_DIR" ] || die "--target-dir is not readable: $TARGET_DIR"
    TARGET="$(cd "$TARGET_DIR" && pwd)"
    [ -n "$(ls -A "$TARGET" 2>/dev/null)" ] || die "--target-dir is empty, there is nothing to scan: $TARGET"
    present=""
    [ "$TRUST_MODE" = "untrusted" ] && present="$(list_repo_owned "$TARGET")"
    if [ -n "$present" ]; then
        # The untrusted preflight would abort on these, and the source directory
        # belongs to the user — scan a sanitized copy instead of editing it.
        copy="$CACHE_DIR/targets/$SLUG-sanitized"
        warn "target carries repo-owned agent configuration: $(printf '%s ' $present)"
        info "scanning a sanitized copy instead (original untouched): $copy"
        rm -rf "$copy"; mkdir -p "$copy"
        if command -v rsync >/dev/null 2>&1; then
            excludes=(); for rel in "${REPO_OWNED_PATHS[@]}"; do excludes+=("--exclude=/$rel"); done
            rsync -a --delete "${excludes[@]}" "$TARGET"/ "$copy"/ || die "copying the target failed"
        else
            cp -a "$TARGET"/. "$copy"/ || die "copying the target failed"
            strip_repo_owned "$copy"
        fi
        TARGET="$copy"
    fi
    ok "scanning $TARGET"
fi

sym_count="$(find "$TARGET" -type l 2>/dev/null | wc -l | tr -d ' ')"
if [ "$sym_count" != "0" ] && [ "$TRUST_MODE" = "untrusted" ]; then
    warn "$sym_count symlink(s) in the target — the untrusted preflight aborts on symlinks that escape the repository root"
fi

# ══════════════════════ 4. Prepare the output directory ══════════════════════
step "Prepare output directory"

[ -n "$OUTPUT_DIR" ] || OUTPUT_DIR="$OUTPUT_DIR_BASE/$SLUG"
mkdir -p "$OUTPUT_DIR" || die "cannot create output directory: $OUTPUT_DIR"
OUTPUT_DIR="$(cd "$OUTPUT_DIR" && pwd)"
LOG_FILE="$OUTPUT_DIR/run.log"

case "$OUTPUT_DIR/" in
    "$TARGET"/docs/security/*|"$TARGET"/docs/security/) : ;;
    "$TARGET"/*)
        # The run fingerprints the target's working tree; files written anywhere
        # but docs/security/ during the run invalidate it mid-scan.
        warn "output directory sits inside the scanned repository outside docs/security/ — this can invalidate the run's repository fingerprint" ;;
esac
# What a rerender consumes, named the way the runtime's own preflight names it:
# the merged and triaged analysis, the model, and at least three compose
# fragments. Asking the same question here means the launcher offers a render
# exactly where the runtime would perform one, instead of on a proxy of its own
# that can be true while the render aborts.
rerender_inputs_missing() {
    local dir="$1" name count missing=""
    for name in threat-model.yaml .threats-merged.json .triage-flags.json; do
        [ -f "$dir/$name" ] || missing="$missing $name"
    done
    count="$(find "$dir/.fragments" -maxdepth 1 -type f 2>/dev/null | wc -l | tr -d ' ')"
    [ "${count:-0}" -ge 3 ] || missing="$missing .fragments/(>=3)"
    printf '%s' "${missing# }"
}

if [ "$SCAN_MODE" = "rerender" ]; then
    # A rerender re-renders the assessment of an earlier run in this very
    # directory; without its artifacts there is nothing to render.
    rerender_missing="$(rerender_inputs_missing "$OUTPUT_DIR")"
    [ -z "$rerender_missing" ] \
        || die "--mode rerender needs the assessment of an earlier run in $OUTPUT_DIR — missing: $rerender_missing; run --mode standard first"
fi

ok "$OUTPUT_DIR"
detail "log: $LOG_FILE"

# GNU and BSD stat agree on nothing but the file they are asked about.
file_date() {
    local d
    d="$(stat -c '%y' "$1" 2>/dev/null | cut -d' ' -f1)" || d=""
    [ -n "$d" ] || d="$(stat -f '%Sm' -t '%Y-%m-%d' "$1" 2>/dev/null || true)"
    printf '%s' "$d"
}

# What is in here, and whether it is a finished assessment at all. threat-model.md
# is the plugin's own completion marker — its runtime_cleanup.py refuses to clean
# a directory without one — and the orchestrator deletes .appsec-checkpoint when
# a run completes, so a checkpoint still lying here is a run that stopped.
# threat-model.yaml settles nothing: it grows while the analysis is still
# running, and a run killed halfway leaves a large one behind that no report was
# ever composed from. Asking "keep it?" about that offered to keep a torso.
CHECKPOINT_FILE="$OUTPUT_DIR/.appsec-checkpoint"
PREVIOUS_REPORT=""
[ -f "$OUTPUT_DIR/threat-model.md" ] && PREVIOUS_REPORT="$OUTPUT_DIR/threat-model.md"
DISCARD_STAGE1=0

# The one interruption this runtime can continue: Stage 1 finished and was
# validated, only the report was never rendered. Everything else it refuses —
# --resume and --incremental are gone, and a fresh run restarts Stage 1 whatever
# a stopped one left behind. The three tokens are the ones the plugin's own guard
# reads, each matched on its own so their order in the line stays irrelevant.
CHECKPOINT_NEEDS_RENDER=0
if [ -f "$CHECKPOINT_FILE" ] \
        && grep -q 'phase=10b'        "$CHECKPOINT_FILE" \
        && grep -q 'status=completed' "$CHECKPOINT_FILE" \
        && grep -q 'need_render=true' "$CHECKPOINT_FILE"; then
    CHECKPOINT_NEEDS_RENDER=1
fi
# That checkpoint says Stage 1 reached the boundary, not that what it left can
# still be rendered — a run killed during the compose leaves the marker and a
# fragment set the renderer rejects. Only offer the render when the runtime's own
# preflight would accept the inputs.
STAGE1_RENDERABLE=0
if [ "$CHECKPOINT_NEEDS_RENDER" = "1" ] && [ -z "$(rerender_inputs_missing "$OUTPUT_DIR")" ]; then
    STAGE1_RENDERABLE=1
fi

# Reassessing keeps the previous report's model, history and cache; a rebuild
# throws all three away and may change finding IDs. Not a decision to make
# silently for someone — but only ask where someone can answer, never where the
# mode was already chosen, and never where the leftovers leave nothing to choose.
if [ "$PROFILE_ONLY" = "0" ] && [ "$MODE_EXPLICIT" = "0" ]; then
    if [ "$STAGE1_RENDERABLE" = "1" ]; then
        prev_when="$(file_date "$CHECKPOINT_FILE")"
        SCAN_MODE="rerender"
        if [ -t 0 ]; then
            if ask_choice \
                "a run from ${prev_when:-an earlier day} finished its analysis but never rendered a report" \
                "render that analysis, nothing is analyzed again" \
                "rebuild from scratch; that finished analysis is discarded"; then
                ok "rendering the finished analysis — nothing is analyzed again"
            else
                SCAN_MODE="rebuild"
                ok "rebuilding — that finished analysis is discarded"
            fi
        else
            info "a run from ${prev_when:-an earlier day} finished its analysis but never rendered a report — rendering it; --mode rebuild starts from scratch"
        fi
    elif [ -n "$PREVIOUS_REPORT" ]; then
        prev_when="$(file_date "$PREVIOUS_REPORT")"
        residue_note=""
        [ -f "$CHECKPOINT_FILE" ] && residue_note="a later run stopped before finishing; either choice clears what it left"
        if [ -t 0 ]; then
            if ask_choice \
                "a report from ${prev_when:-an earlier run} is already here" \
                "reassess and keep that report, its history and finding ids" \
                "rebuild from scratch; history and finding ids are not kept" \
                "$residue_note"; then
                SCAN_MODE="standard"; ok "reassessing — the previous report is kept"
            else
                SCAN_MODE="rebuild";  ok "rebuilding — the previous model, cache and history are cleared"
            fi
        else
            [ -n "$residue_note" ] && detail "$residue_note"
            info "a report from ${prev_when:-an earlier run} is already here — reassessing and keeping it; --mode rebuild starts from scratch"
        fi
    elif [ -f "$CHECKPOINT_FILE" ] || [ -f "$OUTPUT_DIR/threat-model.yaml" ]; then
        # Analysis broken off, no report, and a model file that stopped growing
        # wherever the run died. Reassessing would keep that torso as the run's
        # own prior model — the next model carries its components, boundaries and
        # meta-findings forward, none of which was ever validated or rendered.
        # There is nothing here to keep, so the one question this could ask has
        # one answer: take it, and say so.
        SCAN_MODE="rebuild"
        info "an earlier run stopped in here before it had a report — starting from scratch"
    fi
    # Any run but a render is refused over that Stage-1 boundary unless the
    # discard is stated. Every path that arrives here with another mode has
    # stated it: someone chose it over the offered render, or the boundary points
    # at artifacts that can no longer be rendered at all.
    if [ "$CHECKPOINT_NEEDS_RENDER" = "1" ] && [ "$SCAN_MODE" != "rerender" ]; then DISCARD_STAGE1=1; fi
fi

if [ -n "$OUTPUT_REPO" ]; then
    # Settle reachability now. Discovering an unreachable publishing target
    # after a scan that ran for twenty minutes helps nobody.
    validate_git_url "$OUTPUT_REPO"
    case "$OUTPUT_REPO" in
        https://*) [ -n "$OUTPUT_GIT_TOKEN" ] || warn "no OUTPUT_GIT_TOKEN set — the push will only work if git already has write credentials for $OUTPUT_REPO" ;;
    esac
    check_remote_repo "$OUTPUT_REPO" "the output repository" output 1
    if [ -n "$OUTPUT_REPO_BRANCH" ]; then
        GIT_TIMEOUT="$KEY_FETCH_TIMEOUT" git_output ls-remote --exit-code --heads -- "$OUTPUT_REPO" "$OUTPUT_REPO_BRANCH" >/dev/null 2>&1 \
            || die "branch '$OUTPUT_REPO_BRANCH' does not exist in $OUTPUT_REPO — create it first, publishing does not open new branches"
    fi
    ok "report will be published to $OUTPUT_REPO in $OUTPUT_REPO_PATH/"
    [ "${REMOTE_EMPTY:-0}" = "1" ] && detail "the repository is still empty — this run publishes the first report into it"
fi

# ══════════════════════ 5. Profile the target ════════════════════════════════
step "Profile target"

# Size, language split, build manifests and how much of the tree git does not
# track. Deterministic, no model, no network, and no file content is read, so it
# costs a directory walk. Two invocations because the script renders either text
# or JSON, never both — the same walk twice.
#
# The copy next to this launcher wins: it makes the profile work with any pinned
# ADVISOR_REF. It is a copy of the plugin's scripts/repo_profile.py, which is
# where the file is maintained and tested; the provisioned plugin is the
# fallback when the companion is absent.
PROFILE_SCRIPT="$SCRIPT_DIR/repo_profile.py"
[ -f "$PROFILE_SCRIPT" ] || PROFILE_SCRIPT="$PLUGIN_DIR/scripts/repo_profile.py"
PROFILE_JSON="$OUTPUT_DIR/.target-profile.json"
if [ ! -f "$PROFILE_SCRIPT" ]; then
    # No companion, and a pinned older ADVISOR_REF predates the script in the
    # plugin. No reason to stop a scan, but it is the whole job of --profile-only.
    [ "$PROFILE_ONLY" = "1" ] \
        && die "no repo_profile.py — neither next to this script nor in the provisioned appsec-advisor ($ADVISOR_VERSION)"
    warn "no repo_profile.py next to this script and none in the provisioned appsec-advisor ($ADVISOR_VERSION) — skipping the profile"
elif python3 "$PROFILE_SCRIPT" --repo "$TARGET" 2>&1 | sed 's/^\(.\)/      \1/' | tee -a "$LOG_FILE"; then
    python3 "$PROFILE_SCRIPT" --repo "$TARGET" --json >"$PROFILE_JSON" 2>/dev/null \
        || warn "could not write $PROFILE_JSON"
    detail "profile: $PROFILE_JSON"
else
    [ "$PROFILE_ONLY" = "1" ] && die "profiling $TARGET failed"
    warn "profiling the target failed — the scan continues without a profile"
fi

if [ "$PROFILE_ONLY" = "1" ]; then
    printf '\n'
    ok "profile only — no scan was started, nothing was billed"
    exit 0
fi

# ══════════════════════════════ 6. Scan ══════════════════════════════════════
step "Run threat model (headless)"

ARGS=(--repo "$TARGET" --output "$OUTPUT_DIR"
      --assessment-depth "$ASSESSMENT_DEPTH"
      --trust-mode "$TRUST_MODE")
case "$SCAN_MODE" in
    standard) ARGS+=(--full) ;;
    rebuild)  ARGS+=(--rebuild) ;;
    rerender) ARGS+=(--rerender) ;;
esac
# Step 4 settles this: the runtime refuses to analyze over an unrendered Stage-1
# boundary, and only a run that knowingly leaves that boundary behind says so.
if [ "$DISCARD_STAGE1" = "1" ]; then ARGS+=(--force); fi
[ "$RUN_QA" = "0" ]             && ARGS+=(--no-qa)
[ "$WITH_SARIF" = "1" ]         && ARGS+=(--sarif)
[ "$WITH_THREATDRAGON" = "1" ]  && ARGS+=(--threatdragon)
[ "$WITH_REQUIREMENTS" = "1" ]  && ARGS+=(--requirements)
[ -n "$SESSION_MODEL" ]         && ARGS+=(--model "$SESSION_MODEL")
[ -n "$REASONING_MODEL" ]       && ARGS+=(--reasoning-model "$REASONING_MODEL")
[ -n "$MAX_DURATION" ]          && ARGS+=(--max-duration "$MAX_DURATION")
[ -n "$MAX_BUDGET" ]            && ARGS+=(--max-budget "$MAX_BUDGET")
[ -n "$FAIL_ON" ]               && ARGS+=(--fail-on "$FAIL_ON")
[ -n "$CONTEXT_SRC" ]           && ARGS+=(--context "$CONTEXT_SRC")
[ "$VERBOSITY" = "quiet" ]      && ARGS+=(--quiet)
[ "$VERBOSITY" = "verbose" ]    && ARGS+=(--verbose)
ARGS+=(${EXTRA_ARGS[@]+"${EXTRA_ARGS[@]}"})

info "mode=$SCAN_MODE depth=$ASSESSMENT_DEPTH trust=$TRUST_MODE qa=$([ "$RUN_QA" = 1 ] && echo on || echo off)${SESSION_MODEL:+ model=$SESSION_MODEL}${REASONING_MODEL:+ reasoning=$REASONING_MODEL}"
detail "run-headless.sh ${ARGS[*]}"
printf '\n'

{
    printf '=== create-threat-model %s ===\n' "$(date -u '+%Y-%m-%dT%H:%M:%SZ')"
    printf 'plugin : %s (%s)\n' "$PLUGIN_DIR" "$ADVISOR_VERSION"
    printf 'target : %s\n' "$TARGET"
    printf 'auth   : %s\n' "$AUTH_DESC"
    printf 'command: run-headless.sh %s\n\n' "${ARGS[*]}"
} >>"$LOG_FILE"

cd "$PLUGIN_DIR"
set +e
sh "$RUNNER" "${ARGS[@]}" 2>&1 | tee -a "$LOG_FILE"
RC=${PIPESTATUS[0]}
set -e

# ═══════════════════════════ 7. Result ═══════════════════════════════════════
step "Result"

if [ "$RC" -eq 0 ]; then
    ok "run finished (exit 0)"
else
    warn "run-headless.sh exited with code $RC — see $LOG_FILE"
fi

printf '\n      %sArtifacts in %s%s\n' "$C_DIM" "$OUTPUT_DIR" "$C_NC"
found_any=0
for name in threat-model.md threat-model.yaml threat-model.sarif.json \
            threat-model.threatdragon.json threat-model.pdf threat-model.html run.log; do
    f="$OUTPUT_DIR/$name"
    if [ -f "$f" ]; then
        found_any=1
        printf '      %-34s %s\n' "$name" "$(du -h "$f" | cut -f1)"
    fi
done
[ "$found_any" = "1" ] || warn "no report artifacts were written"

if [ -f "$OUTPUT_DIR/threat-model.yaml" ] && [ -f "$PLUGIN_DIR/scripts/run_summary.py" ]; then
    printf '\n'
    python3 "$PLUGIN_DIR/scripts/run_summary.py" findings "$OUTPUT_DIR/threat-model.yaml" 2>/dev/null || true
fi

# ══════════════════════ 8. Publish the report ════════════════════════════════
if [ -n "$OUTPUT_REPO" ]; then
    step "Publish report to $OUTPUT_REPO"

    PUB_DIR="$CACHE_DIR/publish/$SLUG"
    rm -rf "$PUB_DIR"; mkdir -p "$(dirname "$PUB_DIR")"
    pub_clone=(clone --quiet --depth 1)
    [ -n "$OUTPUT_REPO_BRANCH" ] && pub_clone+=(--branch "$OUTPUT_REPO_BRANCH")
    # git warns "You appear to have cloned an empty repository" on stderr. For a
    # publishing target that is the normal first run, not a problem, and the raw
    # warning reads like one. Swallow that line, pass everything else through.
    pub_err="$(mktemp)"
    if ! git_output "${pub_clone[@]}" -- "$OUTPUT_REPO" "$PUB_DIR" 2>"$pub_err"; then
        sed 's/^/      /' <"$pub_err" >&2
        rm -f "$pub_err"
        die "cannot clone the output repository: $OUTPUT_REPO"
    fi
    if grep -q "cloned an empty repository" "$pub_err" 2>/dev/null; then
        # Step 4 already said so when it checked the remote; saying it twice
        # makes one harmless fact look like a developing problem.
        [ "${REMOTE_EMPTY:-0}" = "1" ] \
            || info "the output repository is empty — this run publishes the first report into it"
    elif [ -s "$pub_err" ]; then
        sed 's/^/      /' <"$pub_err" >&2
    fi
    rm -f "$pub_err"

    PUB_DEST="$PUB_DIR/$OUTPUT_REPO_PATH"
    mkdir -p "$PUB_DEST"
    published=0
    for name in $OUTPUT_REPO_FILES; do
        if [ -f "$OUTPUT_DIR/$name" ]; then
            cp -f "$OUTPUT_DIR/$name" "$PUB_DEST/$name"
            published=$((published + 1))
            detail "staged $OUTPUT_REPO_PATH/$name"
        fi
    done
    if [ "$published" -eq 0 ]; then
        # Say which of the two it is. An empty output repository is fine and
        # says nothing about this; what decides is whether the run produced a
        # report at all.
        if [ "$RC" -ne 0 ]; then
            warn "the scan failed (exit $RC), so no report exists to publish — $OUTPUT_REPO is unchanged"
        else
            warn "the run wrote none of $OUTPUT_REPO_FILES, so there is nothing to publish — $OUTPUT_REPO is unchanged"
        fi
    else
        git -C "$PUB_DIR" add -- "$OUTPUT_REPO_PATH" || die "git add failed in the output clone"
        if git -C "$PUB_DIR" diff --cached --quiet; then
            ok "the published report is unchanged, no commit needed"
        else
            COMMIT_MSG="appsec-advisor: threat model for $SLUG ($(date -u '+%Y-%m-%d'))"
            git -C "$PUB_DIR" -c "user.name=$OUTPUT_GIT_NAME" -c "user.email=$OUTPUT_GIT_EMAIL" \
                commit --quiet -m "$COMMIT_MSG" || die "the commit in the output clone failed"
            ok "committed $published file(s): $COMMIT_MSG"

            if [ "$OUTPUT_REPO_PUSH" != "1" ]; then
                info "OUTPUT_REPO_PUSH=0 — the commit stays in $PUB_DIR"
            else
                push_err="$(mktemp)"
                if ! git_output -C "$PUB_DIR" push --quiet origin HEAD 2>"$push_err"; then
                    push_text="$(tr -d '\r' <"$push_err" | tr '\n' ' ')"
                    case "$push_text" in
                        *"non-fast-forward"*|*"fetch first"*|*"behind"*)
                            # Someone else published in the meantime. Replay this
                            # commit on top of theirs, once.
                            info "the branch moved on the remote — rebasing and pushing again"
                            git_output -C "$PUB_DIR" pull --rebase --quiet origin HEAD \
                                || { rm -f "$push_err"; die "rebasing onto the moved branch failed — resolve it in $PUB_DIR"; }
                            git_output -C "$PUB_DIR" push --quiet origin HEAD \
                                || { rm -f "$push_err"; die "pushing after the rebase failed — the report is complete in $OUTPUT_DIR"; } ;;
                        *"protected branch"*|*"pre-receive hook declined"*)
                            rm -f "$push_err"
                            die "the remote refused the push (protected branch or a hook) — publish to a branch that accepts writes via OUTPUT_REPO_BRANCH; the report is complete in $OUTPUT_DIR" ;;
                        *403*|*"not authorized"*|*"Permission"*|*"denied"*|*"read-only"*)
                            rm -f "$push_err"
                            die "the credentials may read $OUTPUT_REPO but not write to it — the token needs write access; the report is complete in $OUTPUT_DIR" ;;
                        *)
                            printf '%s\n' "$push_text" | sed 's/^/      /' >&2
                            rm -f "$push_err"
                            die "pushing to $OUTPUT_REPO failed — the report is complete in $OUTPUT_DIR" ;;
                    esac
                fi
                rm -f "$push_err"
                ok "pushed to $OUTPUT_REPO (${OUTPUT_REPO_BRANCH:-default branch}), path $OUTPUT_REPO_PATH/"
            fi
        fi
    fi
fi

exit "$RC"
