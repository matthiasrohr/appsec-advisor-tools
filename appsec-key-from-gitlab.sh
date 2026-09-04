#!/usr/bin/env bash
# ─────────────────────────────────────────────────────────────────────────────
# appsec-key-from-gitlab.sh — print one secret from GitLab Secrets Manager
# (OpenBao) on stdout. Used by appsec-scan.sh with KEY_SOURCE=gitlab, and
# usable on its own.
#
# Three calls, as GitLab documents them for non-CI/CD workloads:
#   1. POST /api/v4/projects/<id>/secrets_manager/access_token   → 5-minute JWT
#      plus the OpenBao connection details
#   2. POST <openbao>/v1/auth/<auth_path>/login                  → client token
#   3. GET  <openbao>/v1/<mount>/data/<secrets_path>/<name>      → the value
#
# Nothing but the secret is written to stdout, so the script can be used as a
# credential command. Diagnostics go to stderr.
# ─────────────────────────────────────────────────────────────────────────────

# Uses bash features (arrays, mapfile, pipefail); re-exec when started with sh.
if [ -z "${BASH_VERSION:-}" ]; then
    if command -v bash >/dev/null 2>&1; then
        exec bash "$0" "$@"
    fi
    echo "appsec-key-from-gitlab.sh needs bash — install it, or run: bash $0" >&2
    exit 1
fi
if [ "${BASH_VERSINFO[0]}" -lt 4 ]; then
    echo "appsec-key-from-gitlab.sh needs bash 4 or newer (found $BASH_VERSION)" >&2
    exit 1
fi

set -Eeuo pipefail

GITLAB_URL="${GITLAB_URL:-}"                          # https://gitlab.example.com
GITLAB_PROJECT="${GITLAB_PROJECT:-}"                  # numeric id, or group/project path
GITLAB_SECRET_NAME="${GITLAB_SECRET_NAME:-anthropic-api-key}"
GITLAB_SECRET_FIELD="${GITLAB_SECRET_FIELD:-value}"   # field inside the KV entry

# The token that mints the OpenBao JWT: personal, project, group or service
# account token with the `api` scope. Named here, never written here.
GITLAB_TOKEN="${GITLAB_TOKEN:-}"
GITLAB_TOKEN_FILE="${GITLAB_TOKEN_FILE:-$HOME/.config/appsec-scan/gitlab-token}"

GITLAB_CA_BUNDLE="${GITLAB_CA_BUNDLE:-}"              # private CA of a self-hosted instance
HTTP_TIMEOUT="${HTTP_TIMEOUT:-30}"

usage() {
    cat <<'HELP'
appsec-key-from-gitlab.sh — read one secret from GitLab Secrets Manager (OpenBao)
and print it on stdout.

Usage:
  appsec-key-from-gitlab.sh [--check] [--help]

  --check   Run the prerequisite checks and the full three-call round trip, then
            report success without printing the secret. Use this to verify a
            setup; every other invocation prints the secret and nothing else.

Environment:
  GITLAB_URL            Instance URL, e.g. https://gitlab.example.com   (required)
  GITLAB_PROJECT        Numeric project id, or group/project path       (required)
  GITLAB_SECRET_NAME    Secret name in the project    (default: anthropic-api-key)
  GITLAB_SECRET_FIELD   Field inside the KV entry                 (default: value)
  GITLAB_TOKEN          GitLab token with the api scope
  GITLAB_TOKEN_FILE     File holding that token, owner-readable only (chmod 600)
                        (default: ~/.config/appsec-scan/gitlab-token)
  GITLAB_CA_BUNDLE      CA bundle for a self-hosted instance with a private CA
  HTTP_TIMEOUT          Seconds per request                            (default: 30)

Requirements on the GitLab side:
  • GitLab Premium or Ultimate, Secrets Manager enabled for the project
  • Secrets Manager provisioned in GitLab 19.2 or later; older ones need an
    administrator to enable access from external requests
  • the secrets_manager_api_access feature flag enabled on the instance
  • role at least Reporter, plus the read-value permission on that secret

Use with appsec-scan.sh:
  KEY_SOURCE=gitlab GITLAB_URL=… GITLAB_PROJECT=… appsec-scan.sh --target-dir …
HELP
}

CHECK_ONLY=0
while [ $# -gt 0 ]; do
    case "$1" in
        --check) CHECK_ONLY=1; shift ;;
        -h|--help) usage; exit 0 ;;
        *) usage >&2; printf '\nunknown option: %s\n' "$1" >&2; exit 2 ;;
    esac
done

die()  { printf 'appsec-key-from-gitlab: %s\n' "$*" >&2; exit 1; }
note() { printf 'appsec-key-from-gitlab: %s\n' "$*" >&2; }

ERR_FILE=""
cleanup() { [ -n "$ERR_FILE" ] && rm -f "$ERR_FILE"; }
trap cleanup EXIT

# ── Prerequisites, checked before the first request ──────────────────────────
command -v curl >/dev/null 2>&1 || die "curl not found — install curl"
command -v python3 >/dev/null 2>&1 || die "python3 not found — install python3"

[ -n "$GITLAB_URL" ] || die "GITLAB_URL is not set (e.g. https://gitlab.example.com)"
[ -n "$GITLAB_PROJECT" ] || die "GITLAB_PROJECT is not set (numeric id, or group/project path)"
[ -n "$GITLAB_SECRET_NAME" ] || die "GITLAB_SECRET_NAME is empty"
[ -n "$GITLAB_SECRET_FIELD" ] || die "GITLAB_SECRET_FIELD is empty"
case "$HTTP_TIMEOUT" in
    ''|*[!0-9]*) die "HTTP_TIMEOUT must be a whole number of seconds (got: $HTTP_TIMEOUT)" ;;
esac

GITLAB_URL="${GITLAB_URL%/}"
case "$GITLAB_URL" in
    */api/v4*) die "GITLAB_URL must be the instance URL without an API path (got: $GITLAB_URL)" ;;
esac

# A GitLab token travels in these requests, so the transport has to protect it.
# Plain HTTP is accepted on loopback only, where it never leaves the machine.
case "$GITLAB_URL" in
    https://*) : ;;
    http://127.0.0.1|http://127.0.0.1[:/]*|http://localhost|http://localhost[:/]*|http://\[::1\]|http://\[::1\][:/]*) : ;;
    http://*)  die "GITLAB_URL uses plain http, which would expose the GitLab token in transit — use https (http is accepted on loopback only)" ;;
    *)         die "GITLAB_URL must start with https:// (got: $GITLAB_URL)" ;;
esac

if [ -n "$GITLAB_CA_BUNDLE" ] && [ ! -r "$GITLAB_CA_BUNDLE" ]; then
    die "GITLAB_CA_BUNDLE is not readable: $GITLAB_CA_BUNDLE"
fi

if [ -z "$GITLAB_TOKEN" ] && [ -n "$GITLAB_TOKEN_FILE" ] && [ -f "$GITLAB_TOKEN_FILE" ]; then
    perm="$(stat -c '%a' "$GITLAB_TOKEN_FILE" 2>/dev/null || stat -f '%Lp' "$GITLAB_TOKEN_FILE" 2>/dev/null || true)"
    case "$perm" in
        *00) : ;;
        "")  note "cannot determine the permissions of $GITLAB_TOKEN_FILE" ;;
        *)   die "token file $GITLAB_TOKEN_FILE is readable beyond its owner (mode $perm) — run: chmod 600 $GITLAB_TOKEN_FILE" ;;
    esac
    [ -r "$GITLAB_TOKEN_FILE" ] || die "token file is not readable: $GITLAB_TOKEN_FILE"
    GITLAB_TOKEN="$(cat -- "$GITLAB_TOKEN_FILE")"
fi
GITLAB_TOKEN="$(printf '%s' "$GITLAB_TOKEN" | tr -d '[:space:]')"
if [ -z "$GITLAB_TOKEN" ]; then
    die "no GitLab token — set GITLAB_TOKEN, or put one in $GITLAB_TOKEN_FILE (chmod 600). It needs the api scope."
fi
case "$GITLAB_TOKEN" in
    glcbt-*|glpat-*|gldt-*|glsoat-*|glrt-*|glft-*) : ;;
    *) note "the token does not look like a GitLab token (expected a gl…- prefix); continuing anyway" ;;
esac

# ── HTTP ─────────────────────────────────────────────────────────────────────
ERR_FILE="$(mktemp)"
CURL_BASE=(curl --silent --show-error --max-time "$HTTP_TIMEOUT" --write-out $'\n%{http_code}')
[ -n "$GITLAB_CA_BUNDLE" ] && CURL_BASE+=(--cacert "$GITLAB_CA_BUNDLE")

urlenc() { python3 -c 'import sys,urllib.parse;print(urllib.parse.quote(sys.argv[1], safe=""))' "$1"; }

# Credentials go through a curl config file on stdin, so they never appear in
# the process list.
call() {  # call <url> <json-body-or-empty> <header>...
    local url="$1" data="$2"; shift 2
    local cfg="" h out rc=0
    for h in "$@"; do cfg+="header = \"${h//\"/\\\"}\""$'\n'; done
    if [ -n "$data" ]; then
        cfg+="data = \"${data//\"/\\\"}\""$'\n'
        out="$(printf '%s' "$cfg" | "${CURL_BASE[@]}" --request POST \
               --header 'Content-Type: application/json' --config - "$url" 2>"$ERR_FILE")" || rc=$?
    else
        out="$(printf '%s' "$cfg" | "${CURL_BASE[@]}" --config - "$url" 2>"$ERR_FILE")" || rc=$?
    fi
    CURL_RC=$rc
    if [ "$rc" -ne 0 ]; then BODY=""; HTTP_CODE=""; return 1; fi
    HTTP_CODE="${out##*$'\n'}"
    BODY="${out%$'\n'*}"
    case "$HTTP_CODE" in 2??) return 0 ;; *) return 2 ;; esac
}

transport_error() {  # transport_error <host-description>
    local detail
    detail="$(tr -d '\r' <"$ERR_FILE" | head -2 | tr '\n' ' ')"
    case "$CURL_RC" in
        6)  die "cannot resolve the host of $1 — check GITLAB_URL and your DNS" ;;
        7)  die "cannot connect to $1 — the instance may be unreachable from here (VPN?)" ;;
        28) die "$1 did not answer within ${HTTP_TIMEOUT}s — raise HTTP_TIMEOUT or check the instance" ;;
        35) die "TLS handshake with $1 failed: ${detail:-no detail}" ;;
        60) die "the TLS certificate of $1 is not trusted — point GITLAB_CA_BUNDLE at your CA bundle" ;;
        *)  die "request to $1 failed (curl exit $CURL_RC): ${detail:-no detail}" ;;
    esac
}

# Server-side error text, never the request or its credentials.
api_message() {
    printf '%s' "$BODY" | python3 -c '
import json, sys
try:
    d = json.load(sys.stdin)
except Exception:
    sys.exit(0)
if isinstance(d, dict):
    for k in ("message", "error", "error_description", "errors"):
        v = d.get(k)
        # An empty errors list carries nothing; do not append ": []" to the message.
        if v not in (None, "", [], {}):
            print(str(v)[:200]); break
' 2>/dev/null || true
}

# ── 1. Mint the OpenBao JWT ──────────────────────────────────────────────────
project="$(urlenc "$GITLAB_PROJECT")"
mint_url="$GITLAB_URL/api/v4/projects/$project/secrets_manager/access_token"
if ! call "$mint_url" '{}' "PRIVATE-TOKEN: $GITLAB_TOKEN"; then
    [ "$CURL_RC" -ne 0 ] && transport_error "$GITLAB_URL"
    msg="$(api_message)"
    case "$HTTP_CODE" in
        401) die "GitLab rejected the token (HTTP 401) — it is invalid, expired or revoked${msg:+: $msg}" ;;
        403) die "GitLab refused the request (HTTP 403) — the token needs the api scope and at least the Reporter role on project '$GITLAB_PROJECT'${msg:+: $msg}" ;;
        404) die "no Secrets Manager access-token endpoint for project '$GITLAB_PROJECT' (HTTP 404) — the project may not exist, the token may not see it, Secrets Manager may not be enabled for it, or the instance lacks the secrets_manager_api_access feature flag (GitLab 19.2+, Premium/Ultimate)${msg:+: $msg}" ;;
        405) die "the endpoint does not accept this request (HTTP 405) — the instance is probably older than GitLab 19.2${msg:+: $msg}" ;;
        429) die "GitLab is rate limiting this token (HTTP 429) — retry later${msg:+: $msg}" ;;
        5??) die "GitLab returned a server error (HTTP $HTTP_CODE)${msg:+: $msg}" ;;
        *)   die "minting the Secrets Manager access token failed (HTTP $HTTP_CODE)${msg:+: $msg}" ;;
    esac
fi

mapfile -t V < <(printf '%s' "$BODY" | python3 -c '
import json, sys
v = json.load(sys.stdin)["provider"]["vault"]
print(v["server"].rstrip("/"))
print(v["namespace"])
print(v["path"])
print(v["secrets_path"])
print(v["auth"]["jwt"]["path"])
print(v["auth"]["jwt"]["role"])
print(v["auth"]["jwt"]["token"])
' 2>/dev/null)
[ "${#V[@]}" -eq 7 ] || die "the access-token response is missing provider.vault fields — the instance may run an incompatible Secrets Manager version"
SERVER="${V[0]}"; NAMESPACE="${V[1]}"; MOUNT="${V[2]}"; SECRETS_PATH="${V[3]}"
AUTH_PATH="${V[4]}"; ROLE="${V[5]}"; JWT="${V[6]}"
[ -n "$SERVER" ] || die "the access-token response contains no OpenBao server URL"
case "$SERVER" in
    https://*) : ;;
    http://127.0.0.1*|http://localhost*|http://\[::1\]*) : ;;
    *) die "the OpenBao server URL from GitLab is not https ($SERVER) — refusing to send the token over it" ;;
esac

# ── 2. Exchange it for an OpenBao client token ───────────────────────────────
login_body="$(python3 -c 'import json,sys;print(json.dumps({"role":sys.argv[1],"jwt":sys.argv[2]}))' "$ROLE" "$JWT")"
if ! call "$SERVER/v1/auth/$AUTH_PATH/login" "$login_body" "X-Vault-Namespace: $NAMESPACE"; then
    [ "$CURL_RC" -ne 0 ] && transport_error "the OpenBao backend at $SERVER"
    msg="$(api_message)"
    case "$HTTP_CODE" in
        400|403) die "OpenBao rejected the minted JWT (HTTP $HTTP_CODE) — the token expires after five minutes, and a clock skew between this machine and the instance will reproduce this${msg:+: $msg}" ;;
        404)     die "the OpenBao JWT login path does not exist (HTTP 404, path '$AUTH_PATH')${msg:+: $msg}" ;;
        5??)     die "the OpenBao backend returned a server error (HTTP $HTTP_CODE)${msg:+: $msg}" ;;
        *)       die "the OpenBao JWT login failed (HTTP $HTTP_CODE)${msg:+: $msg}" ;;
    esac
fi
VAULT_TOKEN="$(printf '%s' "$BODY" | python3 -c 'import json,sys;print(json.load(sys.stdin)["auth"]["client_token"])' 2>/dev/null)" \
    || die "the OpenBao login response contains no client token"
[ -n "$VAULT_TOKEN" ] || die "the OpenBao login response contains an empty client token"

# ── 3. Read the secret ───────────────────────────────────────────────────────
secret="$(urlenc "$GITLAB_SECRET_NAME")"
if ! call "$SERVER/v1/$MOUNT/data/$SECRETS_PATH/$secret" "" \
          "X-Vault-Token: $VAULT_TOKEN" "X-Vault-Namespace: $NAMESPACE"; then
    [ "$CURL_RC" -ne 0 ] && transport_error "the OpenBao backend at $SERVER"
    msg="$(api_message)"
    case "$HTTP_CODE" in
        403) die "no permission to read the value of secret '$GITLAB_SECRET_NAME' (HTTP 403) — the Reporter role alone does not expose values, the principal needs the read-value permission on that secret${msg:+: $msg}" ;;
        404) die "secret '$GITLAB_SECRET_NAME' does not exist in project '$GITLAB_PROJECT' (HTTP 404) — check the name, it is case sensitive${msg:+: $msg}" ;;
        5??) die "the OpenBao backend returned a server error (HTTP $HTTP_CODE)${msg:+: $msg}" ;;
        *)   die "reading secret '$GITLAB_SECRET_NAME' failed (HTTP $HTTP_CODE)${msg:+: $msg}" ;;
    esac
fi

VALUE="$(printf '%s' "$BODY" | python3 -c '
import json, sys
field = sys.argv[1]
try:
    data = json.load(sys.stdin)["data"]["data"]
except Exception:
    sys.exit("the OpenBao response has no data.data object")
if field not in data:
    sys.exit("secret has no field %r (present: %s)" % (field, ", ".join(sorted(data)) or "none"))
value = str(data[field]).strip()
if not value:
    sys.exit("field %r is empty" % field)
print(value)
' "$GITLAB_SECRET_FIELD")" || exit 1   # python already said what is wrong

if [ "$CHECK_ONLY" = "1" ]; then
    note "ok — read '$GITLAB_SECRET_NAME' field '$GITLAB_SECRET_FIELD' from project '$GITLAB_PROJECT' (${#VALUE} chars)"
    exit 0
fi
printf '%s\n' "$VALUE"
