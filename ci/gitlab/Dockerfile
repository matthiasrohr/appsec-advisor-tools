# The image threat-model.gitlab-ci.yml runs in. It carries what the launcher
# checks for in its preflight and nothing else: git, python3 with pyyaml and
# jsonschema, and the Claude Code CLI.
#
# Build and push it once, then point the job's `image:` at it:
#     docker build -t $CI_REGISTRY_IMAGE/appsec-advisor:latest ci/gitlab
#     docker push    $CI_REGISTRY_IMAGE/appsec-advisor:latest
#
# The tags below are pinned to a version. Pin the digest instead
# (node:22.14.0-bookworm-slim@sha256:…) where the pipeline must be reproducible
# down to the byte — a tag can be moved, a digest cannot.
FROM node:22.14.0-bookworm-slim

# ca-certificates for https, git for the clones, curl for the host APIs that
# create a report repository, python3 for the pipeline's own scripts.
RUN apt-get update \
    && apt-get install --no-install-recommends -y \
        ca-certificates git curl python3 python3-yaml python3-jsonschema \
    && rm -rf /var/lib/apt/lists/*

# The launcher looks for it on PATH as `claude`.
RUN npm install -g @anthropic-ai/claude-code@latest \
    && claude --version

# A PDF or HTML export needs pandoc, and the PDF also weasyprint. Both are
# large, and the run says so in its preflight rather than failing at the export,
# so they stay out unless WITH_PDF or WITH_HTML is actually used:
#   apt-get install -y pandoc && pip install weasyprint

# Nothing in here runs as root that has to.
RUN useradd --create-home --uid 1001 advisor
USER advisor
WORKDIR /work
