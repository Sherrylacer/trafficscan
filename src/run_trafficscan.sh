#!/bin/bash
# Source-to-Traffic analysis of Xray-core (phase-1 acceptance target).
# Run from src/. Dependencies (Go stdlib of the matching toolchain + go.mod modules)
# are downloaded into ../cache on first use.
set -e
PY=${PY:-../.venv/bin/python}

$PY scan.py \
  --language Go \
  --project-path ../xray-source/Xray-core \
  --scanners trafficscan \
  --go-version 1.27.3 \
  --goarch arm64 \
  --entry-timeout 45 \
  "$@"
# add --use-llm to annotate the top features with the configured LLM (labelled unverified)
