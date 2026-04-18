#!/usr/bin/env bash
set -euo pipefail

OUT_DIR="${1:-out}"
TMP_DIR="$OUT_DIR/.latest-ko-artifact"
ZIP_PATH="$TMP_DIR/latest-ko.zip"

if ! command -v curl >/dev/null 2>&1; then
  echo "curl is required."
  exit 1
fi

if ! command -v unzip >/dev/null 2>&1; then
  echo "unzip is required."
  exit 1
fi

if ! command -v python3 >/dev/null 2>&1; then
  echo "python3 is required."
  exit 1
fi

REMOTE_URL="${GITHUB_REMOTE_URL:-$(git config --get remote.origin.url || true)}"
if [ -z "${GITHUB_REPO:-}" ] && [ -z "$REMOTE_URL" ]; then
  echo "Cannot detect repository. Set GITHUB_REPO=owner/repo."
  exit 1
fi

REPO="${GITHUB_REPO:-$(python3 - "$REMOTE_URL" <<'PY'
import re
import sys

u = sys.argv[1].strip()
patterns = [
    r"^https?://[^/]+/([^/]+/[^/.]+)(?:\.git)?$",
    r"^git@[^:]+:([^/]+/[^/.]+)(?:\.git)?$",
]
for p in patterns:
    m = re.match(p, u)
    if m:
        print(m.group(1))
        raise SystemExit(0)
raise SystemExit(1)
PY
)}"

if [ -z "$REPO" ]; then
  echo "Failed to parse repository from remote URL: $REMOTE_URL"
  exit 1
fi

if [ -z "${GITHUB_TOKEN:-}" ]; then
  GITHUB_USER="$(python3 - "$REMOTE_URL" <<'PY'
import re
import sys

u = sys.argv[1].strip()
m = re.match(r"^https?://([^@/]+)@github\.com/", u)
print(m.group(1) if m else "")
PY
)"
  CRED_QUERY=$'protocol=https\nhost=github.com\n'
  if [ -n "$GITHUB_USER" ]; then
    CRED_QUERY="${CRED_QUERY}username=${GITHUB_USER}"$'\n'
  fi
  CRED_QUERY="${CRED_QUERY}"$'\n'
  CRED_DATA="$(printf "%s" "$CRED_QUERY" | git credential fill 2>/dev/null || true)"
  CRED_TOKEN="$(printf "%s\n" "$CRED_DATA" | awk -F= '$1=="password"{print substr($0,10); exit}')"
  if [ -n "$CRED_TOKEN" ]; then
    GITHUB_TOKEN="$CRED_TOKEN"
  fi
fi

API_BASE="https://api.github.com/repos/$REPO/actions"

api_get() {
  local url="$1"
  if [ -n "${GITHUB_TOKEN:-}" ]; then
    curl -fsSL \
      -H "Accept: application/vnd.github+json" \
      -H "X-GitHub-Api-Version: 2022-11-28" \
      -H "Authorization: Bearer $GITHUB_TOKEN" \
      "$url"
  else
    curl -fsSL \
      -H "Accept: application/vnd.github+json" \
      -H "X-GitHub-Api-Version: 2022-11-28" \
      "$url"
  fi
}

api_download() {
  local url="$1"
  local out="$2"
  if [ -n "${GITHUB_TOKEN:-}" ]; then
    curl -fsSL -L \
      -H "Accept: application/vnd.github+json" \
      -H "X-GitHub-Api-Version: 2022-11-28" \
      -H "Authorization: Bearer $GITHUB_TOKEN" \
      "$url" -o "$out"
  else
    curl -fsSL -L \
      -H "Accept: application/vnd.github+json" \
      -H "X-GitHub-Api-Version: 2022-11-28" \
      "$url" -o "$out"
  fi
}

mkdir -p "$TMP_DIR"
rm -rf "$TMP_DIR/extracted"
rm -f "$TMP_DIR"/*.ko "$ZIP_PATH" 2>/dev/null || true

ARTIFACT_JSON="$(api_get "$API_BASE/artifacts?per_page=100")"

ARTIFACT_PICK="$(python3 -c 'import json,re,sys; d=json.load(sys.stdin); arts=[a for a in d.get("artifacts",[]) if not a.get("expired",False)]; pick=next((a for a in arts if a.get("name")=="latest-ko"),None) or next((a for a in arts if re.search(r"-lkm$", a.get("name",""))),None); print((str(pick.get("id","")) + "\t" + str(pick.get("name",""))) if pick else "")' <<<"$ARTIFACT_JSON")"
ARTIFACT_ID="${ARTIFACT_PICK%%$'\t'*}"
ARTIFACT_NAME="${ARTIFACT_PICK#*$'\t'}"
if [ -z "$ARTIFACT_ID" ] || [ "$ARTIFACT_ID" = "$ARTIFACT_PICK" ]; then
  echo "No downloadable KO artifact found (expected 'latest-ko' or '*-lkm')."
  exit 1
fi

api_download "$API_BASE/artifacts/$ARTIFACT_ID/zip" "$ZIP_PATH"

unzip -o "$ZIP_PATH" -d "$TMP_DIR/extracted" >/dev/null

KO_PATH="$(find "$TMP_DIR/extracted" -type f -name '*.ko' | head -n 1)"
if [ -z "${KO_PATH:-}" ]; then
  echo "No .ko file found in downloaded artifact."
  exit 1
fi

mkdir -p "$OUT_DIR"
cp "$KO_PATH" "$OUT_DIR/latest.ko"

echo "Downloaded ($ARTIFACT_NAME): $OUT_DIR/latest.ko"
