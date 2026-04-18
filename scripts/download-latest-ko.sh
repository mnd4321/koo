#!/usr/bin/env bash
set -euo pipefail

OUT_DIR="${1:-out}"
TMP_DIR="$OUT_DIR/.latest-ko-artifact"
ZIP_PATH="$TMP_DIR/latest-ko.zip"
ZIP_PATH_LKM="$TMP_DIR/latest-lkm.zip"

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
rm -f "$TMP_DIR"/*.ko "$ZIP_PATH" "$ZIP_PATH_LKM" 2>/dev/null || true

ARTIFACT_JSON="$(api_get "$API_BASE/artifacts?per_page=100")"

ARTIFACT_INFO="$(python3 -c 'import json,re,sys; d=json.load(sys.stdin); arts=[a for a in d.get("artifacts",[]) if not a.get("expired",False)]; latest=next((a for a in arts if a.get("name")=="latest-ko"),None); lkm=next((a for a in arts if re.search(r"-lkm$", a.get("name",""))),None); print((str(latest.get("id","")) + "\t" + str(latest.get("name",""))) if latest else "\t"); print((str(lkm.get("id","")) + "\t" + str(lkm.get("name",""))) if lkm else "\t")' <<<"$ARTIFACT_JSON")"

LATEST_KO_LINE="$(printf "%s\n" "$ARTIFACT_INFO" | sed -n '1p')"
LKM_LINE="$(printf "%s\n" "$ARTIFACT_INFO" | sed -n '2p')"

LATEST_KO_ID="${LATEST_KO_LINE%%$'\t'*}"
LATEST_KO_NAME="${LATEST_KO_LINE#*$'\t'}"
LKM_ID="${LKM_LINE%%$'\t'*}"
LKM_NAME="${LKM_LINE#*$'\t'}"

ARTIFACT_ID="$LATEST_KO_ID"
ARTIFACT_NAME="$LATEST_KO_NAME"
if [ -z "$ARTIFACT_ID" ]; then
  ARTIFACT_ID="$LKM_ID"
  ARTIFACT_NAME="$LKM_NAME"
fi

if [ -z "$ARTIFACT_ID" ]; then
  echo "No downloadable KO artifact found (expected 'latest-ko' or '*-lkm')."
  exit 1
fi

api_download "$API_BASE/artifacts/$ARTIFACT_ID/zip" "$ZIP_PATH"
unzip -o "$ZIP_PATH" -d "$TMP_DIR/extracted" >/dev/null

find_loader_bin() {
  local root="$1"
  local pattern1="$2"
  local pattern2="$3"
  local found
  found="$(find "$root" -type f -name "$pattern1" | head -n 1)"
  if [ -z "$found" ]; then
    found="$(find "$root" -type f -name "$pattern2" | head -n 1)"
  fi
  printf "%s" "$found"
}

KO_PATH="$(find "$TMP_DIR/extracted" -type f -name '*.ko' | head -n 1)"
if [ -z "${KO_PATH:-}" ]; then
  echo "No .ko file found in downloaded artifact."
  exit 1
fi

INIT_LOADER_PATH="$(find_loader_bin "$TMP_DIR/extracted" '*_init_module_loader_arm64' 'init_module_loader')"
COMM_LOADER_PATH="$(find_loader_bin "$TMP_DIR/extracted" '*_hello_comm_test_arm64' 'hello_comm_test')"

# If primary artifact is latest-ko and it doesn't include loader bins, fetch one *-lkm artifact.
if { [ -z "$INIT_LOADER_PATH" ] || [ -z "$COMM_LOADER_PATH" ]; } && [ -n "$LKM_ID" ] && [ "$ARTIFACT_ID" != "$LKM_ID" ]; then
  rm -rf "$TMP_DIR/extracted-lkm"
  api_download "$API_BASE/artifacts/$LKM_ID/zip" "$ZIP_PATH_LKM"
  unzip -o "$ZIP_PATH_LKM" -d "$TMP_DIR/extracted-lkm" >/dev/null
  if [ -z "$INIT_LOADER_PATH" ]; then
    INIT_LOADER_PATH="$(find_loader_bin "$TMP_DIR/extracted-lkm" '*_init_module_loader_arm64' 'init_module_loader')"
  fi
  if [ -z "$COMM_LOADER_PATH" ]; then
    COMM_LOADER_PATH="$(find_loader_bin "$TMP_DIR/extracted-lkm" '*_hello_comm_test_arm64' 'hello_comm_test')"
  fi
fi

mkdir -p "$OUT_DIR"
cp "$KO_PATH" "$OUT_DIR/latest.ko"
if [ -n "$INIT_LOADER_PATH" ]; then
  cp "$INIT_LOADER_PATH" "$OUT_DIR/latest_init_module_loader_arm64"
fi
if [ -n "$COMM_LOADER_PATH" ]; then
  cp "$COMM_LOADER_PATH" "$OUT_DIR/latest_hello_comm_test_arm64"
fi

echo "Downloaded ($ARTIFACT_NAME): $OUT_DIR/latest.ko"
if [ -n "$INIT_LOADER_PATH" ]; then
  echo "Downloaded loader: $OUT_DIR/latest_init_module_loader_arm64"
else
  echo "Loader not found: init_module_loader"
fi
if [ -n "$COMM_LOADER_PATH" ]; then
  echo "Downloaded loader: $OUT_DIR/latest_hello_comm_test_arm64"
else
  echo "Loader not found: hello_comm_test"
fi
