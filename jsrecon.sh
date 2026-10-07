#!/usr/bin/env bash
#
# jsrecon.sh — JS collection, download, endpoint & secret analysis
#
# Chains together existing, maintained tools instead of reinventing them:
#   katana   -> crawl target(s) and pull out JS file URLs
#   gau      -> (optional) pull historical JS URLs from Wayback/CommonCrawl/OTX
#   httpx    -> download JS files in parallel, with rate limiting
#   gitleaks -> secret detection (DEFAULT rules always on; --regex-file is ADDITIVE only)
#   python3  -> endpoint extraction (regex) + final report merge
#   jq       -> JSON plumbing
#
set -uo pipefail

# ---------------------------------------------------------------------------
# Paths / defaults
# ---------------------------------------------------------------------------
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
LIB_DIR="${SCRIPT_DIR}/lib"

TARGET_URL=""
TARGET_LIST=""
THREADS=10
RATE_LIMIT=50
DELAY_MS=0
SCOPE=""
USE_WAYBACK=0
REGEX_FILE=""
PROXY=""
HEADERS=()
OUTDIR=""
FORMAT="both"     # json | csv | both
TIMEOUT=10
RETRIES=2

# ---------------------------------------------------------------------------
# Colors
# ---------------------------------------------------------------------------
C_RED="\033[0;31m"; C_GRN="\033[0;32m"; C_YLW="\033[0;33m"; C_BLU="\033[0;34m"; C_RST="\033[0m"
info()  { echo -e "${C_BLU}[*]${C_RST} $*"; }
ok()    { echo -e "${C_GRN}[+]${C_RST} $*"; }
warn()  { echo -e "${C_YLW}[!]${C_RST} $*"; }
err()   { echo -e "${C_RED}[-]${C_RST} $*" 1>&2; }

banner() {
cat <<'EOF'

       _                                       
      (_)___ _ __ ___  ___ ___  _ __           
      | / __| '__/ _ \/ __/ _ \| '_ \          
      | \__ \ | |  __/ (_| (_) | | | |         
      | |___/_|  \___|\___\___/|_| |_|         
     _/ |                                      
    |__/   JS Recon — Collect · Download · Analyze
EOF
echo -e "              ${C_YLW}created by shajan${C_RST}"
echo ""
}

usage() {
cat <<EOF
Usage: ./jsrecon.sh -u <url> | -l <url_list.txt> [options]

Target:
  -u, --url URL             Single target URL
  -l, --list FILE           File containing one URL per line
  --scope DOMAIN             Restrict discovered JS to this domain (e.g. example.com)
  --wayback                  Also pull historical JS URLs via gau (Wayback/CommonCrawl/OTX)

Performance:
  -t, --threads N            Max parallel requests (default: ${THREADS})
  -r, --rate-limit N         Max requests per second (default: ${RATE_LIMIT})
  --delay MS                 Fixed delay between requests in ms (default: 0)
  --timeout SEC               Per-request timeout (default: ${TIMEOUT})
  --retries N                 Retries per request (default: ${RETRIES})

Secret detection:
  Default gitleaks rules (AWS keys, GCP keys, JWTs, Slack/GitHub/Stripe tokens,
  private keys, generic high-entropy secrets, etc.) are ALWAYS run.
  --regex-file FILE           Extra custom rules, ADDITIVE to defaults, one per line:
                               RULE_NAME|REGEX
                               e.g.  INTERNAL_TOKEN|intlk_[a-zA-Z0-9]{32}

Network:
  --proxy URL                 Proxy, e.g. http://127.0.0.1:8080
  -H HEADER                   Extra header, repeatable, e.g. -H "Cookie: session=abc"

Output:
  -o, --output DIR            Output directory (default: ./jsrecon_output_<timestamp>)
  --format FORMAT              json | csv | both (default: both)

  -h, --help                  Show this help
EOF
}

# ---------------------------------------------------------------------------
# Arg parsing
# ---------------------------------------------------------------------------
banner

while [[ $# -gt 0 ]]; do
  case "$1" in
    -u|--url) TARGET_URL="$2"; shift 2 ;;
    -l|--list) TARGET_LIST="$2"; shift 2 ;;
    --scope) SCOPE="$2"; shift 2 ;;
    --wayback) USE_WAYBACK=1; shift ;;
    -t|--threads) THREADS="$2"; shift 2 ;;
    -r|--rate-limit) RATE_LIMIT="$2"; shift 2 ;;
    --delay) DELAY_MS="$2"; shift 2 ;;
    --timeout) TIMEOUT="$2"; shift 2 ;;
    --retries) RETRIES="$2"; shift 2 ;;
    --regex-file) REGEX_FILE="$2"; shift 2 ;;
    --proxy) PROXY="$2"; shift 2 ;;
    -H) HEADERS+=("$2"); shift 2 ;;
    -o|--output) OUTDIR="$2"; shift 2 ;;
    --format) FORMAT="$2"; shift 2 ;;
    -h|--help) usage; exit 0 ;;  # banner already shown above
    *) err "Unknown argument: $1"; usage; exit 1 ;;
  esac
done

if [[ -z "$TARGET_URL" && -z "$TARGET_LIST" ]]; then
  err "You must supply -u <url> or -l <url_list.txt>"
  usage
  exit 1
fi

if [[ -n "$REGEX_FILE" && ! -f "$REGEX_FILE" ]]; then
  err "Regex file not found: $REGEX_FILE"
  exit 1
fi

if [[ -z "$OUTDIR" ]]; then
  OUTDIR="./jsrecon_output_$(date +%Y%m%d_%H%M%S)"
fi
mkdir -p "$OUTDIR"/{js,raw}

# ---------------------------------------------------------------------------
# Tool check + install prompt
# ---------------------------------------------------------------------------
NEED_GO=0
MISSING=()

tool_present() { command -v "$1" >/dev/null 2>&1; }

check() {
  local bin="$1"
  if ! tool_present "$bin"; then
    MISSING+=("$bin")
  fi
}

# httpx collides with the unrelated Python "httpx" HTTP-client library,
# which some systems (e.g. Kali) ship pre-installed as /usr/bin/httpx.
# Work out which real binary name to use before checking tools.
HTTPX_BIN=""
if tool_present httpx-toolkit; then
  HTTPX_BIN="httpx-toolkit"
elif tool_present httpx && httpx -version 2>&1 | grep -qi "projectdiscovery"; then
  HTTPX_BIN="httpx"
fi

check katana
if [[ -z "$HTTPX_BIN" ]]; then
  if tool_present httpx; then
    warn "Found a 'httpx' on PATH that is NOT the ProjectDiscovery recon tool"
    warn "(likely the unrelated Python httpx HTTP-client library instead)."
    if tool_present apt-cache && apt-cache show httpx-toolkit >/dev/null 2>&1; then
      warn "On Kali/Debian, install the correctly-named package: sudo apt install -y httpx-toolkit"
    fi
  fi
  MISSING+=("httpx")
fi
check gitleaks
check jq
check python3
[[ $USE_WAYBACK -eq 1 ]] && check gau

if [[ ${#MISSING[@]} -gt 0 ]]; then
  warn "The following required tools are not installed: ${MISSING[*]}"
  if ! tool_present go; then
    warn "'go' is also not installed; it's needed to install katana/httpx/gau/gitleaks."
  fi
  read -r -p "Attempt to install missing tools now? [y/N] " ans
  if [[ "$ans" =~ ^[Yy]$ ]]; then
    for t in "${MISSING[@]}"; do
      case "$t" in
        katana) info "Installing katana..."; go install github.com/projectdiscovery/katana/cmd/katana@latest ;;
        httpx)
          if tool_present apt-cache && apt-cache show httpx-toolkit >/dev/null 2>&1; then
            info "Installing httpx-toolkit (ProjectDiscovery httpx, Kali-renamed package)..."
            sudo apt-get update -y && sudo apt-get install -y httpx-toolkit
          else
            info "Installing httpx..."
            go install github.com/projectdiscovery/httpx/cmd/httpx@latest
          fi
          ;;
        gau)    info "Installing gau...";    go install github.com/lc/gau/v2/cmd/gau@latest ;;
        gitleaks) info "Installing gitleaks..."; go install github.com/zricethezav/gitleaks/v8@latest ;;
        jq) info "Installing jq (requires sudo apt)..."; sudo apt-get update -y && sudo apt-get install -y jq ;;
        python3) info "Installing python3 (requires sudo apt)..."; sudo apt-get update -y && sudo apt-get install -y python3 python3-pip ;;
      esac
    done
    GOBIN="$(go env GOPATH 2>/dev/null)/bin"
    export PATH="$GOBIN:$PATH"
    if tool_present httpx-toolkit; then
      HTTPX_BIN="httpx-toolkit"
    elif tool_present httpx && httpx -version 2>&1 | grep -qi "projectdiscovery"; then
      HTTPX_BIN="httpx"
    fi
    STILL_MISSING=()
    for t in "${MISSING[@]}"; do
      if [[ "$t" == "httpx" ]]; then
        [[ -z "$HTTPX_BIN" ]] && STILL_MISSING+=("$t")
      else
        tool_present "$t" || STILL_MISSING+=("$t")
      fi
    done
    if [[ ${#STILL_MISSING[@]} -gt 0 ]]; then
      err "Still missing after install attempt: ${STILL_MISSING[*]}"
      err "Make sure \$GOBIN (usually ~/go/bin) is on your PATH, then re-run."
      exit 1
    fi
    ok "All required tools installed."
  else
    err "Cannot proceed without: ${MISSING[*]}. Install them and re-run."
    exit 1
  fi
fi

# ---------------------------------------------------------------------------
# Build target list file
# ---------------------------------------------------------------------------
TARGETS_FILE="${OUTDIR}/raw/targets.txt"
if [[ -n "$TARGET_URL" ]]; then
  echo "$TARGET_URL" > "$TARGETS_FILE"
else
  cp "$TARGET_LIST" "$TARGETS_FILE"
fi

HEADER_ARGS=()
for h in "${HEADERS[@]:-}"; do
  [[ -n "$h" ]] && HEADER_ARGS+=(-H "$h")
done
PROXY_ARG=()
[[ -n "$PROXY" ]] && PROXY_ARG=(-proxy "$PROXY")

# ---------------------------------------------------------------------------
# Stage 1: Collect JS URLs (katana + optional gau)
# ---------------------------------------------------------------------------
info "Stage 1/4: Collecting JS file URLs..."
JS_URLS_RAW="${OUTDIR}/raw/js_urls_raw.txt"
: > "$JS_URLS_RAW"

katana -list "$TARGETS_FILE" -jc -silent -timeout "$TIMEOUT" -retry "$RETRIES" \
  "${HEADER_ARGS[@]}" "${PROXY_ARG[@]}" >> "$JS_URLS_RAW" 2>>"${OUTDIR}/raw/katana.log"

if [[ $USE_WAYBACK -eq 1 ]]; then
  info "  --wayback set: querying gau for historical JS URLs..."
  while IFS= read -r t; do
    domain="$(echo "$t" | sed -E 's#^[a-zA-Z]+://##' | cut -d/ -f1)"
    gau --subs "$domain" 2>>"${OUTDIR}/raw/gau.log" | grep -Ei '\.js(\?|$)' >> "$JS_URLS_RAW"
  done < "$TARGETS_FILE"
fi

if [[ -n "$SCOPE" ]]; then
  grep -i "$SCOPE" "$JS_URLS_RAW" | grep -Ei '\.js(\?|$)' | sort -u > "${OUTDIR}/raw/js_urls.txt"
else
  grep -Ei '\.js(\?|$)' "$JS_URLS_RAW" | sort -u > "${OUTDIR}/raw/js_urls.txt"
fi

JS_URL_COUNT=$(wc -l < "${OUTDIR}/raw/js_urls.txt" | tr -d ' ')
if [[ "$JS_URL_COUNT" -eq 0 ]]; then
  err "No JS URLs found. Check the target(s) are reachable, or try --wayback."
  exit 1
fi
ok "Found ${JS_URL_COUNT} unique JS URLs."

# ---------------------------------------------------------------------------
# Stage 2: Download (httpx, with thread/rate-limit/delay flags)
# ---------------------------------------------------------------------------
info "Stage 2/4: Downloading JS files (threads=${THREADS}, rate-limit=${RATE_LIMIT}/s)..."
DELAY_ARG=()
[[ "$DELAY_MS" -gt 0 ]] && DELAY_ARG=(-delay "${DELAY_MS}ms")

"$HTTPX_BIN" -l "${OUTDIR}/raw/js_urls.txt" \
  -silent -threads "$THREADS" -rl "$RATE_LIMIT" -timeout "$TIMEOUT" -retries "$RETRIES" \
  "${DELAY_ARG[@]}" "${HEADER_ARGS[@]}" "${PROXY_ARG[@]}" \
  -sr -srd "${OUTDIR}/js" >> "${OUTDIR}/raw/httpx.log" 2>&1

DL_COUNT=$(find "${OUTDIR}/js" -type f 2>/dev/null | wc -l | tr -d ' ')
if [[ "$DL_COUNT" -eq 0 ]]; then
  err "No JS files were downloaded. See ${OUTDIR}/raw/httpx.log"
  exit 1
fi
ok "Downloaded ${DL_COUNT} JS files to ${OUTDIR}/js/"

# ---------------------------------------------------------------------------
# Stage 3: Analysis — endpoints (python) + secrets (gitleaks, default+custom)
# ---------------------------------------------------------------------------
info "Stage 3/4: Extracting endpoints..."
python3 "${LIB_DIR}/endpoint_extract.py" "${OUTDIR}/js" "${OUTDIR}/raw/endpoints.json"
EP_COUNT=$(jq 'length' "${OUTDIR}/raw/endpoints.json")
ok "Extracted ${EP_COUNT} candidate endpoints."

info "Stage 3/4: Scanning for secrets (gitleaks default rules$( [[ -n "$REGEX_FILE" ]] && echo ' + custom rules' ))..."
GITLEAKS_CONFIG="${OUTDIR}/raw/gitleaks.toml"
{
  echo '[extend]'
  echo 'useDefault = true'
} > "$GITLEAKS_CONFIG"

if [[ -n "$REGEX_FILE" ]]; then
  idx=0
  while IFS='|' read -r name pattern; do
    [[ -z "${name// }" || -z "${pattern// }" ]] && continue
    [[ "$name" =~ ^# ]] && continue
    idx=$((idx+1))
    safe_id="custom-${idx}-$(echo "$name" | tr -cd '[:alnum:]_-')"
    {
      echo ""
      echo "[[rules]]"
      echo "id = \"${safe_id}\""
      echo "description = \"${name}\""
      echo "regex = '''${pattern}'''"
    } >> "$GITLEAKS_CONFIG"
  done < "$REGEX_FILE"
  ok "  Added ${idx} custom regex rule(s) from ${REGEX_FILE} (on top of defaults)."
fi

gitleaks detect --no-git --source "${OUTDIR}/js" --config "$GITLEAKS_CONFIG" \
  --report-format json --report-path "${OUTDIR}/raw/secrets.json" \
  --exit-code 0 >> "${OUTDIR}/raw/gitleaks.log" 2>&1

[[ -f "${OUTDIR}/raw/secrets.json" ]] || echo "[]" > "${OUTDIR}/raw/secrets.json"
SECRET_COUNT=$(jq 'length' "${OUTDIR}/raw/secrets.json")
ok "Found ${SECRET_COUNT} potential secret(s)."

# ---------------------------------------------------------------------------
# Stage 4: Merge into a clean final report
# ---------------------------------------------------------------------------
info "Stage 4/4: Building final report..."
python3 "${LIB_DIR}/merge_report.py" \
  --endpoints "${OUTDIR}/raw/endpoints.json" \
  --secrets "${OUTDIR}/raw/secrets.json" \
  --outdir "$OUTDIR" \
  --format "$FORMAT"

echo ""
ok "Done. Results in: ${OUTDIR}"
echo "    JS files:        ${OUTDIR}/js/"
echo "    Report:           ${OUTDIR}/report.*"
echo "    Raw stage output: ${OUTDIR}/raw/"
