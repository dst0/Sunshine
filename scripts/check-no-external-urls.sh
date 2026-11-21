#!/usr/bin/env bash
# Check that Sunshine's sources (src/, src_assets/) contain no external URLs or network APIs beyond
# an explicit allowlist. Prints every violation and exits non-zero when there is one.
#
# Allowed without listing: URLs inside comments, local URLs (localhost, 127.0.0.1, [::1], the
# "https://{}" format string of the local Web UI address), XML namespace/DTD identifiers and the
# example.com placeholders in translations. Everything else must be on ALLOWED_URLS (user-facing
# documentation, download and license links that are only opened when a person clicks them) or,
# for network APIs, on ALLOWED_NETWORK_APIS.
#
# Usage: scripts/check-no-external-urls.sh [repository-root]
set -euo pipefail

ROOT=${1:-$(cd "$(dirname "$0")/.." && pwd)}
cd "$ROOT"
SCAN_DIRS=(src src_assets)

# Exact user-facing links (documentation, downloads, license). Never requested automatically.
ALLOWED_URLS=(
  # Documentation links in a log message, the Web UI and the Windows setup script.
  'https://docs.lizardbyte.dev/projects/sunshine'
  'https://docs.lizardbyte.dev/projects/sunshine/latest'
  'https://docs.lizardbyte.dev/projects/sunshine/latest/'
  'https://docs.lizardbyte.dev/projects/sunshine/latest/md_docs_2configuration.html#csrf_allowed_origins'
  # Web UI resource card and license links.
  'https://app.lizardbyte.dev'
  'https://app.lizardbyte.dev/discord'
  'https://github.com/orgs/LizardByte/discussions'
  'https://github.com/SunshineStream/Sunshine/blob/master/LICENSE'
  'https://github.com/SunshineStream/Sunshine/blob/master/NOTICE'
  # Windows version resource (LegalCopyright string).
  'https://raw.githubusercontent.com/SunshineStream/Sunshine/master/LICENSE'
  # Driver download pages linked from the Web UI troubleshooting page.
  'https://github.com/nefarius/ViGEmBus/releases/latest'
  'https://github.com/LizardByte/libvirtualhid/releases/latest'
  # Reference links in configuration help texts.
  'https://github.com/mattingalls/Soundflower'
  'https://github.com/ExistentialAudio/BlackHole'
  'https://learn.microsoft.com/en-us/windows/win32/inputdev/virtual-key-codes'
  'https://en.wikipedia.org/wiki/Video_buffering_verifier'
  'https://devblogs.microsoft.com/directx/hardware-accelerated-gpu-scheduling/'
)

# URL prefixes that are identifiers, local addresses or placeholders (extended regular expressions).
ALLOWED_URL_PATTERNS=(
  '^https?://$'                                                # bare scheme, e.g. starts_with("https://")
  '^https?://(localhost|127\.0\.0\.1|\[::1\])([:/].*)?$'      # loopback
  '^https://\{\}'                                              # std::format of the local Web UI address
  '^http://www\.w3\.org/'                                      # XML/SVG namespaces
  '^http://www\.inkscape\.org/namespaces/'
  '^http://sodipodi\.sourceforge\.net/DTD/'
  '^http://www\.apple\.com/DTDs/'                              # plist DTD identifier
)

# Placeholder hosts used in translated help texts (only allowed in locale files).
LOCALE_PLACEHOLDER='^https://(example\.com|ejemplo\.com)'
LOCALE_DIR='src_assets/common/assets/web/public/assets/locale/'

# Network APIs (extended regular expressions matched against source lines).
NETWORK_APIS='curl_(easy|multi|url|global|share)_|<curl/curl\.h>|getaddrinfo|gethostbyname|ip::(tcp|udp)::resolver|async_resolve|WinHttp|InternetOpen|URLDownloadToFile|NSURLSession|NSURLConnection|QNetworkAccessManager|fetch\([[:space:]]*["'"'"'`]https?:|XMLHttpRequest|new[[:space:]]+WebSocket\(|EventSource\(|sendBeacon\(|\baxios\b|upnpDiscover|UPNP_(Add|Delete|Get)[A-Za-z]*\('

# "file:extended-regex" pairs for reviewed network API uses.
ALLOWED_NETWORK_APIS=(
  # UPnP port mapping with the LAN router; opt-in (upnp = disabled by default).
  'src/upnp.cpp:'
  'src/upnp.h:'
  # Web UI logout: an XMLHttpRequest to "/" on the local Web UI to drop cached credentials.
  'src_assets/common/assets/web/Navbar.vue:XMLHttpRequest'
)

violations=0

report() {
  echo "$1"
  violations=$((violations + 1))
}

is_allowed_url() {
  local file=$1 url=$2 allowed pattern
  for allowed in "${ALLOWED_URLS[@]}"; do
    [[ "$url" == "$allowed" ]] && return 0
  done
  for pattern in "${ALLOWED_URL_PATTERNS[@]}"; do
    [[ "$url" =~ $pattern ]] && return 0
  done
  if [[ "$file" == "$LOCALE_DIR"* && "$url" =~ $LOCALE_PLACEHOLDER ]]; then
    return 0
  fi
  return 1
}

# A URL is in a comment when the line starts with a comment marker, or when a comment opens before
# it ("// " preceded by whitespace, or "/*"); the "//" of URL schemes is ignored.
in_comment() {
  local content=$1 prefix=$2
  [[ "$content" =~ ^[[:space:]]*(//|/\*|\*|#|\<!--|\;|--) ]] && return 0
  prefix=${prefix//:\/\//}
  [[ "$prefix" =~ (^|[[:space:]])//|/\* ]] && return 0
  return 1
}

# 1. URL literals.
url_regex='(https?://[^[:space:]"'"'"'<>)\\`,]*)'
while IFS= read -r line; do
  file=${line%%:*}
  rest=${line#*:}
  number=${rest%%:*}
  content=${rest#*:}
  remaining=$content
  consumed=""
  while [[ "$remaining" =~ $url_regex ]]; do
    url=${BASH_REMATCH[1]}
    before=${remaining%%"$url"*}
    prefix="$consumed$before"
    consumed="$prefix$url"
    remaining=${remaining#*"$url"}
    # Strip trailing punctuation that belongs to the surrounding text.
    url=${url%%[.;]}
    if in_comment "$content" "$prefix"; then
      continue
    fi
    if ! is_allowed_url "$file" "$url"; then
      report "$file:$number: external URL not on the allowlist: $url"
    fi
  done
done < <(grep -rnIE 'https?://' "${SCAN_DIRS[@]}" || true)

# 2. Network APIs.
while IFS= read -r line; do
  file=${line%%:*}
  rest=${line#*:}
  number=${rest%%:*}
  content=${rest#*:}
  allowed=false
  for entry in "${ALLOWED_NETWORK_APIS[@]}"; do
    entry_file=${entry%%:*}
    entry_pattern=${entry#*:}
    if [[ "$file" == "$entry_file" ]] && { [[ -z "$entry_pattern" ]] || [[ "$content" =~ $entry_pattern ]]; }; then
      allowed=true
      break
    fi
  done
  if ! $allowed; then
    report "$file:$number: network API not on the allowlist: $(echo "$content" | sed -E 's/^[[:space:]]+//' | cut -c1-160)"
  fi
done < <(grep -rnIE "$NETWORK_APIS" "${SCAN_DIRS[@]}" || true)

if ((violations > 0)); then
  echo "check-no-external-urls: $violations violation(s)" >&2
  exit 1
fi
echo "check-no-external-urls: no external URLs or network APIs outside the allowlist"
