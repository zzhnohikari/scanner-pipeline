#!/bin/bash
# Fast parallel scanner for JS/API unauthorized access vulnerabilities
# Usage: ./fast_scan.sh [threads] [timeout]

THREADS=${1:-50}
TIMEOUT=${2:-4}
INPUT="/tmp/targets_filtered.txt"
OUTDIR="/tmp/scan_results"
mkdir -p "$OUTDIR"

echo "[*] Starting fast scan with $THREADS threads, timeout=${TIMEOUT}s"
echo "[*] Input: $INPUT"

# Phase 1: Quick HTTP probe - check which IPs respond on web ports
echo "[*] Phase 1: Quick HTTP probe..."
scan_one() {
    local target="$1"
    local timeout="$2"
    local outdir="$3"

    # If it's a full URL, use as-is
    if [[ "$target" == http://* ]] || [[ "$target" == https://* ]]; then
        local url="$target"
    else
        # IP only - try HTTPS first on common ports
        local url=""
        # Quick TCP connect to check ports
        for port in 443 8443 80 8080 8001; do
            if timeout 1 bash -c "echo >/dev/tcp/$target/$port" 2>/dev/null; then
                if [[ $port == 443 ]] || [[ $port == 8443 ]]; then
                    local scheme="https"
                else
                    local scheme="http"
                fi
                url="${scheme}://${target}:${port}"
                break
            fi
        done
    fi

    if [[ -z "$url" ]]; then
        return
    fi

    # HTTP probe
    local resp=$(curl -sk --max-time "$timeout" -o "$outdir/.tmp_$$" -w "%{http_code}|%{size_download}|%{url_effective}" "$url" 2>/dev/null)
    local code="${resp%%|*}"
    local rest="${resp#*|}"
    local size="${rest%%|*}"
    local final_url="${rest#*|}"

    if [[ "$code" =~ ^[0-9]+$ ]] && [ "$code" -lt 500 ] && [ "$size" -gt 0 ]; then
        local title=$(grep -oP '<title[^>]*>\K[^<]+' "$outdir/.tmp_$$" 2>/dev/null | head -1)
        echo "$code|$size|$title|$url|$final_url" >> "$outdir/responsive.txt"
    fi
    rm -f "$outdir/.tmp_$$"
}

export -f scan_one
export TIMEOUT OUTDIR

# Run parallel scan
cat "$INPUT" | xargs -P "$THREADS" -I {} bash -c 'scan_one "{}" "$TIMEOUT" "$OUTDIR"'

# Check results
if [ -f "$OUTDIR/responsive.txt" ]; then
    count=$(wc -l < "$OUTDIR/responsive.txt")
    echo "[*] Phase 1 done: $count responsive targets"
else
    echo "[!] No responsive targets found"
    exit 0
fi

# Phase 2: For responsive targets, download JS and test APIs
echo "[*] Phase 2: JS download + API test on responsive targets..."

test_target() {
    local line="$1"
    local timeout="$2"
    local outdir="$3"

    local url=$(echo "$line" | cut -d'|' -f4)
    local title=$(echo "$line" | cut -d'|' -f3)

    # Get main page
    local html=$(curl -sk --max-time "$timeout" "$url" 2>/dev/null)
    if [ -z "$html" ]; then
        return
    fi

    # Extract JS URLs (handle both quoted and unquoted attributes)
    local js_urls=$(echo "$html" | grep -oP '(?:src|href)=["\x27]?([^"'\'' >]+\.js[^"'\'' >]*)["\x27]?' | sed 's/.*=//;s/"//g;s/'\''//g' | sort -u)

    if [ -z "$js_urls" ]; then
        return
    fi

    # Filter out lib files
    local app_js=""
    while IFS= read -r js; do
        if ! echo "$js" | grep -qiE 'jquery|bootstrap|vue\.min|react\.min|angular|axios\.min|lodash|moment|echarts|swiper|polyfill|chunk-vendor|chunk-common|vendor\.|vendors\.|h265web|ZLMRTC|missile|fontawesome|codemirror|quill|tinymce|leaflet|mapbox|socket\.io|pdf\.js|highlight|markdown|webpack\.runtime'; then
            app_js="$app_js $js"
        fi
    done <<< "$js_urls"

    if [ -z "$app_js" ]; then
        return
    fi

    # Download JS files (max 5) and extract API paths
    local all_apis=""
    for js_url in $app_js; do
        # Make full URL if needed
        if [[ "$js_url" != http* ]]; then
            if [[ "$js_url" == /* ]]; then
                js_url="${url}${js_url}"
            else
                js_url="${url}/${js_url}"
            fi
        fi

        local js_content=$(curl -sk --max-time "$timeout" "$js_url" 2>/dev/null | head -c 500000)
        if [ -n "$js_content" ]; then
            # Extract API paths
            local apis=$(echo "$js_content" | grep -oP '(?:url|path|baseURL)\s*:\s*["\x27]\K/[^"'\'']+(?=["\x27])' | grep -iE '/api/|/user|/admin|/login|/auth|/server|/device|/channel|/record|/platform|/role|/log|/data|/info|/config' | sort -u)
            all_apis="$all_apis $apis"
        fi

        # Limit to 5 JS files
        if [ $(echo "$all_apis" | wc -w) -gt 30 ]; then
            break
        fi
    done

    if [ -z "$all_apis" ]; then
        return
    fi

    # Test each API for unauthenticated access
    echo "$all_apis" | tr ' ' '\n' | sort -u | head -30 | while IFS= read -r api_path; do
        [ -z "$api_path" ] && continue

        # Make full URL
        local api_url=""
        if [[ "$api_path" == http* ]]; then
            api_url="$api_path"
        else
            api_url="${url}${api_path}"
        fi

        local resp=$(curl -sk --max-time "$timeout" -o "$outdir/.api_resp_$$" -w "%{http_code}|%{size_download}" "$api_url" 2>/dev/null)
        local code="${resp%%|*}"
        local size="${resp#*|}"

        if [ "$code" = "200" ] && [ "$size" -gt 50 ]; then
            local content=$(head -c 1000 "$outdir/.api_resp_$$")
            # Check if it's JSON with data (not error/auth required)
            if echo "$content" | grep -qP '^\s*[{\[]'; then
                local has_data=$(echo "$content" | python3 -c "import sys,json;d=json.load(sys.stdin);print('YES' if d.get('data') or (isinstance(d,dict) and d.get('code') in (0,200,'0','200')) else 'NO')" 2>/dev/null)
                if [ "$has_data" = "YES" ]; then
                    echo "  [VULN] $api_url"
                    echo "  $content" | head -5
                    # Save to vuln file
                    echo "URL: $api_url" >> "$outdir/vulns_$title.txt"
                    echo "Title: $title" >> "$outdir/vulns_$title.txt"
                    echo "Response: $content" >> "$outdir/vulns_$title.txt"
                    echo "---" >> "$outdir/vulns_$title.txt"
                fi
            elif echo "$content" | grep -qiP '(password|secret|token|key|admin|config|user|device)'; then
                echo "  [INTERESTING] $api_url ($size bytes)"
            fi
        fi
        rm -f "$outdir/.api_resp_$$"
    done
}

export -f test_target

head -100 "$OUTDIR/responsive.txt" | xargs -P 10 -I {} bash -c 'test_target "{}" "$TIMEOUT" "$OUTDIR"'

echo ""
echo "[*] Scan complete"
echo "[*] Results in $OUTDIR/"
ls -la "$OUTDIR/"vulns_* 2>/dev/null && echo "Vulnerabilities found!" || echo "No vulnerabilities found in this scan."
