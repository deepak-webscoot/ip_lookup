#!/bin/bash

set -euo pipefail

# Script: ip_lookup_abuse_free.sh
# Description: 100% Free IP Threat Intelligence using AlienVault OTX + Blocklists

SCRIPT_NAME="ip_lookup_abuse_free.sh"
CACHE_DIR="/var/cache/abuseipdb"
THREAT_FEEDS_DIR="/etc/ip_threat_feeds"
TEMP_PREFIX="/tmp/ip_lookup_abuse"
OTX_API_KEY="ad3be64c61425dcbca6a5dbd43f3c8e056ced8f3c2662dc5248c20815c083564"

# Blocklist URLs - 100% FREE, no accounts needed
BLOCKLIST_URLS=(
    "https://feodotracker.abuse.ch/downloads/ipblocklist.txt"
    "https://rules.emergingthreats.net/blockrules/compromised-ips.txt"
    "https://blocklist.greensnow.co/greensnow.txt"
    "https://www.binarydefense.com/banlist.txt"
)

# Cleanup function
cleanup() {
    rm -f "${TEMP_PREFIX}.$$."* 2>/dev/null || true
}

trap cleanup EXIT INT TERM

# Display usage
usage() {
    echo "=== 100% FREE IP Threat Intelligence ==="
    echo "Usage: $0"
    echo ""
    echo "This script automatically:"
    echo "• Downloads free threat intelligence feeds"
    echo "• Checks IPs against AlienVault OTX + 4 blocklists"
    echo "• Provides risk scoring for automated blocking"
    echo "• Requires NO paid APIs or subscriptions"
    exit 0
}

if [[ "$#" -gt 0 ]] && [[ "$1" =~ ^(-h|--help)$ ]]; then
    usage
fi

# Check and install dependencies
check_dependencies() {
    local deps=("jq" "curl" "wget")
    local missing=()

    for dep in "${deps[@]}"; do
        if ! command -v "$dep" &>/dev/null; then
            missing+=("$dep")
        fi
    done

    if [[ ${#missing[@]} -gt 0 ]]; then
        echo "Installing missing dependencies: ${missing[*]}"
        apt update && apt install -y "${missing[@]}" 2>/dev/null || {
            echo "Error: Failed to install dependencies. Please run: sudo apt update && sudo apt install jq curl wget"
            exit 1
        }
    fi
}

# Setup threat feeds directory and download blocklists
setup_threat_feeds() {
    echo "Setting up free threat intelligence feeds..."

    # Create directories
    mkdir -p "$THREAT_FEEDS_DIR"
    mkdir -p "$CACHE_DIR"

    # Download all blocklists
    local updated=false
    for url in "${BLOCKLIST_URLS[@]}"; do
        local filename
        filename=$(basename "$url")
        local filepath="$THREAT_FEEDS_DIR/$filename"

        # Download if file doesn't exist or is older than 24 hours
        if [[ ! -f "$filepath" ]] || find "$filepath" -mtime +0 | grep -q .; then
            echo "Downloading: $filename"
            if wget -q -O "$filepath.tmp" "$url"; then
                mv "$filepath.tmp" "$filepath"
                updated=true
                echo "  ✓ Success"
            else
                echo "  ✗ Failed to download $filename"
                rm -f "$filepath.tmp"
            fi
        else
            echo "  ✓ $filename (up to date)"
        fi
    done

    if [[ "$updated" == true ]]; then
        echo "Threat feeds updated successfully"
    else
        echo "Threat feeds are up to date"
    fi
}

# Check if IP is in any blocklist (INSTANT check)
check_blocklists() {
    local ip="$1"
    local matches=0

    for file in "$THREAT_FEEDS_DIR"/*.txt; do
        if [[ -f "$file" ]] && grep -q "^$ip$" "$file" 2>/dev/null; then
            ((matches++))
        fi
    done

    echo "$matches"
}

# Get AlienVault OTX data
get_otx_data() {
    local ip="$1"
    local data
    data=$(curl -s --connect-timeout 10 --max-time 15 \
           "https://otx.alienvault.com/api/v1/indicators/IPv4/$ip/general" \
           -H "X-OTX-API-KEY: $OTX_API_KEY" 2>/dev/null || echo '{}')
    echo "$data"
}

# Calculate risk score
calculate_risk_score() {
    local pulses="$1"
    local blocklist_matches="$2"

    # Pulse-based scoring (0-70 points)
    local pulse_score=0
    if [[ $pulses -gt 10 ]]; then
        pulse_score=70
    elif [[ $pulses -gt 5 ]]; then
        pulse_score=50
    elif [[ $pulses -gt 2 ]]; then
        pulse_score=30
    elif [[ $pulses -gt 0 ]]; then
        pulse_score=10
    fi

    # Blocklist matches (0-30 points)
    local blocklist_score=$((blocklist_matches * 8))
    if [[ $blocklist_score -gt 30 ]]; then
        blocklist_score=30
    fi

    local total_score=$((pulse_score + blocklist_score))
    echo "$total_score"
}

# Get risk level
get_risk_level() {
    local score="$1"
    if [[ "$score" -ge 70 ]]; then
        echo "HIGH"
    elif [[ "$score" -ge 30 ]]; then
        echo "MEDIUM"
    else
        echo "LOW"
    fi
}

# Find log directory
find_log_directory() {
    # Prioritize Apache domlogs first, then other locations
    local candidates=(/var/log/apache2/domlogs /var/log/virtualmin /var/log/nginx /var/log/apache2)
    local best_dir=""
    local max_size=0

    for dir in "${candidates[@]}"; do
        if [[ -d "$dir" ]]; then
            local size
            size=$(du -s "$dir" 2>/dev/null | cut -f1 || echo 0)
            if [[ "$size" -gt "$max_size" ]]; then
                max_size=$size
                best_dir="$dir"
            fi
        fi
    done

    if [[ -z "$best_dir" ]]; then
        echo "Error: No log directory found" >&2
        exit 1
    fi

    echo "$best_dir"
}

# Extract domain from filename (SMART VERSION)
extract_domain_from_filename() {
    local filename="$1"

    # Remove directory path
    local basename
    basename=$(basename "$filename")

    # Remove common suffixes and extract domain
    local domain
    domain=$(echo "$basename" | sed -E 's/[_\-](access|ssl|log|domlog).*$//' | sed -E 's/\.(log|access|ssl).*$//')

    # Validate it looks like a domain (has a dot and valid TLD pattern)
    if [[ "$domain" =~ [a-zA-Z0-9-]+\.[a-zA-Z]{2,} ]]; then
        echo "$domain"
    else
        echo "Unknown"
    fi
}

# SIMPLE domain detection - just use the domain from the aggregated logs
get_domain_for_ip_simple() {
    local ip="$1"
    local today_logs="${TEMP_PREFIX}.$$.today_logs"

    # Extract domain from log lines containing this IP
    local domain_line
    domain_line=$(grep " $ip " "$today_logs" | head -1)

    if [[ -n "$domain_line" ]]; then
        # For Virtualmin logs, the domain is often in the first field with port
        local first_field
        first_field=$(echo "$domain_line" | awk '{print $1}')
        if [[ "$first_field" =~ : ]]; then
            local domain
            domain=$(echo "$first_field" | cut -d: -f1)
            echo "$domain"
            return
        fi
    fi

    echo "Unknown"
}

# Show recent raw log entries for high-risk IPs using grep -Rai
show_recent_raw_logs() {
    local log_dir="$1"
    shift
    local high_risk_ips=("$@")

    if [[ ${#high_risk_ips[@]} -eq 0 ]]; then
        return
    fi

    echo ""
    echo "🔍 RECENT LOG ENTRIES FOR HIGH-RISK IPs:"
    echo "=============================================="

    for ip in "${high_risk_ips[@]}"; do
        echo ""
        echo "🚨 HIGH-RISK IP: $ip"
        echo "----------------------------------------------"

        # Use grep to search through all log files for this IP
        local recent_entries
        recent_entries=$(grep -h "$ip" "$log_dir"/* 2>/dev/null | tail -5)

        if [[ -n "$recent_entries" ]]; then
            echo "Recent log entries:"
            echo "---"
            echo "$recent_entries"
        else
            # Try recursive search if direct search fails
            recent_entries=$(find "$log_dir" -type f -name "*.log" -exec grep -h "$ip" {} \; 2>/dev/null | tail -5)
            if [[ -n "$recent_entries" ]]; then
                echo "Recent log entries:"
                echo "---"
                echo "$recent_entries"
            else
                echo "    No recent log entries found for $ip"
            fi
        fi
        echo ""
    done
}

# Find CURRENT log files (not rotated)
find_current_log_files() {
    local log_dir="$1"
    # Find access log files that are NOT rotated (no .1, .2, etc.) and NOT error logs
    find "$log_dir" -maxdepth 1 -type f \( -name "*access*log" -o -name "*ssl*log" -o -name "*.log" \) \
         ! -name "*.gz" ! -name "*.*[0-9]" ! -name "*_error*" 2>/dev/null | head -20
}

# Main function
main() {
    echo "=== 100% FREE IP Threat Intelligence ==="
    echo "Starting automated analysis..."

    # Check dependencies
    check_dependencies

    # Setup threat feeds
    setup_threat_feeds

    # Find and process logs
    local log_dir
    log_dir=$(find_log_directory)
    echo "Using log directory: $log_dir"

    # Create temp files
    local today_logs="${TEMP_PREFIX}.$$.today_logs"
    local ips_today="${TEMP_PREFIX}.$$.ips_today"

    echo "Finding recent CURRENT log files (excluding rotated logs)..."

    # Find CURRENT log files only (no .1, .2 files)
    local log_files
    log_files=$(find_current_log_files "$log_dir")

    if [[ -z "$log_files" ]]; then
        echo "Error: No current log files found" >&2
        exit 1
    fi

    # Show which log files we found
    echo "Found CURRENT log files:"
    for file in $log_files; do
        local domain
        domain=$(extract_domain_from_filename "$file")
        echo "  📄 $(basename "$file") → Domain: $domain"
    done

    local today_pattern
    today_pattern=$(date +"%d/%b/%Y")
    echo ""
    echo "Extracting today's ($today_pattern) traffic from CURRENT logs..."

    # Extract today's logs from CURRENT files only
    for file in $log_files; do
        if [[ -r "$file" ]]; then
            grep -h "$today_pattern" "$file" 2>/dev/null || true
        fi
    done > "$today_logs"

    local log_count
    log_count=$(wc -l < "$today_logs" 2>/dev/null || echo 0)

    if [[ $log_count -eq 0 ]]; then
        echo "No today's traffic found in current logs. Checking all dates in current logs..."
        # If no today's traffic, use all traffic from current logs
        for file in $log_files; do
            if [[ -r "$file" ]]; then
                cat "$file" 2>/dev/null || true
            fi
        done > "$today_logs"
        log_count=$(wc -l < "$today_logs" 2>/dev/null || echo 0)
    fi

    if [[ $log_count -eq 0 ]]; then
        echo "Error: No log entries found in current log files" >&2
        exit 1
    fi

    echo "Found $log_count log entries"

    # Extract unique IPs
    echo "Extracting IP addresses..."
    awk '
    function is_private_ip(ip) {
        if (ip ~ /^10\./) return 1
        if (ip ~ /^192\.168\./) return 1
        if (ip ~ /^172\.(1[6-9]|2[0-9]|3[0-1])\./) return 1
        if (ip ~ /^127\./) return 1
        return 0
    }
    {
        ip = $1
        if (is_private_ip(ip)) next
        print ip
    }' "$today_logs" | sort | uniq -c | sort -nr | head -30 > "$ips_today"

    local ip_count
    ip_count=$(wc -l < "$ips_today" 2>/dev/null || echo 0)

    if [[ $ip_count -eq 0 ]]; then
        echo "No valid IP addresses found for analysis"
        exit 0
    fi

    echo "Analyzing $ip_count unique IP addresses..."

    # Display results header with explanations
    echo ""
    echo "LEGEND:"
    echo "• Pulses = Number of threat intelligence feeds reporting this IP"
    echo "• BLists = Number of blocklists containing this IP"
    echo "• Score = Risk score (0-100), HIGH = 70+, MEDIUM = 30-69, LOW = 0-29"
    echo ""
    printf "%-6s %-18s %-12s %-8s %-8s %-6s %-8s %s\n" "Hits" "IP" "Country" "Pulses" "BLists" "Score" "Risk" "Domain"
    echo "----------------------------------------------------------------------------------------------------"

    local high_risk_ips=()

    # Process each IP
    while read -r line; do
        local hits
        hits=$(echo "$line" | awk '{print $1}')
        local ip
        ip=$(echo "$line" | awk '{print $2}')

        # Skip if IP is empty
        if [[ -z "$ip" ]]; then
            continue
        fi

        # SIMPLE domain detection
        local domain
        domain=$(get_domain_for_ip_simple "$ip")

        # Shorten domain for display
        if [[ ${#domain} -gt 20 ]]; then
            domain_display="${domain:0:17}..."
        else
            domain_display="$domain"
        fi

        # INSTANT check: Blocklists (0.001 seconds)
        local blocklist_matches
        blocklist_matches=$(check_blocklists "$ip")

        # API check: AlienVault OTX (2-3 seconds)
        local otx_data
        otx_data=$(get_otx_data "$ip")
        local pulses
        pulses=$(echo "$otx_data" | jq -r '.pulse_info.count // 0' 2>/dev/null || echo 0)
        local country
        country=$(echo "$otx_data" | jq -r '.country_name // "Unknown"' 2>/dev/null || echo "Unknown")

        # Shorten country name if too long
        if [[ ${#country} -gt 10 ]]; then
            country="${country:0:9}."
        fi

        # Calculate risk score
        local risk_score
        risk_score=$(calculate_risk_score "$pulses" "$blocklist_matches")
        local risk_level
        risk_level=$(get_risk_level "$risk_score")

        # Track high-risk IPs for detailed logs
        if [[ "$risk_level" == "HIGH" ]]; then
            high_risk_ips+=("$ip")
        fi

        # Display results
        printf "%-6s %-18s %-12s %-8s %-8s %-6s %-8s %s\n" \
               "$hits" "$ip" "$country" "$pulses" "$blocklist_matches" "$risk_score" "$risk_level" "$domain_display"

        # Rate limiting for API calls
        sleep 1

    done < "$ips_today"

    # FIXED: Call show_recent_raw_logs with correct parameters
    show_recent_raw_logs "$log_dir" "${high_risk_ips[@]}"

    echo ""
    echo "=== ANALYSIS COMPLETE ==="
    echo "• Sources: AlienVault OTX + 4 free blocklists"
    echo "• IPs checked: $ip_count"
    echo "• High-risk IPs found: ${#high_risk_ips[@]}"
    echo ""
    echo "🚨 Recommended action: Block IPs with HIGH risk score"

    # Show quick blocking command
    if [[ ${#high_risk_ips[@]} -gt 0 ]]; then
        echo ""
        echo "🔧 Quick blocking command:"
        for ip in "${high_risk_ips[@]}"; do
            echo "csf -d $ip"
        done
        echo ""
    fi
}

# Run main function
main "$@"
