#!/bin/bash

set -euo pipefail

# Script: ip_lookup_abuse_free.sh
# Description: 100% Free IP Threat Intelligence Analyzer

SCRIPT_NAME="ip_lookup_abuse_free.sh"
CACHE_DIR="/var/cache/abuseipdb"
TEMP_PREFIX="/tmp/ip_lookup_abuse"
THREAT_FEEDS_DIR="/etc/ip_threat_feeds"

# Cleanup function
cleanup() {
    rm -f "${TEMP_PREFIX}.$$."* 2>/dev/null || true
}

trap cleanup EXIT INT TERM

# Display usage information
usage() {
    echo "$SCRIPT_NAME - Free IP Threat Intelligence Analyzer"
    echo ""
    echo "Usage:"
    echo "  $SCRIPT_NAME                    # Automatic mode - finds and analyzes all recent logs"
    echo "  $SCRIPT_NAME <logfile>          # Single file mode - analyzes specific log file"
    echo ""
    echo "Examples:"
    echo "  $SCRIPT_NAME                                  # Auto-detect and analyze all logs"
    echo "  $SCRIPT_NAME /var/log/nginx/access.log        # Analyze specific file"
    echo "  $SCRIPT_NAME dominick.fun_access_log          # Analyze current directory file"
    echo ""
}

# Check if jq is installed
if ! command -v jq &>/dev/null; then
    echo "Error: jq is required but not installed. Install it using: sudo apt install jq"
    exit 1
fi

# Check if curl is installed
if ! command -v curl &>/dev/null; then
    echo "Error: curl is required but not installed. Install it using: sudo apt install curl"
    exit 1
fi

# Initialize temp files
TODAY_LOGS="${TEMP_PREFIX}.$$.today_logs"
IPS_TODAY="${TEMP_PREFIX}.$$.ips_today"

# Function to setup threat intelligence feeds
setup_threat_feeds() {
    echo "Setting up free threat intelligence feeds..."

    mkdir -p "$THREAT_FEEDS_DIR"

    local blocklists=(
        "https://feodotracker.abuse.ch/downloads/ipblocklist.txt|ipblocklist.txt"
        "https://rules.emergingthreats.net/blockrules/compromised-ips.txt|compromised-ips.txt"
        "https://blocklist.greensnow.co/greensnow.txt|greensnow.txt"
        "https://www.binarydefense.com/banlist.txt|banlist.txt"
    )

    for list in "${blocklists[@]}"; do
        local url="${list%|*}"
        local filename="${list#*|}"
        local filepath="$THREAT_FEEDS_DIR/$filename"

        if [[ -f "$filepath" ]] && [[ $(find "$filepath" -mtime -1 2>/dev/null | wc -l) -gt 0 ]]; then
            echo "  ✓ $filename (up to date)"
        else
            echo "Downloading: $filename"
            if curl -s --connect-timeout 10 --max-time 30 "$url" -o "$filepath.tmp"; then
                mv "$filepath.tmp" "$filepath"
                echo "  ✓ Success"
            else
                echo "  ✗ Failed to download $filename"
                rm -f "$filepath.tmp"
            fi
        fi
    done

    echo "Threat feeds updated successfully"
}

# Function to check if IP is in blocklists
check_blocklists() {
    local ip="$1"
    local count=0

    for blockfile in "$THREAT_FEEDS_DIR"/*.txt; do
        if [[ -f "$blockfile" ]] && grep -q "^$ip$" "$blockfile" 2>/dev/null; then
            ((count++))
        fi
    done

    echo "$count"
}

# Function to get AlienVault OTX data
get_alienvault_data() {
    local ip="$1"
    local otx_data
    local pulses=0

    otx_data=$(curl -s --connect-timeout 10 --max-time 15 \
        "https://otx.alienvault.com/api/v1/indicators/IPv4/$ip/general" \
        -H "X-OTX-API-KEY: ad3be64c61425dcbca6a5dbd43f3c8e056ced8f3c2662dc5248c20815c083564" 2>/dev/null || echo '{}')

    pulses=$(echo "$otx_data" | jq -r '.pulse_info.count // 0' 2>/dev/null || echo 0)

    echo "$pulses"
}

# Function to calculate risk score
calculate_risk_score() {
    local pulses="$1"
    local blocklists="$2"

    local pulse_score=0
    if [ "$pulses" -gt 10 ]; then
        pulse_score=70
    elif [ "$pulses" -gt 5 ]; then
        pulse_score=50
    elif [ "$pulses" -gt 2 ]; then
        pulse_score=30
    elif [ "$pulses" -gt 0 ]; then
        pulse_score=10
    fi

    local blocklist_score=$((blocklists * 10))
    if [ "$blocklist_score" -gt 30 ]; then
        blocklist_score=30
    fi

    local total_score=$((pulse_score + blocklist_score))
    echo "$total_score"
}

# Function to get risk level
get_risk_level() {
    local score="$1"
    if [ "$score" -ge 70 ]; then
        echo "HIGH"
    elif [ "$score" -ge 30 ]; then
        echo "MEDIUM"
    else
        echo "LOW"
    fi
}

# Function to find log directory
find_log_directory() {
    local candidates=(/var/log/virtualmin /var/log/nginx /var/log/apache2/domlogs /var/log/apache2)
    local best_dir=""
    local max_size=0

    for dir in "${candidates[@]}"; do
        if [[ -d "$dir" ]]; then
            local size
            size=$(du -s "$dir" 2>/dev/null | cut -f1 || echo 0)
            if [ "$size" -gt "$max_size" ]; then
                max_size=$size
                best_dir="$dir"
            fi
        fi
    done

    if [ -z "$best_dir" ]; then
        echo "Error: No suitable log directory found." >&2
        exit 1
    fi

    echo "$best_dir"
}

# Function to extract today's logs from files
extract_todays_logs() {
    local files="$1"
    local today_pattern=$(date +"%d/%b/%Y")

    echo "Extracting today's ($today_pattern) requests from logs..."

    > "$TODAY_LOGS"
    local total_lines=0
    local files_processed=0

    for file in $files; do
        if [ ! -r "$file" ]; then
            echo "Warning: Cannot read log file $file, skipping..." >&2
            continue
        fi

        local file_lines=$(grep -c "$today_pattern" "$file" 2>/dev/null || echo 0)
        if [ "$file_lines" -gt 0 ]; then
            grep -h "$today_pattern" "$file" >> "$TODAY_LOGS" 2>/dev/null || true
            total_lines=$((total_lines + file_lines))
            files_processed=$((files_processed + 1))
        fi
    done

    if [ "$total_lines" -eq 0 ]; then
        echo "No today's traffic found in logs. Possible reasons:"
        echo "  - No traffic today"
        echo "  - Date format mismatch"
        echo "  - Timezone differences"
        echo ""
        echo "Try checking recent traffic instead:"
        echo "  tail -20 /var/log/virtualmin/dominick.fun_access_log"
        return 1
    fi

    echo "Extracted $total_lines log entries from $files_processed files"
    return 0
}

# Function to extract and aggregate IPs
extract_and_aggregate_ips() {
    echo "Analyzing IP addresses..."

    awk '
    function is_private_ip(ip) {
        if (ip ~ /^10\./) return 1
        if (ip ~ /^192\.168\./) return 1
        if (ip ~ /^172\.(1[6-9]|2[0-9]|3[0-1])\./) return 1
        if (ip ~ /^127\./) return 1
        if (ip ~ /^::1$/) return 1
        return 0
    }
    {
        ip = $1
        if (is_private_ip(ip)) next
        print ip
    }' "$TODAY_LOGS" | sort | uniq -c | sort -nr | head -30 > "$IPS_TODAY"

    echo "Found $(wc -l < "$IPS_TODAY") unique IP addresses to analyze"
}

# Main execution function
main() {
    local specific_file="${1:-}"

    echo "=== Free IP Threat Intelligence ==="
    echo "Starting automated analysis..."

    # Setup threat intelligence
    setup_threat_feeds

    # Determine log source
    local LOG_FILES
    local LOG_SOURCE

    if [ -n "$specific_file" ]; then
        if [ ! -f "$specific_file" ]; then
            echo "Error: File '$specific_file' not found" >&2
            exit 1
        fi
        LOG_FILES="$specific_file"
        LOG_SOURCE="File: $(basename "$specific_file")"
        echo "Analyzing specific file: $specific_file"
    else
        local LOG_DIR
        LOG_DIR=$(find_log_directory)
        LOG_SOURCE="Directory: $LOG_DIR"
        echo "Using log directory: $LOG_DIR"

        LOG_FILES=$(find "$LOG_DIR" -maxdepth 1 -type f \( -name "*access*log" -o -name "*ssl*log" \) ! -name "*.gz" ! -name "*.[0-9]*" | head -10)

        if [ -z "$LOG_FILES" ]; then
            echo "Error: No accessible log files found in $LOG_DIR" >&2
            exit 1
        fi

        echo "Found $(echo "$LOG_FILES" | wc -w) current log files"
    fi

    # Extract today's logs
    if ! extract_todays_logs "$LOG_FILES"; then
        echo "Analysis stopped: No today's logs found"
        exit 1
    fi

    # Extract and aggregate IPs
    extract_and_aggregate_ips

    # Display results
    echo ""
    echo "LEGEND:"
    echo "• Pulses = Number of threat intelligence feeds reporting this IP"
    echo "• BLists = Number of blocklists containing this IP"
    echo "• Score = Risk score (0-100), HIGH = 70+, MEDIUM = 30-69, LOW = 0-29"
    echo ""
    printf "%-6s %-18s %-8s %-8s %-6s %-5s\n" "Hits" "IP" "Pulses" "BLists" "Score" "Risk"
    echo "----------------------------------------------------------------"

    # Process each IP
    local high_risk_ips=()

    while read -r line; do
        hits=$(echo "$line" | awk '{print $1}')
        ip=$(echo "$line" | awk '{print $2}')

        # Get threat intelligence data
        pulses=$(get_alienvault_data "$ip")
        blocklists=$(check_blocklists "$ip")
        risk_score=$(calculate_risk_score "$pulses" "$blocklists")
        risk_level=$(get_risk_level "$risk_score")

        printf "%-6s %-18s %-8s %-8s %-6s %-5s\n" \
               "$hits" "$ip" "$pulses" "$blocklists" "$risk_score" "$risk_level"

        if [ "$risk_level" = "HIGH" ]; then
            high_risk_ips+=("$ip")
        fi

    done < "$IPS_TODAY"

    # Generate blocking recommendations
    if [ ${#high_risk_ips[@]} -gt 0 ]; then
        echo ""
        echo "=== ANALYSIS COMPLETE ==="
        echo "• IPs checked: $(wc -l < "$IPS_TODAY")"
        echo "• High-risk IPs found: ${#high_risk_ips[@]}"

        echo ""
        echo "🚨 Recommended action: Block IPs with HIGH risk score"
        echo ""
        echo "🔧 CSF blocking commands:"
        for ip in "${high_risk_ips[@]}"; do
            echo "csf -d $ip  # \"Malicious IP detected via threat intelligence\""
        done
        echo ""
        echo "To unblock later: csf -dr <IP>"
    else
        echo ""
        echo "=== ANALYSIS COMPLETE ==="
        echo "• IPs checked: $(wc -l < "$IPS_TODAY")"
        echo "• No high-risk IPs found"
    fi
}

# Show help if requested
if [ "$#" -gt 0 ] && [[ "$1" =~ ^(-h|--help)$ ]]; then
    usage
    exit 0
fi

# Run main function
main "$@"
