#!/bin/bash
set -euo pipefail

# 1. SETUP - Minimal dependencies
check_deps() {
    command -v grep >/dev/null && command -v awk >/dev/null && command -v curl >/dev/null
}

# 2. FIND LOGS - Simple directory discovery
find_log_dir() {
    for dir in /var/log/virtualmin /var/log/apache2 /var/log/nginx; do
        [[ -d "$dir" ]] && echo "$dir" && return
    done
    exit 1
}

# 3. EXTRACT TODAY'S IPs - ONE reliable method
extract_ips() {
    local log_dir="$1"
    local output_file="$2"
    
    # Get today's date in log format
    local today=$(date +"%d/%b/%Y")
    
    # ONE METHOD: Stream process logs directly
    find "$log_dir" -name "*access*log" -type f ! -name "*.gz" | \
    while read logfile; do
        # Stream process each file - no memory overload
        grep -h "$today" "$logfile" 2>/dev/null | \
        awk '{print $1}' | \
        grep -E '^[0-9]+\.[0-9]+\.[0-9]+\.[0-9]+$'
    done | sort | uniq -c | sort -nr | head -30 > "$output_file"
}

# 4. THREAT CHECK - Simple API calls
check_threat() {
    local ip="$1"
    # Simple curl call with timeout
    curl -s --max-time 5 "https://otx.alienvault.com/api/v1/indicators/IPv4/$ip/general" | \
    jq -r '.pulse_info.count // 0'
}

# 5. MAIN FLOW - Straight line execution
main() {
    echo "=== Starting Analysis ==="
    
    # Setup
    check_deps || { echo "Missing basic tools"; exit 1; }
    local log_dir=$(find_log_dir)
    echo "Using logs: $log_dir"
    
    # Extract IPs
    local ip_file="/tmp/ips.$$"
    extract_ips "$log_dir" "$ip_file"
    
    # Check if we got IPs
    [[ -s "$ip_file" ]] || { echo "No IPs found"; exit 1; }
    
    # Process each IP
    while read count ip; do
        echo "Checking $ip ($count hits)..."
        local threat_count=$(check_threat "$ip")
        echo "  Threats: $threat_count"
        sleep 1
    done < "$ip_file"
    
    # Cleanup
    rm -f "$ip_file"
}

main "$@"
