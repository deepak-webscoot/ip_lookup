#!/bin/bash
set -euo pipefail

# Script: ip_threat_checker.sh
# Description: Simple IP threat intelligence using AlienVault OTX

SCRIPT_NAME="ip_threat_checker.sh"
OTX_API_KEY="ad3be64c61425dcbca6a5dbd43f3c8e056ced8f3c2662dc5248c20815c083564"

# Cleanup function
cleanup() {
    rm -f "/tmp/ips.$$" "/tmp/logs.$$" 2>/dev/null || true
}

trap cleanup EXIT INT TERM

# Display usage
usage() {
    echo "=== Simple IP Threat Intelligence ==="
    echo "Usage: $0"
    echo ""
    echo "Automatically:"
    echo "• Finds web server logs"
    echo "• Extracts today's top IPs" 
    echo "• Checks against AlienVault OTX"
    echo "• Shows risk analysis"
    exit 0
}

if [[ "$#" -gt 0 ]] && [[ "$1" =~ ^(-h|--help)$ ]]; then
    usage
fi

# Check dependencies
check_dependencies() {
    for dep in grep awk curl jq find; do
        if ! command -v "$dep" &>/dev/null; then
            echo "Error: Required tool '$dep' not found"
            exit 1
        fi
    done
}

# Find log directory - SIMPLE AND RELIABLE
find_log_directory() {
    # Check in this exact order
    if [[ -d "/var/log/virtualmin" ]]; then
        echo "/var/log/virtualmin"
    elif [[ -d "/var/log/apache2/domlogs" ]]; then
        echo "/var/log/apache2/domlogs"
    elif [[ -d "/var/log/nginx" ]]; then
        echo "/var/log/nginx"
    elif [[ -d "/var/log/httpd" ]]; then
        echo "/var/log/httpd"
    else
        echo "Error: No log directory found" >&2
        exit 1
    fi
}

# Extract IPs - BULLETPROOF METHOD
extract_todays_ips() {
    local log_dir="$1"
    local output_file="$2"
    
    echo "Finding access logs in: $log_dir"
    
    # Get today's date in log format
    local today_pattern
    today_pattern=$(date +"%d/%b/%Y")
    echo "Searching for logs from: $today_pattern"
    
    # Find ALL log files (not just today's)
    local log_files=()
    while IFS= read -r -d '' file; do
        log_files+=("$file")
    done < <(find "$log_dir" -maxdepth 1 -type f \( -name "*access*log" -o -name "*.log" \) \
             ! -name "*.gz" ! -name "*.*[0-9]" -print0 2>/dev/null)
    
    if [[ ${#log_files[@]} -eq 0 ]]; then
        echo "Error: No log files found in $log_dir" >&2
        return 1
    fi
    
    echo "Found ${#log_files[@]} log files"
    
    # Process each log file
    local total_lines=0
    for logfile in "${log_files[@]}"; do
        if [[ ! -r "$logfile" ]]; then
            echo "  ⚠️  Cannot read: $(basename "$logfile")"
            continue
        fi
        
        # Count lines in this file (for progress)
        local file_lines
        file_lines=$(wc -l < "$logfile" 2>/dev/null || echo 0)
        
        echo "  📄 $(basename "$logfile"): $file_lines lines"
        
        # Extract today's entries OR all entries if none found
        if grep -q "$today_pattern" "$logfile" 2>/dev/null; then
            grep -h "$today_pattern" "$logfile" >> "/tmp/logs.$$" 2>/dev/null || true
        else
            # If no today's entries, use all entries from this file
            cat "$logfile" >> "/tmp/logs.$$" 2>/dev/null || true
        fi
    done
    
    # Check if we got any log entries
    total_lines=$(wc -l < "/tmp/logs.$$" 2>/dev/null || echo 0)
    
    # FIXED: Use string comparison instead of arithmetic to avoid syntax errors
    if [[ "$total_lines" == "0" ]]; then
        echo "Error: No log entries found" >&2
        return 1
    fi
    
    echo "Processing $total_lines log entries for IP extraction..."
    
    # EXTRACT IPs - SIMPLE AND RELIABLE
    # Method 1: Try awk first field
    awk '{print $1}' "/tmp/logs.$$" 2>/dev/null | \
    grep -E '^[0-9]+\.[0-9]+\.[0-9]+\.[0-9]+$' | \
    sort | uniq -c | sort -nr | head -30 > "$output_file"
    
    # Check if we got IPs
    local ip_count=0
    if [[ -f "$output_file" ]]; then
        ip_count=$(wc -l < "$output_file" 2>/dev/null || echo 0)
    fi
    
    # FIXED: Use string comparison
    if [[ "$ip_count" == "0" ]]; then
        echo "Error: No IP addresses could be extracted"
        echo "Debug: First 3 lines of log file:"
        head -3 "/tmp/logs.$$" | sed 's/^/  /'
        return 1
    fi
    
    echo "✓ Successfully extracted $ip_count unique IP addresses"
    return 0
}

# Check IP against AlienVault OTX
check_ip_threat() {
    local ip="$1"
    
    local response
    response=$(curl -s --max-time 10 --connect-timeout 5 \
              "https://otx.alienvault.com/api/v1/indicators/IPv4/$ip/general" \
              -H "X-OTX-API-KEY: $OTX_API_KEY" 2>/dev/null || echo '{}')
    
    local pulses
    pulses=$(echo "$response" | jq -r '.pulse_info.count // 0' 2>/dev/null || echo 0)
    
    local country
    country=$(echo "$response" | jq -r '.country_name // "Unknown"' 2>/dev/null || echo "Unknown")
    
    echo "$pulses|$country"
}

# Calculate risk level
get_risk_level() {
    local pulses="$1"
    
    # FIXED: Use string comparison to avoid syntax errors
    if [[ "$pulses" -gt 10 ]]; then
        echo "HIGH"
    elif [[ "$pulses" -gt 5 ]]; then
        echo "MEDIUM" 
    elif [[ "$pulses" -gt 0 ]]; then
        echo "LOW"
    else
        echo "CLEAN"
    fi
}

# Main function
main() {
    echo "=== Simple IP Threat Intelligence ==="
    echo "Starting analysis..."
    
    # Step 1: Check dependencies
    check_dependencies
    echo "✓ Basic tools available"
    
    # Step 2: Find logs
    local log_dir
    log_dir=$(find_log_directory)
    echo "✓ Using log directory: $log_dir"
    
    # Step 3: Extract IPs
    local ip_file="/tmp/ips.$$"
    if ! extract_todays_ips "$log_dir" "$ip_file"; then
        exit 1
    fi
    
    # Step 4: Analyze IPs
    echo ""
    echo "ANALYZING IP ADDRESSES:"
    echo "======================="
    printf "%-6s %-18s %-12s %-8s %-8s %s\n" "Hits" "IP Address" "Country" "Pulses" "Risk" "Recommendation"
    echo "-----------------------------------------------------------------------"
    
    local high_risk_ips=()
    
    while read -r line; do
        local hits ip
        hits=$(echo "$line" | awk '{print $1}')
        ip=$(echo "$line" | awk '{print $2}')
        
        # Skip if IP is empty
        [[ -z "$ip" ]] && continue
        
        # Check IP threat
        local result
        result=$(check_ip_threat "$ip")
        
        local pulses
        pulses=$(echo "$result" | cut -d'|' -f1)
        local country
        country=$(echo "$result" | cut -d'|' -f2)
        
        # Shorten long country names
        if [[ ${#country} -gt 10 ]]; then
            country="${country:0:9}."
        fi
        
        # Get risk level
        local risk_level
        risk_level=$(get_risk_level "$pulses")
        
        # Track high risk IPs
        if [[ "$risk_level" == "HIGH" ]]; then
            high_risk_ips+=("$ip")
        fi
        
        # Display result
        printf "%-6s %-18s %-12s %-8s %-8s " "$hits" "$ip" "$country" "$pulses" "$risk_level"
        
        # Recommendation
        if [[ "$risk_level" == "HIGH" ]]; then
            echo "🚨 BLOCK"
        elif [[ "$risk_level" == "MEDIUM" ]]; then
            echo "⚠️  MONITOR"
        else
            echo "✓ OK"
        fi
        
        # Rate limiting
        sleep 1
        
    done < "$ip_file"
    
    # Step 5: Show results
    echo ""
    echo "=== ANALYSIS COMPLETE ==="
    echo "IPs checked: $(wc -l < "$ip_file")"
    echo "High-risk IPs: ${#high_risk_ips[@]}"
    
    if [[ ${#high_risk_ips[@]} -gt 0 ]]; then
        echo ""
        echo "🚨 RECOMMENDED ACTIONS:"
        echo "======================="
        for ip in "${high_risk_ips[@]}"; do
            echo "csf -d $ip  # Block high-risk IP"
        done
    fi
    
    echo ""
    echo "Note: High-risk IPs have >10 threat intelligence reports"
}

# Run main function
main "$@"
