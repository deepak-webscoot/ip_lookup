#!/bin/bash
set -euo pipefail

# Script: ip_threat_checker.sh
# Description: Simple IP threat intelligence using AlienVault OTX
# Works on ANY Linux server with basic tools

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
    local deps=("grep" "awk" "curl" "jq" "find")
    for dep in "${deps[@]}"; do
        if ! command -v "$dep" &>/dev/null; then
            echo "Error: Required tool '$dep' not found"
            exit 1
        fi
    done
}

# Find log directory - simple approach
find_log_directory() {
    local candidates=(
        "/var/log/virtualmin"
        "/var/log/apache2" 
        "/var/log/nginx"
        "/var/log/httpd"
    )
    
    for dir in "${candidates[@]}"; do
        if [[ -d "$dir" ]]; then
            echo "$dir"
            return 0
        fi
    done
    
    echo "Error: No log directory found in: ${candidates[*]}" >&2
    exit 1
}

# Extract today's IPs - ONE reliable method
extract_todays_ips() {
    local log_dir="$1"
    local output_file="$2"
    
    echo "Finding today's access logs..."
    
    # Get today's date in log format
    local today_pattern
    today_pattern=$(date +"%d/%b/%Y")
    echo "Today's pattern: $today_pattern"
    
    # Find log files and process them
    local log_files
    log_files=$(find "$log_dir" -maxdepth 1 -type f \( -name "*access*log" -o -name "*.log" \) \
                ! -name "*.gz" ! -name "*.*[0-9]" 2>/dev/null | head -10)
    
    if [[ -z "$log_files" ]]; then
        echo "Error: No log files found in $log_dir" >&2
        return 1
    fi
    
    echo "Found $(echo "$log_files" | wc -l) log files"
    
    # Process each log file for today's entries
    local total_entries=0
    while IFS= read -r logfile; do
        if [[ ! -r "$logfile" ]]; then
            continue
        fi
        
        # Count entries for this file
        local file_entries
        file_entries=$(grep -c "$today_pattern" "$logfile" 2>/dev/null || echo 0)
        
        if [[ "$file_entries" -gt 0 ]]; then
            echo "  📄 $(basename "$logfile"): $file_entries entries"
            grep -h "$today_pattern" "$logfile" 2>/dev/null >> "/tmp/logs.$$" || true
            total_entries=$((total_entries + file_entries))
        fi
    done <<< "$log_files"
    
    if [[ "$total_entries" -eq 0 ]]; then
        echo "No today's entries found. Using all current log entries..."
        while IFS= read -r logfile; do
            if [[ -r "$logfile" ]]; then
                cat "$logfile" 2>/dev/null >> "/tmp/logs.$$" || true
            fi
        done <<< "$log_files"
        total_entries=$(wc -l < "/tmp/logs.$$" 2>/dev/null || echo 0)
    fi
    
    if [[ "$total_entries" -eq 0 ]]; then
        echo "Error: No log entries found" >&2
        return 1
    fi
    
    echo "Processing $total_entries log entries..."
    
    # Extract IPs - SIMPLE AND RELIABLE
    awk '{print $1}' "/tmp/logs.$$" | \
    grep -E '^[0-9]+\.[0-9]+\.[0-9]+\.[0-9]+$' | \
    sort | uniq -c | sort -nr | head -30 > "$output_file"
    
    local ip_count
    ip_count=$(wc -l < "$output_file" 2>/dev/null || echo 0)
    
    if [[ "$ip_count" -eq 0 ]]; then
        echo "Error: No IP addresses extracted" >&2
        return 1
    fi
    
    echo "✓ Extracted $ip_count unique IP addresses"
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

# Main function - straight line execution
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
    
    # Step 5: Show results and recommendations
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
