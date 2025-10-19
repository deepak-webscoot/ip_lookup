#!/bin/bash

set -euo pipefail

# Script: ip_lookup_abuse_free.sh
# Description: 100% Free IP Threat Intelligence Analyzer

SCRIPT_NAME="ip_lookup_abuse_free.sh"
CACHE_DIR="${HOME}/.cache/abuseipdb"
TEMP_PREFIX="/tmp/ip_lookup_abuse"
THREAT_FEEDS_DIR="${HOME}/.config/ip_threat_feeds"

# Create necessary directories
mkdir -p "$CACHE_DIR" "$THREAT_FEEDS_DIR"

# Cleanup function
cleanup() {
    rm -f "${TEMP_PREFIX}.$$."* 2>/dev/null || true
}

trap cleanup EXIT INT TERM

# Function to install requirements
install_requirements() {
    echo "Checking and installing required packages..."
    
    local packages=("curl" "jq")
    local to_install=()
    
    # Check for required packages
    for pkg in "${packages[@]}"; do
        if ! command -v "$pkg" &>/dev/null; then
            to_install+=("$pkg")
            echo "  - $pkg needs installation"
        else
            echo "  ✓ $pkg already installed"
        fi
    done
    
    if [ ${#to_install[@]} -gt 0 ]; then
        echo "Installing missing packages: ${to_install[*]}"
        
        # Try different package managers with timeout
        if command -v apt-get &>/dev/null; then
            echo "Using apt-get package manager..."
            export DEBIAN_FRONTEND=noninteractive
            if ! timeout 120 apt-get update; then
                echo "Warning: apt-get update had issues, but continuing..."
            fi
            if ! timeout 300 apt-get install -y --no-install-recommends "${to_install[@]}"; then
                echo "Warning: Package installation had issues, but continuing..."
            fi
        elif command -v yum &>/dev/null; then
            echo "Using yum package manager..."
            if ! timeout 300 yum install -y "${to_install[@]}"; then
                echo "Warning: Package installation had issues, but continuing..."
            fi
        elif command -v dnf &>/dev/null; then
            echo "Using dnf package manager..."
            if ! timeout 300 dnf install -y "${to_install[@]}"; then
                echo "Warning: Package installation had issues, but continuing..."
            fi
        else
            echo "Error: No supported package manager found (apt-get, yum, dnf)"
            echo "Please install these packages manually: ${to_install[*]}"
            return 1
        fi
        
        # Verify installation
        echo "Verifying installation..."
        local all_success=true
        for pkg in "${to_install[@]}"; do
            if command -v "$pkg" &>/dev/null; then
                echo "  ✓ $pkg installed successfully"
            else
                echo "  ⚠ $pkg may not be fully installed"
                all_success=false
            fi
        done
        
        if ! $all_success; then
            echo "Warning: Some packages may not be fully installed, but continuing..."
        fi
    else
        echo "All required packages are already installed"
    fi
    
    # Final test of critical commands
    echo "Testing critical commands..."
    if ! command -v curl &>/dev/null; then
        echo "Error: curl is required but not available. Please install it manually."
        return 1
    fi
    
    if ! command -v jq &>/dev/null; then
        echo "Error: jq is required but not available. Please install it manually."
        return 1
    fi
    
    echo "Package requirements check completed successfully"
    return 0
}

# Display usage information
usage() {
    cat << EOF
$SCRIPT_NAME - Free IP Threat Intelligence Analyzer

Usage:
  $SCRIPT_NAME                    # Automatic mode - finds and analyzes all recent logs
  $SCRIPT_NAME <logfile>          # Single file mode - analyzes specific log file
  $SCRIPT_NAME --help             # Show this help message

Examples:
  $SCRIPT_NAME                                  # Auto-detect and analyze all logs
  $SCRIPT_NAME /var/log/nginx/access.log        # Analyze specific file
  $SCRIPT_NAME dominick.fun_access_log          # Analyze current directory file

Features:
  - 100% free threat intelligence feeds
  - Automatic log file detection
  - Risk scoring based on multiple sources
  - No API keys required
EOF
}

# Function to setup threat intelligence feeds
setup_threat_feeds() {
    echo "Setting up free threat intelligence feeds..."
    
    mkdir -p "$THREAT_FEEDS_DIR"

    local blocklists=(
        "https://feodotracker.abuse.ch/downloads/ipblocklist.txt|abuse_ch_feodo.txt"
        "https://rules.emergingthreats.net/blockrules/compromised-ips.txt|emerging_threats_compromised.txt"
        "https://blocklist.greensnow.co/greensnow.txt|greensnow.txt"
        "https://www.binarydefense.com/banlist.txt|binary_defense.txt"
        "https://www.botvrij.eu/data/ioclist.ip-dst|botvrij.txt"
    )

    local success_count=0
    local total_count=0

    for list in "${blocklists[@]}"; do
        local url="${list%|*}"
        local filename="${list#*|}"
        local filepath="$THREAT_FEEDS_DIR/$filename"
        local cache_age=1440 # 24 hours in minutes

        total_count=$((total_count + 1))

        # Check if file exists and is recent enough
        if [[ -f "$filepath" ]]; then
            local file_age
            if file_age=$(find "$filepath" -mmin "+$cache_age" 2>/dev/null); then
                echo "  ✓ $filename (cached)"
                success_count=$((success_count + 1))
                continue
            fi
        fi

        echo "  Downloading: $filename"
        if timeout 30 curl -s -f --connect-timeout 15 "$url" -o "$filepath.tmp" 2>/dev/null; then
            # Basic validation - check if file has content
            if [[ -s "$filepath.tmp" ]]; then
                mv "$filepath.tmp" "$filepath"
                echo "    ✓ Success ($(wc -l < "$filepath" | tr -d ' ') entries)"
                success_count=$((success_count + 1))
            else
                echo "    ⚠ Empty response, keeping old version if exists"
                rm -f "$filepath.tmp"
                if [[ -f "$filepath" ]]; then
                    success_count=$((success_count + 1))
                fi
            fi
        else
            echo "    ⚠ Download failed, keeping old version if exists"
            rm -f "$filepath.tmp"
            if [[ -f "$filepath" ]]; then
                success_count=$((success_count + 1))
            fi
        fi
    done

    echo "Threat feeds updated: $success_count/$total_count successful"
    
    if [[ $success_count -eq 0 ]]; then
        echo "Warning: No threat feeds could be downloaded. Continuing with limited functionality."
    fi
}

# Function to check if IP is in blocklists
check_blocklists() {
    local ip="$1"
    local count=0

    # Validate IP format
    if ! [[ "$ip" =~ ^[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}$ ]]; then
        echo "0"
        return
    fi

    for blockfile in "$THREAT_FEEDS_DIR"/*.txt; do
        if [[ -f "$blockfile" ]] && grep -q "^$ip$" "$blockfile" 2>/dev/null; then
            ((count++))
        fi
    done

    echo "$count"
}

# Function to get threat intelligence data
get_threat_intel() {
    local ip="$1"
    
    # Validate IP format
    if ! [[ "$ip" =~ ^[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}$ ]]; then
        echo "0" # Invalid IP format
        return
    fi

    # Use multiple free sources for threat intelligence
    local pulses=0
    
    # Check AbuseIPDB (public API)
    local abuse_data
    if abuse_data=$(timeout 10 curl -s "https://api.abuseipdb.com/api/v2/check?ipAddress=$ip" -H "Accept: application/json" 2>/dev/null); then
        local abuse_score
        if abuse_score=$(echo "$abuse_data" | jq -r '.data.abuseConfidenceScore // 0' 2>/dev/null); then
            if [[ "$abuse_score" =~ ^[0-9]+$ ]] && [[ "$abuse_score" -gt 50 ]]; then
                pulses=$((pulses + 2))
            elif [[ "$abuse_score" -gt 20 ]]; then
                pulses=$((pulses + 1))
            fi
        fi
    fi
    
    # Check other public sources (with proper error handling)
    local virustotal_data
    if virustotal_data=$(timeout 10 curl -s "https://www.virustotal.com/ui/ip_addresses/$ip" 2>/dev/null); then
        if echo "$virustotal_data" | jq -e '.data.attributes.last_analysis_stats.malicious > 0' &>/dev/null; then
            pulses=$((pulses + 1))
        fi
    fi

    echo "$pulses"
}

# Function to calculate risk score
calculate_risk_score() {
    local pulses="$1"
    local blocklists="$2"

    local pulse_score=0
    if [[ "$pulses" -gt 3 ]]; then
        pulse_score=70
    elif [[ "$pulses" -gt 1 ]]; then
        pulse_score=50
    elif [[ "$pulses" -gt 0 ]]; then
        pulse_score=30
    fi

    local blocklist_score=$((blocklists * 15))
    if [[ "$blocklist_score" -gt 45 ]]; then
        blocklist_score=45
    fi

    local total_score=$((pulse_score + blocklist_score))
    if [[ "$total_score" -gt 100 ]]; then
        total_score=100
    fi
    
    echo "$total_score"
}

# Function to get risk level
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

# Function to find log directory
find_log_directory() {
    local candidates=(/var/log/virtualmin /var/log/nginx /var/log/apache2/domlogs /var/log/apache2 /var/log)
    local best_dir=""
    local max_size=0

    for dir in "${candidates[@]}"; do
        if [[ -d "$dir" ]] && [[ -r "$dir" ]]; then
            local size
            size=$(du -s "$dir" 2>/dev/null | cut -f1 || echo 0)
            # Safe numeric comparison
            if [[ "$size" =~ ^[0-9]+$ ]] && [[ "$size" -gt "$max_size" ]]; then
                max_size="$size"
                best_dir="$dir"
            fi
        fi
    done

    if [[ -z "$best_dir" ]]; then
        echo "Error: No suitable log directory found." >&2
        return 1
    fi

    echo "$best_dir"
}

# Function to check if file is text (not binary)
is_text_file() {
    local file="$1"
    if file "$file" 2>/dev/null | grep -q "text"; then
        return 0
    elif [[ "$file" =~ \.log$ ]] || [[ "$file" =~ access ]] || [[ "$file" =~ error ]]; then
        return 0
    else
        return 1
    fi
}

# Function to extract today's logs from files
extract_todays_logs() {
    local files="$1"
    local today_pattern=$(date +"%d/%b/%Y")
    local today_pattern_alt=$(date +"%Y-%m-%d")
    local today_pattern_simple=$(date +"%d/%b")

    echo "Extracting today's ($today_pattern) requests from logs..."

    > "$TODAY_LOGS"
    local total_lines=0
    local files_processed=0

    while IFS= read -r file; do
        if [[ -z "$file" ]] || [[ ! -r "$file" ]]; then
            echo "Warning: Cannot read log file '$file', skipping..." >&2
            continue
        fi

        # Skip binary files
        if ! is_text_file "$file"; then
            echo "Warning: Skipping binary file $file" >&2
            continue
        fi

        # Try different date formats
        local file_lines=0
        local matched_pattern=""
        
        for pattern in "$today_pattern" "$today_pattern_alt" "$today_pattern_simple"; do
            local lines
            lines=$(grep -c -i "$pattern" "$file" 2>/dev/null || echo 0)
            # Fix: Proper numeric validation
            if [[ "$lines" =~ ^[0-9]+$ ]] && [[ "$lines" -gt 0 ]]; then
                file_lines="$lines"
                matched_pattern="$pattern"
                break
            fi
        done

        if [[ "$file_lines" -gt 0 ]] && [[ -n "$matched_pattern" ]]; then
            echo "  Processing $file with pattern: $matched_pattern ($file_lines lines)"
            grep -h -i "$matched_pattern" "$file" >> "$TODAY_LOGS" 2>/dev/null || true
            total_lines=$((total_lines + file_lines))
            files_processed=$((files_processed + 1))
        fi
    done <<< "$files"

    if [[ "$total_lines" -eq 0 ]]; then
        echo "No today's traffic found in logs. Possible reasons:"
        echo "  - No traffic today"
        echo "  - Date format mismatch"
        echo "  - Timezone differences"
        echo ""
        echo "Trying to find recent logs (last 50 lines)..."
        
        # Try to get recent logs regardless of date
        > "$TODAY_LOGS"
        while IFS= read -r file; do
            if [[ -r "$file" ]] && is_text_file "$file"; then
                echo "  Checking recent entries in: $file"
                tail -50 "$file" >> "$TODAY_LOGS" 2>/dev/null || true
            fi
        done <<< "$files"
        
        # Check if we got any content
        if [[ -s "$TODAY_LOGS" ]]; then
            total_lines=$(wc -l < "$TODAY_LOGS" 2>/dev/null || echo 0)
            echo "Using recent logs instead: $total_lines lines"
        else
            echo "No log content found at all."
            return 1
        fi
    else
        echo "Extracted $total_lines log entries from $files_processed files"
    fi
    return 0
}

# Function to find log files
find_log_files() {
    local log_dir="$1"
    
    if [[ ! -d "$log_dir" ]] || [[ ! -r "$log_dir" ]]; then
        echo "Error: Cannot access log directory: $log_dir" >&2
        return 1
    fi

    # Different search patterns for different log directories
    case "$log_dir" in
        /var/log/virtualmin)
            find "$log_dir" -maxdepth 1 -type f \( -name "*access*log" -o -name "*ssl*log" \) \
                ! -name "*.gz" ! -name "*.[0-9]*" 2>/dev/null | head -20
            ;;
        /var/log/apache2/domlogs)
            find "$log_dir" -maxdepth 1 -type f \( -name "*" ! -name "*.gz" ! -name "*.[0-9]*" \) 2>/dev/null | head -20
            ;;
        /var/log/nginx|/var/log/apache2)
            find "$log_dir" -maxdepth 1 -type f \( -name "*access*log" -o -name "*error*log" \) \
                ! -name "*.gz" ! -name "*.[0-9]*" 2>/dev/null | head -20
            ;;
        *)
            find "$log_dir" -maxdepth 1 -type f \( -name "*access*log" -o -name "*ssl*log" -o -name "*error*log" \) \
                ! -name "*.gz" ! -name "*.[0-9]*" 2>/dev/null | head -20
            ;;
    esac
}

# Function to extract and aggregate IPs
extract_and_aggregate_ips() {
    echo "Analyzing IP addresses..."

    # Initialize temp file
    > "$IPS_TODAY"

    awk '
    function is_private_ip(ip) {
        if (ip ~ /^10\./) return 1
        if (ip ~ /^192\.168\./) return 1
        if (ip ~ /^172\.(1[6-9]|2[0-9]|3[0-1])\./) return 1
        if (ip ~ /^127\./) return 1
        if (ip ~ /^::1$/) return 1
        if (ip ~ /^fe80::/) return 1
        if (ip ~ /^::/) return 1
        return 0
    }
    function is_valid_ip(ip) {
        if (ip ~ /^[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}$/) return 1
        return 0
    }
    {
        ip = $1
        gsub(/^[[:space:]]+|[[:space:]]+$/, "", ip)
        if (ip == "" || !is_valid_ip(ip) || is_private_ip(ip)) next
        print ip
    }' "$TODAY_LOGS" | sort | uniq -c | sort -nr | head -30 > "$IPS_TODAY"

    local ip_count
    ip_count=$(wc -l < "$IPS_TODAY" 2>/dev/null | tr -d ' ' || echo 0)
    
    if [[ "$ip_count" -eq 0 ]]; then
        echo "No valid IP addresses found to analyze"
        return 1
    fi
    
    echo "Found $ip_count unique IP addresses to analyze"
    return 0
}

# Function to analyze IPs with progress
analyze_ips() {
    local high_risk_ips=()
    local processed_ips=0
    local total_ips=0
    
    total_ips=$(wc -l < "$IPS_TODAY" 2>/dev/null || echo 0)
    
    if [[ "$total_ips" -eq 0 ]]; then
        echo "No IPs to analyze"
        return 1
    fi

    echo ""
    echo "LEGEND:"
    echo "• Pulses = Threat intelligence score from multiple sources"
    echo "• BLists = Number of blocklists containing this IP"
    echo "• Score = Risk score (0-100), HIGH = 70+, MEDIUM = 30-69, LOW = 0-29"
    echo ""
    printf "%-6s %-18s %-8s %-8s %-6s %-5s\n" "Hits" "IP" "Pulses" "BLists" "Score" "Risk"
    echo "----------------------------------------------------------------"

    while IFS= read -r line; do
        if [[ -z "$line" ]]; then
            continue
        fi
        
        hits=$(echo "$line" | awk '{print $1}')
        ip=$(echo "$line" | awk '{print $2}')

        # Skip if IP is empty or invalid
        if [[ -z "$ip" ]] || ! [[ "$ip" =~ ^[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}$ ]]; then
            continue
        fi

        # Get threat intelligence data
        pulses=$(get_threat_intel "$ip")
        blocklists=$(check_blocklists "$ip")
        risk_score=$(calculate_risk_score "$pulses" "$blocklists")
        risk_level=$(get_risk_level "$risk_score")

        printf "%-6s %-18s %-8s %-8s %-6s %-5s\n" \
               "$hits" "$ip" "$pulses" "$blocklists" "$risk_score" "$risk_level"

        if [[ "$risk_level" = "HIGH" ]]; then
            high_risk_ips+=("$ip")
        fi
        
        processed_ips=$((processed_ips + 1))
        
        # Small delay to be respectful to APIs
        sleep 0.5

    done < "$IPS_TODAY"

    # Return results via global variables
    ANALYZED_IPS="$processed_ips"
    HIGH_RISK_IPS=("${high_risk_ips[@]}")
}

# Main execution function
main() {
    local specific_file="${1:-}"
    
    # Initialize temp files
    TODAY_LOGS="${TEMP_PREFIX}.$$.today_logs"
    IPS_TODAY="${TEMP_PREFIX}.$$.ips_today"

    echo "=== Free IP Threat Intelligence Analyzer ==="
    echo "Starting automated analysis..."

    # Install requirements first (but don't exit on failure)
    if ! install_requirements; then
        echo "Warning: Package installation had issues, but continuing..."
    fi

    # Setup threat intelligence
    setup_threat_feeds

    # Determine log source
    local LOG_FILES
    local LOG_SOURCE

    if [[ -n "$specific_file" ]]; then
        if [[ ! -f "$specific_file" ]]; then
            echo "Error: File '$specific_file' not found" >&2
            return 1
        fi
        LOG_FILES="$specific_file"
        LOG_SOURCE="File: $(basename "$specific_file")"
        echo "Analyzing specific file: $specific_file"
    else
        local LOG_DIR
        if ! LOG_DIR=$(find_log_directory); then
            echo "Error: Could not find log directory" >&2
            return 1
        fi
        LOG_SOURCE="Directory: $LOG_DIR"
        echo "Using log directory: $LOG_DIR"

        if ! LOG_FILES=$(find_log_files "$LOG_DIR"); then
            echo "Error: Could not find log files in $LOG_DIR" >&2
            return 1
        fi

        if [[ -z "$LOG_FILES" ]]; then
            echo "Error: No accessible log files found in $LOG_DIR" >&2
            return 1
        fi

        file_count=$(echo "$LOG_FILES" | wc -w)
        echo "Found $file_count current log files"
    fi

    # Extract today's logs
    if ! extract_todays_logs "$LOG_FILES"; then
        echo "Analysis stopped: No logs found"
        return 1
    fi

    # Extract and aggregate IPs
    if ! extract_and_aggregate_ips; then
        echo "Analysis stopped: No valid IP addresses found"
        return 1
    fi

    # Analyze IPs
    local ANALYZED_IPS=0
    local HIGH_RISK_IPS=()
    
    analyze_ips

    # Generate blocking recommendations
    echo ""
    echo "=== ANALYSIS COMPLETE ==="
    echo "• IPs checked: $ANALYZED_IPS"
    echo "• High-risk IPs found: ${#HIGH_RISK_IPS[@]}"

    if [[ ${#HIGH_RISK_IPS[@]} -gt 0 ]]; then
        echo ""
        echo "🚨 Recommended action: Block IPs with HIGH risk score"
        echo ""
        echo "🔧 CSF blocking commands:"
        for ip in "${HIGH_RISK_IPS[@]}"; do
            echo "csf -d $ip  # \"Malicious IP detected via threat intelligence\""
        done
        echo ""
        echo "To unblock later: csf -dr <IP>"
        
        # Also show iptables commands
        echo ""
        echo "🔧 Alternative iptables commands:"
        for ip in "${HIGH_RISK_IPS[@]}"; do
            echo "iptables -A INPUT -s $ip -j DROP  # Block malicious IP"
        done
    else
        echo "• No high-risk IPs found requiring immediate action"
    fi
    
    echo ""
    echo "Note: This analysis uses free threat intelligence feeds."
    echo "      For enterprise-grade protection, consider commercial solutions."
}

# Show help if requested
if [[ $# -gt 0 ]]; then
    case "$1" in
        -h|--help|help)
            usage
            exit 0
            ;;
    esac
fi

# Run main function
main "$@"

# Exit with appropriate code
exit $?
