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
    # Self-delete if running from temporary location
    if [[ "$0" =~ ^/tmp/.*\.sh$ ]] || [[ "$0" =~ ^/dev/fd/.* ]]; then
        rm -f "$0" 2>/dev/null || true
    fi
}

trap cleanup EXIT INT TERM

# Function to install requirements
install_requirements() {
    echo "Checking and installing required packages..."
    
    local packages=("curl" "jq")
    local to_install=()
    
    for pkg in "${packages[@]}"; do
        if ! command -v "$pkg" &>/dev/null; then
            to_install+=("$pkg")
        fi
    done
    
    if [ ${#to_install[@]} -gt 0 ]; then
        echo "Installing missing packages: ${to_install[*]}"
        export DEBIAN_FRONTEND=noninteractive
        if command -v apt-get &>/dev/null; then
            apt-get update >/dev/null 2>&1
            apt-get install -y --no-install-recommends "${to_install[@]}" >/dev/null 2>&1
        elif command -v yum &>/dev/null; then
            yum install -y "${to_install[@]}" >/dev/null 2>&1
        else
            echo "Error: Cannot install packages - no package manager found"
            exit 1
        fi
        
        # Verify installation
        for pkg in "${to_install[@]}"; do
            if command -v "$pkg" &>/dev/null; then
                echo "  ✓ $pkg installed successfully"
            else
                echo "  ✗ Failed to install $pkg"
                exit 1
            fi
        done
    else
        echo "All required packages are already installed"
    fi
}

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

        if [[ -f "$filepath" ]] && [[ $(find "$filepath" -mtime -1 2>/dev/null) ]]; then
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
            # Fix: Proper numeric comparison
            if [ "${size:-0}" -gt "${max_size:-0}" ] 2>/dev/null; then
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

    for file in $files; do
        if [ ! -r "$file" ]; then
            echo "Warning: Cannot read log file $file, skipping..." >&2
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
            if grep -i "$pattern" "$file" 2>/dev/null | head -1 >/dev/null; then
                file_lines=$(grep -c -i "$pattern" "$file" 2>/dev/null || echo 0)
                if [ "$file_lines" -gt 0 ]; then
                    matched_pattern="$pattern"
                    break
                fi
            fi
        done

        if [ "$file_lines" -gt 0 ] && [ -n "$matched_pattern" ]; then
            echo "  Processing $file with pattern: $matched_pattern ($file_lines lines)"
            grep -h -i "$matched_pattern" "$file" >> "$TODAY_LOGS" 2>/dev/null || true
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

# Function to find log files
find_log_files() {
    local log_dir="$1"
    
    # Different search patterns for different log directories
    case "$log_dir" in
        /var/log/virtualmin)
            find "$log_dir" -maxdepth 1 -type f \( -name "*access*log" -o -name "*ssl*log" \) \
                ! -name "*.gz" ! -name "*.[0-9]*" | head -20
            ;;
        /var/log/apache2/domlogs)
            find "$log_dir" -maxdepth 1 -type f \( -name "*" ! -name "*.gz" ! -name "*.[0-9]*" \) | head -20
            ;;
        /var/log/nginx|/var/log/apache2)
            find "$log_dir" -maxdepth 1 -type f \( -name "*access*log" -o -name "*error*log" \) \
                ! -name "*.gz" ! -name "*.[0-9]*" | head -20
            ;;
        *)
            find "$log_dir" -maxdepth 1 -type f \( -name "*access*log" -o -name "*ssl*log" -o -name "*error*log" \) \
                ! -name "*.gz" ! -name "*.[0-9]*" | head -20
            ;;
    esac
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
        if (ip ~ /^fe80::/) return 1
        if (ip ~ /^::/) return 1
        return 0
    }
    {
        ip = $1
        gsub(/^[[:space:]]+|[[:space:]]+$/, "", ip)
        if (ip == "" || is_private_ip(ip)) next
        print ip
    }' "$TODAY_LOGS" | sort | uniq -c | sort -nr | head -30 > "$IPS_TODAY"

    local ip_count=$(wc -l < "$IPS_TODAY" | tr -d ' ')
    echo "Found $ip_count unique IP addresses to analyze"
}

# Main execution function
main() {
    local specific_file="${1:-}"

    echo "=== Free IP Threat Intelligence ==="
    echo "Starting automated analysis..."

    # Install requirements first
    install_requirements

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

        LOG_FILES=$(find_log_files "$LOG_DIR")

        if [ -z "$LOG_FILES" ]; then
            echo "Error: No accessible log files found in $LOG_DIR" >&2
            exit 1
        fi

        echo "Found $(echo "$LOG_FILES" | wc -w) current log files"
        echo "Files: $(echo "$LOG_FILES" | tr '\n' ' ')"
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
    local processed_ips=0

    while read -r line; do
        if [ -z "$line" ]; then
            continue
        fi
        
        hits=$(echo "$line" | awk '{print $1}')
        ip=$(echo "$line" | awk '{print $2}')

        # Skip if IP is empty
        if [ -z "$ip" ]; then
            continue
        fi

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
        
        processed_ips=$((processed_ips + 1))

    done < "$IPS_TODAY"

    # Generate blocking recommendations
    echo ""
    echo "=== ANALYSIS COMPLETE ==="
    echo "• IPs checked: $processed_ips"
    echo "• High-risk IPs found: ${#high_risk_ips[@]}"

    if [ ${#high_risk_ips[@]} -gt 0 ]; then
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
