# Overall Threat Intelligence Scanner

A lightweight, automatic IP threat detection script that finds and analyzes web server logs to identify malicious IP addresses.

## 🚀 One-Command Execution

### Run Immediately (No Installation)
```bash
curl -sL https://raw.githubusercontent.com/deepak-webscoot/singlefile_iplookup/main/ip_threat_checker.sh | bash
```

### Permanent Installation
Add to your `~/.bashrc` or `~/.zshrc`:
```bash
ws-threatscan() {
    local temp_script=$(mktemp)
    curl -sL https://raw.githubusercontent.com/deepak-webscoot/singlefile_iplookup/main/ip_threat_checker.sh -o "$temp_script"
    chmod +x "$temp_script"
    "$temp_script"
    rm -f "$temp_script"
}
```

Then use:
```bash
source ~/.bashrc
ws-threatscan
```

## 🎯 What Makes This Script Different

**Fully Automatic** - No arguments needed! The script:
- 🔍 **Automatically finds** your web server logs
- 📅 **Focuses on today's** activity (or all logs if none found)
- 🛡️ **Checks IP reputation** via AlienVault OTX
- 🚨 **Highlights threats** with clear recommendations
- 🔧 **Suggests blocking** commands for CSF firewall

## 📋 Sample Output

```
=== Simple IP Threat Intelligence ===
Starting analysis...
✓ Basic tools available
✓ Using log directory: /var/log/virtualmin
Finding access logs in: /var/log/virtualmin
Searching for logs from: 25/Oct/2025
Found 12 log files
  📄 domain1.com_access_log: 1500 lines
  📄 domain2.com_access_log: 800 lines
✓ Successfully extracted 25 unique IP addresses

ANALYZING IP ADDRESSES:
=======================
Hits   IP Address         Country   Pulses  Risk    Recommendation
-------------------------------------------------------------------
165    192.168.1.100     USA       25      HIGH    🚨 BLOCK
42     10.0.0.50         China     8       MEDIUM  ⚠️ MONITOR
15     172.16.1.200      Germany   0       CLEAN   ✓ OK

=== ANALYSIS COMPLETE ===
IPs checked: 25
High-risk IPs: 1

🚨 RECOMMENDED ACTIONS:
=======================
csf -d 192.168.1.100  # Block high-risk IP
```

## 🔍 How It Works

### Automatic Log Discovery
The script searches in this order:
1. **Virtualmin** - `/var/log/virtualmin/`
2. **Apache** - `/var/log/apache2/domlogs/`
3. **Nginx** - `/var/log/nginx/`
4. **HTTPD** - `/var/log/httpd/`

### Smart IP Extraction
- ✅ Finds **all access logs** automatically
- ✅ Focuses on **today's activity** by default
- ✅ Falls back to **all logs** if no recent entries
- ✅ Extracts **top 30 IPs** by request count
- ✅ Handles **multiple log formats**

### Threat Intelligence
- ✅ **AlienVault OTX** - World's largest threat database
- ✅ **Pulse Count** - Number of threat reports
- ✅ **Country Detection** - Geographic origin
- ✅ **Risk Scoring** - Automated risk assessment

## 🛡️ Risk Levels Explained

| Risk Level | Pulses | Meaning | Action |
|------------|--------|---------|---------|
| 🟢 **CLEAN** | 0 | No known threats | ✅ No action |
| 🟡 **LOW** | 1-5 | Minor threat history | 👀 Monitor |
| 🟠 **MEDIUM** | 6-10 | Moderate threat history | ⚠️ Close monitoring |
| 🔴 **HIGH** | 10+ | Significant threat history | 🚨 Block immediately |

## ⚙️ Requirements

### Essential Tools
```bash
# Ubuntu/Debian
sudo apt update && sudo apt install curl jq

# CentOS/RHEL
sudo yum install curl jq
```

### Supported Web Servers
- ✅ **Virtualmin** (primary)
- ✅ **Apache** with domlogs
- ✅ **Nginx**
- ✅ **HTTPD**

## 🚀 Usage Examples

### Basic Scan
```bash
ws-threatscan
```

### One-Time Check
```bash
curl -sL https://raw.githubusercontent.com/deepak-webscoot/singlefile_iplookup/main/ip_threat_checker.sh | bash
```

### After Installation
```bash
# Just run it - no arguments needed!
ws-threatscan
```

## 🔧 Blocking Malicious IPs

The script provides ready-to-use CSF commands:

```bash
# Copy and run commands from the output:
csf -d 192.168.1.100

# Verify the IP is blocked:
csf -g 192.168.1.100
```

## 📊 What Are "Pulses"?

**Pulses** represent the number of threat intelligence reports about an IP in AlienVault OTX database:
- **0 pulses** = Clean IP, no known threats
- **1-5 pulses** = Minor suspicious activity
- **6-10 pulses** = Moderate threat level
- **10+ pulses** = Known malicious actor

## ❓ Frequently Asked Questions

### Q: Do I need to specify log files?
**A:** No! The script automatically finds and analyzes all available web server logs.

### Q: What if I have multiple domains?
**A:** Perfect! The script processes ALL access logs found in the log directory.

### Q: Is an API key required?
**A:** No, the script includes a built-in AlienVault OTX API key.

### Q: How often should I run this?
**A:** 
- **Daily** for routine security monitoring
- **After attacks** to identify compromised IPs
- **Weekly** for comprehensive security review

### Q: Can it run automatically?
**A:** Yes! Add to crontab for daily scans:
```bash
# Daily at 6 AM
0 6 * * * curl -sL https://raw.githubusercontent.com/deepak-webscoot/singlefile_iplookup/main/ip_threat_checker.sh | bash
```

## 🐛 Troubleshooting

### Common Issues

**"No log directory found"**
- Check if Virtualmin/Apache is installed
- Verify log directories exist
- Ensure script has read permissions

**"No IP addresses could be extracted"**
- Logs might be in different format
- Check if logs have recent entries
- Verify log file permissions

**"Required tool not found"**
```bash
# Install missing packages
sudo apt install curl jq
```

## 🔒 Security Features

- ✅ **Read-only** - No modifications to logs or system
- ✅ **Rate-limited** - Safe API calls to AlienVault
- ✅ **Automatic cleanup** - Temporary files removed
- ✅ **Manual blocking** - You control which IPs to block

## 📝 Supported Log Formats

Works with common web server formats:
```
# Apache/Virtualmin
192.168.1.1 - - [25/Oct/2025:10:30:45 +0000] "GET / HTTP/1.1" 200 1234

# Nginx
192.168.1.1 - - [25/Oct/2025:10:30:45 +0000] "GET / HTTP/1.1" 200 1234 "http://example.com" "Mozilla/5.0..."
```

---

**Start protecting your server in 30 seconds!** 🚀

Just run: `ws-threatscan` and let the script do the rest.
