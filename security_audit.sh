#!/bin/bash

# ==========================================
# Security Misconfiguration Audit Script
# Works on Kali Linux
# ==========================================

OUTPUT_DIR="audit_outputs"
TARGET="srmap.edu.in"
HOST="srmap.edu.in"

HEADER_REPORT="$OUTPUT_DIR/header_analysis.txt"
FINAL_REPORT="$OUTPUT_DIR/final_report.txt"

# Create output directory
mkdir -p "$OUTPUT_DIR"

echo "======================================"
echo "     Security Misconfiguration Audit   "
echo "======================================"

# -----------------------------
# 1. NMAP FULL PORT & SERVICE SCAN
# -----------------------------
echo ""
echo "=== Running Nmap Scan on $HOST ==="
sudo nmap -sS -sV -p- --script=http-title,http-headers -oA "$OUTPUT_DIR/nmap" "$HOST"


# -----------------------------
# 2. CURL HEADER CHECK
# -----------------------------
echo ""
echo "=== Extracting HTTP Headers Using curl ==="
curl -I "https://$TARGET" 2>/dev/null | tee "$OUTPUT_DIR/curl_headers.txt"


# -----------------------------
# 3. AUTOMATED SECURITY HEADER ANALYSIS
# -----------------------------
echo ""
echo "=== Checking for Missing Security Headers ==="

echo "Security Header Analysis Report" > "$HEADER_REPORT"
echo "----------------------------------" >> "$HEADER_REPORT"

curl -I "https://$TARGET" 2>/dev/null | {
  grep -qi "Strict-Transport-Security" || echo "[!] Missing Strict-Transport-Security (HSTS)" >> "$HEADER_REPORT"
  grep -qi "Content-Security-Policy" || echo "[!] Missing Content-Security-Policy (CSP)" >> "$HEADER_REPORT"
  grep -qi "X-Frame-Options" || echo "[!] Missing X-Frame-Options (Clickjacking Protection)" >> "$HEADER_REPORT"
  grep -qi "X-Content-Type-Options" || echo "[!] Missing X-Content-Type-Options (MIME Sniffing Protection)" >> "$HEADER_REPORT"
  grep -qi "Referrer-Policy" || echo "[!] Missing Referrer-Policy" >> "$HEADER_REPORT"
  grep -qi "Permissions-Policy" || echo "[!] Missing Permissions-Policy" >> "$HEADER_REPORT"
}


# -----------------------------
# 4. DIRECTORY ENUMERATION (GOBUSTER)
# -----------------------------
echo ""
echo "=== Running Gobuster Directory Enumeration ==="
gobuster dir -u "https://$TARGET" \
  -w /usr/share/wordlists/dirb/common.txt \
  -x php,html,txt \
  -o "$OUTPUT_DIR/gobuster.txt"


# -----------------------------
# 5. NIKTO VULNERABILITY SCAN
# -----------------------------
echo ""
echo "=== Running Nikto Vulnerability Scan ==="
nikto -h "https://$TARGET" -output "$OUTPUT_DIR/nikto.txt"


# -----------------------------
# 6. GENERATE FINAL REPORT
# -----------------------------
echo ""
echo "=== Generating Final Report ==="

{
  echo "==============================================="
  echo "      Security Misconfiguration Audit Report"
  echo "==============================================="
  echo ""
  echo "Target          : $TARGET"
  echo "Scan Date       : $(date)"
  echo "Tools Used      : Nmap, curl, Gobuster, Nikto"
  echo "Output Folder   : $OUTPUT_DIR"
  echo ""
  echo "-----------------------------------------------"
  echo "1. HTTP Security Headers Summary"
  echo "-----------------------------------------------"
  echo ""
  cat "$HEADER_REPORT"
  echo ""
  echo "Detailed Misconfigurations & Remediations:"
  echo ""

  # === HEADER-BASED ISSUES WITH EXPLANATION + REMEDIATION ===

  if grep -q "Missing Strict-Transport-Security" "$HEADER_REPORT"; then
    cat << 'EOF'
[Issue] Missing Strict-Transport-Security (HSTS)
Severity: High
Impact:
  - Allows HTTPS connections to be downgraded to HTTP.
  - Enables SSL stripping attacks and man-in-the-middle interception.
Remediation:
  - Enforce HTTPS site-wide.
  - Add this header on HTTPS responses:
      Strict-Transport-Security: max-age=63072000; includeSubDomains; preload
  - Ensure all HTTP requests are redirected to HTTPS.

EOF
  fi

  if grep -q "Missing Content-Security-Policy" "$HEADER_REPORT"; then
    cat << 'EOF'
[Issue] Missing Content-Security-Policy (CSP)
Severity: High
Impact:
  - Increases risk of XSS (Cross-Site Scripting) and content injection.
  - Attackers can inject malicious scripts, steal cookies, or perform phishing overlays.
Remediation:
  - Define a restrictive CSP suited to the app.
  - Basic starting policy:
      Content-Security-Policy: default-src 'self'; script-src 'self'; object-src 'none';
  - Gradually refine for external resources (CDNs, APIs, fonts).

EOF
  fi

  if grep -q "Missing X-Frame-Options" "$HEADER_REPORT"; then
    cat << 'EOF'
[Issue] Missing X-Frame-Options Header
Severity: Medium
Impact:
  - Application pages can be embedded inside iframes on malicious websites.
  - Enables clickjacking attacks where users unknowingly click hidden buttons.
Remediation:
  - Add one of the following headers:
      X-Frame-Options: DENY
    or
      X-Frame-Options: SAMEORIGIN
  - Alternatively, use CSP:
      Content-Security-Policy: frame-ancestors 'none';

EOF
  fi

  if grep -q "Missing X-Content-Type-Options" "$HEADER_REPORT"; then
    cat << 'EOF'
[Issue] Missing X-Content-Type-Options Header
Severity: Medium
Impact:
  - Browser may MIME-sniff content and interpret non-script files as scripts.
  - Can lead to XSS in some edge cases.
Remediation:
  - Add:
      X-Content-Type-Options: nosniff
  - Ensure correct Content-Type headers are set for all responses.

EOF
  fi

  if grep -q "Missing Referrer-Policy" "$HEADER_REPORT"; then
    cat << 'EOF'
[Issue] Missing Referrer-Policy Header
Severity: Low
Impact:
  - Full URLs (including parameters) may be sent in the Referer header to external domains.
  - Can leak internal paths or identifiers.
Remediation:
  - Add a privacy-friendly policy, e.g.:
      Referrer-Policy: strict-origin-when-cross-origin

EOF
  fi

  if grep -q "Missing Permissions-Policy" "$HEADER_REPORT"; then
    cat << 'EOF'
[Issue] Missing Permissions-Policy Header
Severity: Medium
Impact:
  - Browser features like camera, microphone, geolocation, etc., may not be explicitly restricted.
Remediation:
  - Add a restrictive header, e.g.:
      Permissions-Policy: camera=(), microphone=(), geolocation=()
  - Enable only the APIs actually needed by the application.

EOF
  fi

  echo "-----------------------------------------------"
  echo "2. Open Ports & Services (Nmap Summary)"
  echo "-----------------------------------------------"
  echo ""
  if [ -f "$OUTPUT_DIR/nmap.nmap" ]; then
    echo "The following open TCP ports were detected:"
    echo ""
    grep -E '^[0-9]+/tcp.*open' "$OUTPUT_DIR/nmap.nmap" || echo "No open ports parsed or scan failed."
    echo ""
    cat << 'EOF'
General Remediation:
  - Close any ports that are not required for application functionality.
  - Restrict access using a firewall (e.g., ufw, iptables, security groups).
  - Ensure services on open ports are patched, hardened, and properly authenticated.

EOF
  else
    echo "Nmap output file not found."
  fi

  echo "-----------------------------------------------"
  echo "3. Directory Enumeration (Gobuster Summary)"
  echo "-----------------------------------------------"
  echo ""
  if [ -f "$OUTPUT_DIR/gobuster.txt" ]; then
    echo "Discovered paths (HTTP 200/301/etc.):"
    echo ""
    # Show only lines with a status code
    grep -E 'Status: [0-9]+' "$OUTPUT_DIR/gobuster.txt" || echo "No directories or files discovered or gobuster scan failed."
    echo ""
    cat << 'EOF'
General Remediation:
  - Restrict access to sensitive directories (admin panels, backups, test endpoints).
  - Disable directory listing in the web server configuration.
  - Remove unused or legacy paths.
  - Protect administrative areas with strong authentication and authorization.

EOF
  else
    echo "Gobuster output file not found."
  fi

  echo "-----------------------------------------------"
  echo "4. Nikto Findings (High-Level Summary)"
  echo "-----------------------------------------------"
  echo ""
  if [ -f "$OUTPUT_DIR/nikto.txt" ]; then
    echo "Potential issues reported by Nikto (partial):"
    echo ""
    # Show lines starting with '+' as typical Nikto findings
    grep '^+' "$OUTPUT_DIR/nikto.txt" | head -n 40 || echo "No major issues found or nikto scan failed."
    echo ""
    cat << 'EOF'
General Remediation:
  - Review each Nikto finding and verify if it is applicable.
  - Remove default files, sample applications, and debug endpoints.
  - Patch or upgrade any outdated server software or frameworks.
  - Disable HTTP methods that are not required (e.g., TRACE, PUT, DELETE).

EOF
  else
    echo "Nikto output file not found."
  fi

  echo "-----------------------------------------------"
  echo "5. Overall Conclusion"
  echo "-----------------------------------------------"
  echo ""
  cat << 'EOF'
The audit identified potential security misconfigurations related to HTTP headers,
service exposure, directory enumeration, and known issues reported by Nikto.

Addressing the missing security headers (CSP, HSTS, X-Frame-Options, etc.) and
hardening the web server configuration will significantly improve the security
posture of the application.

This report should be used as a baseline to:
  - Implement secure defaults.
  - Regularly patch and update software.
  - Continuously monitor and test the application with follow-up security audits.

EOF

} > "$FINAL_REPORT"

echo ""
echo "======================================"
echo "         AUDIT COMPLETED"
echo "======================================"
echo "All scan outputs saved in the folder: $OUTPUT_DIR"
echo "Generated report: $FINAL_REPORT"
echo ""
echo "Files to review manually (if needed):"
echo " - nmap.nmap / nmap.xml / nmap.gnmap"
echo " - curl_headers.txt"
echo " - header_analysis.txt"
echo " - gobuster.txt"
echo " - nikto.txt"
echo " - final_report.txt"
echo "======================================"
