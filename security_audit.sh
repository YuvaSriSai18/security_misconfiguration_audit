#!/bin/bash

# ==========================================
# Security Misconfiguration Audit Script
# Works on Kali Linux
# ==========================================

OUTPUT_DIR="audit_outputs"
TARGET="srmap.edu.in"
HOST="srmap.edu.in"

# Create output directory
mkdir -p $OUTPUT_DIR

echo "======================================"
echo "     Security Misconfiguration Audit   "
echo "======================================"

# -----------------------------
# 1. NMAP FULL PORT & SERVICE SCAN
# -----------------------------
echo ""
echo "=== Running Nmap Scan on $HOST ==="
sudo nmap -sS -sV -p- --script=http-title,http-headers -oA $OUTPUT_DIR/nmap $HOST


# -----------------------------
# 2. CURL HEADER CHECK
# -----------------------------
echo ""
echo "=== Extracting HTTP Headers Using curl ==="
curl -I $TARGET | tee $OUTPUT_DIR/curl_headers.txt


# -----------------------------
# 3. AUTOMATED SECURITY HEADER ANALYSIS
# -----------------------------
echo ""
echo "=== Checking for Missing Security Headers ==="
HEADER_REPORT="$OUTPUT_DIR/header_analysis.txt"

echo "Security Header Analysis Report" > $HEADER_REPORT
echo "----------------------------------" >> $HEADER_REPORT

curl -I $TARGET 2>/dev/null | {
  grep -qi "Strict-Transport-Security" || echo "[!] Missing Strict-Transport-Security (HSTS)" >> $HEADER_REPORT
  grep -qi "Content-Security-Policy" || echo "[!] Missing Content-Security-Policy (CSP)" >> $HEADER_REPORT
  grep -qi "X-Frame-Options" || echo "[!] Missing X-Frame-Options (Clickjacking Protection)" >> $HEADER_REPORT
  grep -qi "X-Content-Type-Options" || echo "[!] Missing X-Content-Type-Options (MIME Sniffing Protection)" >> $HEADER_REPORT
  grep -qi "Referrer-Policy" || echo "[!] Missing Referrer-Policy" >> $HEADER_REPORT
  grep -qi "Permissions-Policy" || echo "[!] Missing Permissions-Policy" >> $HEADER_REPORT
}


# -----------------------------
# 4. DIRECTORY ENUMERATION (GOBUSTER)
# -----------------------------
echo ""
echo "=== Running Gobuster Directory Enumeration ==="
gobuster dir -u $TARGET \
-w /usr/share/wordlists/dirb/common.txt \
-x php,html,txt \
-o $OUTPUT_DIR/gobuster.txt


# -----------------------------
# 5. NIKTO VULNERABILITY SCAN
# -----------------------------
echo ""
echo "=== Running Nikto Vulnerability Scan ==="
nikto -h $TARGET -output $OUTPUT_DIR/nikto.txt


# -----------------------------
# 6. SUMMARY OUTPUT
# -----------------------------
echo ""
echo "======================================"
echo "         AUDIT COMPLETED"
echo "======================================"
echo "All scan outputs saved in the folder: $OUTPUT_DIR"
echo ""
echo "Review these files:"
echo " - nmap.nmap / nmap.xml / nmap.gnmap"
echo " - curl_headers.txt"
echo " - header_analysis.txt"
echo " - gobuster.txt"
echo " - nikto.txt"
echo ""
echo "======================================"
