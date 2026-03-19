#!/bin/bash
# Nmap Reconnaissance Script — Metasploitable 2 Lab
# Author: Kousik Gunasekaran
# Usage: ./nmap_scan.sh <target_ip>

TARGET=${1:-10.56.237.233}
OUTPUT_DIR="./scan_results"
TIMESTAMP=$(date +%Y%m%d_%H%M%S)

mkdir -p $OUTPUT_DIR

echo "[*] Starting reconnaissance on $TARGET"
echo "[*] Output directory: $OUTPUT_DIR"
echo "============================================"

# Phase 1: Quick ping sweep
echo "[1/5] Host discovery..."
nmap -sn $TARGET -oN "$OUTPUT_DIR/host_discovery_$TIMESTAMP.txt"

# Phase 2: Full TCP port scan
echo "[2/5] Full TCP port scan..."
nmap -p- --min-rate 5000 -T4 $TARGET \
  -oN "$OUTPUT_DIR/full_tcp_$TIMESTAMP.txt" \
  -oX "$OUTPUT_DIR/full_tcp_$TIMESTAMP.xml"

# Phase 3: Service version detection on open ports
echo "[3/5] Service & version detection..."
nmap -sV -sC -p 21,22,23,25,53,80,111,139,445,512,513,514,1099,1524,2049,2121,3306,3632,5432,5900,6000,6667,8009,8180 \
  $TARGET \
  -oN "$OUTPUT_DIR/service_scan_$TIMESTAMP.txt"

# Phase 4: OS detection
echo "[4/5] OS fingerprinting..."
nmap -O $TARGET -oN "$OUTPUT_DIR/os_scan_$TIMESTAMP.txt"

# Phase 5: Vulnerability scripts
echo "[5/5] NSE vulnerability scripts..."
nmap --script vuln $TARGET \
  -oN "$OUTPUT_DIR/vuln_scan_$TIMESTAMP.txt"

echo "============================================"
echo "[*] Scan complete. Results saved to $OUTPUT_DIR"
echo "[*] Summary of open ports:"
grep "open" "$OUTPUT_DIR/service_scan_$TIMESTAMP.txt" | grep -v "Nmap"
