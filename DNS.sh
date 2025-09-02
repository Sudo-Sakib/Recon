#!/bin/bash

# ==========================================
# Subdomain Enumeration (Accurate + Enriched)
# Dependencies: subfinder, dnsx, wafw00f, httpx-toolkit, grep, tee, awk, sort, uniq, curl, chaos-client, cero
# ==========================================

# Ask user for input file
read -p "Enter the input file containing Domains/Acquisitions: " INPUT_FILE

if [[ ! -f "$INPUT_FILE" ]]; then
    echo "[!] Input file not found!"
    exit 1
fi

OUTPUT_DIR="recon_output"
mkdir -p "$OUTPUT_DIR"

# Step 0: Prepare resolvers
if [[ ! -f resolvers.txt ]]; then
    echo "[*] Fetching fresh resolvers..."
    curl -s https://raw.githubusercontent.com/trickest/resolvers/refs/heads/main/resolvers-trusted.txt -o resolvers.txt
fi

# Step 1: Subfinder Enumeration (Round 1)
echo "[*] Running Subfinder (Round 1)..."
subfinder -silent -all -recursive -dL "$INPUT_FILE" -o "$OUTPUT_DIR/subfinder_round1.txt"

# Step 2: Subfinder Enumeration (Round 2 on Round 1 result)
echo "[*] Running Subfinder (Round 2 on Round 1 results)..."
subfinder -silent -all -recursive -dL "$OUTPUT_DIR/subfinder_round1.txt" -o "$OUTPUT_DIR/subfinder_round2.txt"

# Step 3: Certificate Transparency Enumeration (cero)
echo "[*] Pulling subdomains from Certificate Transparency logs (cero)..."
cero -dL "$INPUT_FILE" | sort -u > "$OUTPUT_DIR/cero.txt"

# Step 4: Chaos Dataset Enumeration
echo "[*] Pulling subdomains from ProjectDiscovery Chaos dataset..."
chaos -dL "$INPUT_FILE" -silent -o "$OUTPUT_DIR/chaos.txt"

# Step 5: Merge & Deduplicate subdomains
echo "[*] Merging and deduplicating all sources..."
cat "$OUTPUT_DIR/subfinder_round1.txt" \
    "$OUTPUT_DIR/subfinder_round2.txt" \
    "$OUTPUT_DIR/cero.txt" \
    "$OUTPUT_DIR/chaos.txt" | sort -u > "$OUTPUT_DIR/all_subdomains.txt"

echo "[*] Total unique subdomains collected: $(wc -l < "$OUTPUT_DIR/all_subdomains.txt")"

# Step 6: DNSX for Valid Subdomains
echo "[*] Resolving subdomains with dnsx..."
dnsx -silent -r resolvers.txt -l "$OUTPUT_DIR/all_subdomains.txt" -o "$OUTPUT_DIR/resolved_subdomains.txt"

echo "[*] Final resolved subdomains saved in $OUTPUT_DIR/resolved_subdomains.txt"
