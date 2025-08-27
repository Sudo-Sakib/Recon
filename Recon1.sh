#!/bin/bash

# ==========================================
# Subdomain Enumeration + Crawling Flow Script
# Author: Saint Paul's Assistant
# Dependencies: subfinder, dnsx, wafw00f, httpx-toolkit, grep, tee, awk, sort, uniq
# ==========================================

# Ask user for input file
read -p "Enter the input file containing Domains/Acquisitions: " INPUT_FILE

if [[ ! -f "$INPUT_FILE" ]]; then
    echo "[!] Input file not found!"
    exit 1
fi

OUTPUT_DIR="recon_output"
mkdir -p "$OUTPUT_DIR"

# Step 1: Subfinder Enumeration (Round 1)
echo "[*] Running Subfinder (Round 1)..."
subfinder -silent -all -recursive -dL "$INPUT_FILE" -o "$OUTPUT_DIR/subfinder_round1.txt"

# Step 2: Subfinder Enumeration (Round 2 on Round 1 result)
echo "[*] Running Subfinder (Round 2 on Round 1 results)..."
subfinder -silent -all -recursive -dL "$OUTPUT_DIR/subfinder_round1.txt" -o "$OUTPUT_DIR/subfinder_round2.txt"

# Step 3: Merge & Deduplicate subdomains
cat "$OUTPUT_DIR/subfinder_round1.txt" "$OUTPUT_DIR/subfinder_round2.txt" | sort -u > "$OUTPUT_DIR/all_subdomains.txt"

# Step 4: DNSX for Valid Subdomains
echo "[*] Resolving subdomains with dnsx..."
dnsx -silent -resp-only -r 1.1.1.1,8.8.8.8 -l "$OUTPUT_DIR/all_subdomains.txt" -o "$OUTPUT_DIR/resolved_subdomains.txt"

# Step 5: DNSX to Get Unique IP Addresses
echo "[*] Getting IPs for resolved subdomains..."
dnsx -silent -a -r 1.1.1.1,8.8.8.8 -l "$OUTPUT_DIR/resolved_subdomains.txt" | awk '{print $2}' | sort -u > "$OUTPUT_DIR/resolved_ips.txt"

# Step 6: Run Wafw00f on Each Subdomain
echo "[*] Running Wafw00f..."
while read -r sub; do
    wafw00f "$sub" | tee -a "$OUTPUT_DIR/wafw00f_results.txt"
done < "$OUTPUT_DIR/resolved_subdomains.txt"

# Step 7: Run Httpx Toolkit with Tech Detection
echo "[*] Running Httpx with technology detection..."
httpx -silent -tech-detect -title -status-code -cdn -cname -ip -l "$OUTPUT_DIR/resolved_subdomains.txt" -o "$OUTPUT_DIR/httpx_results.txt"

# Step 8: Grep tech stack results
echo "[*] Extracting technology-specific subdomains..."
declare -a techs=("Php" "WordPress" "Apache" "IIS" "Nginx" "Express" "Node.js" "Joomla" "Drupal")

for tech in "${techs[@]}"; do
    grep -i "$tech" "$OUTPUT_DIR/httpx_results.txt" | tee "$OUTPUT_DIR/${tech}_domains.txt"
done

# 8. Cloud Asset Discovery
echo "[*] Running Cloud Asset Discovery ..."
awk '{print $1}' httpx_result.txt | sort -u > live_domains.txt

# Example: simple grep for known cloud patterns
grep -Ei "s3\.amazonaws\.com|blob\.core\.windows\.net|storage\.googleapis\.com|cloudfront\.net" live_domains.txt > cloud_assets.txt

echo "[*] Cloud assets saved in cloud_assets.txt"

# 9. Bucket Exposure Testing
echo "[*] Checking for exposed buckets ..."

mkdir -p Bucket_Exposure

while read -r asset; do
    if [[ "$asset" =~ s3\.amazonaws\.com ]]; then
        bucket=$(echo "$asset" | awk -F'.s3' '{print $1}' | sed 's~https\?://~~')
        echo "  [+] Testing S3 bucket: $bucket"
        aws s3 ls "s3://$bucket" --no-sign-request > "Bucket_Exposure/${bucket}_s3.txt" 2>&1
    elif [[ "$asset" =~ blob\.core\.windows\.net ]]; then
        bucket=$(echo "$asset" | awk -F'.blob.core.windows.net' '{print $1}' | sed 's~https\?://~~')
        echo "  [+] Testing Azure Blob: $bucket"
        az storage blob list --account-name "$bucket" --container-name '$root' --auth-mode key > "Bucket_Exposure/${bucket}_azure.txt" 2>&1
    elif [[ "$asset" =~ storage\.googleapis\.com ]]; then
        bucket=$(echo "$asset" | awk -F'.storage.googleapis.com' '{print $1}' | sed 's~https\?://~~')
        echo "  [+] Testing GCP Bucket: $bucket"
        gsutil ls "gs://$bucket" > "Bucket_Exposure/${bucket}_gcp.txt" 2>&1
    fi
done < cloud_assets.txt

echo "[*] Bucket exposure testing complete. Results saved in Bucket_Exposure/"


echo "[+] Recon flow completed. All results saved in '$OUTPUT_DIR/'"
