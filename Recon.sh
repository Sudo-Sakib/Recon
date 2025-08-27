#!/bin/bash

# Recon Flow Script
# Dependencies: httpx-toolkit, grep, awk, tee, wafw00f

# 1. Ask user for input
read -p "Enter target domain or acquisition file: " target

# Check if input is a file or single domain
if [[ -f "$target" ]]; then
    input="$target"
else
    echo "$target" > temp_input.txt
    input="temp_input.txt"
fi

# 2. Run httpx-toolkit with technology detection
echo "[*] Running httpx-toolkit on $target ..."
httpx-toolkit -l "$input" -tech-detect -status-code -title -silent -o httpx_result.txt

echo "[*] httpx results saved in httpx_result.txt"

# 3. Segregate domains by grepping known technologies
mkdir -p Segregated_Domains

techs=("Php" "WordPress" "Apache" "Nginx" "ASP" "IIS" "Drupal" "Joomla" "Django" "Flask" "SpringBoot" "Shopify" "Laravel" "Java" "MySQL")

for tech in "${techs[@]}"; do
    safe_tech=$(echo "$tech" | tr '[:upper:]' '[:lower:]' | tr ' ' '_' )

    # Create subfolder for this tech
    mkdir -p "Segregated_Domains/${safe_tech}"

    full_file="Segregated_Domains/${safe_tech}/${safe_tech}_full.txt"
    urls_file="Segregated_Domains/${safe_tech}/${safe_tech}_urls.txt"

    grep -i "$tech" httpx_result.txt | tee "$full_file" > /dev/null
    awk '{print $1}' "$full_file" | tee "$urls_file" > /dev/null

    if [[ -s "$full_file" ]]; then
        echo "  [+] Found $tech → $full_file (detailed), $urls_file (urls only)"
    else
        rm -f "$full_file" "$urls_file"
        rmdir --ignore-fail-on-non-empty "Segregated_Domains/${safe_tech}"
    fi
done

echo "[*] Segregation complete. Check the 'Segregated_Domains' folder."

# 4. Run WAF Detection on all alive URLs (save in current directory only)
echo "[*] Running WAF detection with wafw00f ..."
awk '{print $1}' httpx_result.txt | sort -u | while read -r url; do
    if [[ -n "$url" ]]; then
        wafw00f "$url" -a | tee -a waf_detection.txt
        echo "----" >> waf_detection.txt
    fi
done

echo "[*] WAF detection complete. Results saved in waf_detection.txt"
