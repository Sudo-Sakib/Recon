#!/bin/bash

# ================= Colors =================
RED="\033[0;31m"
GREEN="\033[0;32m"
YELLOW="\033[1;33m"
BLUE="\033[1;34m"
NC="\033[0m"

# ================= Help Menu =================
usage() {
    echo -e "${GREEN}Usage:${NC}"
    echo -e "  $0 -d <domain> -o <output.txt> [-w <wordlist.txt>] [-r <resolvers.txt>] [-t <tmp_dir>]"
    echo -e "  $0 -l <domain_list.txt> -o <output.txt> [-w <wordlist.txt>] [-r <resolvers.txt>] [-t <tmp_dir>]"
    echo -e "\n${YELLOW}Options:${NC}"
    echo -e "  -d DOMAIN\t\tSingle domain to enumerate"
    echo -e "  -l LIST\t\tList of domains to enumerate"
    echo -e "  -o OUTPUT\t\tFinal output file (required)"
    echo -e "  -w WORDLIST\t\tSubdomain brute-force wordlist"
    echo -e "  -r RESOLVERS\t\tCustom resolvers file"
    echo -e "  -t TMPDIR\t\tTemporary directory"
    echo -e "  -h\t\t\tDisplay this help menu"

    echo -e "\n${BLUE}Examples:${NC}"
    echo -e "  $0 -d example.com -o result.txt"
    echo -e "  $0 -d example.com -o result.txt -w words.txt"
    echo -e "  $0 -l domains.txt -o final.txt -w words.txt -r myresolvers.txt"
    exit 0
}

# ================= Parse Arguments =================
while getopts ":d:l:o:w:r:t:h" opt; do
    case $opt in
        d) domain=$OPTARG ;;
        l) list=$OPTARG ;;
        o) output_file=$OPTARG ;;
        w) wordlist=$OPTARG ;;
        r) resolvers_file=$OPTARG ;;
        t) tmpdir=$OPTARG ;;
        h) usage ;;
        *) usage ;;
    esac
done

if [[ -z $output_file || ( -z $domain && -z $list ) ]]; then
    usage
fi

# ================= Tool GitHub Paths =================
declare -A tool_paths=(
    [subfinder]="github.com/projectdiscovery/subfinder/v2/cmd/subfinder"
    [puredns]="github.com/d3mondev/puredns/v2"
    [dnsx]="github.com/projectdiscovery/dnsx/cmd/dnsx"
    [httpx]="github.com/projectdiscovery/httpx/cmd/httpx"
    [dnsvalidator]="github.com/vortexau/dnsvalidator"
    [cero]="github.com/projectdiscovery/cero/cmd/cero"
)

# ================= Install Tools =================
install_tool() {
    local tool="$1"
    local path="${tool_paths[$tool]}"

    if ! command -v "$tool" &>/dev/null; then
        echo -e "${YELLOW}[!] Installing $tool from $path...${NC}"
        if command -v go &>/dev/null; then
            go install "$path@latest"
            [[ -f ~/go/bin/$tool ]] && sudo mv ~/go/bin/$tool /usr/local/bin/
        else
            echo -e "${RED}[-] Go is not installed. Cannot install $tool.${NC}"
            exit 1
        fi
    else
        echo -e "${GREEN}[+] $tool already installed.${NC}"
    fi
}

# Install required tools
required_tools=(subfinder puredns dnsx httpx dnsvalidator)
for tool in "${required_tools[@]}"; do install_tool "$tool"; done

# Optional: Cero
if command -v cero &>/dev/null; then
    use_cero=true
else
    echo -e "${YELLOW}[!] Optional tool 'cero' not found. Skipping verification stage.${NC}"
    use_cero=false
fi

# ================= Setup Directories =================
tmpdir="${tmpdir:-$(mktemp -d)}"
mkdir -p "$tmpdir"
done_file="$tmpdir/.done"
touch "$done_file"

echo -e "${GREEN}[+] Temporary directory: $tmpdir${NC}"

# ================= DNS Resolver Handling =================
if [[ -z $resolvers_file ]]; then
    echo -e "${YELLOW}[!] No resolvers provided. Running dnsvalidator...${NC}"
    dnsvalidator -tL https://public-dns.info/nameservers.txt -threads 100 -o "$tmpdir/resolvers.txt"
    resolvers_file="$tmpdir/resolvers.txt"
else
    [[ ! -f $resolvers_file ]] && { echo -e "${RED}[-] Resolvers file not found: $resolvers_file${NC}"; exit 1; }
fi

# ================= Wildcard Check =================
is_wildcard() {
    local d="$1"
    local random=$(head /dev/urandom | tr -dc a-z | head -c 12).$d
    local res=$(dig +short "$random" @"$(head -n1 "$resolvers_file")")
    [[ -n "$res" ]]
}

# ================= Domain Enumeration =================
enumerate_domain() {
    local d="$1"
    local safe=$(echo "$d" | tr '/:' '_')

    if grep -qx "$d" "$done_file"; then
        echo -e "${YELLOW}[!] Skipping already done: $d${NC}"
        return
    fi

    echo -e "${GREEN}[*] Enumerating $d...${NC}"
    subfinder -silent -d "$d" | tee "$tmpdir/${safe}_subfinder.txt"

    if [[ -n $wordlist ]]; then
        if is_wildcard "$d"; then
            echo -e "${RED}[!] Wildcard detected. Skipping brute-force for $d.${NC}"
        else
            echo -e "${YELLOW}[*] Brute-forcing with puredns...${NC}"
            puredns bruteforce "$wordlist" "$d" -r "$resolvers_file" \
                --resolvers-trusted "$resolvers_file" \
                --wildcard-batch 100 --wildcard-tests 10 \
                -w "$tmpdir/${safe}_puredns.txt"
        fi
    fi

    echo "$d" >> "$done_file"
}

# ================= Enumerate Domains =================
[[ -n $domain ]] && enumerate_domain "$domain"
if [[ -n $list ]]; then
    while IFS= read -r d; do
        [[ -z "$d" || "$d" =~ ^# ]] && continue
        enumerate_domain "$d"
    done < "$list"
fi

# ================= Merge & Resolve =================
echo -e "${YELLOW}[*] Merging results...${NC}"
cat "$tmpdir"/*.txt | sort -u > "$tmpdir/all_subs.txt"

resolved="${output_file%.*}_resolved.txt"
dnsx -silent -r "$resolvers_file" -l "$tmpdir/all_subs.txt" -o "$resolved"
echo -e "${GREEN}[+] Resolved domains saved: $resolved${NC}"

# ================= Optional: Verify with Cero =================
if $use_cero; then
    verified="${output_file%.*}_verified.txt"
    cero -l "$resolved" -o "$verified"
    cp "$verified" "$output_file"
    echo -e "${GREEN}[+] Verified subdomains saved: $output_file${NC}"
else
    cp "$resolved" "$output_file"
fi

# ================= HTTPx Probing =================
httpx_out="${output_file%.*}_httpx.txt"
httpx -silent -threads 100 -l "$output_file" -o "$httpx_out"
echo -e "${GREEN}[+] Live HTTP(s) endpoints saved: $httpx_out${NC}"

# ================= Final Summary =================
echo -e "\n${BLUE}[✓] Complete Summary:${NC}"
echo -e "  Raw Subdomains:     $tmpdir/all_subs.txt"
echo -e "  Resolved Domains:   $resolved"
$use_cero && echo -e "  Verified (cero):    $output_file"
echo -e "  Live HTTP(s):       $httpx_out"
echo -e "${GREEN}[✓] Done.${NC}"
