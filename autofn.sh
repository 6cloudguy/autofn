#!/bin/bash

# === Colors ===
RED="\e[31m"
GREEN="\e[32m"
YELLOW="\e[33m"
BLUE="\e[34m"
CYAN="\e[36m"
MAGENTA="\e[35m"
WHITE="\e[37m"
BOLD="\e[1m"
RESET="\e[0m"

# === Enhanced Banner ===
echo -e "${CYAN}${BOLD}
╔═══════════════════════════════════════════════════════════════════════════════╗
║                                                                               ║
║    ██████╗ ███████╗ ██████╗ ██████╗ ███╗   ██╗    ███████╗███╗   ██╗          ║
║    ██╔══██╗██╔════╝██╔════╝██╔═══██╗████╗  ██║    ██╔════╝████╗  ██║          ║
║    ██████╔╝█████╗  ██║     ██║   ██║██╔██╗ ██║    █████╗  ██╔██╗ ██║          ║
║    ██╔══██╗██╔══╝  ██║     ██║   ██║██║╚██╗██║    ██╔══╝  ██║╚██╗██║          ║
║    ██║  ██║███████╗╚██████╗╚██████╔╝██║ ╚████║    ██║     ██║ ╚████║          ║
║    ╚═╝  ╚═╝╚══════╝ ╚═════╝ ╚═════╝ ╚═╝  ╚═══╝    ╚═╝     ╚═╝  ╚═══╝          ║
║                                                                               ║
║                           ${WHITE}Automated Recon Tool${CYAN}                                ║
║                               ${YELLOW}By 6cloudguy${CYAN}                                    ║
║                                                                               ║
╚═══════════════════════════════════════════════════════════════════════════════╝
${RESET}"

# === Input Check ===
if [ -z "$1" ]; then
  echo -e "${RED}${BOLD}[!] Usage: $0 <domain>${RESET}"
  echo -e "${YELLOW}    Example: $0 example.com${RESET}"
  exit 1
fi

TARGET=$1
DATE=$(date +%Y%m%d_%H%M%S)
OUTDIR="recon_output/${TARGET}_${DATE}"
mkdir -p "$OUTDIR/screenshots"

# === Function to check if screenshot tool is available ===
check_screenshot_tool() {
    if command -v wkhtmltopdf &> /dev/null; then
        echo "wkhtmltopdf"
    elif command -v cutycapt &> /dev/null; then
        echo "cutycapt"
    elif command -v chromium-browser &> /dev/null; then
        echo "chromium"
    elif command -v google-chrome &> /dev/null; then
        echo "chrome"
    elif command -v firefox &> /dev/null; then
        echo "firefox"
    else
        echo "none"
    fi
}

# === Function to take screenshot ===
take_screenshot() {
    local url="$1"
    local filename="$2"
    local tool="$3"
    
    case "$tool" in
        "wkhtmltopdf")
            timeout 30 wkhtmltopdf --page-width 1920 --page-height 1080 --disable-javascript --load-error-handling ignore --load-media-error-handling ignore "$url" "$filename.pdf" &>/dev/null
            ;;
        "cutycapt")
            timeout 30 cutycapt --url="$url" --out="$filename.png" --max-wait=10000 &>/dev/null
            ;;
        "chromium"|"chrome")
            local chrome_cmd="chromium-browser"
            if [ "$tool" == "chrome" ]; then
                chrome_cmd="google-chrome"
            fi
            timeout 30 "$chrome_cmd" --headless --disable-gpu --window-size=1920,1080 --screenshot="$filename.png" "$url" &>/dev/null
            ;;
        "firefox")
            timeout 30 firefox --headless --screenshot="$filename.png" --window-size=1920,1080 "$url" &>/dev/null
            ;;
        *)
            echo -e "${RED}[!] No screenshot tool available${RESET}"
            return 1
            ;;
    esac
}

# === Function to parse user selection ===
parse_selection() {
    local selection="$1"
    local max_num="$2"
    local -a selected_indices=()
    
    if [[ "$selection" =~ ^[Aa][Ll][Ll]$ ]]; then
        for ((i=1; i<=max_num; i++)); do
            selected_indices+=("$i")
        done
    else
        IFS=',' read -ra PARTS <<< "$selection"
        for part in "${PARTS[@]}"; do
            part=$(echo "$part" | xargs) # trim whitespace
            if [[ "$part" =~ ^[0-9]+$ ]]; then
                # Single number
                if [ "$part" -ge 1 ] && [ "$part" -le "$max_num" ]; then
                    selected_indices+=("$part")
                fi
            elif [[ "$part" =~ ^[0-9]+-[0-9]+$ ]]; then
                # Range
                start=$(echo "$part" | cut -d'-' -f1)
                end=$(echo "$part" | cut -d'-' -f2)
                if [ "$start" -le "$end" ] && [ "$start" -ge 1 ] && [ "$end" -le "$max_num" ]; then
                    for ((i=start; i<=end; i++)); do
                        selected_indices+=("$i")
                    done
                fi
            fi
        done
    fi
    
    # Remove duplicates and sort
    printf '%s\n' "${selected_indices[@]}" | sort -nu
}

# === Check available screenshot tool ===
SCREENSHOT_TOOL=$(check_screenshot_tool)
if [ "$SCREENSHOT_TOOL" != "none" ]; then
    echo -e "${GREEN}[✓] Screenshot tool found: $SCREENSHOT_TOOL${RESET}"
    SCREENSHOTS_ENABLED=true
else
    echo -e "${YELLOW}[!] No screenshot tool found. Install one of these for screenshots:${RESET}"
    echo -e "${CYAN}    • wkhtmltopdf:     ${WHITE}sudo apt-get install wkhtmltopdf${RESET}"
    echo -e "${CYAN}    • cutycapt:        ${WHITE}sudo apt-get install cutycapt${RESET}"
    echo -e "${CYAN}    • chromium:        ${WHITE}sudo apt-get install chromium-browser${RESET}"
    echo -e "${CYAN}    • firefox:         ${WHITE}sudo apt-get install firefox${RESET}"
    echo -e "${MAGENTA}[*] Continuing without screenshots...${RESET}"
    SCREENSHOTS_ENABLED=false
fi

# === Subdomain Enumeration ===
echo -e "${YELLOW}${BOLD}[+] Enumerating subdomains with assetfinder...${RESET}"
assetfinder --subs-only "$TARGET" | sort -u > "$OUTDIR/subdomains.txt"

# === Display Subdomains with Numbers ===
echo -e "${GREEN}${BOLD}[✓] Subdomains found:${RESET}"
echo -e "${BLUE}╭─────────────────────────────────────────────────────────────╮${RESET}"
echo -e "${BLUE}│                     DISCOVERED SUBDOMAINS                   │${RESET}"
echo -e "${BLUE}╰─────────────────────────────────────────────────────────────╯${RESET}"

mapfile -t subdomains < "$OUTDIR/subdomains.txt"
total_subs=${#subdomains[@]}

if [ "$total_subs" -eq 0 ]; then
    echo -e "${RED}[!] No subdomains found for $TARGET${RESET}"
    exit 1
fi

for i in "${!subdomains[@]}"; do
    printf "${CYAN}[%3d]${RESET} ${WHITE}%s${RESET}\n" $((i+1)) "${subdomains[$i]}"
done

echo -e "${BLUE}╭─────────────────────────────────────────────────────────────╮${RESET}"
echo -e "${BLUE}│                 Total: ${WHITE}$total_subs${BLUE} subdomains found                 │${RESET}"
echo -e "${BLUE}╰─────────────────────────────────────────────────────────────╯${RESET}"

# === Subdomain Selection ===
echo -e "\n${YELLOW}${BOLD}[?] Select subdomains to scan:${RESET}"
echo -e "${CYAN}    Examples:${RESET}"
echo -e "${WHITE}    • Single:      ${GREEN}5${RESET}"
echo -e "${WHITE}    • Multiple:    ${GREEN}1,3,7,12${RESET}"
echo -e "${WHITE}    • Range:       ${GREEN}1-5${RESET}"
echo -e "${WHITE}    • Mixed:       ${GREEN}1,3-7,12,15-20${RESET}"
echo -e "${WHITE}    • All:         ${GREEN}all${RESET}"
echo ""

while true; do
    read -p "$(echo -e "${BLUE}Enter your selection: ${RESET}")" user_selection
    
    if [ -z "$user_selection" ]; then
        echo -e "${RED}[!] Please enter a valid selection${RESET}"
        continue
    fi
    
    selected_nums=$(parse_selection "$user_selection" "$total_subs")
    
    if [ -z "$selected_nums" ]; then
        echo -e "${RED}[!] Invalid selection. Please try again.${RESET}"
        continue
    fi
    
    break
done

# === Create Selected Subdomains List ===
> "$OUTDIR/selected_subdomains.txt"
echo -e "\n${GREEN}${BOLD}[✓] Selected subdomains:${RESET}"
echo -e "${BLUE}╭─────────────────────────────────────────────────────────────╮${RESET}"
echo -e "${BLUE}│                    SELECTED FOR SCANNING                    │${RESET}"
echo -e "${BLUE}╰─────────────────────────────────────────────────────────────╯${RESET}"

while read -r num; do
    subdomain="${subdomains[$((num-1))]}"
    echo "$subdomain" >> "$OUTDIR/selected_subdomains.txt"
    printf "${CYAN}[%3d]${RESET} ${GREEN}%s${RESET}\n" "$num" "$subdomain"
done <<< "$selected_nums"

selected_count=$(wc -l < "$OUTDIR/selected_subdomains.txt")
echo -e "${BLUE}╭─────────────────────────────────────────────────────────────╮${RESET}"
echo -e "${BLUE}│              Selected: ${WHITE}$selected_count${BLUE} subdomains for scanning            │${RESET}"
echo -e "${BLUE}╰─────────────────────────────────────────────────────────────╯${RESET}"

# === Ask user about scan options ===
echo -e "\n${YELLOW}${BOLD}[?] Scan Options:${RESET}"

# Ask about FFUF
echo -e "${CYAN}[?] Run directory fuzzing with ffuf? ${WHITE}(recommended for finding hidden paths)${RESET}"
while true; do
    read -p "$(echo -e "${BLUE}Run FFUF directory scan? [Y/n]: ${RESET}")" ffuf_choice
    ffuf_choice=${ffuf_choice:-Y}  # Default to Y if empty
    case $ffuf_choice in
        [Yy]* ) RUN_FFUF=true; break;;
        [Nn]* ) RUN_FFUF=false; break;;
        * ) echo -e "${RED}Please answer yes or no.${RESET}";;
    esac
done

# Ask about Nmap
echo -e "${CYAN}[?] Run Nmap port scanning? ${WHITE}(recommended for finding open services)${RESET}"
while true; do
    read -p "$(echo -e "${BLUE}Run Nmap scan? [Y/n]: ${RESET}")" nmap_choice
    nmap_choice=${nmap_choice:-Y}  # Default to Y if empty
    case $nmap_choice in
        [Yy]* ) RUN_NMAP=true; break;;
        [Nn]* ) RUN_NMAP=false; break;;
        * ) echo -e "${RED}Please answer yes or no.${RESET}";;
    esac
done

echo -e "\n${GREEN}${BOLD}[✓] Scan Configuration:${RESET}"
echo -e "${WHITE}📁 Directory Fuzzing (FFUF): ${RESET}$([ "$RUN_FFUF" = true ] && echo -e "${GREEN}Enabled${RESET}" || echo -e "${RED}Disabled${RESET}")"
echo -e "${WHITE}🔍 Port Scanning (Nmap):    ${RESET}$([ "$RUN_NMAP" = true ] && echo -e "${GREEN}Enabled${RESET}" || echo -e "${RED}Disabled${RESET}")"

# === Continue with scanning selected subdomains ===
echo -e "\n${YELLOW}${BOLD}[+] Starting scan on selected subdomains...${RESET}"

# === FFUF on Selected Live Subdomains ===
if [ "$RUN_FFUF" = true ]; then
    echo -e "${YELLOW}[+] Running ffuf on selected live subdomains...${RESET}"
else
    echo -e "${BLUE}[ℹ] Skipping FFUF directory scanning (user choice)${RESET}"
fi

> "$OUTDIR/live_subs.txt"

WORDLIST="/usr/share/wordlists/dirb/common.txt"
IMPORTANT_403_PATTERNS="\.git|\.env|\.htaccess|\.svn|\.bash|\.passwd|\.config|\.mysql|\.DS_Store|\.log|\.aws|\.npmrc"

while read sub; do
    echo -e "${CYAN}[*] Checking if $sub is live...${RESET}"
    
    # Check both HTTP and HTTPS
    is_live=false
    protocol=""
    
    if curl --silent --head --max-time 10 "https://$sub" | grep -q "HTTP" 2>/dev/null; then
        echo "$sub" >> "$OUTDIR/live_subs.txt"
        echo -e "${GREEN}[✓] $sub is live on HTTPS!${RESET}"
        is_live=true
        protocol="https"
    elif curl --silent --head --max-time 10 "http://$sub" | grep -q "HTTP" 2>/dev/null; then
        echo "$sub" >> "$OUTDIR/live_subs.txt"
        echo -e "${GREEN}[✓] $sub is live on HTTP!${RESET}"
        is_live=true
        protocol="http"
    else
        echo -e "${RED}[✗] $sub is not responding${RESET}"
    fi
    
    if [ "$is_live" = true ]; then
        # === Take Screenshot ===
        if [ "$SCREENSHOTS_ENABLED" = true ]; then
            echo -e "${MAGENTA}[📸] Taking screenshot of $sub...${RESET}"
            screenshot_name="$OUTDIR/screenshots/${sub//[^a-zA-Z0-9]/_}_screenshot"
            
            if take_screenshot "$protocol://$sub" "$screenshot_name" "$SCREENSHOT_TOOL"; then
                echo -e "${GREEN}[✓] Screenshot saved: ${screenshot_name}${RESET}"
            else
                echo -e "${YELLOW}[!] Failed to take screenshot of $sub${RESET}"
            fi
        else
            echo -e "${BLUE}[ℹ] Skipping screenshot (no tool available)${RESET}"
        fi
        
        # === Directory Enumeration ===
        if [ "$RUN_FFUF" = true ]; then
            echo -e "${GREEN}[*] Detecting default 403 size on $sub...${RESET}"
            DEFAULT_403_SIZE=$(curl -s -o /dev/null -w "%{size_download}" "$protocol://$sub/sddhhfisdbhisbfibebfisfhjakfkfigekfbhkaslavihfabvofkv" 2>/dev/null)
            echo -e "${BLUE}[-] Default 403 size = $DEFAULT_403_SIZE${RESET}"

            SCAN_FILE="$OUTDIR/ffuf_${sub//[^a-zA-Z0-9]/_}.md"
            IMPORTANT_FILE="$OUTDIR/important_403s_${sub//[^a-zA-Z0-9]/_}.txt"

            echo -e "${GREEN}[*] FFUF scan on $sub...${RESET}"
            ffuf -u "$protocol://$sub/FUZZ" \
                 -w "$WORDLIST" \
                 -t 40 \
                 -mc 200,204,301,302,403 \
                 -fs "$DEFAULT_403_SIZE" \
                 -of md \
                 -o "$SCAN_FILE" > /dev/null 2>&1
                 
            echo -e "${CYAN}[*] Results for $sub:${RESET}"

            if [ -f "$SCAN_FILE" ]; then
                while IFS= read -r line; do
                    if [[ "$line" =~ ^[^|]*\|[^|]*\|[^|]*\|[^|]*$ ]]; then
                        path=$(echo "$line" | awk -F'|' '{print $1}' | xargs)
                        status=$(echo "$line" | awk -F'|' '{print $2}' | xargs)

                        # Is it a sensitive path?
                        if echo "$path" | grep -Eq "$IMPORTANT_403_PATTERNS"; then
                            if [[ "$status" == "200" || "$status" == "301" || "$status" == "302" ]]; then
                                echo -e "${RED}[!] Sensitive + Accessible → $path (Status: $status)${RESET}"
                            else
                                echo -e "${YELLOW}[-] Sensitive (403) → $path (Status: $status)${RESET}"
                            fi
                        else
                            if [[ "$status" == "200" || "$status" == "301" || "$status" == "302" ]]; then
                                echo -e "${GREEN}[+] Accessible → $path (Status: $status)${RESET}"
                            fi
                        fi
                    fi
                done < "$SCAN_FILE"

                # Extract important 403s from this one scan
                grep -E "$IMPORTANT_403_PATTERNS" "$SCAN_FILE" > "$IMPORTANT_FILE" 2>/dev/null

                if [ -s "$IMPORTANT_FILE" ]; then
                    echo -e "${MAGENTA}[!] Found potential sensitive 403s on $sub${RESET}"
                    cat "$IMPORTANT_FILE"
                fi
            fi
        else
            echo -e "${BLUE}[ℹ] Skipping FFUF scan for $sub (disabled)${RESET}"
        fi
    fi
done < "$OUTDIR/selected_subdomains.txt"

# === IP Resolution ===
if [ -s "$OUTDIR/live_subs.txt" ]; then
    echo -e "\n${YELLOW}[+] Resolving live subdomains to IPs...${RESET}"
    > "$OUTDIR/resolved_ips.txt"

    while read sub; do
        ip=$(dig +short "$sub" 2>/dev/null | grep -Eo '([0-9]{1,3}\.){3}[0-9]{1,3}' | head -n 1)
        if [ -n "$ip" ]; then
            echo "$ip # $sub" | tee -a "$OUTDIR/resolved_ips.txt"
        fi
    done < "$OUTDIR/live_subs.txt"

    awk '{print $1}' "$OUTDIR/resolved_ips.txt" | sort -u > "$OUTDIR/ip_list.txt"

    # === Nmap on IPs ===
    if [ -s "$OUTDIR/ip_list.txt" ] && [ "$RUN_NMAP" = true ]; then
        echo -e "${YELLOW}[+] Running Nmap scan on resolved IPs...${RESET}"
        > "$OUTDIR/nmap.txt"

        while read ip; do
            echo -e "${GREEN}[*] Scanning $ip...${RESET}"
            echo -e "\n=== $ip ===" >> "$OUTDIR/nmap.txt"
            nmap -sV -T4 -Pn "$ip" >> "$OUTDIR/nmap.txt" 2>/dev/null
        done < "$OUTDIR/ip_list.txt"

        # === Searchsploit for CVEs ===
        echo -e "${YELLOW}[+] Searching for known CVEs with searchsploit...${RESET}"
        > "$OUTDIR/cves.txt"

        if command -v searchsploit &> /dev/null; then
            echo -e "${BLUE}[*] Analyzing nmap output for services and versions...${RESET}"
            
            # Count services found
            services_found=0
            
            # Look for version information in nmap output
            while read -r line; do
                if echo "$line" | grep -qi "open"; then
                    
                    # Extract service and version patterns
                    service_version=""
                    
                    # SSH
                    if echo "$line" | grep -qiE "ssh"; then
                        version=$(echo "$line" | grep -oiE "openssh [0-9]+\.[0-9]+[0-9p\.]*" | head -1)
                        if [ ! -z "$version" ]; then
                            service_version="$version"
                        fi
                    fi
                    
                    # HTTP/Apache
                    if echo "$line" | grep -qiE "(http|apache)"; then
                        version=$(echo "$line" | grep -oiE "apache[/ ]([0-9]+\.[0-9]+[0-9\.]*)" | head -1)
                        if [ ! -z "$version" ]; then
                            service_version="$version"
                        fi
                    fi
                    
                    # Nginx
                    if echo "$line" | grep -qiE "nginx"; then
                        version=$(echo "$line" | grep -oiE "nginx[/ ]([0-9]+\.[0-9]+[0-9\.]*)" | head -1)
                        if [ ! -z "$version" ]; then
                            service_version="$version"
                        fi
                    fi
                    
                    # FTP
                    if echo "$line" | grep -qiE "ftp"; then
                        version=$(echo "$line" | grep -oiE "(proftpd|vsftpd|filezilla)[/ ]([0-9]+\.[0-9]+[0-9\.]*)" | head -1)
                        if [ ! -z "$version" ]; then
                            service_version="$version"
                        fi
                    fi
                    
                    # MySQL
                    if echo "$line" | grep -qiE "mysql"; then
                        version=$(echo "$line" | grep -oiE "mysql[/ ]([0-9]+\.[0-9]+[0-9\.]*)" | head -1)
                        if [ ! -z "$version" ]; then
                            service_version="$version"
                        fi
                    fi
                    
                    # Generic version pattern (service name + version)
                    if [ -z "$service_version" ]; then
                        service_version=$(echo "$line" | grep -oiE "[a-zA-Z0-9\-]+[/ ]([0-9]+\.[0-9]+[0-9\.]*)" | head -1)
                    fi
                    
                    # If we found a service with version, search for exploits
                    if [ ! -z "$service_version" ]; then
                        echo -e "${GREEN}[>] Found: $service_version${RESET}"
                        echo -e "${GREEN}[>] $service_version:${RESET}" >> "$OUTDIR/cves.txt"
                        
                        # Search for exploits
                        exploit_results=$(searchsploit "$service_version" 2>/dev/null)
                        if [ ! -z "$exploit_results" ]; then
                            echo "$exploit_results" >> "$OUTDIR/cves.txt"
                            services_found=$((services_found + 1))
                        else
                            echo "No exploits found for $service_version" >> "$OUTDIR/cves.txt"
                        fi
                        echo -e "\n" >> "$OUTDIR/cves.txt"
                    fi
                fi
            done < "$OUTDIR/nmap.txt"
            
            if [ $services_found -eq 0 ]; then
                echo -e "${YELLOW}[!] No services with versions found in nmap output${RESET}"
                echo "No services with versions found in nmap output" >> "$OUTDIR/cves.txt"
            else
                echo -e "${GREEN}[✓] Found $services_found services with potential exploits${RESET}"
            fi
            
        else
            echo -e "${YELLOW}[!] Searchsploit not found, skipping CVE search${RESET}"
            echo "Searchsploit tool not found on system" >> "$OUTDIR/cves.txt"
        fi
    elif [ -s "$OUTDIR/ip_list.txt" ] && [ "$RUN_NMAP" = false ]; then
        echo -e "${BLUE}[ℹ] Skipping Nmap scan (user choice)${RESET}"
        echo "Nmap scan skipped by user choice" > "$OUTDIR/nmap.txt"
        echo "Nmap scan was disabled by user" > "$OUTDIR/cves.txt"
    fi
fi

# === Generate Screenshots Summary ===
if [ "$SCREENSHOTS_ENABLED" = true ] && [ -s "$OUTDIR/live_subs.txt" ]; then
    echo -e "\n${YELLOW}[+] Generating screenshots summary...${RESET}"
    SCREENSHOT_SUMMARY="$OUTDIR/screenshots_summary.txt"
    echo "=== SCREENSHOTS SUMMARY ===" > "$SCREENSHOT_SUMMARY"
    echo "Date: $(date)" >> "$SCREENSHOT_SUMMARY"
    echo "" >> "$SCREENSHOT_SUMMARY"
    
    screenshot_count=0
    for screenshot in "$OUTDIR/screenshots"/*; do
        if [ -f "$screenshot" ]; then
            filename=$(basename "$screenshot")
            subdomain=$(echo "$filename" | sed 's/_screenshot\.\(png\|pdf\)$//' | sed 's/_/./g')
            echo "[$((++screenshot_count))] $subdomain -> $filename" >> "$SCREENSHOT_SUMMARY"
        fi
    done
    
    echo "" >> "$SCREENSHOT_SUMMARY"
    echo "Total screenshots: $screenshot_count" >> "$SCREENSHOT_SUMMARY"
elif [ "$SCREENSHOTS_ENABLED" = false ] && [ -s "$OUTDIR/live_subs.txt" ]; then
    echo -e "\n${BLUE}[ℹ] Screenshots skipped - no screenshot tool available${RESET}"
    echo -e "${CYAN}[💡] Install wkhtmltopdf, cutycapt, chromium, or firefox to enable screenshots${RESET}"
fi

# === Final Report Merge ===
REPORT="$OUTDIR/FINAL_REPORT.txt"
echo -e "===== RECON FN - FINAL REPORT =====\n" > "$REPORT"
echo -e "Target: $TARGET" >> "$REPORT"
echo -e "Date: $(date)" >> "$REPORT"
echo -e "Selected Subdomains: $selected_count out of $total_subs total" >> "$REPORT"
echo -e "FFUF Directory Scanning: $([ "$RUN_FFUF" = true ] && echo "Enabled" || echo "Disabled")" >> "$REPORT"
echo -e "Nmap Port Scanning: $([ "$RUN_NMAP" = true ] && echo "Enabled" || echo "Disabled")" >> "$REPORT"
echo -e "Screenshots: $([ "$SCREENSHOTS_ENABLED" = true ] && echo "Enabled" || echo "Disabled")" >> "$REPORT"
echo -e "" >> "$REPORT"

echo -e "--- All Discovered Subdomains ---" >> "$REPORT"
cat "$OUTDIR/subdomains.txt" >> "$REPORT"

echo -e "\n\n--- Selected Subdomains ---" >> "$REPORT"
cat "$OUTDIR/selected_subdomains.txt" >> "$REPORT"

if [ -s "$OUTDIR/live_subs.txt" ]; then
    echo -e "\n\n--- Live Subdomains ---" >> "$REPORT"
    cat "$OUTDIR/live_subs.txt" >> "$REPORT"
fi

if [ -f "$OUTDIR/screenshots_summary.txt" ]; then
    echo -e "\n\n--- Screenshots Summary ---" >> "$REPORT"
    cat "$OUTDIR/screenshots_summary.txt" >> "$REPORT"
fi

if [ "$RUN_FFUF" = true ]; then
    for FILE in "$OUTDIR"/ffuf_*.md; do
        if [ -f "$FILE" ]; then
            echo -e "\n\n--- FFUF Results (${FILE##*/}) ---" >> "$REPORT"
            cat "$FILE" >> "$REPORT"
        fi
    done
else
    echo -e "\n\n--- FFUF Results ---" >> "$REPORT"
    echo "FFUF directory scanning was disabled by user choice" >> "$REPORT"
fi

if [ "$RUN_NMAP" = true ]; then
    if [ -s "$OUTDIR/nmap.txt" ]; then
        echo -e "\n\n--- Nmap Scan ---" >> "$REPORT"
        cat "$OUTDIR/nmap.txt" >> "$REPORT"
    fi

    if [ -s "$OUTDIR/cves.txt" ]; then
        echo -e "\n\n--- CVE Suggestions (Searchsploit) ---" >> "$REPORT"
        cat "$OUTDIR/cves.txt" >> "$REPORT"
    fi
else
    echo -e "\n\n--- Nmap Scan ---" >> "$REPORT"
    echo "Nmap port scanning was disabled by user choice" >> "$REPORT"
    echo -e "\n\n--- CVE Suggestions ---" >> "$REPORT"
    echo "CVE search was disabled (requires Nmap)" >> "$REPORT"
fi

# === Completion Message ===
echo -e "\n${GREEN}${BOLD}╭─────────────────────────────────────────────────────────────╮${RESET}"
echo -e "${GREEN}${BOLD}│                   RECON FN COMPLETED!                       │${RESET}"
echo -e "${GREEN}${BOLD}╰─────────────────────────────────────────────────────────────╯${RESET}"
echo -e "${WHITE}📁 Results saved to: ${CYAN}$OUTDIR${RESET}"
echo -e "${WHITE}📄 Final report: ${CYAN}$REPORT${RESET}"
echo -e "${WHITE}🎯 Target: ${YELLOW}$TARGET${RESET}"
echo -e "${WHITE}📊 Subdomains scanned: ${GREEN}$selected_count${RESET}/${BLUE}$total_subs${RESET}"
echo -e "${WHITE}📁 Directory Fuzzing: ${RESET}$([ "$RUN_FFUF" = true ] && echo -e "${GREEN}Enabled${RESET}" || echo -e "${RED}Disabled${RESET}")"
echo -e "${WHITE}🔍 Port Scanning: ${RESET}$([ "$RUN_NMAP" = true ] && echo -e "${GREEN}Enabled${RESET}" || echo -e "${RED}Disabled${RESET}")"

if [ -s "$OUTDIR/live_subs.txt" ]; then
    live_count=$(wc -l < "$OUTDIR/live_subs.txt")
    echo -e "${WHITE}🟢 Live subdomains: ${GREEN}$live_count${RESET}"
fi

if [ "$SCREENSHOTS_ENABLED" = true ] && [ -s "$OUTDIR/live_subs.txt" ]; then
    screenshot_count=$(find "$OUTDIR/screenshots" -type f \( -name "*.png" -o -name "*.pdf" \) 2>/dev/null | wc -l)
    echo -e "${WHITE}📸 Screenshots taken: ${MAGENTA}$screenshot_count${RESET}"
    echo -e "${WHITE}📂 Screenshots folder: ${CYAN}$OUTDIR/screenshots${RESET}"
elif [ "$SCREENSHOTS_ENABLED" = false ] && [ -s "$OUTDIR/live_subs.txt" ]; then
    echo -e "${BLUE}📷 Screenshots: ${YELLOW}Disabled (no tool found)${RESET}"
    echo -e "${CYAN}💡 Install a screenshot tool to enable this feature${RESET}"
fi

echo -e "\n${YELLOW}Happy hacking! 🚀${RESET}"
