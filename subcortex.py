import os
import argparse
import time
import subprocess
import sys

def print_banner():
    banner = r"""
     _________    ___.   _________                __                 
    /   _____/__ _\_ |__ \_   ___ \  ____________/  |_  ____ ___  ___
    \_____  \|  |  \ __ \/    \  \/ /  _ \_  __ \   __\/ __ \\  \/  /
     /        \  |  / \_\ \     \___(  <_> )  | \/|  | \  ___/ >    < 
    /_______  /____/|___  /\______  /\____/|__|   |__|  \___  >__/\_ \
            \/          \/        \/                        \/      \/ 
            
            			by @E5R with ❤
            							v1.2


	My Github Profile: 		https://github.com/EN5R
	My X Profile:			https://x.com/EN544R
	My Telegram Channel: 		https://t.me/+K3G9CJmZfShmOGI0
	
    """
    print(banner)

def run_command(command, description, retries=3, delay=5):
    """Run the command and if you encounter an error, try again"""
    attempt = 0
    print(f"\033[34mINFO:\033[0m \033[31m {description}\033[0m")
    while attempt < retries:
        result = os.system(command)
        if result == 0:
            print(f"\033[34mINFO:\033[0m \033[32m The command completed successfully.\033[0m")
            return
        attempt += 1
        print(f"\033[34mERROR:\033[0m \033[31m The command failed, waiting for {delay} seconds and retrying... ({attempt}/{retries})\033[0m")
        time.sleep(delay)
    print(f"\033[34mERROR:\033[0m \033[31m The command failed after {retries} attempts.\033[0m")

def gather_subdomains(domain):
    """Collecting subdomains with various tools"""
    
    VT_API_KEY = 'your_virustotal_api_key_here'
    
    # API anahtarının boş olup olmadığını kontrol et
    if VT_API_KEY == 'your_virustotal_api_key_here' or not VT_API_KEY.strip():
        print("\033[34mERROR:\033[0m \033[31m Your VirusTotal API key is missing. Please replace 'your_virustotal_api_key_here' with your actual API key in the script.\033[0m")
        sys.exit(1)  # Programdan çıkış yap
        
    commands = [
        (f'''curl -s "https://crt.sh/?q=%25.{domain}&output=json" | jq -r 'if type=="array" then . else empty end' | jq -r '.[].name_value' | sed 's/\\*\\.//g' | sort -u | anew crt''', "Collecting subdomains from crt.sh"),
        (f'''curl -s --request GET --url 'https://api.securitytrails.com/v1/domain/apple.com/subdomains?children_only=true&include_inactive=false' --header 'APIKEY: WGPKBLH-RODuVKrhDQ8WPb2HSgrKfaa8' --header 'accept: application/json' | jq -r '.subdomains[] | . + ".apple.com"' | anew securitytrails''', "Collecting subdomains from SecurityTrails"),
        (f'''curl -s "https://www.virustotal.com/api/v3/domains/{domain}/subdomains" -H "x-apikey: {VT_API_KEY}" | jq -r '.data[]?.attributes?.last_https_certificate?.extensions?.subject_alternative_name[]? // empty' | sort -u | anew virustotal''', "Collecting subdomains from VirusTotal"),
        (f'''curl -s "https://api.certspotter.com/v1/issuances?domain=apple.com&include_subdomains=true&expand=dns_names" | jq -r '.[].dns_names[]' | grep -Po '([\\w.-]+\\.[\\w]+\\.[A-z]+)' | sort -u | anew certspotter''', "Collecting subdomains from CertSpotter API"),
        (f'''curl -s "http://web.archive.org/cdx/search/cdx?url=*.{domain}/*&output=text&fl=original&collapse=urlkey" | sed -e 's_https*://__' -e 's/\\/.*//' | sort -u | anew webarchive''', "Collecting subdomains from Web Archive"),
        (f'''curl -s "https://jldc.me/anubis/subdomains/{domain}" | grep -Po '((http|https):\\/\\/)?([\\w.-]+\\.[\\w]+\\.[A-z]+)' | sort -u | anew jldc''', "Collecting subdomains from JLDC API"),
        (f'''curl -s "https://api.hackertarget.com/hostsearch/?q={domain}" | awk -F',' '{{print $1}}' | anew hackertarget''', "Collecting subdomains from HackerTarget API"),
        (f'''curl -s "https://otx.alienvault.com/api/v1/indicators/domain/{domain}/url_list?limit=1000" | grep -o '"hostname": *"[^"]*"' | sed 's/"hostname": "//' | sed 's/"$//' | sort -u | anew alienvault''', "Collecting subdomains from AlienVault API"),
        (f'''curl -s "https://api.subdomain.center/?domain={domain}" | jq -r '.[]' | sort -u | anew subdomaincenter''', "Collecting subdomains from Subdomain Center API"),
        (f'''curl -s "https://rapiddns.io/subdomain/{domain}?full=1" | grep -oE "[a-zA=Z0-9.-]+\\.{domain}" | sort -u | anew rapiddns''', "Collecting subdomains from RapidDNS API"),
        (f'subfinder -d {domain} -all -recursive | anew subfinder', "Collecting subdomains from Subfinder"),
        (f'assetfinder -subs-only {domain} | tee assetfinder', "Collecting subdomains from Assetfinder"),
        (f'traceninja -d {domain} -o traceninja', "Collecting subdomains from TraceNinja")
    ]
    
    retry_commands = commands[:8]
    for cmd, description in retry_commands:
        run_command(cmd, description)

    direct_commands = commands[8:]
    for cmd, description in direct_commands:
        print(f"\033[34mINFO:\033[0m \033[31m {description}\033[0m")
        os.system(cmd)
        print(f"\033[34mINFO:\033[0m \033[31m Command completed: {description}\033[0m")

def merge_subdomains():
    """Merge all files and delete the old ones"""
    print("\033[34mINFO:\033[0m \033[31m All subdomains are being merged...\033[0m")
    run_command("cat crt certspotter webarchive jldc hackertarget alienvault subdomaincenter rapiddns subfinder assetfinder traceninja virustotal securitytrails | sort -u > subdomain.txt", "Tüm subdomain dosyaları birleştiriliyor")
    
    files_to_remove = ["crt", "certspotter", "webarchive", "jldc", "hackertarget", "alienvault", "subdomaincenter", "rapiddns", "subfinder", "assetfinder", "traceninja", "virustotal", "securitytrails"]
    for file in files_to_remove:
        if os.path.exists(file):
            print(f"\033[34mINFO:\033[0m \033[31m {file} is being deleted...\033[0m")
            run_command(f"rm {file}", f"{file} is being deleted")
        else:
            print(f"\033[34mINFO:\033[0m \033[31m {file} not found, deletion skipped.\033[0m")

def run_subfinder():
    """Let's re-scan the subdomains we found with Subfinder."""
    print("\033[34mINFO:\033[0m \033[31m Performing the final scan with Subfinder...\033[0m")
    run_command("subfinder -dL subdomain.txt -all -recursive -o all.txt", "Final scan is being conducted with Subfinder")

if __name__ == "__main__":
    # Banner'ı yazdır
    print_banner()

    parser = argparse.ArgumentParser(description="Subdomain Enumeration Script")
    parser.add_argument("-d", "--domain", help="domain to enumerate subdomains for", required=True)
    args = parser.parse_args()

    domain = args.domain

    # Subdomain'leri topla
    gather_subdomains(domain)

    # Tüm subdomain'leri birleştir
    merge_subdomains()

    # Subfinder ile tarama yap
    run_subfinder()
