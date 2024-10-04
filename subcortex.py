import re
from bs4 import BeautifulSoup
import warnings
import aiofiles
import asyncio
import aiohttp
from fake_useragent import UserAgent
from colorama import Fore, Style
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
            							v2.0


	My Github Profile: 		https://github.com/EN5R
	My X Profile:			https://x.com/EN544R
	My Telegram Channel: 		https://t.me/+K3G9CJmZfShmOGI0
	My Buy Me a Coffee Page:	https://buymeacoffee.com/EN5R
	
    """
    print(banner)

async def run_command(command, description, retries=3, delay=5):
    """Run the command and if you encounter an error, try again."""
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
            

async def gather_subdomains(domain):
    """Collecting subdomains with various tools"""
    
    print("\033[34mINFO:\033[0m \033[31m Starting Tor service...\033[0m")
    os.system("sudo systemctl restart tor")  # Tor servisini başlat
    
    time.sleep(5)  # Tor'un başlatılması için kısa bir bekleme süresi
    
    VT_API_KEY = 'your_virustotal_api_key_here'
    
    # API anahtarının boş olup olmadığını kontrol et
    if VT_API_KEY == 'your_virustotal_api_key_here' or not VT_API_KEY.strip():
        print("\033[34mERROR:\033[0m \033[31m Your VirusTotal API key is missing. Please replace 'your_virustotal_api_key_here' with your actual API key in the script.\033[0m")
        sys.exit(1)  # Programdan çıkış yap
        
    commands = [
        (f'''curl --socks5 127.0.0.1:9050 -s --request GET --url 'https://api.securitytrails.com/v1/domain/{domain}/subdomains?children_only=true&include_inactive=false' --header 'APIKEY: EOXcuwwIWDizrnj2JFnh9xFo5yjlYWYU' --header 'accept: application/json' | jq -r '.subdomains[] | . + ".{domain}"' | anew securitytrails''', "Collecting subdomains from SecurityTrails"),
        (f'''curl --socks5 127.0.0.1:9050 -s "https://www.virustotal.com/api/v3/domains/{domain}/subdomains" -H "x-apikey: {VT_API_KEY}" | jq -r '.data[]?.attributes?.last_https_certificate?.extensions?.subject_alternative_name[]? // empty' | sort -u | anew virustotal''', "Collecting subdomains from VirusTotal"),
        (f'''curl --socks5 127.0.0.1:9050 -s "https://api.certspotter.com/v1/issuances?domain={domain}&include_subdomains=true&expand=dns_names" | jq -r '.[].dns_names[]' | sort -u | anew certspotter''', "Collecting subdomains from CertSpotter API"),
        (f'''curl --socks5 127.0.0.1:9050 -s "https://jldc.me/anubis/subdomains/{domain}" | grep -Po '((http|https):\\/\\/)?([\\w.-]+\\.[\\w]+\\.[A-z]+)' | sort -u | anew jldc''', "Collecting subdomains from JLDC API"),
        (f'subfinder -d {domain} -all -recursive | anew subfinder', "Collecting subdomains from Subfinder"),
        (f'assetfinder -subs-only {domain} | tee assetfinder', "Collecting subdomains from Assetfinder"),
        (f'traceninja -d {domain} -o traceninja', "Collecting subdomains from TraceNinja")
    ]
    
    for cmd, description in commands:
    	await run_command(cmd, description)  # await ekleyerek asenkron çağırıyoruz
        
    print("\033[34mINFO:\033[0m \033[31m Stopping Tor service...\033[0m")
    os.system("sudo systemctl stop tor")  # Tor servisini durdur
    
    
async def abuseipdb(domain, session):
    print(f"\033[34mINFO:\033[0m \033[32m Collecting subdomains from AbuseIPDB\033[0m")
    
    try:
        url = f"https://www.abuseipdb.com/whois/{domain}"
        headers = {
            "User-Agent": UserAgent().random,
            "Cookie": "abuseipdb_session="
        }

        async with session.get(url, timeout=1000, headers=headers, ssl=False) as response:
            if response.status != 200:
                print(f"[ERROR]: Unable to fetch data for {domain}: {response.status}", file=sys.stderr)
                return []

            data = await response.text()
            # Regex to capture subdomains
            tags = re.findall(r'<li>(.+?)</li>', data)
            subdomains = [tag.strip() for tag in tags if tag.strip()]

            # Save the subdomains to a file asynchronously
            if subdomains:
                async with aiofiles.open("abuseipdb", "a") as f:
                    for subdomain in subdomains:
                        await f.write(f"{subdomain}\n")
                        print(subdomain)

            return subdomains
            
    except Exception as e:
        print(f"[WARNING]: Exception occurred in AbuseIPDB: {e}", file=sys.stderr)
                        

async def alienvault(domain, session, args):
    print(f"\033[34mINFO:\033[0m \033[32m Collecting subdomains from AlienVault\033[0m")
    
    alienvaults = []
    url = f"https://otx.alienvault.com/api/v1/indicators/hostname/{domain}/passive_dns"
    proxy = args.proxy if args.proxy else None

    max_retries = 3  # Maksimum tekrar sayısı
    retries = 0

    while retries < max_retries:
        try:
            async with session.get(url, timeout=1000, proxy=proxy, ssl=False) as response:
                if response.status != 200:
                    print(f"\033[34mERROR:\033[0m \033[31m Unable to fetch data for {domain}: {response.status}\033[0m", file=sys.stderr)
                    return []

                data = await response.json()
                for entry in data['passive_dns']:
                    subdomain = entry['hostname']
                    if subdomain.endswith(f".{domain}"):
                        alienvaults.append(subdomain)

                break  # Başarılı bir şekilde veri alındı, döngüyü kır

        except asyncio.TimeoutError:
            retries += 1
            print(f"\033[34mWARNING:\033[0m \033[31m Timeout error occurred, retrying... ({retries}/{max_retries})\033[0m", file=sys.stderr)
        except aiohttp.ClientConnectionError:
            print(f"\033[34mERROR:\033[0m \033[31m Client connection error occurred for AlienVault.\033[0m", file=sys.stderr)
            return []
        except Exception as e:
            if args.sec_deb:
                print(f"\033[34mWRN:\033[0m \033[31m Exception occurred in AlienVault: {e}, {type(e)}\033[0m", file=sys.stderr)
            return []

    # Subdomain'leri dosyaya asenkron olarak yazma
    if alienvaults:
        async with aiofiles.open("alienvault", "a") as f:
            for subdomain in alienvaults:
                await f.write(f"{subdomain}\n")
                print(subdomain)

    return alienvaults
                        
            
async def anubis(domain, session, args):
    print(f"\033[34mINFO:\033[0m \033[32m Collecting subdomains from Anubis\033[0m")
    
    anubiss = []
    url = f"https://jonlu.ca/anubis/subdomains/{domain}"
    proxy = args.proxy if args.proxy else None
    
    max_retries = 3  # Maksimum tekrar sayısı
    retries = 0

    while retries < max_retries:
        try:
            async with session.get(url, timeout=1000, proxy=proxy, ssl=False) as response:
                if response.status != 200:
                    print(f"\033[34mERROR:\033[0m \033[31m Unable to fetch data for {domain}: {response.status}\033[0m", file=sys.stderr)
                    return []

                data = await response.json()
                for subdomain in data:
                    if subdomain.endswith(f".{domain}"):
                        anubiss.append(subdomain)

                break  # Başarılı bir şekilde veri alındı, döngüyü kır

        except asyncio.TimeoutError:
            retries += 1
            print(f"\033[34mWARNING:\033[0m \033[31m Timeout error occurred, retrying... ({retries}/{max_retries})\033[0m", file=sys.stderr)
        except aiohttp.ClientConnectionError:
            print(f"\033[34mERROR:\033[0m \033[31m Client connection error occurred for Anubis.\033[0m", file=sys.stderr)
            return []
        except Exception as e:
            if args.sec_deb:
                print(f"\033[34mWRN:\033[0m \033[31m Exception occurred in Anubis: {e}, {type(e)}\033[0m", file=sys.stderr)
            return []

    # Subdomain'leri dosyaya asenkron olarak yazma
    if anubiss:
        async with aiofiles.open("anubis", "a") as f:
            for subdomain in anubiss:
                await f.write(f"{subdomain}\n")
                print(subdomain)

    return anubiss
            

async def crtsh(domain, session, args):
    print(f"\033[34mINFO:\033[0m \033[32m Collecting subdomains from crt.sh\033[0m")

    url = f"https://crt.sh/?q=%25.{domain}&output=json"
    headers = {
        "User-Agent": UserAgent().random
    }
    
    max_retries = 3  # Maksimum tekrar sayısı
    retries = 0

    while retries < max_retries:
        try:
            async with session.get(url, timeout=1000, headers=headers, ssl=False) as response:
                if response.status != 200:
                    print(f"\033[34mERROR:\033[0m \033[31m Failed to fetch data from crt.sh: {response.status}\033[0m", file=sys.stderr)
                    return []

                data = await response.json()
                subdomains = [entry['name_value'] for entry in data]

                # Subdomain'leri dosyaya asenkron olarak yazma
                if subdomains:
                    async with aiofiles.open("crtsh", "a") as f:
                        for subdomain in subdomains:
                            await f.write(f"{subdomain}\n")
                            print(subdomain)

                return subdomains
            
        except aiohttp.ServerConnectionError:
            print(f"\033[34mWARNING:\033[0m \033[31m Server connection error occurred for crt.sh. Retrying... ({retries + 1}/{max_retries})\033[0m", file=sys.stderr)
            retries += 1
        except asyncio.TimeoutError:
            print(f"\033[34mWARNING:\033[0m \033[31m Timeout reached for crt.sh. Retrying... ({retries + 1}/{max_retries})\033[0m", file=sys.stderr)
            retries += 1
        except aiohttp.ClientConnectionError:
            print(f"\033[34mWARNING:\033[0m \033[31m Client connection error occurred for crt.sh. Retrying... ({retries + 1}/{max_retries})\033[0m", file=sys.stderr)
            retries += 1
        except KeyboardInterrupt:
            print(f"\033[34mINFO:\033[0m \033[32m Operation cancelled by user.\033[0m")
            quit()
        except Exception as e:
            print(f"\033[34mWARNING:\033[0m \033[31m Exception at crt.sh: {e}, {type(e)}\033[0m", file=sys.stderr)
            return []

    print(f"\033[34mERROR:\033[0m \033[31m Maximum retries reached for crt.sh. Exiting...\033[0m", file=sys.stderr)
    return []
            

async def dnsrepo(domain, session, args):
    print(f"\033[34mINFO:\033[0m \033[32m Collecting subdomains from Dnsrepo\033[0m")

    url = f"https://dnsrepo.noc.org/?domain={domain}"
    proxy = args.proxy if args.proxy else None
    max_retries = 3  # Maksimum tekrar sayısı
    retries = 0

    while retries < max_retries:
        try:
            async with session.get(url, timeout=1000, proxy=proxy, ssl=False) as response:
                if response.status != 200:
                    print(f"\033[34mERROR:\033[0m \033[31m Failed to fetch data from Dnsrepo: {response.status}\033[0m", file=sys.stderr)
                    return []

                data = await response.text()
                filterdomain = re.escape(domain)
                pattern = r'(?i)(?:https?://)?([a-zA-Z0-9*_.-]+\.' + filterdomain + r')'
                subdomains = re.findall(pattern, data)

                unique_subdomains = list(set(subdomains))  # Duplicate subdomains are removed

                # Save the subdomains to a file asynchronously
                if unique_subdomains:
                    async with aiofiles.open("dnsrepo", "a") as f:
                        for subdomain in unique_subdomains:
                            await f.write(f"{subdomain}\n")
                            print(subdomain)

                return unique_subdomains

        except aiohttp.ServerConnectionError:
            print(f"\033[34mWARNING:\033[0m \033[31m Server connection error occurred for Dnsrepo. Retrying... ({retries + 1}/{max_retries})\033[0m", file=sys.stderr)
            retries += 1
        except asyncio.TimeoutError:
            print(f"\033[34mWARNING:\033[0m \033[31m Timeout reached for Dnsrepo. Retrying... ({retries + 1}/{max_retries})\033[0m", file=sys.stderr)
            retries += 1
        except aiohttp.ClientConnectionError:
            print(f"\033[34mWARNING:\033[0m \033[31m Client connection error occurred for Dnsrepo. Retrying... ({retries + 1}/{max_retries})\033[0m", file=sys.stderr)
            retries += 1
        except KeyboardInterrupt:
            print(f"\033[34mINFO:\033[0m \033[32m Operation cancelled by user.\033[0m")
            quit()
        except Exception as e:
            print(f"\033[34mWARNING:\033[0m \033[31m Exception occurred at Dnsrepo: {e}, {type(e)}\033[0m", file=sys.stderr)
            return []

    print(f"\033[34mERROR:\033[0m \033[31m Maximum retries reached for Dnsrepo. Exiting...\033[0m", file=sys.stderr)
    return []
            

async def hackertarget(domain, session, args):
    print(f"\033[34mINFO:\033[0m \033[32mCollecting subdomains from HackerTarget\033[0m")  # Bilgilendirme mesajı

    hackertargets = []
    url = f"https://api.hackertarget.com/hostsearch/?q={domain}"
    proxy = args.proxy if args.proxy else None
    max_retries = 3  # Maksimum tekrar sayısı
    retries = 0

    while retries < max_retries:
        try:
            async with session.get(url, timeout=1000, proxy=proxy, ssl=False) as response:
                if response.status != 200:
                    print(f"\033[34mERROR:\033[0m \033[31mAPI call failed, HTTP Status: {response.status}\033[0m", file=sys.stderr)
                    return []

                responsed = await response.text()
                data = responsed.splitlines()
                for subdomain in data:
                    if "API count exceeded - Increase Quota with Membership" not in subdomain:
                        subdomain = subdomain.split(",")[0]
                        hackertargets.append(subdomain)

                # Unique subdomains to file asynchronously
                unique_hackertargets = list(set(hackertargets))
                if unique_hackertargets:
                    async with aiofiles.open("hackertarget.txt", "a") as f:
                        for subdomain in unique_hackertargets:
                            await f.write(f"{subdomain}\n")
                            print(subdomain)

                return unique_hackertargets

        except aiohttp.ServerConnectionError:
            print(f"\033[34mWARNING:\033[0m \033[31mServer connection error occurred. Retrying... ({retries + 1}/{max_retries})\033[0m", file=sys.stderr)
            retries += 1
        except asyncio.TimeoutError:
            print(f"\033[34mWARNING:\033[0m \033[31mAPI request timed out. Retrying... ({retries + 1}/{max_retries})\033[0m", file=sys.stderr)
            retries += 1
        except aiohttp.ClientConnectionError:
            print(f"\033[34mWARNING:\033[0m \033[31mClient connection error occurred. Retrying... ({retries + 1}/{max_retries})\033[0m", file=sys.stderr)
            retries += 1
        except KeyboardInterrupt:
            print(f"\033[34mINFO:\033[0m \033[32mOperation cancelled by user.\033[0m")
            quit()
        except Exception as e:
            print(f"\033[34mWARNING:\033[0m \033[31mException occurred: {e}, {type(e)}\033[0m", file=sys.stderr)

    print(f"\033[34mERROR:\033[0m \033[31mMaximum retries reached for HackerTarget. Exiting...\033[0m", file=sys.stderr)
    return []
                

async def myssl(domain, session, args):
    print(f"\033[34mINFO:\033[0m \033[32m Collecting subdomains from MySSL\033[0m")

    myssls = []
    url = f"https://myssl.com/api/v1/discover_sub_domain?domain=*.{domain}"
    headers = {
        "User-Agent": UserAgent().random
    }
    proxy = args.proxy if args.proxy else None
    max_retries = 3  # Maksimum tekrar sayısı
    retries = 0

    while retries < max_retries:
        try:
            async with session.get(url, headers=headers, timeout=1000, ssl=False, proxy=proxy) as response:
                if response.status != 200:
                    print(f"\033[34mERROR:\033[0m \033[31m API call failed, HTTP Status: {response.status}\033[0m", file=sys.stderr)
                    return []

                data = await response.json()

                # Kontrol: 'data' anahtarı var mı ve doğru formatta mı?
                if 'data' in data and isinstance(data['data'], list):
                    for subdomain_info in data['data']:
                        subdomain = subdomain_info.get('domain', '')
                        if subdomain and subdomain.endswith(f".{domain}"):
                            myssls.append(subdomain)
                else:
                    print(f"\033[34mWARNING:\033[0m \033[31m Expected 'data' format not received. Received data: {data}\033[0m", file=sys.stderr)
                    return []

                # Unique subdomains to file asynchronously
                unique_myssls = list(set(myssls))
                if unique_myssls:
                    async with aiofiles.open("myssl", "a") as f:
                        for subdomain in unique_myssls:
                            await f.write(f"{subdomain}\n")
                            print(subdomain)

                return unique_myssls

        except aiohttp.ServerConnectionError:
            print(f"\033[34mWARNING:\033[0m \033[31m Server connection error occurred. Retrying... ({retries + 1}/{max_retries})\033[0m", file=sys.stderr)
            retries += 1
        except asyncio.TimeoutError:
            print(f"\033[34mWARNING:\033[0m \033[31m API request timed out. Retrying... ({retries + 1}/{max_retries})\033[0m", file=sys.stderr)
            retries += 1
        except aiohttp.ClientConnectionError:
            print(f"\033[34mWARNING:\033[0m \033[31m Client connection error occurred. Retrying... ({retries + 1}/{max_retries})\033[0m", file=sys.stderr)
            retries += 1
        except KeyboardInterrupt:
            print(f"\033[34mINFO:\033[0m \033[32m Operation cancelled by user.\033[0m")
            quit()
        except Exception as e:
            print(f"\033[34mWARNING:\033[0m \033[31m Exception occurred: {e}, {type(e)}\033[0m", file=sys.stderr)

    print(f"\033[34mERROR:\033[0m \033[31m Maximum retries reached for MySSL. Exiting...\033[0m", file=sys.stderr)
    return []
            

async def racent(domain, session, args):
    print(f"\033[34mINFO:\033[0m \033[32m Collecting subdomains from Racent\033[0m")

    racents = []
    url = f"https://face.racent.com/tool/query_ctlog?keyword={domain}"
    headers = {
        "User-Agent": UserAgent().random
    }
    proxy = args.proxy if args.proxy else None
    max_retries = 3  # Maksimum tekrar sayısı
    retries = 0

    while retries < max_retries:
        try:
            async with session.get(url, headers=headers, ssl=False, proxy=proxy, timeout=1000) as response:
                if response.status != 200:
                    print(f"\033[34mERROR:\033[0m \033[31m API call failed, HTTP Status: {response.status}\033[0m", file=sys.stderr)
                    return []
                
                data = await response.json()

                # API'den dönen verinin kontrolü
                if "CTLog 查询超过限制" in data:
                    print(f"\033[34mINFO:\033[0m \033[32m Query limit exceeded for Racent API.\033[0m", file=sys.stderr)
                    return []

                # 'data' anahtarının olup olmadığını kontrol et
                if 'data' in data and 'list' in data['data']:
                    for subdomains in data['data']['list']:
                        if 'dnsnames' in subdomains:  # 'dnsnames' anahtarının varlığını kontrol et
                            for subdomain in subdomains['dnsnames']:
                                racents.append(subdomain)
                else:
                    print(f"\033[34mWARNING:\033[0m \033[31m Unexpected response format: {data}\033[0m", file=sys.stderr)
                    return []

                unique_racents = list(set(racents))  # Benzersiz subdomain'ler için set kullanıyoruz

                # Asenkron dosya yazma işlemi
                if unique_racents:
                    file_path = "racent"  # .txt uzantısı olmadan
                    async with aiofiles.open(file_path, "a") as f:
                        for subdomain in unique_racents:
                            await f.write(f"{subdomain}\n")
                            print(subdomain)

                return unique_racents

        except aiohttp.ServerConnectionError:
            print(f"\033[34mWARNING:\033[0m \033[31m Server connection error occurred. Retrying... ({retries + 1}/{max_retries})\033[0m", file=sys.stderr)
            retries += 1
        except asyncio.TimeoutError:
            print(f"\033[34mWARNING:\033[0m \033[31m Racent API request timed out. Retrying... ({retries + 1}/{max_retries})\033[0m", file=sys.stderr)
            retries += 1
        except aiohttp.ClientConnectionError:
            print(f"\033[34mWARNING:\033[0m \033[31m Client connection error occurred. Retrying... ({retries + 1}/{max_retries})\033[0m", file=sys.stderr)
            retries += 1
        except KeyboardInterrupt:
            print(f"\033[34mINFO:\033[0m \033[32m Operation cancelled by user.\033[0m")
            quit()
        except Exception as e:
            print(f"\033[34mWARNING:\033[0m \033[31m Exception occurred at Racent API: {e}, {type(e)}\033[0m", file=sys.stderr)

    print(f"\033[34mERROR:\033[0m \033[31m Maximum retries reached for Racent. Exiting...\033[0m", file=sys.stderr)
    return []
                

async def rapiddns(domain, session, args):
    print(f"\033[34mINFO:\033[0m \033[32m Collecting subdomains from RapidDNS\033[0m")

    try:
        rapiddnss = []
        max_retries = 3  # Maksimum tekrar sayısı

        for pagenum in range(1, 8):
            url = f"https://rapiddns.io/subdomain/{domain}?page={pagenum}"
            headers = {
                "User-Agent": UserAgent().random
            }
            
            retries = 0
            while retries < max_retries:
                try:
                    async with session.get(url, headers=headers, timeout=1000, ssl=False) as response:
                        if response.status != 200:
                            print(f"\033[34mERROR:\033[0m \033[31m Failed to fetch data from RapidDNS: {response.status}\033[0m", file=sys.stderr)
                            return []

                        data = await response.text()
                        filterdomain = re.escape(domain)
                        pattern = r'(?i)(?:https?://)?([a-zA-Z0-9*_.-]+\.' + filterdomain + r')'
                        subdomains = re.findall(pattern, data)
                        rapiddnss.extend(subdomains)

                        if "Next" not in data:
                            break
                        break  # Başarılı bir istek sonrası döngüden çık

                except (asyncio.TimeoutError, aiohttp.ClientConnectionError):
                    retries += 1
                    print(f"\033[34mWRN:\033[0m \033[31m Timeout or connection error occurred, retrying... ({retries}/{max_retries})\033[0m", file=sys.stderr)

        unique_rapiddnss = list(set(rapiddnss))  # Benzersiz subdomain'ler için set kullanıyoruz
        
        if unique_rapiddnss:
            # Asenkron dosya yazma işlemi
            file_path = "rapiddns"  # .txt uzantısı olmadan
            async with aiofiles.open(file_path, "a") as f:
                for subdomain in unique_rapiddnss:
                    await f.write(f"{subdomain}\n")
                    print(subdomain)
        
        return unique_rapiddnss

    except aiohttp.ServerConnectionError:
        print(f"\033[34mINFO:\033[0m \033[32m Server connection error occurred for RapidDNS.\033[0m", file=sys.stderr)
    except Exception as e:
        print(f"\033[34mWRN:\033[0m \033[31m Exception at rapiddns: {e}, {type(e)}\033[0m", file=sys.stderr)
    
    return []
            

async def shodan(domain, session, args):
    print(f"\033[34mINFO:\033[0m \033[32m Collecting subdomains from Shodan\033[0m")

    shodans = []
    url = f"https://www.shodan.io/domain/{domain}"
    headers = {
        "User-Agent": UserAgent().random
    }
    max_retries = 3  # Maksimum tekrar sayısı
    retries = 0

    while retries < max_retries:
        try:
            async with session.get(url, headers=headers, timeout=1000, ssl=False) as response:
                if response.status != 200:
                    print(f"\033[34mERROR:\033[0m \033[31m Failed to fetch data from Shodan: {response.status}\033[0m", file=sys.stderr)
                    return []
                
                data = await response.text()
                with warnings.catch_warnings():
                    warnings.filterwarnings("ignore", category=UserWarning)
                    soup = BeautifulSoup(data, "lxml")
                    ul = soup.find('ul', id='subdomains')
                    if not ul:
                        print(f"\033[34mINFO:\033[0m \033[32m No subdomains found for {domain}\033[0m", file=sys.stderr)
                        return []
                    
                    subdomains = ul.findAll("li")
                    for result in subdomains:
                        subdomain = f"{result.text.strip()}.{domain}"
                        shodans.append(subdomain)

            unique_shodans = list(set(shodans))  # Benzersiz subdomain'ler için set kullanıyoruz
            
            if unique_shodans:
                # Asenkron dosya yazma işlemi
                file_path = "shodan"  # .txt uzantısı olmadan
                async with aiofiles.open(file_path, "a") as f:
                    for subdomain in unique_shodans:
                        await f.write(f"{subdomain}\n")
                        print(subdomain)

                # Terminalde dosyayı görüntüleme
                subprocess.run(["cat", file_path])  # Eğer isterseniz dosyayı terminalde görüntüleyin

            return unique_shodans

        except aiohttp.ServerConnectionError:
            print(f"\033[34mWARNING:\033[0m \033[31m Server connection error occurred for Shodan. Retrying... ({retries + 1}/{max_retries})\033[0m", file=sys.stderr)
            retries += 1
        except aiohttp.ClientConnectionError:
            print(f"\033[34mWARNING:\033[0m \033[31m Client connection error occurred for Shodan. Retrying... ({retries + 1}/{max_retries})\033[0m", file=sys.stderr)
            retries += 1
        except asyncio.TimeoutError:
            print(f"\033[34mWARNING:\033[0m \033[31m Shodan request timed out. Retrying... ({retries + 1}/{max_retries})\033[0m", file=sys.stderr)
            retries += 1
        except Exception as e:
            print(f"\033[34mWARNING:\033[0m \033[31m Exception in Shodan request block: {e}, {type(e)}\033[0m", file=sys.stderr)

    print(f"\033[34mERROR:\033[0m \033[31m Maximum retries reached for Shodan. Exiting...\033[0m", file=sys.stderr)
    return []
            

async def shrewdeye(domain, session, args):
    print(f"\033[34mINFO:\033[0m \033[32m Collecting subdomains from ShrewdEye\033[0m")

    shrewdeyes = []
    url = f"https://shrewdeye.app/domains/{domain}.txt"
    max_retries = 3  # Maksimum tekrar sayısı
    retries = 0

    while retries < max_retries:
        try:
            async with session.get(url, timeout=1000, ssl=False) as response:
                if response.status != 200:
                    print(f"\033[34mERROR:\033[0m \033[31m Failed to fetch data from ShrewdEye: {response.status}\033[0m", file=sys.stderr)
                    return []

                data = await response.text()
                if not data.strip():  # Boş verileri kontrol et
                    print(f"\033[34mINFO:\033[0m \033[32m No subdomains found for {domain}\033[0m", file=sys.stderr)
                    return []

                subdomains = data.splitlines()  # Satırlara göre ayır
                for subdomain in subdomains:
                    shrewdeyes.append(subdomain.strip())

            unique_shrewdeyes = list(set(shrewdeyes))  # Benzersiz subdomain'ler için set kullanıyoruz

            if unique_shrewdeyes:
                # Asenkron dosya yazma işlemi
                file_path = "shrewdeye"  # .txt uzantısı olmadan
                async with aiofiles.open(file_path, "a") as f:
                    for subdomain in unique_shrewdeyes:
                        await f.write(f"{subdomain}\n")
                        print(subdomain)

                # Terminalde dosyayı görüntüleme
                subprocess.run(["cat", file_path])  # Eğer isterseniz dosyayı terminalde görüntüleyin

            return unique_shrewdeyes

        except aiohttp.ServerConnectionError:
            print(f"\033[34mWARNING:\033[0m \033[31m Server connection error occurred for ShrewdEye. Retrying... ({retries + 1}/{max_retries})\033[0m", file=sys.stderr)
            retries += 1
        except aiohttp.ClientConnectionError:
            print(f"\033[34mWARNING:\033[0m \033[31m Client connection error occurred for ShrewdEye. Retrying... ({retries + 1}/{max_retries})\033[0m", file=sys.stderr)
            retries += 1
        except asyncio.TimeoutError:
            print(f"\033[34mWARNING:\033[0m \033[31m ShrewdEye request timed out. Retrying... ({retries + 1}/{max_retries})\033[0m", file=sys.stderr)
            retries += 1
        except Exception as e:
            print(f"\033[34mWRN:\033[0m \033[31m Exception in ShrewdEye request block: {e}, {type(e)}\033[0m", file=sys.stderr)

    print(f"\033[34mERROR:\033[0m \033[31m Maximum retries reached for ShrewdEye. Exiting...\033[0m", file=sys.stderr)
    return []
            

async def sitedossier(domain, session):
    print(f"\033[34mINFO:\033[0m \033[32m Collecting subdomains from SiteDossier\033[0m")

    try:
        sitedossiers = []
        page = 1
        max_retries = 3  # Maksimum tekrar sayısı
        retries = 0

        while True:
            url = f"http://www.sitedossier.com/parentdomain/{domain}/{page}"
            while retries < max_retries:
                try:
                    async with session.get(url, timeout=1000, ssl=False) as response:
                        if response.status != 200:
                            print(f"\033[34mERROR:\033[0m \033[31m Failed to fetch data from SiteDossier: {response.status}\033[0m", file=sys.stderr)
                            return sitedossiers if sitedossiers else []

                        data = await response.text()
                        filterdomain = re.escape(domain)
                        pattern = r'(?i)(?:https?://)?([a-zA-Z0-9*_.-]+\.' + filterdomain + r')'
                        subdomains = re.findall(pattern, data)

                        sitedossiers.extend(subdomains)

                        if "Show next 100 items" not in data:
                            return sitedossiers if sitedossiers else []

                        page += 1
                        retries = 0  # Başarılı bir şekilde veri alındı, tekrar sayısını sıfırla
                        break  # İç döngüyü kır

                except asyncio.TimeoutError:
                    retries += 1
                    print(f"\033[34mWARNING:\033[0m \033[31m Timeout occurred, retrying... ({retries}/{max_retries})\033[0m", file=sys.stderr)
                except aiohttp.ServerConnectionError:
                    print(f"\033[34mERROR:\033[0m \033[31m Server connection error occurred for SiteDossier.\033[0m", file=sys.stderr)
                    return []
                except aiohttp.ClientConnectionError:
                    print(f"\033[34mERROR:\033[0m \033[31m Client connection error occurred for SiteDossier.\033[0m", file=sys.stderr)
                    return []

    except Exception as e:
        print(f"\033[34mWRN:\033[0m \033[31m Exception in SiteDossier request block: {e}, {type(e)}\033[0m", file=sys.stderr)

    return []
            

async def subdomaincenter(domain, session, args):
    print(f"\033[34mINFO:\033[0m \033[32m Collecting subdomains from Subdomain Center\033[0m")

    try:
        subdomaincenters = []
        url = f"https://api.subdomain.center/?domain={domain}"
        
        max_retries = 3  # Maksimum tekrar sayısı
        retries = 0

        while retries < max_retries:
            try:
                async with session.get(url, timeout=1000, ssl=False) as response:
                    if response.status != 200:
                        print(f"\033[34mERROR:\033[0m \033[31m Failed to fetch data from Subdomain Center: {response.status}\033[0m", file=sys.stderr)
                        return []

                    data = await response.json()
                    subdomaincenters.extend(data)  # Verileri direkt olarak ekleyin

                    break  # Başarılı bir şekilde veri alındı, döngüyü kır

            except asyncio.TimeoutError:
                retries += 1
                print(f"\033[34mWARNING:\033[0m \033[31m Timeout occurred, retrying... ({retries}/{max_retries})\033[0m", file=sys.stderr)
            except aiohttp.ServerConnectionError:
                print(f"\033[34mERROR:\033[0m \033[31m Server connection error occurred for Subdomain Center.\033[0m", file=sys.stderr)
                return []
            except aiohttp.ClientConnectionError:
                print(f"\033[34mERROR:\033[0m \033[31m Client connection error occurred for Subdomain Center.\033[0m", file=sys.stderr)
                return []

        unique_subdomaincenters = list(set(subdomaincenters))  # Benzersiz subdomain'ler için set kullanıyoruz

        # Asenkron dosya yazma işlemi
        if unique_subdomaincenters:
            file_path = "subdomaincenter"  # .txt uzantısı olmadan
            async with aiofiles.open(file_path, "a") as f:
                for subdomain in unique_subdomaincenters:
                    await f.write(f"{subdomain}\n")
                    print(subdomain)

            # Terminalde dosyayı görüntüleme (cat komutu)
            subprocess.run(["cat", file_path])  # Eğer isterseniz dosyayı terminalde görüntüleyin

        return unique_subdomaincenters

    except Exception as e:
        print(f"\033[34mWRN:\033[0m \033[31m Exception in Subdomain Center request block: {e}, {type(e)}\033[0m", file=sys.stderr)

    return []
            

async def urlscan(domain, session, args):
    print(f"\033[34mINFO:\033[0m \033[32m Collecting subdomains from Urlscan\033[0m")

    urlscans = []
    url = f"https://urlscan.io/api/v1/search/?q=page.domain:{domain}&size=10000"

    max_retries = 3  # Maksimum tekrar sayısı
    retries = 0

    while retries < max_retries:
        try:
            async with session.get(url, timeout=1000, ssl=False) as response:
                if response.status != 200:
                    print(f"\033[34mERROR:\033[0m \033[31m Failed to fetch data from Urlscan. Status code: {response.status}\033[0m", file=sys.stderr)
                    return []

                data = await response.json()
                for entry in data['results']:
                    subdomain = entry['page']['domain']
                    urlscans.append(subdomain)

                break  # Başarılı bir şekilde veri alındı, döngüyü kır

        except asyncio.TimeoutError:
            retries += 1
            print(f"\033[34mWARNING:\033[0m \033[31m Timeout occurred, retrying... ({retries}/{max_retries})\033[0m", file=sys.stderr)
        except aiohttp.ServerConnectionError:
            print(f"\033[34mERROR:\033[0m \033[31m Server connection error occurred for Urlscan.\033[0m", file=sys.stderr)
            return []
        except aiohttp.ClientConnectionError:
            print(f"\033[34mERROR:\033[0m \033[31m Client connection error occurred for Urlscan.\033[0m", file=sys.stderr)
            return []
        except Exception as e:
            print(f"\033[34mWRN:\033[0m \033[31m Exception in Urlscan request block: {e}, {type(e)}\033[0m", file=sys.stderr)
            return []

    unique_urlscans = list(set(urlscans))  # Benzersiz subdomain'ler için set kullanıyoruz

    # Asenkron dosya yazma işlemi
    if unique_urlscans:
        file_path = "urlscan"  # .txt uzantısı olmadan
        async with aiofiles.open(file_path, "a") as f:
            for subdomain in unique_urlscans:
                await f.write(f"{subdomain}\n")
                print(subdomain)

        # Terminalde dosyayı görüntüleme (cat komutu)
        subprocess.run(["cat", file_path])  # Eğer isterseniz dosyayı terminalde görüntüleyin

    return unique_urlscans
            

async def waybackarchive(domain, session, args):
    print(f"\033[34mINFO:\033[0m \033[32m Collecting subdomains from Wayback Archive\033[0m")

    try:
        url = f"http://web.archive.org/cdx/search/cdx?url=*.{domain}/*&output=txt&fl=original&collapse=urlkey"
        auth = {
            "User-Agent": UserAgent().random
        }

        max_retries = 3  # Maksimum tekrar sayısı

        retries = 0
        while retries < max_retries:
            try:
                async with session.get(url, headers=auth, timeout=1000, ssl=False) as response:
                    if response.status != 200:
                        print(f"\033[34mERROR:\033[0m \033[31m Failed to fetch data from Wayback Archive. Status code: {response.status}\033[0m", file=sys.stderr)
                        return []

                    data = await response.text()
                    filterdomain = re.escape(domain)
                    pattern = r'(?i)(?:https?://)?([a-zA-Z0-9*_.-]+\.' + filterdomain + r')'
                    subdomains = re.findall(pattern, data)
                    
                    unique_subdomains = list(set(subdomains))  # Benzersiz subdomain'ler için set kullanıyoruz
                    
                    if unique_subdomains:
                        # Asenkron dosya yazma işlemi
                        file_path = "waybackarchive"  # .txt uzantısı olmadan
                        async with aiofiles.open(file_path, "a") as f:
                            for subdomain in unique_subdomains:
                                await f.write(f"{subdomain}\n")
                                print(subdomain)

                        # Terminalde dosyayı görüntüleme (cat komutu)
                        subprocess.run(["cat", file_path])  # Eğer isterseniz dosyayı terminalde görüntüleyin

                    return unique_subdomains

            except asyncio.TimeoutError:
                retries += 1
                print(f"\033[34mWRN:\033[0m \033[31m Timeout occurred, retrying... ({retries}/{max_retries})\033[0m", file=sys.stderr)
            except aiohttp.ClientConnectionError:
                print(f"\033[34mINFO:\033[0m \033[32m Client connection error occurred for Wayback Archive.\033[0m", file=sys.stderr)
                return []
        
        print(f"\033[34mERROR:\033[0m \033[31m All retries failed for Wayback Archive.\033[0m", file=sys.stderr)
        
    except aiohttp.ServerConnectionError:
        print(f"\033[34mINFO:\033[0m \033[32m Server connection error occurred for Wayback Archive.\033[0m", file=sys.stderr)
    except Exception as e:
        print(f"\033[34mWRN:\033[0m \033[31m Exception in Wayback Archive request block: {e}, {type(e)}\033[0m", file=sys.stderr)

    return []
                        
    
async def collect_subdomains(domain, args):
    async with aiohttp.ClientSession() as session:
        # Her bir alt alan toplama işlevini sırayla çalıştır
        await abuseipdb(domain, session)
        await alienvault(domain, session, args)
        await anubis(domain, session, args)
        await crtsh(domain, session, args)
        await dnsrepo(domain, session, args)
        await hackertarget(domain, session, args)
        await myssl(domain, session, args)
        await racent(domain, session, args)
        await rapiddns(domain, session, args)
        await shodan(domain, session, args)
        await shrewdeye(domain, session, args)
        await sitedossier(domain, session)
        await subdomaincenter(domain, session, args)
        await urlscan(domain, session, args)
        await waybackarchive(domain, session, args)
                          

async def filter_unique_subdomains(input_file, output_file):
    """Filter unique subdomains from the input file."""
    command = f"sort -u {input_file} > {output_file}"
    await run_command(command, f"Filtering unique subdomains from {input_file}")

async def merge_subdomains():
    """Tüm dosyaları birleştir ve benzersiz subdomain'leri filtrele."""
    print("\033[34mINFO:\033[0m \033[32m Tüm subdomain'ler birleştiriliyor...\033[0m")

    # Tüm subdomain'leri birleştir ve benzersiz hale getir
    command = (
        "cat crtsh urlscan sitedossier shrewdeye shodan rapiddns "
        "myssl racent dnsrepo certspotter waybackarchive "
        "jldc hackertarget alienvault subdomaincenter subfinder "
        "assetfinder traceninja virustotal securitytrails anubis abuseipdb "
        "| sort -u > subdomain.txt"
    )
    await run_command(command, "Çeşitli kaynaklardan subdomain'leri birleştiriyor")

    # Benzersiz subdomain'leri filtrele
    await filter_unique_subdomains("subdomain.txt", "subdomains.txt")

    # subdomain.txt dosyasını sil
    if os.path.exists("subdomain.txt"):
        print("\033[34mINFO:\033[0m \033[32m subdomain.txt being deleted...\033[0m")
        await run_command("rm subdomain.txt", "Deleting subdomain.txt")

    # Diğer çıktı dosyalarını silme işlemi
    files_to_remove = [
        "crtsh", "shodan", "urlscan", "sitedossier", "shrewdeye",
        "certspotter", "myssl", "dnsrepo", "waybackarchive", "jldc",
        "hackertarget", "alienvault", "subdomaincenter", "rapiddns",
        "racent", "subfinder", "assetfinder", "traceninja",
        "virustotal", "anubis", "abuseipdb", "securitytrails"
    ]

    for file in files_to_remove:
        if os.path.exists(file):
            print(f"\033[34mINFO:\033[0m \033[32m {file} being deleted...\033[0m")
            await run_command(f"rm {file}", f"{file} being deleted...")
        else:
            print(f"\033[34mINFO:\033[0m \033[32m {file} not found, skipped deletion.\033[0m")
            

async def run_subfinder():
    """Tespit edilen subdomain'leri Subfinder ile yeniden tarama yapalım."""
    print("\033[34mINFO:\033[0m \033[32m Performing the final scan with Subfinder...\033[0m")
    
    # Subfinder ile subdomain taraması yapma
    await run_command("subfinder -dL subdomains.txt -all -recursive -o all.txt", "Final scan is being conducted with Subfinder")
    

async def main(domain, timeout=1000, proxy=None, sec_deb=False):
    """Main function to gather subdomains and process them."""
    await gather_subdomains(domain)  # Asenkron fonksiyonu çağır
    await collect_subdomains(domain, args)
    await merge_subdomains()          # Merge subdomains
    await run_subfinder()             # Run subfinder
    print(f"Domain: {domain}, Timeout: {timeout}, Proxy: {proxy}, Security Debug: {sec_deb}")

if __name__ == "__main__":
    # Banner'ı yazdır
    print_banner()

    parser = argparse.ArgumentParser(description='Your script description')
    parser.add_argument('-d', '--domain', required=True, help='Domain to analyze')
    parser.add_argument('--timeout', type=int, default=1000, help='Request timeout in seconds')
    parser.add_argument('--proxy', type=str, help='Proxy URL')
    parser.add_argument('--sec_deb', action='store_true', help='Enable security debug mode')

    args = parser.parse_args()
    
    asyncio.run(main(args.domain, args.timeout, args.proxy, args.sec_deb))  # Asynchronous execution
