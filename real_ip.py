#!/usr/bin/env python3

import sys
import argparse
import requests
import json
from pathlib import Path
import urllib3
from urllib.parse import urljoin, urlparse
from fake_useragent import UserAgent
import mmh3
import codecs
from bs4 import BeautifulSoup
import re
import base64
import hashlib
from cryptography import x509
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.backends import default_backend

urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

CONFIG_FILE = Path.home() / ".cf-osint-keys.conf"

def is_behind_cloudflare(domain):
    """
    Simple check: Is domain behind Cloudflare?
    Returns: True or False
    """
    # 1. NS check (nhanh và chính xác nhất)
    try:
        import dns.resolver
        answers = dns.resolver.resolve(domain, 'NS')
        ns_list = [str(rdata.target).lower() for rdata in answers]
        if any('cloudflare.com' in ns for ns in ns_list):
            return True
    except:
        pass

    # 2. Headers check (Server/CF-Ray/CF-Cache-Status)
    try:
        ua = UserAgent()
        headers = {"User-Agent": ua.chrome}
        resp = requests.get(f"https://{domain}", headers=headers, timeout=5, allow_redirects=True, verify=False)
        server = resp.headers.get('Server', '').lower()
        if 'cloudflare' in server or 'cf-ray' in resp.headers.lower() or 'cf-cache-status' in resp.headers.lower():
            return True
    except:
        pass

    # 3. IP range check (tự fetch từ Cloudflare, nếu fail thì bỏ qua)
    try:
        resp = requests.get("https://www.cloudflare.com/ips/", timeout=5)
        if resp.status_code == 200:
            lines = resp.text.strip().splitlines()
            cf_ranges = [line.strip() for line in lines if re.match(r'^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}/\d{1,2}$', line.strip())]
            if cf_ranges:
                import ipaddress, socket
                ip = socket.gethostbyname(domain)
                ip_obj = ipaddress.ip_address(ip)
                if any(ip_obj in ipaddress.ip_network(cidr) for cidr in cf_ranges):
                    return True
    except:
        pass

    return False


def load_api_keys():
    if not CONFIG_FILE.exists():
        sys.stderr.write(f"[!] Config file {CONFIG_FILE} does not exist. Create it with API keys for automatic queries.\n")
        return {}
    
    try:
        with open(CONFIG_FILE, "r") as f:
            return json.load(f)
    except Exception as e:
        sys.stderr.write(f"[!] Error loading config: {str(e)}\n")
        return {}
    

def normalize_base_url(user_input):
    input_str = user_input.strip()
    parsed = urlparse(input_str)
    
    if not parsed.scheme and not parsed.netloc:
        return f"https://{input_str.rstrip('/')}/"
    
    if not parsed.scheme:
        return f"https://{input_str}"
    
    if not parsed.path.endswith('/'):
        return input_str.rstrip('/') + '/'
    
    return input_str    



def extract_favicon_url(base_url):
    ua = UserAgent()
    headers = {"User-Agent": ua.chrome}
    
    try:
        resp = requests.get(base_url, headers=headers, timeout=12, allow_redirects=True, verify=False)
        if resp.status_code != 200:
            sys.stderr.write(f"[!] Status {resp.status_code} when accessing {base_url}\n")
            return urljoin(base_url, "/favicon.ico")
        
        soup = BeautifulSoup(resp.text, "html.parser")
        
        icon_links = soup.find_all("link", rel=re.compile(r"(?i)(icon|shortcut icon)"))
        
        if icon_links:
            for link in icon_links:
                href = link.get("href")
                if href:
                    full_url = urljoin(base_url, href.strip())
                    sys.stdout.write(f"[+] Found favicon in HTML: {full_url}\n")
                    return full_url
        
        fallback = urljoin(base_url, "/favicon.ico")
        sys.stdout.write(f"[*] No icon link found in HTML → fallback: {fallback}\n")
        return fallback
    
    except Exception as e:
        sys.stderr.write(f"[!] Error parsing HTML: {str(e)}\n")
        return urljoin(base_url, "/favicon.ico")
    
def calculate_mmh3_hash(favicon_url):
    ua = UserAgent()
    headers = {"User-Agent": ua.chrome}
    
    try:
        response = requests.get(
            favicon_url,
            headers=headers,
            timeout=10,
            allow_redirects=True,
            verify=False
        )
        
        if response.status_code != 200:
            sys.stderr.write(f"[!] Error: Status {response.status_code} when fetching favicon {favicon_url}\n")
            return None
        
        content = response.content
        if not content or len(content) == 0:
            sys.stderr.write("[!] Favicon is empty (0 bytes)\n")
            return None
        
        b64_encoded = codecs.encode(content, 'base64')
        b64_str = b64_encoded.decode('ascii')
        
        hash_value = mmh3.hash(b64_str)
        
        sys.stdout.write(f"[DEBUG] Favicon content length: {len(content)} bytes\n")
        sys.stdout.write(f"[DEBUG] Base64 length: {len(b64_str)} chars\n")
        sys.stdout.write(f"[DEBUG] Base64 sample (first 100 chars): {b64_str[:100]}...\n")
        sys.stdout.write(f"[+] Favicon MMH3 hash: {hash_value}\n")
        
        return hash_value
    
    except requests.RequestException as req_err:
        sys.stderr.write(f"[!] Request error when fetching favicon: {str(req_err)}\n")
        return None
    except Exception as e:
        sys.stderr.write(f"[!] Error calculating favicon hash: {str(e)}\n")
        return None    
    
def calculate_banner_hash(response):
    try:
        server = response.headers.get('Server', '')
        body = response.content[:1024]
        combined = f"{server}{body.decode('utf-8', errors='ignore')}".encode()
        return hashlib.sha256(combined).hexdigest()
    except:
        return None
        
def calculate_title_hash(html_content):
    try:
        soup = BeautifulSoup(html_content, "html.parser")
        title = soup.title.string.strip() if soup.title else ""
        if not title:
            return None
        b64 = codecs.encode(title.encode(), "base64").decode('ascii').rstrip("\n")
        return mmh3.hash(b64)
    except:
        return None

def calculate_cert_hash(cert_der):
    try:
        cert = x509.load_der_x509_certificate(cert_der, default_backend())
        subject = cert.subject.rfc4514_string()
        issuer = cert.issuer.rfc4514_string()
        combined = f"{subject}{issuer}".encode()
        return hashlib.sha256(combined).hexdigest()
    except:
        return None            
    
def query_shodan(api_key, query_type, value, domain=None):
    if query_type == "favicon":
        query = f"http.favicon.hash:{value}"
    elif query_type == "banner":
        query = f"http.banner.hash:{value}"
    elif query_type == "title":
        query = f"http.title:\"{value}\""
    elif query_type == "cert":
        query = f"ssl.cert.subject.cn:\"{value}\""
    elif query_type == "dns":
        return []  # Shodan does not support historical DNS
    else:
        return []

    try:
        url = f"https://api.shodan.io/shodan/host/search?key={api_key}&query={query}"
        resp = requests.get(url)
        if resp.status_code == 200:
            data = resp.json()
            ips = {match.get("ip_str") for match in data.get("matches", [])}
            return list(ips)
        else:
            sys.stderr.write(f"[!] Shodan ({query_type}) error: {resp.status_code} - {resp.text}\n")
            return []
    except Exception as e:
        sys.stderr.write(f"[!] Shodan exception ({query_type}): {str(e)}\n")
        return []


def query_censys(censys_id, censys_secret, query_type, value, domain=None):
    auth = (censys_id, censys_secret)
    if query_type == "favicon":
        q = f"services.http.response.favicons.mmh3_hash: {value}"
    elif query_type == "banner":
        q = f"services.http.response.body_hash: {value}"  # Censys uses SHA256 for body
    elif query_type == "title":
        q = f"services.http.response.html_title: \"{value}\""
    elif query_type == "cert":
        q = f"services.tls.certificates.leaf_data.subject_dn: \"{value}\""
    elif query_type == "dns":
        return []  # Censys does not support historical DNS
    else:
        return []

    try:
        url = "https://search.censys.io/api/v2/hosts/search"
        params = {"q": q}
        resp = requests.get(url, auth=auth, params=params)
        if resp.status_code == 200:
            data = resp.json()
            ips = {hit.get("ip") for hit in data["result"].get("hits", [])}
            return list(ips)
        else:
            sys.stderr.write(f"[!] Censys ({query_type}) error: {resp.status_code} - {resp.text}\n")
            return []
    except Exception as e:
        sys.stderr.write(f"[!] Censys exception ({query_type}): {str(e)}\n")
        return []


def query_zoomeye(api_key, query_type, value, domain=None):
    headers = {"API-KEY": api_key}
    if query_type == "favicon":
        query = f"iconhash:{value}"
    elif query_type == "banner":
        query = f"banner:\"{value}\""
    elif query_type == "title":
        query = f"title:\"{value}\""
    elif query_type == "cert":
        query = f"cert:\"{value}\""
    elif query_type == "dns":
        return []
    else:
        return []

    try:
        url = f"https://api.zoomeye.org/host/search?query={query}"
        resp = requests.get(url, headers=headers)
        if resp.status_code == 200:
            data = resp.json()
            ips = {match.get("ip") for match in data.get("matches", [])}
            return list(ips)
        else:
            sys.stderr.write(f"[!] ZoomEye ({query_type}) error: {resp.status_code} - {resp.text}\n")
            return []
    except Exception as e:
        sys.stderr.write(f"[!] ZoomEye exception ({query_type}): {str(e)}\n")
        return []


def query_fofa(fofa_email, fofa_key, query_type, value, domain=None):
    if query_type == "favicon":
        query = f'icon_hash="{value}"'
    elif query_type == "banner":
        query = f'banner="{value}"'
    elif query_type == "title":
        query = f'title="{value}"'
    elif query_type == "cert":
        query = f'cert="{value}"'
    elif query_type == "dns":
        return []
    else:
        return []

    try:
        qbase64 = base64.b64encode(query.encode()).decode()
        url = f"https://fofa.info/api/v1/search/all?email={fofa_email}&key={fofa_key}&qbase64={qbase64}&size=100"
        resp = requests.get(url)
        if resp.status_code == 200:
            data = resp.json()
            if data.get("error"):
                sys.stderr.write(f"[!] FoFa error: {data.get('errmsg')}\n")
                return []
            ips = {result[0].split(":")[0] for result in data.get("results", [])}
            return list(ips)
        else:
            sys.stderr.write(f"[!] FoFa ({query_type}) error: {resp.status_code} - {resp.text}\n")
            return []
    except Exception as e:
        sys.stderr.write(f"[!] FoFa exception ({query_type}): {str(e)}\n")
        return []


def query_securitytrails(api_key, domain):
    """Query SecurityTrails for historical DNS (A records) - no hash, uses domain"""
    try:
        headers = {"APIKEY": api_key}
        url = f"https://api.securitytrails.com/v1/history/{domain}/dns/a"
        resp = requests.get(url, headers=headers)
        if resp.status_code == 200:
            data = resp.json()
            ips = set()
            for record in data.get("records", []):
                for value in record.get("values", []):
                    ips.add(value.get("ip"))
            return list(ips)
        else:
            sys.stderr.write(f"[!] SecurityTrails error: {resp.status_code} - {resp.text}\n")
            return []
    except Exception as e:
        sys.stderr.write(f"[!] SecurityTrails exception: {str(e)}\n")
        return []

def filter_real_origin_ips(domain, ip_list):
    real_ips = []
    headers = {"Host": domain}
    ua = UserAgent()
    headers["User-Agent"] = ua.chrome
    
    for ip in ip_list:
        try:
            url = f"https://{ip}"
            resp = requests.get(
                url,
                headers=headers,
                timeout=10,
                verify=False,
                allow_redirects=True
            )
            # Check nếu response giống site thật (ví dụ status 200 và có keyword đặc trưng)
            if resp.status_code == 200:
                # Thay bằng keyword của site mày (title, meta, hoặc body snippet)
                if "example domain" in resp.text.lower() or "<title>" in resp.text:  # Ví dụ
                    real_ips.append(ip)
                    sys.stdout.write(f"[+] REAL ORIGIN IP: {ip} (response matches site)\n")
                else:
                    sys.stdout.write(f"[-] Cloudflare IP: {ip} (response does NOT match)\n")
            else:
                sys.stdout.write(f"[-] Cloudflare IP: {ip} (status {resp.status_code})\n")
        except Exception as e:
            sys.stdout.write(f"[-] Error checking {ip}: {str(e)}\n")
    
    return real_ips

def main():
    parser = argparse.ArgumentParser(description="Find origin IP behind Cloudflare using multiple OSINT methods")
    parser.add_argument("target", nargs="?", default=None, help="Single domain or URL (e.g. vnpt.vn)")
    parser.add_argument("--file", help="File containing list of domains (one per line)")
    parser.add_argument("-o", "--output", help="Output file in JSON Lines format (each line is one origin IP)")
    parser.add_argument("--favicon", action="store_true", help="Search using favicon hash (default)")
    parser.add_argument("--banner", action="store_true", help="Search using banner hash")
    parser.add_argument("--title", action="store_true", help="Search using title hash/text")
    parser.add_argument("--cert", action="store_true", help="Search using TLS cert hash")
    parser.add_argument("--dns", action="store_true", help="Search using historical DNS (SecurityTrails)")
    parser.add_argument("--all", action="store_true", help="Run all methods")

    args = parser.parse_args()

    # Xác định nguồn input
    targets = []

    if args.file:
        try:
            with open(args.file, "r") as f:
                targets = [line.strip() for line in f if line.strip() and not line.strip().startswith('#')]
            sys.stdout.write(f"[*] Loaded {len(targets)} domains from file: {args.file}\n")
        except Exception as e:
            sys.stderr.write(f"[!] Error reading file {args.file}: {str(e)}\n")
            sys.exit(1)

    elif not sys.stdin.isatty():
        targets = [line.strip() for line in sys.stdin if line.strip() and not line.strip().startswith('#')]
        sys.stdout.write(f"[*] Loaded {len(targets)} domains from stdin\n")

    elif args.target:
        targets = [args.target]
        sys.stdout.write(f"[*] Processing single target: {args.target}\n")

    else:
        sys.stderr.write("[!] No target provided. Use: real_ip domain.com [--options] or cat hosts.txt | real_ip [--options] or --file hosts.txt\n")
        sys.exit(1)

    if not targets:
        sys.stderr.write("[!] No valid targets found.\n")
        sys.exit(1)

    # Các phương pháp
    methods = []
    if args.all:
        methods = ["favicon", "banner", "title", "cert", "dns"]
    else:
        if args.favicon or not (args.banner or args.title or args.cert or args.dns):
            methods.append("favicon")
        if args.banner:
            methods.append("banner")
        if args.title:
            methods.append("title")
        if args.cert:
            methods.append("cert")
        if args.dns:
            methods.append("dns")

    if not methods:
        methods = ["dns"]

    # Mở file output nếu có
    output_file = None
    if args.output:
        try:
            output_file = open(args.output, "w", encoding="utf-8")
            sys.stdout.write(f"[*] Output will be saved to: {args.output} (JSON Lines format)\n")
        except Exception as e:
            sys.stderr.write(f"[!] Error opening output file {args.output}: {str(e)}\n")
            sys.exit(1)

    # Xử lý từng target
    for idx, target in enumerate(targets, 1):
        sys.stdout.write(f"\n{'='*60}\n")
        sys.stdout.write(f"[*] Processing target {idx}/{len(targets)}: {target}\n")
        sys.stdout.write(f"{'='*60}\n")

        is_cf = is_behind_cloudflare(target)
        if is_cf:
            sys.stdout.write(f"[+] {target} Cloudflare: True\n")
        else:
            sys.stdout.write(f"[-] {target} Cloudflare: False\n")

        base_url = normalize_base_url(target)
        parsed = urlparse(base_url)
        domain = parsed.netloc or parsed.path  # fallback nếu không có netloc

        api_keys = load_api_keys()  # load mỗi lần để an toàn

        all_ips = set()

        favicon_url = None
        favicon_hash = None
        banner_hash = None
        title_hash = None
        cert_hash = None
        response = None
        cert_der = None

        # Lấy trang chính nếu cần
        if any(m in methods for m in ["favicon", "banner", "title"]):
            try:
                ua = UserAgent()
                headers = {"User-Agent": ua.chrome}
                response = requests.get(base_url, headers=headers, timeout=12, allow_redirects=True, verify=False)
            except Exception as e:
                sys.stderr.write(f"[!] Error fetching main page for {target}: {e}\n")

        if "favicon" in methods:
            favicon_url = extract_favicon_url(base_url)
            favicon_hash = calculate_mmh3_hash(favicon_url)
            if favicon_hash:
                sys.stdout.write(f"[+] Favicon hash: {favicon_hash}\n")
            else:
                sys.stderr.write("[!] Failed to calculate favicon hash → skipping favicon\n")

        if "banner" in methods and response:
            banner_hash = calculate_banner_hash(response)
            if banner_hash:
                sys.stdout.write(f"[+] Banner hash (SHA256): {banner_hash}\n")

        if "title" in methods and response:
            title_hash = calculate_title_hash(response.text)
            if title_hash:
                sys.stdout.write(f"[+] Title hash: {title_hash}\n")
            else:
                sys.stdout.write("[!] No title found or empty\n")

        if "cert" in methods:
            try:
                import ssl
                import socket
                ctx = ssl.create_default_context()
                with socket.create_connection((domain, 443), timeout=10) as sock:
                    with ctx.wrap_socket(sock, server_hostname=domain) as ssock:
                        cert_der = ssock.getpeercert(binary_form=True)
                        cert_hash = calculate_cert_hash(cert_der)
                        if cert_hash:
                            sys.stdout.write(f"[+] Cert hash (SHA256 subject+issuer): {cert_hash}\n")
            except Exception as e:
                sys.stderr.write(f"[!] Error fetching TLS cert for {target}: {e}\n")

        # Query từng method
        for method in methods:
            sys.stdout.write(f"\n[*] Running method: {method.upper()} for {target}\n")
            value = {
                "favicon": favicon_hash,
                "banner": banner_hash,
                "title": title_hash,
                "cert": cert_hash,
                "dns": domain
            }.get(method)

            if not value and method != "dns":
                sys.stdout.write(f"[!] No {method} hash/value → skip\n")
                continue

            if "shodan" in api_keys:
                sys.stdout.write("  - Querying Shodan...\n")
                ips = query_shodan(api_keys["shodan"], method, value, domain)
                all_ips.update(ips)

            if "censys_id" in api_keys and "censys_secret" in api_keys:
                sys.stdout.write("  - Querying Censys...\n")
                ips = query_censys(api_keys["censys_id"], api_keys["censys_secret"], method, value, domain)
                all_ips.update(ips)

            if "zoomeye" in api_keys:
                sys.stdout.write("  - Querying ZoomEye...\n")
                ips = query_zoomeye(api_keys["zoomeye"], method, value, domain)
                all_ips.update(ips)

            if "fofa_email" in api_keys and "fofa_key" in api_keys:
                sys.stdout.write("  - Querying FoFa...\n")
                ips = query_fofa(api_keys["fofa_email"], api_keys["fofa_key"], method, value, domain)
                all_ips.update(ips)

            if method == "dns" and "securitytrails" in api_keys:
                sys.stdout.write("  - Querying SecurityTrails (historical DNS)...\n")
                ips = query_securitytrails(api_keys["securitytrails"], domain)
                all_ips.update(ips)

        # In kết quả cho domain này
        if all_ips:
            sys.stdout.write(f"\n[+] Filtering real origin IPs for {target}...\n")
            real_origin = filter_real_origin_ips(target, list(all_ips))
            
            # Xuất ra file JSON Lines nếu có --output
            if output_file and real_origin:
                for ip in real_origin:
                    json_line = {
                        "url": target,
                        "origin_ip": ip,
                        "cloudflare": is_cf
                    }
                    output_file.write(json.dumps(json_line, ensure_ascii=False) + "\n")
                    output_file.flush()  # Ghi ngay để tránh mất dữ liệu

            if real_origin:
                sys.stdout.write(f"[+] Real origin IPs found: {', '.join(real_origin)}\n")
            else:
                sys.stderr.write("[-] No real origin IP detected (all seem to be Cloudflare)\n")
        else:
            sys.stdout.write(f"[*] No IPs found for {target}\n")

    if output_file:
        output_file.close()
        sys.stdout.write(f"[*] Output saved to {args.output}\n")    
    sys.stdout.write(f"\n[*] Completed processing {len(targets)} targets.\n")

if __name__ == "__main__":
    main()