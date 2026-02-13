#!/usr/bin/env python3

import json
import xml.etree.ElementTree as ET
import sys
import subprocess
import os
import datetime
from collections import defaultdict

# Mapping tech → tên hàm run
TECH_TO_RUN_FUNCTION = {
    "wordpress": "run_wpscan",
    "joomla": "run_joomscan",
    "drupal": "run_droopescan",
    "magento": "run_nuclei_magento",
    "shopify": "run_nuclei_shopify",
    "laravel": "run_nuclei_laravel",
    "django": "run_nuclei_django",
    "ruby on rails": "run_nuclei_rails",
    "node.js": "run_nuclei_nodejs",
    "express": "run_nuclei_express",
    "php": "run_nuclei_php",
    "apache": "run_nikto_nuclei_apache",
    "nginx": "run_nikto_nuclei_nginx",
    "litespeed": "run_nikto_nuclei_litespeed",
    "tomcat": "run_nuclei_tomcat",
    "cloudflare": "run_whatwaf_cf",
    "akamai": "run_whatwaf_akamai",
    "sucuri": "run_whatwaf_sucuri",
    "modsecurity": "run_nuclei_modsecurity",
}

def run_tool(tool_name, command, url_or_ip, output_dir="."):
    timestamp = datetime.datetime.now().strftime("%Y%m%d_%H%M%S")
    output_file = os.path.join(output_dir, f"{tool_name}_output_{timestamp}.txt")
    
    try:
        result = subprocess.run(command, shell=True, capture_output=True, text=True)
        
        # Tạo thư mục nếu chưa tồn tại
        os.makedirs(output_dir, exist_ok=True)
        
        with open(output_file, "w", encoding="utf-8") as f:
            f.write(f"=== {tool_name.upper()} OUTPUT for {url_or_ip} at {timestamp} ===\n")
            f.write(f"Command: {command}\n\n")
            f.write("STDOUT:\n")
            f.write(result.stdout)
            if result.stderr:
                f.write("\nSTDERR:\n")
                f.write(result.stderr)
        
        print(f"  → {tool_name} done → lưu file: {output_file}")
    except Exception as e:
        print(f"[!] Lỗi chạy {tool_name}: {e}")

# Các hàm run đơn giản (chỉ gọi run_tool)
def run_wpscan(url_or_ip, output_dir="."):
    cmd = f"wpscan --url {url_or_ip} --enumerate vp,at,u --plugins-detection aggressive --no-banner"
    run_tool("wpscan", cmd, url_or_ip, output_dir)

def run_joomscan(url_or_ip, output_dir="."):
    cmd = f"joomscan --url {url_or_ip}"
    run_tool("joomscan", cmd, url_or_ip, output_dir)

def run_droopescan(url_or_ip, output_dir="."):
    cmd = f"droopescan scan drupal -u {url_or_ip}"
    run_tool("droopescan", cmd, url_or_ip, output_dir)

def run_nuclei_magento(url_or_ip, output_dir="."):
    cmd = f"nuclei -u {url_or_ip} -t technologies/magento/ -t vulnerabilities/magento/ -silent"
    run_tool("nuclei_magento", cmd, url_or_ip, output_dir)

def run_nuclei_shopify(url_or_ip, output_dir="."):
    cmd = f"nuclei -u {url_or_ip} -t technologies/shopify/ -t vulnerabilities/shopify/ -silent"
    run_tool("nuclei_shopify", cmd, url_or_ip, output_dir)

def run_nuclei_laravel(url_or_ip, output_dir="."):
    cmd = f"nuclei -u {url_or_ip} -t technologies/laravel/ -t vulnerabilities/laravel/ -silent"
    run_tool("nuclei_laravel", cmd, url_or_ip, output_dir)

def run_nuclei_django(url_or_ip, output_dir="."):
    cmd = f"nuclei -u {url_or_ip} -t technologies/django/ -t vulnerabilities/django/ -silent"
    run_tool("nuclei_django", cmd, url_or_ip, output_dir)

def run_nuclei_rails(url_or_ip, output_dir="."):
    cmd = f"nuclei -u {url_or_ip} -t technologies/rails/ -t vulnerabilities/rails/ -silent"
    run_tool("nuclei_rails", cmd, url_or_ip, output_dir)

def run_nuclei_nodejs(url_or_ip, output_dir="."):
    cmd = f"nuclei -u {url_or_ip} -t technologies/nodejs/ -t vulnerabilities/nodejs/ -silent"
    run_tool("nuclei_nodejs", cmd, url_or_ip, output_dir)

def run_nuclei_express(url_or_ip, output_dir="."):
    cmd = f"nuclei -u {url_or_ip} -t technologies/express/ -t vulnerabilities/express/ -silent"
    run_tool("nuclei_express", cmd, url_or_ip, output_dir)

def run_nuclei_php(url_or_ip, output_dir="."):
    cmd = f"nuclei -u {url_or_ip} -t technologies/php/ -t vulnerabilities/php/ -silent"
    run_tool("nuclei_php", cmd, url_or_ip, output_dir)

def run_nikto_nuclei_apache(url_or_ip, output_dir="."):
    nikto_cmd = f"nikto -h {url_or_ip} -Tuning x -Format txt"
    run_tool("nikto_apache", nikto_cmd, url_or_ip, output_dir)
    
    nuclei_cmd = f"nuclei -u {url_or_ip} -t technologies/apache/ -t vulnerabilities/apache/ -silent"
    run_tool("nuclei_apache", nuclei_cmd, url_or_ip, output_dir)

def run_nikto_nuclei_nginx(url_or_ip, output_dir="."):
    nikto_cmd = f"nikto -h {url_or_ip} -Tuning x -Format txt"
    run_tool("nikto_nginx", nikto_cmd, url_or_ip, output_dir)
    
    nuclei_cmd = f"nuclei -u {url_or_ip} -t technologies/nginx/ -t vulnerabilities/nginx/ -silent"
    run_tool("nuclei_nginx", nuclei_cmd, url_or_ip, output_dir)

def run_nikto_nuclei_litespeed(url_or_ip, output_dir="."):
    nikto_cmd = f"nikto -h {url_or_ip} -Tuning x -Format txt"
    run_tool("nikto_litespeed", nikto_cmd, url_or_ip, output_dir)
    
    nuclei_cmd = f"nuclei -u {url_or_ip} -t technologies/litespeed/ -t vulnerabilities/litespeed/ -silent"
    run_tool("nuclei_litespeed", nuclei_cmd, url_or_ip, output_dir)

def run_nuclei_tomcat(url_or_ip, output_dir="."):
    cmd = f"nuclei -u {url_or_ip} -t technologies/tomcat/ -t vulnerabilities/tomcat/ -silent"
    run_tool("nuclei_tomcat", cmd, url_or_ip, output_dir)

def run_whatwaf_cf(url_or_ip, output_dir="."):
    cmd = f"whatwaf -u {url_or_ip}"
    run_tool("whatwaf_cloudflare", cmd, url_or_ip, output_dir)

def run_whatwaf_akamai(url_or_ip, output_dir="."):
    cmd = f"whatwaf -u {url_or_ip}"
    run_tool("whatwaf_akamai", cmd, url_or_ip, output_dir)

def run_whatwaf_sucuri(url_or_ip, output_dir="."):
    cmd = f"whatwaf -u {url_or_ip}"
    run_tool("whatwaf_sucuri", cmd, url_or_ip, output_dir)

def run_nuclei_modsecurity(url_or_ip, output_dir="."):
    cmd = f"nuclei -u {url_or_ip} -t technologies/modsecurity/ -t vulnerabilities/modsecurity/ -silent"
    run_tool("nuclei_modsecurity", cmd, url_or_ip, output_dir)

# ====================== PARSE HTTXP JSON ======================
def parse_httpx_json(file_path):
    techs_by_url = defaultdict(set)
    with open(file_path, 'r', encoding='utf-8') as f:
        for line in f:
            line = line.strip()
            if not line:
                continue
            try:
                data = json.loads(line)
                url = data.get('url') or data.get('input', 'Unknown')
                tech_list = data.get('tech', [])
                if tech_list:
                    techs_by_url[url].update(tech_list)
            except:
                pass
    return {url: sorted(list(tech_set)) for url, tech_set in techs_by_url.items()}

# ====================== PARSE NMAP XML ======================
def parse_nmap_xml(file_path):
    techs_by_ip = defaultdict(set)
    try:
        tree = ET.parse(file_path)
        root = tree.getroot()
        for host in root.findall('host'):
            addr = host.find('address')
            if addr is None:
                continue
            ip = addr.get('addr', 'Unknown')
            services = set()
            for port in host.findall('ports/port'):
                service = port.find('service')
                if service is not None:
                    name = service.get('name', '')
                    product = service.get('product', '')
                    version = service.get('version', '')
                    tech_str = name
                    if product:
                        tech_str += f" ({product}"
                        if version:
                            tech_str += f" {version}"
                        tech_str += ")"
                    if tech_str.strip():
                        services.add(tech_str.strip())
            if services:
                techs_by_ip[ip] = services
    except Exception as e:
        print(f"[!] Lỗi parse Nmap XML: {e}")
    return {ip: sorted(list(tech_set)) for ip, tech_set in techs_by_ip.items()}

# ====================== TỰ ĐỘNG GỌI HÀM RUN TOOL ======================
def auto_scan_tech(tech_list, url_or_ip, output_dir="."):
    tech_lower = [t.lower() for t in tech_list]
    
    for tech_key, run_func_name in TECH_TO_RUN_FUNCTION.items():
        if any(tech_key in t for t in tech_lower):
            print(f"[+] Phát hiện {tech_key} trên {url_or_ip} → chạy tool")
            # Gọi hàm với output_dir
            globals()[run_func_name](url_or_ip, output_dir)

# ====================== MAIN ======================
def main():
    if len(sys.argv) < 2:
        print("Usage:")
        print("  python3 tool.py /path/to/httpx.json [ /path/to/nmap.xml ] [-o /output/dir]")
        sys.exit(1)
    
    httpx_file = None
    nmap_file  = None
    output_dir = "."  # mặc định thư mục hiện tại
    
    # Parse tham số
    args = sys.argv[1:]
    i = 0
    while i < len(args):
        arg = args[i]
        if arg.lower().endswith('.json'):
            httpx_file = arg
        elif arg.lower().endswith('.xml'):
            nmap_file = arg
        elif arg == "-o" or arg == "--output":
            i += 1
            if i < len(args):
                output_dir = args[i]
            else:
                print("[!] Thiếu đường dẫn sau -o")
                sys.exit(1)
        i += 1
    
    if httpx_file is None and nmap_file is None:
        print("[!] Cần ít nhất file JSON hoặc XML")
        sys.exit(1)
    
    # Parse và hiển thị tech
    if httpx_file:
        try:
            print("HTTXP TECH:")
            httpx_tech = parse_httpx_json(httpx_file)
            for url, techs in httpx_tech.items():
                print(f"URL: {url} → Tech: {', '.join(techs)}")
                auto_scan_tech(techs, url, output_dir)
        except FileNotFoundError:
            print(f"[!] Không tìm thấy file httpx: {httpx_file}")
    
    if nmap_file:
        try:
            print("\nNMAP TECH:")
            nmap_tech = parse_nmap_xml(nmap_file)
            for ip, services in nmap_tech.items():
                print(f"IP: {ip} → Tech: {', '.join(services)}")
                auto_scan_tech(services, ip, output_dir)
        except FileNotFoundError:
            print(f"[!] Không tìm thấy file nmap: {nmap_file}")

if __name__ == "__main__":
    main()