#!/usr/bin/env python3

import json
import xml.etree.ElementTree as ET
import sys
import subprocess
from collections import defaultdict

# ====================== BẢNG MAPPING TECH → TÊN HÀM RUN ======================
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
    "jquery": "run_retire_js",
    "jquery ui": "run_retire_js",
    "react": "run_retire_js",
    "vue.js": "run_retire_js",
    "angular": "run_retire_js",
    "slick": "run_retire_js",
    "imagesloaded": "run_retire_js",
    "bootstrap": "run_retire_js",
    "underscore": "run_retire_js",
    "lodash": "run_retire_js",
    "moment.js": "run_retire_js",
    "apache": "run_nikto_nuclei_apache",
    "nginx": "run_nikto_nuclei_nginx",
    "litespeed": "run_nikto_nuclei_litespeed",
    "tomcat": "run_nuclei_tomcat",
    "cloudflare": "run_whatwaf_cf",
    "akamai": "run_whatwaf_akamai",
    "sucuri": "run_whatwaf_sucuri",
}

# ====================== CÁC HÀM RUN TOOL RIÊNG BIỆT ======================
def run_wpscan(url_or_ip):
    print("wpcaning")
    """Chạy wpscan cho WordPress - tự động"""
    command = f"wpscan --url {url_or_ip} --enumerate vp,at,u --plugins-detection aggressive --no-banner --no-update"
    print(f"    Lệnh sẽ chạy: {command}")
    
    try:
        print(f"    Đang chạy wpscan cho {url_or_ip}...")
        result = subprocess.run(command, shell=True, capture_output=True, text=True)
        print("\n" + "="*60)
        print("KẾT QUẢ WPSCAN:")
        print(result.stdout)
        if result.stderr:
            print("\nLỖI (nếu có):")
            print(result.stderr)
        print("="*60)
    except Exception as e:
        print(f"[!] Lỗi chạy wpscan: {e}")

def run_joomscan(url_or_ip):
    print("joomscan")
    """Chạy joomscan cho Joomla - tự động, lệnh basic"""
    command = f"joomscan --url {url_or_ip}"
    print(f"    Lệnh sẽ chạy: {command}")
    
    try:
        print(f"    Đang chạy joomscan cho {url_or_ip}...")
        result = subprocess.run(command, shell=True, capture_output=True, text=True)
        print("\n" + "="*60)
        print("KẾT QUẢ JOOMSCAN:")
        print(result.stdout)
        if result.stderr:
            print("\nLỖI (nếu có):")
            print(result.stderr)
        print("="*60)
    except Exception as e:
        print(f"[!] Lỗi chạy joomscan: {e}")
def run_droopescan(url_or_ip):
    print("droopescan")
    """Chạy droopescan cho Drupal - tự động, lệnh basic"""
    command = f"droopescan scan drupal -u {url_or_ip}"
    print(f"    Lệnh sẽ chạy: {command}")
    
    try:
        print(f"    Đang chạy droopescan cho {url_or_ip}...")
        result = subprocess.run(command, shell=True, capture_output=True, text=True)
        print("\n" + "="*60)
        print("KẾT QUẢ DROOPESCAN:")
        print(result.stdout)
        if result.stderr:
            print("\nLỖI (nếu có):")
            print(result.stderr)
        print("="*60)
    except Exception as e:
        print(f"[!] Lỗi chạy droopescan: {e}")

def run_nuclei_magento(url_or_ip):
    """Chạy nuclei cho Magento - tự động"""
    command = f"nuclei -u {url_or_ip} -t technologies/magento/ -t vulnerabilities/magento/ -silent"
    print(f"    Lệnh sẽ chạy: {command}")
    
    try:
        print(f"    Đang chạy nuclei cho Magento tại {url_or_ip}...")
        result = subprocess.run(command, shell=True, capture_output=True, text=True)
        print("\n" + "="*60)
        print("KẾT QUẢ NUCLEI (Magento):")
        print(result.stdout)
        if result.stderr:
            print("\nLỖI (nếu có):")
            print(result.stderr)
        print("="*60)
    except Exception as e:
        print(f"[!] Lỗi chạy nuclei cho Magento: {e}")

def run_nuclei_laravel(url_or_ip):
    """Chạy nuclei cho Laravel - tự động, dùng template Laravel"""
    command = f"nuclei -u {url_or_ip} -t technologies/laravel/ -t vulnerabilities/laravel/ -silent"
    print(f"    Lệnh sẽ chạy: {command}")
    
    try:
        print(f"    Đang chạy nuclei cho Laravel tại {url_or_ip}...")
        result = subprocess.run(command, shell=True, capture_output=True, text=True)
        print("\n" + "="*60)
        print("KẾT QUẢ NUCLEI (Laravel):")
        print(result.stdout)
        if result.stderr:
            print("\nLỖI (nếu có):")
            print(result.stderr)
        print("="*60)
    except Exception as e:
        print(f"[!] Lỗi chạy nuclei cho Laravel: {e}")

def run_nuclei_django(url_or_ip):
    """Chạy nuclei cho Django - tự động, dùng template Django"""
    command = f"nuclei -u {url_or_ip} -t technologies/django/ -t vulnerabilities/django/ -silent"
    print(f"    Lệnh sẽ chạy: {command}")
    
    try:
        print(f"    Đang chạy nuclei cho Django tại {url_or_ip}...")
        result = subprocess.run(command, shell=True, capture_output=True, text=True)
        print("\n" + "="*60)
        print("KẾT QUẢ NUCLEI (Django):")
        print(result.stdout)
        if result.stderr:
            print("\nLỖI (nếu có):")
            print(result.stderr)
        print("="*60)
    except Exception as e:
        print(f"[!] Lỗi chạy nuclei cho Django: {e}")

def run_nuclei_rails(url_or_ip):
    """Chạy nuclei cho Ruby on Rails - tự động, dùng template Rails"""
    command = f"nuclei -u {url_or_ip} -t technologies/rails/ -t vulnerabilities/rails/ -silent"
    print(f"    Lệnh sẽ chạy: {command}")
    
    try:
        print(f"    Đang chạy nuclei cho Ruby on Rails tại {url_or_ip}...")
        result = subprocess.run(command, shell=True, capture_output=True, text=True)
        print("\n" + "="*60)
        print("KẾT QUẢ NUCLEI (Ruby on Rails):")
        print(result.stdout)
        if result.stderr:
            print("\nLỖI (nếu có):")
            print(result.stderr)
        print("="*60)
    except Exception as e:
        print(f"[!] Lỗi chạy nuclei cho Ruby on Rails: {e}")

def run_nuclei_nodejs(url_or_ip):
    """Chạy nuclei cho Node.js - tự động, dùng template Node.js"""
    command = f"nuclei -u {url_or_ip} -t technologies/nodejs/ -t vulnerabilities/nodejs/ -silent"
    print(f"    Lệnh sẽ chạy: {command}")
    
    try:
        print(f"    Đang chạy nuclei cho Node.js tại {url_or_ip}...")
        result = subprocess.run(command, shell=True, capture_output=True, text=True)
        print("\n" + "="*60)
        print("KẾT QUẢ NUCLEI (Node.js):")
        print(result.stdout)
        if result.stderr:
            print("\nLỖI (nếu có):")
            print(result.stderr)
        print("="*60)
    except Exception as e:
        print(f"[!] Lỗi chạy nuclei cho Node.js: {e}")

def run_nuclei_express(url_or_ip):
    """Chạy nuclei cho Express - tự động, dùng template Express"""
    command = f"nuclei -u {url_or_ip} -t technologies/express/ -t vulnerabilities/express/ -silent"
    print(f"    Lệnh sẽ chạy: {command}")
    
    try:
        print(f"    Đang chạy nuclei cho Express tại {url_or_ip}...")
        result = subprocess.run(command, shell=True, capture_output=True, text=True)
        print("\n" + "="*60)
        print("KẾT QUẢ NUCLEI (Express):")
        print(result.stdout)
        if result.stderr:
            print("\nLỖI (nếu có):")
            print(result.stderr)
        print("="*60)
    except Exception as e:
        print(f"[!] Lỗi chạy nuclei cho Express: {e}")

def run_retire_js(url_or_ip):
    """Chạy retire.js nếu có JS libs - tự động"""
    command = f"retire --url {url_or_ip}"
    print(f"    Lệnh sẽ chạy: {command}")
    
    try:
        print(f"    Đang chạy retire.js cho JS libs tại {url_or_ip}...")
        result = subprocess.run(command, shell=True, capture_output=True, text=True)
        print("\n" + "="*60)
        print("KẾT QUẢ RETIRE.JS:")
        print(result.stdout)
        if result.stderr:
            print("\nLỖI (nếu có):")
            print(result.stderr)
        print("="*60)
    except Exception as e:
        print(f"[!] Lỗi chạy retire.js: {e}")

def run_nikto_nuclei_apache(url_or_ip):
    """Chạy nikto + nuclei cho Apache (cũ) - tự động"""
    
    # Lệnh nikto cơ bản
    nikto_command = f"nikto -h {url_or_ip} -Tuning x -Format txt"
    print(f"    Lệnh nikto sẽ chạy: {nikto_command}")
    
    # Lệnh nuclei cho Apache
    nuclei_command = f"nuclei -u {url_or_ip} -t technologies/apache/ -t vulnerabilities/apache/ -silent"
    print(f"    Lệnh nuclei sẽ chạy: {nuclei_command}")
    
    try:
        # Chạy nikto trước
        print(f"    Đang chạy nikto cho Apache tại {url_or_ip}...")
        nikto_result = subprocess.run(nikto_command, shell=True, capture_output=True, text=True)
        print("\n" + "="*60)
        print("KẾT QUẢ NIKTO (Apache):")
        print(nikto_result.stdout)
        if nikto_result.stderr:
            print("\nLỖI nikto (nếu có):")
            print(nikto_result.stderr)
        print("="*60)
        
        # Chạy nuclei sau
        print(f"    Đang chạy nuclei cho Apache tại {url_or_ip}...")
        nuclei_result = subprocess.run(nuclei_command, shell=True, capture_output=True, text=True)
        print("\n" + "="*60)
        print("KẾT QUẢ NUCLEI (Apache):")
        print(nuclei_result.stdout)
        if nuclei_result.stderr:
            print("\nLỖI nuclei (nếu có):")
            print(nuclei_result.stderr)
        print("="*60)
        
    except Exception as e:
        print(f"[!] Lỗi chạy nikto/nuclei cho Apache: {e}")

def run_nikto_nuclei_nginx(url_or_ip):
    """Chạy nikto + nuclei cho Nginx (cũ) - tự động"""
    
    # Lệnh nikto cơ bản
    nikto_command = f"nikto -h {url_or_ip} -Tuning x -Format txt"
    print(f"    Lệnh nikto sẽ chạy: {nikto_command}")
    
    # Lệnh nuclei cho Nginx
    nuclei_command = f"nuclei -u {url_or_ip} -t technologies/nginx/ -t vulnerabilities/nginx/ -silent"
    print(f"    Lệnh nuclei sẽ chạy: {nuclei_command}")
    
    try:
        # Chạy nikto trước
        print(f"    Đang chạy nikto cho Nginx tại {url_or_ip}...")
        nikto_result = subprocess.run(nikto_command, shell=True, capture_output=True, text=True)
        print("\n" + "="*60)
        print("KẾT QUẢ NIKTO (Nginx):")
        print(nikto_result.stdout)
        if nikto_result.stderr:
            print("\nLỖI nikto (nếu có):")
            print(nikto_result.stderr)
        print("="*60)
        
        # Chạy nuclei sau
        print(f"    Đang chạy nuclei cho Nginx tại {url_or_ip}...")
        nuclei_result = subprocess.run(nuclei_command, shell=True, capture_output=True, text=True)
        print("\n" + "="*60)
        print("KẾT QUẢ NUCLEI (Nginx):")
        print(nuclei_result.stdout)
        if nuclei_result.stderr:
            print("\nLỖI nuclei (nếu có):")
            print(nuclei_result.stderr)
        print("="*60)
        
    except Exception as e:
        print(f"[!] Lỗi chạy nikto/nuclei cho Nginx: {e}")       

def run_nikto_nuclei_litespeed(url_or_ip):
    """Chạy nikto + nuclei cho LiteSpeed - tự động"""
    
    # Lệnh nikto cơ bản
    nikto_command = f"nikto -h {url_or_ip} -Tuning x -Format txt"
    print(f"    Lệnh nikto sẽ chạy: {nikto_command}")
    
    # Lệnh nuclei cho LiteSpeed
    nuclei_command = f"nuclei -u {url_or_ip} -t technologies/litespeed/ -t vulnerabilities/litespeed/ -silent"
    print(f"    Lệnh nuclei sẽ chạy: {nuclei_command}")
    
    try:
        # Chạy nikto trước
        print(f"    Đang chạy nikto cho LiteSpeed tại {url_or_ip}...")
        nikto_result = subprocess.run(nikto_command, shell=True, capture_output=True, text=True)
        print("\n" + "="*60)
        print("KẾT QUẢ NIKTO (LiteSpeed):")
        print(nikto_result.stdout)
        if nikto_result.stderr:
            print("\nLỖI nikto (nếu có):")
            print(nikto_result.stderr)
        print("="*60)
        
        # Chạy nuclei sau
        print(f"    Đang chạy nuclei cho LiteSpeed tại {url_or_ip}...")
        nuclei_result = subprocess.run(nuclei_command, shell=True, capture_output=True, text=True)
        print("\n" + "="*60)
        print("KẾT QUẢ NUCLEI (LiteSpeed):")
        print(nuclei_result.stdout)
        if nuclei_result.stderr:
            print("\nLỖI nuclei (nếu có):")
            print(nuclei_result.stderr)
        print("="*60)
        
    except Exception as e:
        print(f"[!] Lỗi chạy nikto/nuclei cho LiteSpeed: {e}")

def run_nuclei_tomcat(url_or_ip):
    """Chạy nuclei cho Tomcat - tự động, dùng template Tomcat"""
    command = f"nuclei -u {url_or_ip} -t technologies/tomcat/ -t vulnerabilities/tomcat/ -silent"
    print(f"    Lệnh sẽ chạy: {command}")
    
    try:
        print(f"    Đang chạy nuclei cho Tomcat tại {url_or_ip}...")
        result = subprocess.run(command, shell=True, capture_output=True, text=True)
        print("\n" + "="*60)
        print("KẾT QUẢ NUCLEI (Tomcat):")
        print(result.stdout)
        if result.stderr:
            print("\nLỖI (nếu có):")
            print(result.stderr)
        print("="*60)
    except Exception as e:
        print(f"[!] Lỗi chạy nuclei cho Tomcat: {e}")

def run_whatwaf_cf(url_or_ip):
    """Chạy whatwaf + cf-clearance cho Cloudflare - tự động"""
    
    # Lệnh whatwaf cơ bản (detect WAF)
    whatwaf_command = f"whatwaf -u {url_or_ip}"
    print(f"    Lệnh whatwaf sẽ chạy: {whatwaf_command}")
    
    # Lệnh cf-clearance (nếu cần bypass, dùng curl với cf-clearance nếu có)
    cf_clearance_command = f"curl -v -A 'Mozilla/5.0' --resolve {url_or_ip.split('//')[1]}:443:104.21.42.236 {url_or_ip}  # Thử bypass Cloudflare"
    print(f"    Lệnh cf-clearance thử nghiệm: {cf_clearance_command}")
    
    try:
        # Chạy whatwaf trước
        print(f"    Đang chạy whatwaf cho Cloudflare tại {url_or_ip}...")
        whatwaf_result = subprocess.run(whatwaf_command, shell=True, capture_output=True, text=True)
        print("\n" + "="*60)
        print("KẾT QUẢ WHATWAF (Cloudflare):")
        print(whatwaf_result.stdout)
        if whatwaf_result.stderr:
            print("\nLỖI whatwaf (nếu có):")
            print(whatwaf_result.stderr)
        print("="*60)
        
        # Nếu whatwaf confirm Cloudflare, gợi ý thử cf-clearance (không tự chạy curl để tránh rủi ro)
        if "cloudflare" in whatwaf_result.stdout.lower():
            print("\n[+] Xác nhận Cloudflare WAF → Thử bypass bằng cf-clearance (copy lệnh trên để chạy thủ công)")
        
    except Exception as e:
        print(f"[!] Lỗi chạy whatwaf cho Cloudflare: {e}")

def run_whatwaf_akamai(url_or_ip):
    """Chạy whatwaf cho Akamai - tự động, lệnh basic"""
    command = f"whatwaf -u {url_or_ip}"
    print(f"    Lệnh sẽ chạy: {command}")
    
    try:
        print(f"    Đang chạy whatwaf cho Akamai tại {url_or_ip}...")
        result = subprocess.run(command, shell=True, capture_output=True, text=True)
        print("\n" + "="*60)
        print("KẾT QUẢ WHATWAF (Akamai):")
        print(result.stdout)
        if result.stderr:
            print("\nLỖI (nếu có):")
            print(result.stderr)
        print("="*60)
    except Exception as e:
        print(f"[!] Lỗi chạy whatwaf cho Akamai: {e}")

def run_whatwaf_sucuri(url_or_ip):
    """Chạy whatwaf cho Sucuri - tự động, lệnh basic"""
    command = f"whatwaf -u {url_or_ip}"
    print(f"    Lệnh sẽ chạy: {command}")
    
    try:
        print(f"    Đang chạy whatwaf cho Sucuri tại {url_or_ip}...")
        result = subprocess.run(command, shell=True, capture_output=True, text=True)
        print("\n" + "="*60)
        print("KẾT QUẢ WHATWAF (Sucuri):")
        print(result.stdout)
        if result.stderr:
            print("\nLỖI (nếu có):")
            print(result.stderr)
        print("="*60)
    except Exception as e:
        print(f"[!] Lỗi chạy whatwaf cho Sucuri: {e}")

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
def auto_scan_tech(tech_list, url_or_ip):
    tech_lower = [t.lower() for t in tech_list]
    
    for tech_key, run_func_name in TECH_TO_RUN_FUNCTION.items():
        if any(tech_key in t for t in tech_lower):
            print(f"\n[+] Phát hiện {tech_key.capitalize()} trên {url_or_ip}")
            # Gọi hàm tương ứng (run_wpscan, run_joomscan,...)
            globals()[run_func_name](url_or_ip)
            print("-" * 60)

# ====================== MAIN ======================
def main():
    if len(sys.argv) < 2:
        print("Usage:")
        print("  python3 tool.py /path/to/httpx.json")
        print("  python3 tool.py /path/to/nmap.xml")
        print("  python3 tool.py /path/to/httpx.json /path/to/nmap.xml")
        sys.exit(1)
    
    httpx_file = None
    nmap_file  = None
    
    for arg in sys.argv[1:]:
        if arg.lower().endswith('.json'):
            httpx_file = arg
        elif arg.lower().endswith('.xml'):
            nmap_file = arg
    
    if httpx_file is None and nmap_file is None:
        print("[!] Cần ít nhất 1 file (JSON hoặc XML)")
        sys.exit(1)
    
    # Parse và hiển thị tech
    if httpx_file:
        try:
            print("=" * 60)
            print("TECH TỪ HTTXP (JSON)")
            print("=" * 60)
            httpx_tech = parse_httpx_json(httpx_file)
            for url, techs in httpx_tech.items():
                print(f"URL: {url}")
                print(f"Tech: {', '.join(techs)}")
                auto_scan_tech(techs, url)
        except FileNotFoundError:
            print(f"[!] Không tìm thấy file httpx: {httpx_file}")
    
    if nmap_file:
        try:
            print("\n" + "=" * 60)
            print("TECH TỪ NMAP (XML)")
            print("=" * 60)
            nmap_tech = parse_nmap_xml(nmap_file)
            for ip, services in nmap_tech.items():
                print(f"IP: {ip}")
                print(f"Tech: {', '.join(services)}")
                auto_scan_tech(services, ip)
        except FileNotFoundError:
            print(f"[!] Không tìm thấy file nmap: {nmap_file}")

if __name__ == "__main__":
    main()