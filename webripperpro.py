import requests
from bs4 import BeautifulSoup
import re
import time
from colorama import init, Fore, Back, Style
import sys
import json
from urllib.parse import urlparse
import concurrent.futures
from functools import cmp_to_key

# Initialize colorama
init(autoreset=True)

# ===== CONFIGURATION =====
USER_AGENT = "WebRipper Pro/2.0 (+https://github.com/MrpasswordTz/webripper-pro)"
TIMEOUT = 20
THREADS = 5

# Common paths for sensitive files
SENSITIVE_PATHS = [
    # Git related
    "/.git/", "/.git/config", "/.git/HEAD", "/.git/logs/HEAD", "/.git/index", "/.git/description",

    # Configuration files
    "/.env", "/config.php", "/wp-config.php", "/configuration.php", "/settings.php", "/.htaccess", "/web.config",

    # Lock files
    "/composer.lock", "/package-lock.json", "/yarn.lock",

    # Info files
    "/phpinfo.php", "/info.php", "/test.php", "/debug.php", "/server-status", "/server-info",

    # Admin panels
    "/admin/", "/wp-admin/", "/administrator/", "/cpanel/", "/webmin/",
    "/plesk/", "/manager/", "/backend/", "/admin/login.php", "/admin/index.php",

    # Upload scripts
    "/upload.php", "/uploads.php", "/uploaded.php", "/uploader.php", "/upload_file.php",
    "/fileupload.php", "/file_upload.php", "/uploadimage.php", "/uploadimg.php",
    "/imageupload.php", "/media_upload.php", "/upload_test.php", "/multi_upload.php",
    "/upload_handler.php", "/async-upload.php", "/uploadify.php", "/simple-upload.php",
    "/upload_file_form.php", "/upload_process.php", "/upload_exec.php", "/upload_backend.php",

    # Upload HTML interfaces
    "/upload.html", "/uploads.html", "/uploader.html", "/uploadform.html", "/dropzone.html",

    # Upload directories
    "/uploads/", "/uploaded/", "/media/", "/media/uploads/", "/files/", "/user_uploads/",
    "/upload_dir/", "/uploads/images/", "/uploaded_files/", "/fileuploads/",
    "/assets/uploads/", "/uploads/temp/", "/tmp/uploads/", "/tmp/files/", "/temp/uploads/",
    "/backup/uploads/", "/uploads/private/", "/content/uploads/", "/static/uploads/",
    "/data/uploads/", "/public/uploads/", "/public_html/uploads/", "/uploads_backup/",

    # Suspicious/malicious PHP files
    "/shell.php", "/cmd.php", "/backdoor.php", "/evil.php", "/execute.php", "/remote.php",
    "/rce.php", "/inject.php", "/adminer.php", "/webshell.php", "/connect.php", "/hack.php",
    "/eval.php", "/command.php", "/php-reverse-shell.php", "/exploit.php", "/bypass.php",
    "/include.php", "/config-backup.php", "/phpinfo2.php", "/whoami.php", "/test-shell.php",

    # Misc directories
    "/cgi-bin/", "/cgi-bin/test.cgi", "/cgi-bin/php.cgi", "/cgi-bin/perl.cgi",
    "/_admin/", "/panel/", "/adminarea/", "/controlpanel/", "/private/", "/restricted/"
]

# Known vulnerable versions database (expanded)
VULN_DB = {
    "PHP": {
        "5.6.40": ["CVE-2019-11043", "CVE-2019-11045"],
        "7.0.33": ["CVE-2019-11042"],
        "7.1.0": ["CVE-2018-19518"],
        "7.2.0": ["CVE-2019-9637"],
        "7.3.0": ["CVE-2019-9024"],
        "7.4.0": ["CVE-2020-7060"],
    },
    "Apache": {
        "2.4.49": ["CVE-2021-41773"],
        "2.4.50": ["CVE-2021-42013"],
    },
    "Nginx": {
        "1.20.0": ["CVE-2021-23017"],
    },
    "WordPress": {
        "5.7.2": ["CVE-2021-29447"],
    },
    "Git": {
        "all": ["Directory Listing Exposure", "Source Code Disclosure"]
    },
    "File Upload": {
        "all": ["Unrestricted File Upload", "RCE via File Upload"]
    }
}

# Enhanced CVE database with version patterns for multiple technologies
CVE_DATABASE = {
    # Web Servers
    "Apache": {
        "versions": {
            "2.4.50": ["CVE-2021-42013", "CVE-2021-41773"],
            "2.4.49": ["CVE-2021-41773"],
            "2.4.48": ["CVE-2021-40438"],
            "2.4.46": ["CVE-2021-30641", "CVE-2021-26690"],
            "2.4.43": ["CVE-2020-11984", "CVE-2020-11993"]
        },
        "pattern": r"Apache/(\d+\.\d+\.\d+)"
    },
    "Nginx": {
        "versions": {
            "1.21.0": ["CVE-2021-23017"],
            "1.19.10": ["CVE-2020-12440"],
            "1.17.7": ["CVE-2019-20372"],
            "1.16.1": ["CVE-2018-16845", "CVE-2018-16844"]
        },
        "pattern": r"nginx/(\d+\.\d+\.\d+)"
    },
    "IIS": {
        "versions": {
            "10.0": ["CVE-2021-31166", "CVE-2020-0645"],
            "8.5": ["CVE-2015-1635"]
        },
        "pattern": r"Microsoft-IIS/(\d+\.\d+)"
    },

    # Databases
    "MySQL": {
        "versions": {
            "8.0.25": ["CVE-2021-2144"],
            "5.7.34": ["CVE-2021-2156"],
            "5.6.51": ["CVE-2021-2154"],
            "5.5.62": ["CVE-2019-2503"]
        },
        "pattern": r"MySQL[ -](\d+\.\d+\.\d+)"
    },
    "PostgreSQL": {
        "versions": {
            "13.3": ["CVE-2021-32027"],
            "12.7": ["CVE-2021-32028"],
            "11.12": ["CVE-2021-32029"],
            "10.17": ["CVE-2021-32030"]
        },
        "pattern": r"PostgreSQL (\d+\.\d+\.\d+)"
    },
    "MongoDB": {
        "versions": {
            "4.4.6": ["CVE-2021-20330"],
            "4.2.12": ["CVE-2021-20329"],
            "4.0.23": ["CVE-2021-20328"]
        },
        "pattern": r"MongoDB (\d+\.\d+\.\d+)"
    },

    # Programming Languages
    "PHP": {
        "versions": {
            "7.4.21": ["CVE-2021-21703"],
            "7.3.28": ["CVE-2021-21702"],
            "7.2.34": ["CVE-2020-7069"],
            "5.6.40": ["CVE-2019-11043"]
        },
        "pattern": r"PHP/(\d+\.\d+\.\d+)"
    },
    "Node.js": {
        "versions": {
            "14.17.0": ["CVE-2021-22931"],
            "12.22.1": ["CVE-2021-22930"],
            "10.24.1": ["CVE-2021-22918"]
        },
        "pattern": r"Node\.js/(\d+\.\d+\.\d+)"
    },

    # CMS
    "WordPress": {
        "versions": {
            "5.8": ["CVE-2021-29447"],
            "5.7": ["CVE-2021-29445"],
            "5.6": ["CVE-2021-29442"],
            "5.5": ["CVE-2020-28032"]
        },
        "pattern": r"WordPress (\d+\.\d+(?:\.\d+)?)"
    },
    "Joomla": {
        "versions": {
            "3.9.27": ["CVE-2021-23132"],
            "3.8.13": ["CVE-2020-10225"],
            "3.7.0": ["CVE-2017-8917"]
        },
        "pattern": r"Joomla! (\d+\.\d+\.\d+)"
    },
    "Drupal": {
        "versions": {
            "9.2": ["CVE-2021-29403"],
            "8.9": ["CVE-2020-13671"],
            "7.69": ["CVE-2019-6340"]
        },
        "pattern": r"Drupal (\d+\.\d+(?:\.\d+)?)"
    },

    # Frameworks
    "Laravel": {
        "versions": {
            "8.0": ["CVE-2021-3129"],
            "7.0": ["CVE-2020-28188"],
            "6.0": ["CVE-2019-9081"]
        },
        "pattern": r"Laravel.*?(\d+\.\d+(?:\.\d+)?)"
    },
    "Django": {
        "versions": {
            "3.2": ["CVE-2021-33203"],
            "3.1": ["CVE-2021-33571"],
            "2.2": ["CVE-2021-23336"]
        },
        "pattern": r"Django/(\d+\.\d+(?:\.\d+)?)"
    },

    # Operating Systems
    "Linux": {
        "versions": {
            "5.11": ["CVE-2021-3490"],
            "5.10": ["CVE-2021-3347"],
            "5.4": ["CVE-2021-22555"]
        },
        "pattern": r"Linux (\d+\.\d+)"
    },
    "Windows": {
        "versions": {
            "10": ["CVE-2021-34527"],
            "8.1": ["CVE-2021-31166"],
            "7": ["CVE-2020-0601"]
        },
        "pattern": r"Windows NT (\d+\.\d+)"
    }
}

# Signature databases from second script
CMS_SIGNATURES = {
    "WordPress": ["wp-content", "wp-includes", "wp-login"],
    "Joomla": ["index.php?option=", "Joomla!"],
    "Drupal": ["sites/all", "misc/drupal.js"],
    "Magento": ["skin/frontend", "Mage.Cookies"]
}

FRAMEWORK_SIGNATURES = {
    "Laravel": ["X-Powered-By: Laravel", "laravel_session"],
    "Django": ["csrftoken", "sessionid"],
    "Express.js": ["X-Powered-By: Express"],
    "Ruby on Rails": ["_rails_session"]
}

VERSION_SIGNATURES = {
    "Apache": ["Apache/2", "Apache/"],
    "Nginx": ["nginx/"],
    "PHP": ["X-Powered-By: PHP"],
    "ASP.NET": ["X-Powered-By: ASP.NET"]
}

# API Endpoints to check
API_ENDPOINTS = [
    "/api/v1/", "/api/v2/", "/graphql", "/rest/", 
    "/swagger/", "/openapi/", "/oauth/", "/auth/",
    "/v1/", "/v2/", "/v3/", "/json/", "/xmlrpc/"
]

# Sensitive keywords to check for disclosure
SENSITIVE_KEYWORDS = [
    "password", "secret", "api_key", "database", 
    "credentials", "token", "aws_key", "ssh_key",
    "private_key", "admin_pass", "connection_string"
]

# Version patterns for technology extraction
VERSION_PATTERNS = {
    "PHP": r"PHP/(\d+\.\d+\.\d+)",
    "WordPress": r"WordPress (\d+\.\d+\.\d+)",
    "Joomla": r"Joomla! (\d+\.\d+\.\d+)",
    "Drupal": r"Drupal (\d+\.\d+)",
    "Laravel": r"laravel/(\d+\.\d+\.\d+)",
    "Apache": r"Apache/(\d+\.\d+\.\d+)",
    "Nginx": r"nginx/(\d+\.\d+\.\d+)"
}

# ===== UTILITY FUNCTIONS =====
def print_banner():
    banner = f"""
{Fore.CYAN}     
▄▄▌ ▐ ▄▌▄▄▄ .▄▄▄▄· ▄▄▄  ▪   ▄▄▄· ▄▄▄·▄▄▄ .▄▄▄  
██· █▌▐█▀▄.▀·▐█ ▀█▪▀▄ █·██ ▐█ ▄█▐█ ▄█▀▄.▀·▀▄ █·
██▪▐█▐▐▌▐▀▀▪▄▐█▀▀█▄▐▀▀▄ ▐█· ██▀· ██▀·▐▀▀▪▄▐▀▀▄ 
▐█▌██▐█▌▐█▄▄▌██▄▪▐█▐█•█▌▐█▌▐█▪·•▐█▪·•▐█▄▄▌▐█•█▌
 ▀▀▀▀ ▀▪ ▀▀▀ ·▀▀▀▀ .▀  ▀▀▀▀.▀   .▀    ▀▀▀ .▀  ▀
{Fore.YELLOW}
Web Vulnerability Scanner v3.0
  
{Fore.GREEN}              
Github By: MrpasswordTz
{Fore.RESET}
"""
    print(banner)

def check_vulnerabilities(software, version):
    """Check if version has known vulnerabilities"""
    if software in VULN_DB:
        # Check exact version matches first
        if version in VULN_DB[software]:
            return VULN_DB[software][version]
        
        # Check version patterns
        for vuln_version, cves in VULN_DB[software].items():
            if version.startswith(vuln_version):
                return cves
                
        # Check for "all" vulnerabilities
        if "all" in VULN_DB[software]:
            return VULN_DB[software]["all"]
    return None

def pretty_print(title, value, status="info"):
    """Print formatted output with colors"""
    colors = {
        "info": Fore.CYAN,
        "success": Fore.GREEN,
        "warning": Fore.YELLOW,
        "danger": Fore.RED,
        "highlight": Fore.MAGENTA
    }
    print(f"{colors.get(status, Fore.CYAN)}[•] {title.ljust(25)}: {Fore.RESET}{value}")

def detect_waf(headers):
    waf_signatures = {
        "cloudflare": "Cloudflare",
        "sucuri": "Sucuri WAF",
        "akamai": "Akamai",
        "aws": "AWS WAF",
        "barracuda": "Barracuda WAF",
        "imperva": "Imperva SecureSphere",
        "fortinet": "FortiWeb",
        "f5": "F5 BIG-IP"
    }
    for key, waf in waf_signatures.items():
        for h, v in headers.items():
            if key in v.lower():
                return waf
    return None

def extract_versions(response_text, headers):
    """Extract software versions from response"""
    versions = {}
    headers_str = str(headers).lower()
    response_text_lower = response_text.lower()
    
    for tech, pattern in VERSION_PATTERNS.items():
        # Check in headers first
        match = re.search(pattern, headers_str, re.IGNORECASE)
        if not match:
            # Check in response body if not found in headers
            match = re.search(pattern, response_text_lower, re.IGNORECASE)
        if match:
            versions[tech] = match.group(1)
    
    return versions

def check_info_disclosure(response_text):
    """Check for sensitive information in response"""
    disclosures = []
    text_lower = response_text.lower()
    
    for keyword in SENSITIVE_KEYWORDS:
        if keyword.lower() in text_lower:
            start_pos = text_lower.find(keyword.lower())
            context = response_text[max(0, start_pos-50):start_pos+50]
            disclosures.append({
                "keyword": keyword,
                "context": context.strip()
            })
    
    return disclosures

def scan_api_endpoints(target):
    """Scan for common API endpoints"""
    found_endpoints = []
    for endpoint in API_ENDPOINTS:
        full_url = target.rstrip("/") + endpoint
        try:
            res = requests.get(full_url, timeout=5, headers={"User-Agent": USER_AGENT})
            if res.status_code in [200, 403, 401]:
                content_type = res.headers.get('Content-Type', '')
                if 'json' in content_type or 'api' in content_type.lower():
                    found_endpoints.append({
                        "url": full_url,
                        "status": res.status_code,
                        "type": "API Endpoint"
                    })
                    pretty_print("API Found", f"{full_url} (Status: {res.status_code})", "success")
            sys.stdout.write(f"\r[Progress] Scanning API endpoints... {len(found_endpoints)} found")
            sys.stdout.flush()
        except Exception as e:
            pretty_print("Error", f"Failed to scan {full_url}: {str(e)}", "warning")
            continue
    return found_endpoints

def compare_versions(v1, v2):
    """Compare two version strings"""
    def normalize(v):
        return [int(x) for x in re.sub(r'(\.0+)*$', '', v).split(".")]
    
    v1_parts = normalize(v1)
    v2_parts = normalize(v2)
    
    for i in range(max(len(v1_parts), len(v2_parts))):
        v1_part = v1_parts[i] if i < len(v1_parts) else 0
        v2_part = v2_parts[i] if i < len(v2_parts) else 0
        if v1_part < v2_part:
            return -1
        elif v1_part > v2_part:
            return 1
    return 0

def enhanced_detect_cves(tech_info):
    """Enhanced CVE detection with version comparison"""
    vulnerabilities = []
    
    for tech_name, tech_data in tech_info.items():
        if tech_name in CVE_DATABASE:
            # Extract version from tech info
            version_match = re.search(CVE_DATABASE[tech_name]["pattern"], str(tech_data), re.IGNORECASE)
            if not version_match:
                continue
                
            current_version = version_match.group(1)
            pretty_print("Version", f"Found {tech_name} version: {current_version}", "info")
            
            # Compare against vulnerable versions
            for vuln_version, cves in CVE_DATABASE[tech_name]["versions"].items():
                if compare_versions(current_version, vuln_version) < 0:
                    for cve in cves:
                        vulnerabilities.append({
                            "cve": cve,
                            "tech": tech_name,
                            "vulnerable_version": vuln_version,
                            "detected_version": current_version
                        })
                        pretty_print("VULN", f"{cve} - {tech_name} {current_version} < {vuln_version}", "danger")
    
    return vulnerabilities

def generate_report(target, technologies, found_paths, vulnerabilities, api_endpoints, phpinfo_results):
    report = {
        "target": target,
        "scan_date": time.strftime("%Y-%m-%d %H:%M:%S"),
        "technologies": technologies,
        "found_paths": [{"path": p[0], "status": p[1], "size": p[2]} for p in found_paths],
        "vulnerabilities": vulnerabilities,
        "api_endpoints": api_endpoints,
        "phpinfo": phpinfo_results
    }
    
    filename = f"scan_report_{urlparse(target).netloc}_{int(time.time())}.json"
    with open(filename, "w") as f:
        json.dump(report, f, indent=4)
    return filename

def validate_url(url):
    try:
        result = urlparse(url)
        return all([result.scheme, result.netloc])
    except:
        return False

def check_path(target, path):
    full_url = target.rstrip("/") + path
    try:
        res = requests.get(full_url, timeout=5, headers={'User-Agent': USER_AGENT}, allow_redirects=False)
        if res.status_code in [200, 403, 401, 302]:
            return (path, res.status_code, len(res.content))
    except Exception as e:
        pretty_print("Error", f"Failed to check {full_url}: {str(e)}", "warning")
    return None

def scan_directories(target, wordlist=None, max_workers=20):
    if wordlist is None:
        wordlist = SENSITIVE_PATHS
    
    found = []
    start_time = time.time()
    total_paths = len(wordlist)
    
    with concurrent.futures.ThreadPoolExecutor(max_workers=max_workers) as executor:
        future_to_path = {executor.submit(check_path, target, path): path for path in wordlist}
        
        for i, future in enumerate(concurrent.futures.as_completed(future_to_path)):
            path = future_to_path[future]
            try:
                result = future.result()
                if result:
                    found.append(result)
                    status_color = "danger" if result[1] == 200 else "warning"
                    pretty_print("Found", f"{result[0]} (Status: {result[1]}, Size: {result[2]})", status_color)
                
                # Progress update
                sys.stdout.write(f"\r[Progress] {i+1}/{total_paths} paths scanned, {len(found)} found")
                sys.stdout.flush()
            except Exception as e:
                pretty_print("Error", f"Failed to check {path}: {e}", "warning")
    
    elapsed = time.time() - start_time
    print(f"\n{Fore.CYAN}[Stats] Scanned {total_paths} paths in {elapsed:.2f} seconds ({total_paths/elapsed:.2f} req/sec){Fore.RESET}")
    return found

# ===== SCANNING FUNCTIONS =====
def scan_sensitive_files(target):
    """Scan for sensitive files and directories"""
    found_items = []
    
    for path in SENSITIVE_PATHS:
        url = target.rstrip('/') + path
        try:
            response = requests.get(url, headers={"User-Agent": USER_AGENT}, timeout=TIMEOUT, allow_redirects=False)
            
            if response.status_code == 200:
                status = f"{Fore.GREEN}FOUND{Fore.RESET}"
                
                # Special handling for .git directory
                if ".git/" in path:
                    if "directory listing denied" not in response.text.lower():
                        found_items.append((".git Exposure", url, "critical"))
                
                # Check for file upload
                elif "upload" in path.lower():
                    found_items.append(("File Upload", url, "warning"))
                
                # Check for admin panels
                elif "admin" in path.lower() or "cpanel" in path.lower():
                    found_items.append(("Admin Panel", url, "high"))
                
                else:
                    found_items.append(("Sensitive File", url, "medium"))
                    
            elif response.status_code == 403:
                status = f"{Fore.YELLOW}FORBIDDEN{Fore.RESET}"
            elif response.status_code == 404:
                status = f"{Fore.LIGHTBLACK_EX}NOT FOUND{Fore.RESET}"
            else:
                status = f"{Fore.LIGHTBLACK_EX}CODE {response.status_code}{Fore.RESET}"
                
            print(f"{Fore.LIGHTBLACK_EX}├── {path.ljust(25)}: {status}{Fore.RESET}")
            time.sleep(0.2)  # Rate limiting
            
        except Exception as e:
            print(f"{Fore.LIGHTBLACK_EX}├── {path.ljust(25)}: {Fore.RED}ERROR{Fore.RESET}")
    
    return found_items

def detect_technologies(target):
    """Detect technologies used on the website"""
    tech_found = {}
    
    try:
        response = requests.get(target, headers={"User-Agent": USER_AGENT}, timeout=TIMEOUT)
        content = response.text.lower()
        headers = response.headers
        
        # Check for PHP
        if "x-powered-by" in headers and "php" in headers["x-powered-by"].lower():
            php_version = re.search(r"php/?([0-9.]+)", headers["x-powered-by"], re.I)
            if php_version:
                tech_found["PHP"] = php_version.group(1)
        
        # CMS Detection from second script
        for cms, sigs in CMS_SIGNATURES.items():
            for sig in sigs:
                if sig.lower() in content:
                    tech_found["CMS"] = cms
                    break
        
        # Framework Detection from second script
        for fw, sigs in FRAMEWORK_SIGNATURES.items():
            for sig in sigs:
                if sig.lower() in content or sig.lower() in str(headers).lower():
                    tech_found["Framework"] = fw
                    break
        
        # Check for web servers
        if "server" in headers:
            if "apache" in headers["server"].lower():
                tech_found["Web Server"] = "Apache"
            elif "nginx" in headers["server"].lower():
                tech_found["Web Server"] = "Nginx"
            elif "iis" in headers["server"].lower():
                tech_found["Web Server"] = "IIS"
        
        # Check for databases
        if "mysql" in content or "mysqli_connect" in content:
            tech_found["Database"] = "MySQL"
        elif "postgresql" in content:
            tech_found["Database"] = "PostgreSQL"
        elif "mongodb" in content:
            tech_found["Database"] = "MongoDB"
            
        # Check for frontend frameworks
        if "jquery" in content:
            tech_found["JavaScript"] = "jQuery"
        if "react" in content:
            tech_found["JavaScript"] = "React"
        elif "angular" in content:
            tech_found["JavaScript"] = "Angular"
            
        # Check for PHP frameworks
        if "laravel" in content:
            tech_found["PHP Framework"] = "Laravel"
        elif "symfony" in content:
            tech_found["PHP Framework"] = "Symfony"
        elif "codeigniter" in content:
            tech_found["PHP Framework"] = "CodeIgniter"
            
        # Check for CDNs
        if "bootstrap" in content:
            tech_found["CSS Framework"] = "Bootstrap"
        if "fontawesome" in content:
            tech_found["Icons"] = "FontAwesome"
            
        # WAF Detection from second script
        waf = detect_waf(headers)
        if waf:
            tech_found["WAF"] = waf
            
        # Version detection from second script
        versions = extract_versions(response.text, headers)
        if versions:
            tech_found["versions"] = versions
            
        # Sensitive info check from second script
        disclosures = check_info_disclosure(response.text)
        if disclosures:
            tech_found["disclosures"] = disclosures
            
    except Exception as e:
        pretty_print("Detection Error", str(e), "danger")
        
    return tech_found

def scan_phpinfo(url):
    """Scan phpinfo page for detailed information"""
    try:
        response = requests.get(url, headers={"User-Agent": USER_AGENT}, timeout=TIMEOUT)
        response.raise_for_status()

        if "phpinfo()" not in response.text.lower():
            return None

        soup = BeautifulSoup(response.text, 'html.parser')
        results = {
            'php_version': 'Not Found',
            'system': 'Not Found',
            'server': 'Not Found',
            'architecture': 'Not Found',
            'modules': [],
            'additional': {}
        }

        # PHP Version
        php_version = soup.find('h1', string=re.compile('PHP Version'))
        if php_version:
            results['php_version'] = php_version.get_text().split('>')[-1].strip()

        # System Info
        system_row = soup.find('td', string='System')
        if system_row:
            results['system'] = system_row.find_next_sibling('td').get_text(strip=True)

        # Server Info
        server_row = soup.find('td', string='Server API')
        if server_row:
            results['server'] = server_row.find_next_sibling('td').get_text(strip=True)

        # Architecture
        arch_row = soup.find('td', string='Architecture')
        if arch_row:
            results['architecture'] = arch_row.find_next_sibling('td').get_text(strip=True)

        # Additional interesting info
        additional_fields = [
            'Loaded Configuration File', 'PHP Extension Build',
            'Server Software', 'System', 'HTTP Headers Information'
        ]
        
        for field in additional_fields:
            row = soup.find('td', string=field)
            if row:
                results['additional'][field] = row.find_next_sibling('td').get_text(strip=True)

        # Modules (first 15)
        modules = []
        for row in soup.find_all('td', string=re.compile('^[a-zA-Z]')):
            if row.find_next_sibling('td'):
                modules.append(row.get_text(strip=True))
        results['modules'] = modules[:15]

        return results

    except Exception as e:
        pretty_print("Scan Error", str(e), "danger")
        return None

# ===== MAIN FUNCTION =====
def main():
    print_banner()
    
    while True:
        try:
            target = input(f"{Fore.YELLOW}[?] Enter Target URL (or 'exit' to quit): {Fore.RESET}").strip()
            
            if target.lower() == 'exit':
                print(f"{Fore.GREEN}[+] Goodbye!{Fore.RESET}")
                break
                
            if not target.startswith(('http://', 'https://')):
                target = f"http://{target}"

            if not validate_url(target):
                pretty_print("Error", "Invalid URL format", "danger")
                continue

            print(f"\n{Fore.BLUE}=== Starting WebInspect Scan ==={Fore.RESET}")
            
            # Phase 1: Technology Detection
            print(f"\n{Fore.MAGENTA}=== Technology Detection ==={Fore.RESET}")
            technologies = detect_technologies(target)
            
            if technologies:
                for tech, version in technologies.items():
                    if tech == "versions":
                        for name, ver in version.items():
                            vulns = check_vulnerabilities(name, str(ver))
                            status = "danger" if vulns else "success"
                            pretty_print(name, ver, status)
                            if vulns:
                                pretty_print("→ Vulnerabilities", ", ".join(vulns), "danger")
                    elif tech not in ["disclosures", "WAF"]:
                        vulns = check_vulnerabilities(tech, str(version))
                        status = "danger" if vulns else "success"
                        pretty_print(tech, version, status)
                        if vulns:
                            pretty_print("→ Vulnerabilities", ", ".join(vulns), "danger")
                
                if "disclosures" in technologies:
                    pretty_print("Warning", "Potential sensitive information found!", "danger")
                    for item in technologies["disclosures"]:
                        pretty_print(f"  {item['keyword']}", item['context'], "warning")
                
                if "WAF" in technologies:
                    pretty_print("WAF Detected", technologies["WAF"], "warning")
            else:
                pretty_print("No technologies detected", "Using basic scan", "warning")
            
            # Phase 2: Sensitive File Scanning
            print(f"\n{Fore.MAGENTA}=== Sensitive File Scan ==={Fore.RESET}")
            found_vulns = scan_sensitive_files(target)
            
            if found_vulns:
                print(f"\n{Fore.RED}=== Found Vulnerable Items ==={Fore.RESET}")
                for vuln in found_vulns:
                    pretty_print(vuln[0], vuln[1], vuln[2])
            else:
                pretty_print("No sensitive files found", "Basic checks passed", "success")
            
            # Phase 3: Directory Scanning (from second script)
            print(f"\n{Fore.MAGENTA}=== Directory Scanning ==={Fore.RESET}")
            found_paths = scan_directories(target)
            
            # Phase 4: API Endpoints Scanning (from second script)
            print(f"\n{Fore.MAGENTA}=== API Endpoints Scan ==={Fore.RESET}")
            api_endpoints = scan_api_endpoints(target)
            if not api_endpoints:
                pretty_print("Info", "No API endpoints detected", "info")
            
            # Phase 5: PHP Info Scan
            phpinfo_url = target.rstrip('/') + '/info.php'
            print(f"\n{Fore.MAGENTA}=== PHP Info Scan ==={Fore.RESET}")
            phpinfo_results = scan_phpinfo(phpinfo_url)
            
            if phpinfo_results:
                print(f"\n{Fore.GREEN}=== PHP Information ==={Fore.RESET}")
                pretty_print("PHP Version", phpinfo_results['php_version'], "success")
                
                vulns = check_vulnerabilities("PHP", phpinfo_results['php_version'])
                if vulns:
                    pretty_print("Vulnerabilities", ", ".join(vulns), "danger")
                
                pretty_print("System", phpinfo_results['system'])
                pretty_print("Server", phpinfo_results['server'])
                pretty_print("Architecture", phpinfo_results['architecture'])
                
                print(f"\n{Fore.CYAN}=== Loaded Modules ==={Fore.RESET}")
                print(", ".join(phpinfo_results['modules']))
            else:
                pretty_print("No phpinfo found", "Skipping PHP details", "info")

            # Phase 6: Enhanced Vulnerability Detection (from second script)
            print(f"\n{Fore.MAGENTA}=== Vulnerability Analysis ==={Fore.RESET}")
            vulnerabilities = enhanced_detect_cves(technologies)
            
            if not vulnerabilities:
                pretty_print("Info", "No known CVEs detected", "info")
            
            # Generate Report
            report_file = generate_report(target, technologies, found_paths, vulnerabilities, api_endpoints, phpinfo_results)
            pretty_print("Report", f"Scan report saved to {report_file}", "success")

            print(f"\n{Fore.BLUE}=== Scan Complete ==={Fore.RESET}\n")
            
        except KeyboardInterrupt:
            print(f"\n{Fore.RED}[!] Scan interrupted by user{Fore.RESET}")
            break
        except Exception as e:
            pretty_print("Error", str(e), "danger")

if __name__ == "__main__":
    main()
