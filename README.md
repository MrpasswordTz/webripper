# Webripper Pro

**Webripper Pro** is a comprehensive, professional-grade web vulnerability scanner that automates the detection of security flaws in websites. It is designed for penetration testers, bug bounty hunters, and security professionals seeking fast, actionable insights into the security posture of web applications.

![Webripper Pro Banner](https://github.com/MrpasswordTz/webripper-pro/blob/main/main/banner.png) <!-- (Optional: add a banner image) -->

---

## Features

- **Technology Detection**  
  Automatically identifies backend technologies, CMS (WordPress, Joomla, Drupal, Magento), frameworks (Laravel, Django, Express, Rails), web servers (Apache, Nginx, IIS), and databases (MySQL, PostgreSQL, MongoDB).
- **Sensitive File & Directory Scanning**  
  Scans for `.git`, config files, admin panels, upload scripts, backup files, and dangerous PHP shells.
- **Directory Bruteforcing**  
  Discovers hidden and sensitive directories using a comprehensive wordlist.
- **API Endpoint Discovery**  
  Detects REST, GraphQL, and other common API endpoints and documentation (Swagger, OpenAPI, etc.).
- **CVE Checks**  
  Flags outdated software components and versions with known vulnerabilities using an embedded CVE database.
- **PHP Info Analysis**  
  Extracts detailed server and PHP environment information if `phpinfo()` is exposed.
- **WAF Detection**  
  Identifies popular Web Application Firewalls (Cloudflare, Sucuri, Akamai, AWS, Barracuda, Imperva, Fortinet, F5).
- **Sensitive Information Disclosure Detection**  
  Searches for keywords like passwords, API keys, tokens, and other secrets exposed in responses.
- **Comprehensive Report Generation**  
  Outputs a JSON report containing all findings for further analysis.

---

## Installation

1. **Clone the repository**
    ```bash
    git clone https://github.com/MrpasswordTz/webripper-pro.git
    cd webripper-pro
    ```

2. **Install dependencies**
    ```bash
    pip install -r requirements.txt
    ```

---

## Usage

Run the tool and follow the interactive prompts:

```bash
python webripperpro.py
```

- Enter the target URL when prompted (e.g., `https://example.com`).
- The tool will automatically:
    - Detect technologies
    - Scan for sensitive files and directories
    - Brute-force common directories
    - Discover API endpoints
    - Analyze PHP info pages
    - Detect known vulnerabilities (CVEs)
    - Generate a JSON report with all findings

**Sample Output:**
```
[?] Enter Target URL (or 'exit' to quit): https://example.com

=== Starting Webripper Pro Scan ===
...
[•] PHP               : 7.2.0
[•] → Vulnerabilities : CVE-2019-9637
[•] Admin Panel       : https://example.com/admin/
...
[•] Report            : Scan report saved to scan_report_example.com_1699036716.json
```

---

## Example JSON Report

```json
{
  "target": "https://example.com",
  "scan_date": "2025-07-04 21:56:12",
  "technologies": {
    "PHP": "7.2.0",
    "CMS": "WordPress",
    "Web Server": "Apache",
    "versions": {
      "PHP": "7.2.0",
      "Apache": "2.4.50"
    },
    "disclosures": [
      {
        "keyword": "password",
        "context": "...password=secret123..."
      }
    ]
  },
  "found_paths": [
    {
      "path": "/.git/config",
      "status": 200,
      "size": 217
    }
  ],
  "vulnerabilities": [
    {
      "cve": "CVE-2019-9637",
      "tech": "PHP",
      "vulnerable_version": "7.2.0",
      "detected_version": "7.2.0"
    }
  ],
  "api_endpoints": [
    {
      "url": "https://example.com/api/v1/",
      "status": 200,
      "type": "API Endpoint"
    }
  ],
  "phpinfo": {
    "php_version": "7.2.0",
    "system": "Linux server 5.11",
    "server": "Apache 2.4.50",
    "architecture": "x86_64",
    "modules": ["curl", "mbstring", "..."],
    "additional": {
      "Loaded Configuration File": "/etc/php/7.2/apache2/php.ini"
    }
  }
}
```

---

## Why "Webripper Pro"?

- **Professional-grade:** Delivers advanced scanning and actionable results.
- **Industry-standard:** Name and user-agent string (`Webripper Pro/2.0`) align with professional security tools.
- **Open-source:** Use, customize, and contribute to make it even better!

---

## Contributing

- Issues, feature requests, and pull requests are welcome!
- Please open an [issue](https://github.com/your-username/webripper-pro/issues) or submit a [pull request](https://github.com/MrpasswordTz/webripper-pro/pulls).

---

## License

[MIT License](LICENSE)  
Copyright © 2025 MrpasswordTz

---

**Happy Hunting!**  
*Developed by [MrpasswordTz](https://github.com/MrpasswordTz)*

---

Let me know if you want badges, extra sections (FAQ, troubleshooting, advanced usage), or anything more specialized!
