"""
Security Headers & Configuration Analyzer for WordPress
Analyzes HTTP security headers, SSL/TLS configuration, and WordPress hardening
"""

import asyncio
import json
import ssl
import socket
from typing import Dict, Any, List
from urllib.parse import urlparse
import httpx


SECURITY_HEADERS = {
    'Strict-Transport-Security': {
        'required': True,
        'description': 'Forces HTTPS connections',
        'recommendation': 'max-age=31536000; includeSubDomains'
    },
    'Content-Security-Policy': {
        'required': True,
        'description': 'Prevents XSS and injection attacks',
        'recommendation': "default-src 'self'; script-src 'self' 'unsafe-inline'"
    },
    'X-Frame-Options': {
        'required': True,
        'description': 'Prevents clickjacking',
        'recommendation': 'DENY or SAMEORIGIN'
    },
    'X-Content-Type-Options': {
        'required': True,
        'description': 'Prevents MIME sniffing',
        'recommendation': 'nosniff'
    },
    'Referrer-Policy': {
        'required': True,
        'description': 'Controls referrer information',
        'recommendation': 'strict-origin-when-cross-origin'
    },
    'Permissions-Policy': {
        'required': False,
        'description': 'Controls browser features',
        'recommendation': 'geolocation=(), microphone=(), camera=()'
    },
    'X-XSS-Protection': {
        'required': False,
        'description': 'Legacy XSS protection (deprecated)',
        'recommendation': '0 (disabled, use CSP instead)'
    }
}


def check_csp_strength(csp_value: str) -> Dict[str, Any]:
    """Analyze Content Security Policy strength"""
    issues = []
    score = 100
    
    dangerous_directives = [
        "unsafe-inline",
        "unsafe-eval",
        "*",
        "data:",
        "blob:",
        "javascript:",
    ]
    
    for directive in dangerous_directives:
        if directive in csp_value.lower():
            issues.append(f"CSP contains dangerous directive: {directive}")
            score -= 20
    
    # Check for frame-ancestors (clickjacking protection)
    if "frame-ancestors" not in csp_value.lower():
        issues.append("Missing frame-ancestors directive (clickjacking risk)")
        score -= 15
    
    return {
        "score": max(0, score),
        "issues": issues,
        "strength": "Strong" if score >= 80 else "Moderate" if score >= 50 else "Weak"
    }


async def security_headers_scanner(target: str) -> Dict[str, Any]:
    """
    Scan HTTP security headers for WordPress target.
    
    Args:
        target: Target URL
        
    Returns:
        Dict with header analysis findings
    """
    base = target if target.startswith(('http://', 'https://')) else f"https://{target}"
    if not base.endswith('/'):
        base += '/'
    
    findings = {
        "missing_headers": [],
        "misconfigured_headers": [],
        "good_headers": [],
        "score": 100,
        "severity": "None"
    }
    
    try:
        async with httpx.AsyncClient() as client:
            resp = await client.get(base, follow_redirects=True, timeout=15.0)
            headers = {k.lower(): v for k, v in resp.headers.items()}
            
            for header, config in SECURITY_HEADERS.items():
                header_lower = header.lower()
                
                if header_lower not in headers:
                    if config['required']:
                        findings["missing_headers"].append({
                            "header": header,
                            "description": config['description'],
                            "recommendation": config['recommendation']
                        })
                        findings["score"] -= 10
                else:
                    value = headers[header_lower]
                    
                    # Special CSP analysis
                    if header == 'Content-Security-Policy':
                        csp_analysis = check_csp_strength(value)
                        if csp_analysis["score"] < 80:
                            findings["misconfigured_headers"].append({
                                "header": header,
                                "value": value,
                                "issues": csp_analysis["issues"],
                                "strength": csp_analysis["strength"]
                            })
                            findings["score"] -= (100 - csp_analysis["score"]) / 10
                    
                    # X-Frame-Options check
                    elif header == 'X-Frame-Options':
                        if value.upper() not in ['DENY', 'SAMEORIGIN']:
                            findings["misconfigured_headers"].append({
                                "header": header,
                                "value": value,
                                "issue": "Invalid value for X-Frame-Options"
                            })
                            findings["score"] -= 10
                    
                    findings["good_headers"].append({
                        "header": header,
                        "value": value
                    })
            
            # Server header information disclosure
            if 'server' in headers:
                server = headers['server']
                if any(x in server.lower() for x in ['apache', 'nginx', 'iis', 'litespeed']):
                    findings["information_disclosure"] = {
                        "header": "Server",
                        "value": server,
                        "risk": "Low",
                        "note": "Server version exposed - consider removing"
                    }
                    findings["score"] -= 5
            
            # X-Powered-By check
            if 'x-powered-by' in headers:
                findings["information_disclosure"] = findings.get("information_disclosure", {})
                findings["information_disclosure"]["x_powered_by"] = headers['x-powered-by']
                findings["score"] -= 5
            
            # Calculate severity
            score = max(0, int(findings["score"]))
            if score < 50:
                findings["severity"] = "High"
            elif score < 70:
                findings["severity"] = "Medium"
            elif score < 90:
                findings["severity"] = "Low"
            else:
                findings["severity"] = "None"
            
            findings["score"] = score
            findings["total_headers_analyzed"] = len(SECURITY_HEADERS)
            
            return findings
            
    except Exception as e:
        return {
            "error": str(e),
            "note": "Security headers scan failed"
        }


async def wordpress_hardening_check(target: str) -> Dict[str, Any]:
    """
    Check WordPress-specific hardening configurations.
    
    Args:
        target: Target URL
        
    Returns:
        Dict with hardening status
    """
    base = target if target.startswith(('http://', 'https://')) else f"https://{target}"
    if not base.endswith('/'):
        base += '/'
    
    checks = {
        "file_edit_disabled": {"tested": False, "passed": False, "severity": "High"},
        "debug_mode_disabled": {"tested": False, "passed": False, "severity": "Medium"},
        "backup_files_exposed": {"tested": False, "passed": True, "severity": "Critical"},
        "wp_config_protected": {"tested": False, "passed": False, "severity": "Critical"},
        "xmlrpc_accessible": {"tested": False, "passed": True, "severity": "High"},
        "rest_api_user_enum": {"tested": False, "passed": True, "severity": "Medium"},
        "login_page_exposed": {"tested": False, "passed": True, "severity": "Low"},
    }
    
    exposed_files = []
    
    try:
        async with httpx.AsyncClient() as client:
            # Check wp-config.php protection
            try:
                resp = await client.get(f"{base}wp-config.php", timeout=10.0)
                checks["wp_config_protected"]["tested"] = True
                # Should return 403 or 404, not 200 with content
                if resp.status_code == 200 and len(resp.text) > 0:
                    if "DB_HOST" in resp.text or "DB_PASSWORD" in resp.text:
                        checks["wp_config_protected"]["passed"] = False
                        exposed_files.append("wp-config.php")
                    else:
                        checks["wp_config_protected"]["passed"] = True
                else:
                    checks["wp_config_protected"]["passed"] = True
            except:
                checks["wp_config_protected"]["tested"] = True
                checks["wp_config_protected"]["passed"] = True
            
            # Check for backup files
            backup_patterns = [
                ("wp-config.php.bak", "Config Backup"),
                ("wp-config.php.old", "Old Config"),
                ("wp-config.php~", "Backup with tilde"),
                ("wp-config.php.save", "Saved Config"),
                ("wp-config.php.swp", "Vim Swap"),
                (".env", "Environment File"),
                (".env.backup", "Env Backup"),
                ("backup.zip", "Full Backup"),
                ("backup.sql", "Database Backup"),
                ("database.sql", "Database Dump"),
                ("dump.sql", "Database Dump"),
                ("wordpress.sql", "WordPress Dump"),
                ("wp-content/backup", "Content Backup"),
                ("wp-content/uploads/backup", "Uploads Backup"),
            ]
            
            for file_path, description in backup_patterns:
                try:
                    resp = await client.get(f"{base}{file_path}", timeout=5.0)
                    if resp.status_code == 200:
                        file_info = {
                            "file": file_path,
                            "type": description,
                            "size": len(resp.content)
                        }
                        # Check if it's actually a backup file
                        content_start = resp.text[:500].lower()
                        if any(x in content_start for x in ['db_host', 'db_password', 'wordpress', 'wp_', '--', 'create table']):
                            exposed_files.append(file_info)
                except:
                    pass
            
            if exposed_files:
                checks["backup_files_exposed"]["tested"] = True
                checks["backup_files_exposed"]["passed"] = False
                checks["backup_files_exposed"]["files_found"] = exposed_files
            else:
                checks["backup_files_exposed"]["tested"] = True
            
            # Check debug.log
            try:
                resp = await client.get(f"{base}wp-content/debug.log", timeout=5.0)
                checks["debug_mode_disabled"]["tested"] = True
                if resp.status_code == 200 and len(resp.text) > 0:
                    checks["debug_mode_disabled"]["passed"] = False
                    checks["debug_mode_disabled"]["log_size"] = len(resp.content)
                else:
                    checks["debug_mode_disabled"]["passed"] = True
            except:
                checks["debug_mode_disabled"]["tested"] = True
                checks["debug_mode_disabled"]["passed"] = True
            
            # Check XML-RPC
            try:
                resp = await client.get(f"{base}xmlrpc.php", timeout=5.0)
                checks["xmlrpc_accessible"]["tested"] = True
                if resp.status_code == 200 and ('xmlrpc' in resp.text.lower() or 'accepting' in resp.text.lower()):
                    checks["xmlrpc_accessible"]["passed"] = False
                else:
                    checks["xmlrpc_accessible"]["passed"] = True
            except:
                checks["xmlrpc_accessible"]["tested"] = True
                checks["xmlrpc_accessible"]["passed"] = True
            
            # Check REST API user enumeration
            try:
                resp = await client.get(f"{base}wp-json/wp/v2/users", timeout=5.0)
                checks["rest_api_user_enum"]["tested"] = True
                if resp.status_code == 200:
                    try:
                        users = resp.json()
                        if len(users) > 0:
                            checks["rest_api_user_enum"]["passed"] = False
                            checks["rest_api_user_enum"]["users_exposed"] = len(users)
                    except:
                        checks["rest_api_user_enum"]["passed"] = True
                else:
                    checks["rest_api_user_enum"]["passed"] = True
            except:
                checks["rest_api_user_enum"]["tested"] = True
                checks["rest_api_user_enum"]["passed"] = True
    
    except Exception as e:
        return {
            "error": str(e),
            "checks": checks
        }
    
    # Calculate hardening score
    tested_checks = [c for c in checks.values() if c["tested"]]
    passed_checks = [c for c in tested_checks if c["passed"]]
    
    total_score = int((len(passed_checks) / len(tested_checks)) * 100) if tested_checks else 0
    
    # Count critical issues
    critical_issues = sum(1 for c in checks.values() if c["tested"] and not c["passed"] and c["severity"] == "Critical")
    high_issues = sum(1 for c in checks.values() if c["tested"] and not c["passed"] and c["severity"] == "High")
    
    return {
        "hardening_score": total_score,
        "severity": "Critical" if critical_issues > 0 else "High" if high_issues > 0 else "Medium" if total_score < 70 else "Low",
        "checks": checks,
        "summary": {
            "total_checks": len(tested_checks),
            "passed": len(passed_checks),
            "failed": len(tested_checks) - len(passed_checks),
            "critical_issues": critical_issues,
            "high_issues": high_issues
        },
        "recommendations": [
            f"{'✓' if checks.get('wp_config_protected', {}).get('passed') else '✗'} Protect wp-config.php" if checks.get('wp_config_protected', {}).get('tested') else "○ Test wp-config.php protection",
            f"{'✓' if checks.get('backup_files_exposed', {}).get('passed') else '✗'} Remove exposed backup files" if checks.get('backup_files_exposed', {}).get('tested') else "○ Check for backup files",
            f"{'✓' if checks.get('debug_mode_disabled', {}).get('passed') else '✗'} Disable debug mode" if checks.get('debug_mode_disabled', {}).get('tested') else "○ Check debug mode",
            f"{'✓' if checks.get('xmlrpc_accessible', {}).get('passed') else '✗'} Disable XML-RPC if not needed" if checks.get('xmlrpc_accessible', {}).get('tested') else "○ Check XML-RPC",
        ]
    }


async def ssl_tls_security_scan(target: str) -> Dict[str, Any]:
    """
    Basic SSL/TLS security scan.
    
    Args:
        target: Target URL
        
    Returns:
        Dict with SSL/TLS findings
    """
    parsed = urlparse(target if target.startswith(('http://', 'https://')) else f"https://{target}")
    hostname = parsed.netloc or parsed.path
    
    findings = {
        "hostname": hostname,
        "ssl_issues": [],
        "recommendations": []
    }
    
    try:
        context = ssl.create_default_context()
        
        with socket.create_connection((hostname, 443), timeout=10) as sock:
            with context.wrap_socket(sock, server_hostname=hostname) as ssock:
                cert = ssock.getpeercert()
                version = ssock.version()
                cipher = ssock.cipher()
                
                findings["ssl_version"] = version
                findings["cipher"] = cipher[0] if cipher else "Unknown"
                
                # Check for old TLS versions
                if version in ['TLSv1', 'TLSv1.1']:
                    findings["ssl_issues"].append(f"Outdated TLS version: {version}")
                    findings["severity"] = "High"
                
                # Check certificate expiration
                if cert and 'notAfter' in cert:
                    findings["cert_expiry"] = cert['notAfter']
                
                if not findings["ssl_issues"]:
                    findings["severity"] = "None"
                    
    except Exception as e:
        findings["error"] = str(e)
        findings["note"] = "SSL/TLS scan failed - site may not support HTTPS"
    
    return findings


# MCP Tool Wrappers
async def wordpress_security_audit(target: str) -> str:
    """
    Complete WordPress security audit covering headers, hardening, and SSL.
    
    Args:
        target: Target URL
        
    Returns:
        JSON string with complete audit results
    """
    results = await asyncio.gather(
        security_headers_scanner(target),
        wordpress_hardening_check(target),
        ssl_tls_security_scan(target)
    )
    
    combined_score = int((results[0].get("score", 0) + results[1].get("hardening_score", 0)) / 2)
    
    return json.dumps({
        "scan_type": "WordPress Security Audit",
        "target": target,
        "security_headers": results[0],
        "hardening": results[1],
        "ssl_tls": results[2],
        "overall_security_score": combined_score,
        "executive_summary": {
            "header_score": results[0].get("score", 0),
            "hardening_score": results[1].get("hardening_score", 0),
            "ssl_status": results[2].get("ssl_version", "Unknown"),
            "critical_findings": sum(1 for r in results if r.get("severity") == "Critical"),
            "high_findings": sum(1 for r in results if r.get("severity") == "High")
        }
    }, indent=2)
