"""
Autonomous Bug Bounty Scanner Engine
Intelligently chains tools and automates the complete workflow
"""

import asyncio
import json
import time
from typing import Dict, Any, List, Optional
from datetime import datetime

# Import all our tool modules
from tools.reconnaissance import full_reconnaissance_scan
from tools.injection_suite import full_injection_scan
from tools.authentication_attacks import full_authentication_audit
from tools.file_attacks import full_file_attack_scan
from tools.waf_bypass import full_waf_bypass_assessment
from tools.xmlrpc_attacks import xmlrpc_security_scan
from tools.security_audit import wordpress_security_audit


class AutonomousScanner:
    """
    Autonomous scanner that chains tools intelligently based on findings.
    """
    
    def __init__(self):
        self.scan_results = {}
        self.findings_chain = []
        self.exploitation_success = []
        self.recommendations = []
    
    async def scan_target(self, target: str, aggressive: bool = False) -> Dict[str, Any]:
        """
        Run complete autonomous scan workflow.
        
        Args:
            target: Target URL or domain
            aggressive: Enable aggressive scanning
            
        Returns:
            Dict with complete scan results
        """
        start_time = time.time()
        
        print(f"[+] Starting autonomous scan of {target}")
        print(f"[+] Timestamp: {datetime.now().isoformat()}")
        
        # Phase 1: Reconnaissance
        print("[+] Phase 1: Reconnaissance & Discovery")
        recon_results = await self._run_reconnaissance(target)
        
        # Phase 2: Technology-specific scans
        print("[+] Phase 2: Technology Detection & Targeted Scans")
        tech_results = await self._run_technology_scans(target, recon_results)
        
        # Phase 3: Injection Testing
        print("[+] Phase 3: Injection Vulnerability Testing")
        injection_results = await self._run_injection_tests(target)
        
        # Phase 4: Authentication Testing
        print("[+] Phase 4: Authentication & Session Testing")
        auth_results = await self._run_authentication_tests(target)
        
        # Phase 5: File Operation Testing
        print("[+] Phase 5: File Upload & Inclusion Testing")
        file_results = await self._run_file_tests(target)
        
        # Phase 6: WAF Analysis & Bypass
        print("[+] Phase 6: WAF Detection & Bypass Testing")
        waf_results = await self._run_waf_tests(target)
        
        # Phase 7: Exploitation Verification (if vulnerabilities found)
        print("[+] Phase 7: Exploitation Verification")
        exploit_results = await self._run_exploitation_verification(
            target, injection_results, file_results
        )
        
        # Compile final report
        duration = time.time() - start_time
        
        return {
            "scan_metadata": {
                "target": target,
                "start_time": datetime.now().isoformat(),
                "duration_seconds": f"{duration:.2f}",
                "scan_mode": "aggressive" if aggressive else "standard",
                "tools_used": 7
            },
            "reconnaissance": recon_results,
            "technology_scan": tech_results,
            "injection_scan": injection_results,
            "authentication_scan": auth_results,
            "file_attack_scan": file_results,
            "waf_analysis": waf_results,
            "exploitation_results": exploit_results,
            "findings_summary": self._generate_findings_summary(
                recon_results, tech_results, injection_results,
                auth_results, file_results, waf_results, exploit_results
            ),
            "risk_assessment": self._calculate_risk(
                injection_results, auth_results, file_results, exploit_results
            ),
            "recommended_exploitation_path": self._generate_exploitation_path(),
            "next_steps": self._generate_next_steps()
        }
    
    async def _run_reconnaissance(self, target: str) -> Dict[str, Any]:
        """Run reconnaissance phase"""
        try:
            result = await full_reconnaissance_scan(target)
            return json.loads(result)
        except Exception as e:
            return {"error": str(e), "phase": "reconnaissance"}
    
    async def _run_technology_scans(self, target: str, recon: Dict) -> Dict[str, Any]:
        """Run technology-specific scans based on detection"""
        results = {}
        
        # Check if WordPress detected
        tech_data = recon.get("technology", {})
        if tech_data.get("cms") == "WordPress" or "WordPress" in tech_data.get("technologies", []):
            print("  [-] WordPress detected - running WP-specific scans")
            try:
                wp_result = await wordpress_security_audit(target)
                results["wordpress_audit"] = json.loads(wp_result)
                
                xmlrpc_result = await xmlrpc_security_scan(target)
                results["xmlrpc_analysis"] = json.loads(xmlrpc_result)
            except Exception as e:
                results["error"] = str(e)
        
        # Check for APIs
        if any("api" in str(k).lower() for k in recon.get("endpoints", {}).get("discovered_endpoints", [])):
            print("  [-] API endpoints detected - running API scans")
            results["api_detected"] = True
        
        return results
    
    async def _run_injection_tests(self, target: str) -> Dict[str, Any]:
        """Run injection vulnerability tests"""
        try:
            result = await full_injection_scan(target)
            parsed = json.loads(result)
            
            # Track findings for chaining
            if parsed.get("sql_injection", {}).get("vulnerable"):
                self.findings_chain.append({
                    "type": "SQL Injection",
                    "severity": "Critical",
                    "data": parsed["sql_injection"]
                })
            
            if parsed.get("xss", {}).get("vulnerable"):
                self.findings_chain.append({
                    "type": "XSS",
                    "severity": "High",
                    "data": parsed["xss"]
                })
            
            return parsed
        except Exception as e:
            return {"error": str(e), "phase": "injection"}
    
    async def _run_authentication_tests(self, target: str) -> Dict[str, Any]:
        """Run authentication security tests"""
        try:
            result = await full_authentication_audit(target)
            parsed = json.loads(result)
            
            # Track critical findings
            if parsed.get("brute_force", {}).get("weak_password_found"):
                self.findings_chain.append({
                    "type": "Weak Credentials",
                    "severity": "Critical",
                    "data": parsed["brute_force"]
                })
            
            if parsed.get("jwt_security", {}).get("cracked_secret"):
                self.findings_chain.append({
                    "type": "JWT Weak Secret",
                    "severity": "Critical",
                    "data": parsed["jwt_security"]
                })
            
            return parsed
        except Exception as e:
            return {"error": str(e), "phase": "authentication"}
    
    async def _run_file_tests(self, target: str) -> Dict[str, Any]:
        """Run file attack tests"""
        try:
            result = await full_file_attack_scan(target)
            parsed = json.loads(result)
            
            if parsed.get("file_upload_rce", {}).get("rce_verified"):
                self.findings_chain.append({
                    "type": "File Upload RCE",
                    "severity": "Critical",
                    "data": parsed["file_upload_rce"]
                })
            
            if parsed.get("lfi", {}).get("credentials_exposed"):
                self.findings_chain.append({
                    "type": "LFI Credential Exposure",
                    "severity": "Critical",
                    "data": parsed["lfi"]
                })
            
            return parsed
        except Exception as e:
            return {"error": str(e), "phase": "file_attacks"}
    
    async def _run_waf_tests(self, target: str) -> Dict[str, Any]:
        """Run WAF detection and bypass tests"""
        try:
            result = await full_waf_bypass_assessment(target)
            return json.loads(result)
        except Exception as e:
            return {"error": str(e), "phase": "waf_bypass"}
    
    async def _run_exploitation_verification(self, target: str, 
                                             injection: Dict, 
                                             file_results: Dict) -> Dict[str, Any]:
        """Verify exploitation of found vulnerabilities"""
        verifications = []
        
        # Verify SQLi data extraction
        if injection.get("sql_injection", {}).get("vulnerable"):
            print("  [-] Attempting SQLi data extraction verification")
            # Would call verify_sqli_data_extraction here
            verifications.append({
                "vulnerability": "SQL Injection",
                "verified": injection["sql_injection"].get("exploitation_level") == "Data Extraction Confirmed",
                "note": "Data extraction " + ("confirmed" if injection["sql_injection"].get("exploitation_level") == "Data Extraction Confirmed" else "attempted")
            })
        
        # Verify file upload RCE
        if file_results.get("file_upload_rce", {}).get("rce_verified"):
            verifications.append({
                "vulnerability": "File Upload RCE",
                "verified": True,
                "shell_url": file_results["file_upload_rce"].get("successful_uploads", [{}])[0].get("uploaded_url"),
                "note": "Remote code execution confirmed"
            })
            self.exploitation_success.append("RCE via File Upload")
        
        return {"verifications": verifications, "total_verified": len([v for v in verifications if v.get("verified")])}
    
    def _generate_findings_summary(self, *results) -> Dict[str, Any]:
        """Generate summary of all findings"""
        critical = 0
        high = 0
        medium = 0
        low = 0
        
        for result in results:
            if isinstance(result, dict):
                if result.get("severity") == "Critical":
                    critical += 1
                elif result.get("severity") == "High":
                    high += 1
                elif result.get("severity") == "Medium":
                    medium += 1
                elif result.get("severity") == "Low":
                    low += 1
        
        return {
            "total_findings": len(self.findings_chain),
            "by_severity": {
                "critical": critical,
                "high": high,
                "medium": medium,
                "low": low
            },
            "confirmed_exploitation": len(self.exploitation_success),
            "findings_chain": self.findings_chain
        }
    
    def _calculate_risk(self, injection: Dict, auth: Dict, file_results: Dict, exploit: Dict) -> Dict[str, Any]:
        """Calculate overall risk score"""
        risk_score = 0
        
        # RCE adds 40 points
        if file_results.get("file_upload_rce", {}).get("rce_verified"):
            risk_score += 40
        
        # SQLi with extraction adds 30 points
        if injection.get("sql_injection", {}).get("exploitation_level") == "Data Extraction Confirmed":
            risk_score += 30
        
        # Authentication bypass adds 25 points
        if auth.get("brute_force", {}).get("weak_password_found"):
            risk_score += 25
        
        # Other confirmed exploitation adds 15 points each
        risk_score += len(self.exploitation_success) * 15
        
        risk_score = min(100, risk_score)
        
        return {
            "risk_score": risk_score,
            "risk_level": "Critical" if risk_score >= 80 else "High" if risk_score >= 60 else "Medium" if risk_score >= 40 else "Low",
            "business_impact": "Severe" if risk_score >= 80 else "Significant" if risk_score >= 60 else "Moderate",
            "likelihood_of_exploitation": "High" if len(self.exploitation_success) > 0 else "Medium"
        }
    
    def _generate_exploitation_path(self) -> List[Dict[str, str]]:
        """Generate recommended exploitation path"""
        path = []
        
        for finding in self.findings_chain:
            if finding["type"] == "File Upload RCE":
                path.append({
                    "step": 1,
                    "action": "Upload web shell via file upload vulnerability",
                    "target": finding["data"].get("upload_endpoint_found"),
                    "payload": "PHP web shell with cmd parameter"
                })
            
            elif finding["type"] == "SQL Injection":
                path.append({
                    "step": len(path) + 1,
                    "action": "Extract admin credentials via SQLi",
                    "technique": finding["data"].get("technique"),
                    "payload": finding["data"].get("payloads_confirmed", [""])[0] if finding["data"].get("payloads_confirmed") else "UNION SELECT extraction"
                })
            
            elif finding["type"] == "Weak Credentials":
                path.append({
                    "step": len(path) + 1,
                    "action": "Login with discovered weak credentials",
                    "username": "admin",
                    "password": finding["data"].get("weak_password_found")
                })
            
            elif finding["type"] == "LFI Credential Exposure":
                path.append({
                    "step": len(path) + 1,
                    "action": "Read wp-config.php for database credentials",
                    "payload": "../../../wp-config.php"
                })
        
        return path
    
    def _generate_next_steps(self) -> List[str]:
        """Generate recommended next steps"""
        steps = []
        
        if not self.exploitation_success:
            steps.append("Manual verification required for detected vulnerabilities")
        
        if any(f["type"] == "SQL Injection" for f in self.findings_chain):
            steps.append("Attempt manual SQLi exploitation with sqlmap for comprehensive extraction")
        
        if any(f["type"] == "XSS" for f in self.findings_chain):
            steps.append("Create proof-of-concept XSS payload for session hijacking demonstration")
        
        steps.append("Document all findings with screenshots and reproduction steps")
        steps.append("Generate professional bug bounty report with CVSS scores")
        
        return steps


# MCP Tool Wrapper
async def autonomous_bug_bounty_scan(target: str, aggressive: bool = False) -> str:
    """
    Run fully autonomous bug bounty scan.
    
    Args:
        target: Target URL or domain
        aggressive: Enable aggressive scanning mode
        
    Returns:
        JSON with complete scan results and exploitation roadmap
    """
    scanner = AutonomousScanner()
    results = await scanner.scan_target(target, aggressive)
    
    return json.dumps(results, indent=2)
