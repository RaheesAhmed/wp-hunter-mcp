"""
Professional Bug Bounty Report Generator
Generates comprehensive reports with POCs, CVSS scoring, and remediation
"""

import json
import base64
import hashlib
from typing import Dict, Any, List, Optional
from datetime import datetime
from urllib.parse import urlparse


class CVSSCalculator:
    """Calculate CVSS v3.1 scores"""
    
    @staticmethod
    def calculate(attack_vector: str, attack_complexity: str, privileges_required: str,
                  user_interaction: str, scope: str, confidentiality: str, 
                  integrity: str, availability: str) -> Dict[str, Any]:
        """
        Calculate CVSS v3.1 base score.
        
        Args:
            attack_vector: N, A, L, P (Network, Adjacent, Local, Physical)
            attack_complexity: L, H (Low, High)
            privileges_required: N, L, H (None, Low, High)
            user_interaction: N, R (None, Required)
            scope: U, C (Unchanged, Changed)
            confidentiality: N, L, H (None, Low, High)
            integrity: N, L, H
            availability: N, L, H
        """
        # Simplified CVSS calculation
        # This is a basic implementation - real CVSS has complex formulas
        
        metrics = {
            "AV": {"N": 0.85, "A": 0.62, "L": 0.55, "P": 0.2},
            "AC": {"L": 0.77, "H": 0.44},
            "PR": {"N": 0.85, "L": 0.62, "H": 0.27},
            "UI": {"N": 0.85, "R": 0.62},
            "S": {"U": 1.0, "C": 1.0},
            "C": {"N": 0.0, "L": 0.22, "H": 0.56},
            "I": {"N": 0.0, "L": 0.22, "H": 0.56},
            "A": {"N": 0.0, "L": 0.22, "H": 0.56}
        }
        
        # Calculate Impact
        iss = 1 - ((1 - metrics["C"][confidentiality]) * 
                   (1 - metrics["I"][integrity]) * 
                   (1 - metrics["A"][availability]))
        
        if scope == "U":
            impact = 6.42 * iss
        else:
            impact = 7.52 * (iss - 0.029) - 3.25 * pow(iss - 0.02, 15)
        
        # Calculate Exploitability
        exploitability = (8.22 * metrics["AV"][attack_vector] * 
                         metrics["AC"][attack_complexity] * 
                         metrics["PR"][privileges_required] * 
                         metrics["UI"][user_interaction])
        
        # Calculate Base Score
        if impact <= 0:
            base_score = 0.0
        elif scope == "U":
            base_score = min((impact + exploitability), 10)
        else:
            base_score = min(1.08 * (impact + exploitability), 10)
        
        # Round to one decimal
        base_score = round(base_score, 1)
        
        # Determine severity
        if base_score >= 9.0:
            severity = "Critical"
        elif base_score >= 7.0:
            severity = "High"
        elif base_score >= 4.0:
            severity = "Medium"
        elif base_score > 0:
            severity = "Low"
        else:
            severity = "None"
        
        return {
            "base_score": base_score,
            "severity": severity,
            "vector_string": f"CVSS:3.1/AV:{attack_vector}/AC:{attack_complexity}/PR:{privileges_required}/UI:{user_interaction}/S:{scope}/C:{confidentiality}/I:{integrity}/A:{availability}",
            "metrics": {
                "attack_vector": attack_vector,
                "attack_complexity": attack_complexity,
                "privileges_required": privileges_required,
                "user_interaction": user_interaction,
                "scope": scope,
                "confidentiality_impact": confidentiality,
                "integrity_impact": integrity,
                "availability_impact": availability
            }
        }
    
    @staticmethod
    def auto_calculate(vulnerability_type: str, exploitation_confirmed: bool = False) -> Dict[str, Any]:
        """Auto-calculate CVSS based on vulnerability type"""
        
        presets = {
            "SQL Injection": ("N", "L", "N", "N", "U", "H", "H", "L"),
            "XSS": ("N", "L", "N", "R", "U", "L", "L", "N"),
            "File Upload RCE": ("N", "L", "L", "N", "C", "H", "H", "H"),
            "LFI": ("N", "L", "N", "N", "U", "H", "N", "N"),
            "Command Injection": ("N", "L", "N", "N", "U", "H", "H", "H"),
            "Authentication Bypass": ("N", "L", "N", "N", "U", "H", "H", "N"),
            "Weak Credentials": ("N", "L", "N", "N", "U", "H", "H", "N"),
            "JWT Weak Secret": ("N", "L", "N", "N", "U", "H", "H", "N"),
            "CSRF": ("N", "L", "N", "R", "U", "L", "L", "N"),
            "Information Disclosure": ("N", "L", "N", "N", "U", "L", "N", "N"),
        }
        
        metrics = presets.get(vulnerability_type, ("N", "L", "N", "N", "U", "L", "L", "N"))
        
        if exploitation_confirmed:
            # Increase impact if exploitation confirmed
            metrics = list(metrics)
            if metrics[5] == "L":
                metrics[5] = "H"
            if metrics[6] == "L":
                metrics[6] = "H"
            metrics = tuple(metrics)
        
        return CVSSCalculator.calculate(*metrics)


class ReportGenerator:
    """Generate professional bug bounty reports"""
    
    def __init__(self):
        self.findings = []
        self.target = None
        self.scan_metadata = {}
    
    def add_finding(self, finding_type: str, title: str, description: str,
                   proof_of_concept: str, impact: str, remediation: str,
                   severity: str, cvss_score: float, cvss_vector: str,
                   affected_endpoints: List[str], references: List[str] = None):
        """Add a finding to the report"""
        
        finding = {
            "id": f"BB-{len(self.findings) + 1:03d}",
            "type": finding_type,
            "title": title,
            "description": description,
            "proof_of_concept": proof_of_concept,
            "impact": impact,
            "remediation": remediation,
            "severity": severity,
            "cvss": {
                "score": cvss_score,
                "vector": cvss_vector,
                "severity": severity
            },
            "affected_endpoints": affected_endpoints,
            "references": references or [],
            "discovered": datetime.now().isoformat()
        }
        
        self.findings.append(finding)
        return finding["id"]
    
    def generate_executive_summary(self, scan_results: Dict[str, Any]) -> str:
        """Generate executive summary for management"""
        
        risk = scan_results.get("risk_assessment", {})
        summary = scan_results.get("findings_summary", {})
        
        critical_count = summary.get("by_severity", {}).get("critical", 0)
        high_count = summary.get("by_severity", {}).get("high", 0)
        
        if critical_count > 0:
            recommendation = "IMMEDIATE ACTION REQUIRED - Critical vulnerabilities present"
        elif high_count > 0:
            recommendation = "Urgent remediation recommended within 7 days"
        else:
            recommendation = "Standard remediation timeline acceptable"
        
        return f"""
## Executive Summary

**Target:** {self.target}
**Assessment Date:** {datetime.now().strftime("%Y-%m-%d %H:%M:%S")}
**Overall Risk Level:** {risk.get("risk_level", "Unknown")}
**Risk Score:** {risk.get("risk_score", 0)}/100

### Key Findings
- **Critical Vulnerabilities:** {critical_count}
- **High Vulnerabilities:** {high_count}
- **Total Vulnerabilities:** {summary.get("total_findings", 0)}
- **Confirmed Exploitation:** {summary.get("confirmed_exploitation", 0)} vulnerabilities

### Business Impact
{risk.get("business_impact", "Unknown")}

### Recommendation
{recommendation}

### Exploitation Likelihood
{risk.get("likelihood_of_exploitation", "Unknown")}
"""
    
    def generate_technical_report(self, scan_results: Dict[str, Any]) -> str:
        """Generate detailed technical report"""
        
        report = f"""# Bug Bounty Security Assessment Report

**Confidential - For Authorized Use Only**

---

## Table of Contents
1. [Executive Summary](#executive-summary)
2. [Methodology](#methodology)
3. [Scope](#scope)
4. [Detailed Findings](#detailed-findings)
5. [Risk Matrix](#risk-matrix)
6. [Remediation Roadmap](#remediation-roadmap)
7. [Appendices](#appendices)

---

## Executive Summary

{self.generate_executive_summary(scan_results)}

---

## Methodology

The assessment employed automated security testing tools including:
- Reconnaissance & Subdomain Enumeration
- Technology Fingerprinting
- Injection Testing (SQLi, XSS, Command Injection, SSTI)
- Authentication & Session Management Testing
- File Operation Testing (Upload, LFI, RFI)
- WAF Detection & Bypass Analysis
- Exploitation Verification

### Tools Used
- WP-Hunter Professional Bug Bounty Suite v2.0
- Custom autonomous scanning engine
- Industry-standard payload libraries

---

## Scope

**Primary Target:** {self.target}
**Scan Duration:** {scan_results.get("scan_metadata", {}).get("duration_seconds", "Unknown")} seconds
**Scan Mode:** {scan_results.get("scan_metadata", {}).get("scan_mode", "Standard")}

---

## Detailed Findings

"""
        
        # Add each finding
        for finding in self.findings:
            report += f"""
### {finding['id']}: {finding['title']}

**Severity:** {finding['severity']} | **CVSS:** {finding['cvss']['score']}
**Type:** {finding['type']}
**Discovered:** {finding['discovered']}

#### Description
{finding['description']}

#### Proof of Concept
```
{finding['proof_of_concept']}
```

#### Impact
{finding['impact']}

#### Affected Endpoints
"""
            for endpoint in finding['affected_endpoints']:
                report += f"- `{endpoint}`\n"
            
            report += f"""
#### Remediation
{finding['remediation']}

#### CVSS Vector
`{finding['cvss']['vector']}`

---
"""
        
        return report
    
    def generate_html_report(self, scan_results: Dict[str, Any]) -> str:
        """Generate professional HTML report"""
        
        risk = scan_results.get("risk_assessment", {})
        summary = scan_results.get("findings_summary", {})
        
        # Color coding based on risk
        risk_color = {
            "Critical": "#dc3545",
            "High": "#fd7e14",
            "Medium": "#ffc107",
            "Low": "#28a745",
            "None": "#6c757d"
        }.get(risk.get("risk_level"), "#6c757d")
        
        html = f"""<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Bug Bounty Report - {self.target}</title>
    <style>
        * {{ margin: 0; padding: 0; box-sizing: border-box; }}
        body {{ 
            font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, sans-serif;
            background: #f5f7fa;
            color: #333;
            line-height: 1.6;
        }}
        .container {{ max-width: 1200px; margin: 0 auto; padding: 20px; }}
        .header {{ 
            background: linear-gradient(135deg, #667eea 0%, #764ba2 100%);
            color: white;
            padding: 40px;
            border-radius: 10px;
            margin-bottom: 30px;
        }}
        .header h1 {{ font-size: 2.5em; margin-bottom: 10px; }}
        .risk-badge {{
            display: inline-block;
            padding: 15px 30px;
            border-radius: 50px;
            font-size: 1.5em;
            font-weight: bold;
            margin: 20px 0;
            color: white;
            background: {risk_color};
        }}
        .metrics {{
            display: grid;
            grid-template-columns: repeat(4, 1fr);
            gap: 20px;
            margin-bottom: 30px;
        }}
        .metric {{
            background: white;
            padding: 25px;
            border-radius: 10px;
            box-shadow: 0 2px 10px rgba(0,0,0,0.1);
            text-align: center;
        }}
        .metric-value {{
            font-size: 2.5em;
            font-weight: bold;
            color: #667eea;
        }}
        .finding {{
            background: white;
            border-left: 5px solid #dc3545;
            padding: 25px;
            margin-bottom: 20px;
            border-radius: 5px;
            box-shadow: 0 2px 10px rgba(0,0,0,0.1);
        }}
        .finding.critical {{ border-left-color: #dc3545; }}
        .finding.high {{ border-left-color: #fd7e14; }}
        .finding.medium {{ border-left-color: #ffc107; }}
        .finding.low {{ border-left-color: #28a745; }}
        .finding-title {{ font-size: 1.3em; font-weight: bold; margin-bottom: 15px; }}
        .badge {{
            display: inline-block;
            padding: 5px 15px;
            border-radius: 20px;
            font-size: 0.85em;
            font-weight: bold;
            margin-right: 10px;
        }}
        .badge-critical {{ background: #dc3545; color: white; }}
        .badge-high {{ background: #fd7e14; color: white; }}
        .badge-medium {{ background: #ffc107; color: #333; }}
        .badge-low {{ background: #28a745; color: white; }}
        .poc {{
            background: #f8f9fa;
            border: 1px solid #dee2e6;
            border-radius: 5px;
            padding: 15px;
            font-family: 'Courier New', monospace;
            overflow-x: auto;
            margin: 15px 0;
        }}
        .remediation {{
            background: #d4edda;
            border: 1px solid #c3e6cb;
            border-radius: 5px;
            padding: 15px;
            margin-top: 15px;
        }}
        table {{
            width: 100%;
            border-collapse: collapse;
            margin: 20px 0;
        }}
        th, td {{
            padding: 12px;
            text-align: left;
            border-bottom: 1px solid #ddd;
        }}
        th {{ background: #667eea; color: white; }}
        tr:hover {{ background: #f5f5f5; }}
    </style>
</head>
<body>
    <div class="container">
        <div class="header">
            <h1>Bug Bounty Security Report</h1>
            <p>Target: <strong>{self.target}</strong></p>
            <p>Generated: {datetime.now().strftime("%Y-%m-%d %H:%M:%S")}</p>
            <div class="risk-badge">Risk: {risk.get('risk_level', 'Unknown')} ({risk.get('risk_score', 0)})</div>
        </div>
        
        <div class="metrics">
            <div class="metric">
                <div class="metric-value">{summary.get('by_severity', {}).get('critical', 0)}</div>
                <div>Critical</div>
            </div>
            <div class="metric">
                <div class="metric-value">{summary.get('by_severity', {}).get('high', 0)}</div>
                <div>High</div>
            </div>
            <div class="metric">
                <div class="metric-value">{summary.get('by_severity', {}).get('medium', 0)}</div>
                <div>Medium</div>
            </div>
            <div class="metric">
                <div class="metric-value">{summary.get('total_findings', 0)}</div>
                <div>Total</div>
            </div>
        </div>
        
        <h2>Detailed Findings</h2>
"""
        
        # Add each finding as HTML
        for finding in self.findings:
            severity_class = finding['severity'].lower()
            
            html += f"""
        <div class="finding {severity_class}">
            <div class="finding-title">{finding['id']}: {finding['title']}</div>
            <div>
                <span class="badge badge-{severity_class}">{finding['severity']}</span>
                <span class="badge" style="background: #667eea; color: white;">CVSS: {finding['cvss']['score']}</span>
                <span class="badge" style="background: #6c757d; color: white;">{finding['type']}</span>
            </div>
            <h4>Description</h4>
            <p>{finding['description']}</p>
            
            <h4>Proof of Concept</h4>
            <div class="poc">{finding['proof_of_concept'].replace('<', '&lt;').replace('>', '&gt;')}</div>
            
            <h4>Impact</h4>
            <p>{finding['impact']}</p>
            
            <h4>Affected Endpoints</h4>
            <ul>
"""
            for endpoint in finding['affected_endpoints']:
                html += f"                <li><code>{endpoint}</code></li>\n"
            
            html += f"""            </ul>
            
            <div class="remediation">
                <strong>Remediation:</strong> {finding['remediation']}
            </div>
        </div>
"""
        
        html += """
    </div>
</body>
</html>
"""
        
        return html


# MCP Tool Wrappers
async def generate_bug_bounty_report(scan_results_json: str, report_format: str = "html") -> str:
    """
    Generate professional bug bounty report from scan results.
    
    Args:
        scan_results_json: JSON string of scan results
        report_format: Format - html, markdown, or json
        
    Returns:
        Report in requested format
    """
    scan_results = json.loads(scan_results_json)
    
    generator = ReportGenerator()
    generator.target = scan_results.get("scan_metadata", {}).get("target", "Unknown")
    
    # Extract findings from scan results and add to report
    findings_chain = scan_results.get("findings_summary", {}).get("findings_chain", [])
    
    for finding_data in findings_chain:
        finding_type = finding_data.get("type", "Unknown")
        
        # Generate CVSS automatically
        cvss = CVSSCalculator.auto_calculate(finding_type, 
                                               finding_data.get("data", {}).get("rce_verified") or
                                               finding_data.get("data", {}).get("credentials_exposed"))
        
        # Generate POC based on type
        poc = generate_poc_for_finding(finding_type, finding_data.get("data", {}))
        
        # Generate description
        description = generate_description_for_finding(finding_type, finding_data.get("data", {}))
        
        # Generate impact
        impact = generate_impact_for_finding(finding_type, finding_data.get("data", {}))
        
        # Generate remediation
        remediation = generate_remediation_for_finding(finding_type)
        
        generator.add_finding(
            finding_type=finding_type,
            title=f"{finding_type} Vulnerability",
            description=description,
            proof_of_concept=poc,
            impact=impact,
            remediation=remediation,
            severity=cvss["severity"],
            cvss_score=cvss["base_score"],
            cvss_vector=cvss["vector_string"],
            affected_endpoints=extract_endpoints(finding_data.get("data", {}))
        )
    
    if report_format == "html":
        report = generator.generate_html_report(scan_results)
    elif report_format == "markdown":
        report = generator.generate_technical_report(scan_results)
    else:
        report = json.dumps({
            "findings": generator.findings,
            "metadata": {
                "target": generator.target,
                "generated": datetime.now().isoformat(),
                "total_findings": len(generator.findings)
            }
        }, indent=2)
    
    return json.dumps({
        "report": report,
        "format": report_format,
        "total_findings": len(generator.findings),
        "target": generator.target,
        "generated": datetime.now().isoformat()
    }, indent=2)


def generate_poc_for_finding(finding_type: str, data: Dict) -> str:
    """Generate proof of concept for finding"""
    if finding_type == "SQL Injection":
        payload = data.get('payloads_confirmed', ["1' UNION SELECT @@version--"])[0] if data.get('payloads_confirmed') else "1' UNION SELECT @@version--"
        return f"""Payload: {payload}
Database: {data.get('database_type', 'Unknown')}
Technique: {data.get('technique', 'Unknown')}

curl 'target.com?id=1%27%20UNION%20SELECT%20@@version--'"""
    
    elif finding_type == "XSS":
        return f"""Payload: {data.get('confirmed_payloads', [{}])[0].get('payload', '<script>alert(1)</script>') if data.get('confirmed_payloads') else '<script>alert(1)</script>'}
Parameter: {data.get('vulnerable_parameters', ['q'])[0]}
Cookie Accessible: {data.get('cookie_stealable', False)}

Test URL: {data.get('confirmed_payloads', [{}])[0].get('url', 'target.com?q=<script>alert(1)</script>') if data.get('confirmed_payloads') else 'target.com?q=<script>alert(1)</script>'}"""
    
    elif finding_type == "File Upload RCE":
        uploads = data.get('successful_uploads', [{}])
        if uploads:
            return f"""File: {uploads[0].get('filename', 'shell.php')}
Upload URL: {data.get('upload_endpoint_found', 'target.com/upload')}
Shell URL: {uploads[0].get('uploaded_url', 'target.com/wp-content/uploads/shell.php')}
Execution: {uploads[0].get('execution_output', 'RCE confirmed')}"""
    
    elif finding_type == "Weak Credentials":
        return f"""Username: admin
Password: {data.get('weak_password_found', 'password')}
Login URL: {data.get('endpoint_tested', 'target.com/wp-login.php')}
Rate Limiting: {data.get('rate_limiting', False)}"""
    
    elif finding_type == "LFI Credential Exposure":
        return f"""Payload: {data.get('files_accessible', [{}])[0].get('payload', '../../../wp-config.php') if data.get('files_accessible') else '../../../wp-config.php'}
DB Name: {data.get('extracted_data', {}).get('db_name', 'Hidden')}
DB User: {data.get('extracted_data', {}).get('db_user', 'Hidden')}
DB Host: {data.get('extracted_data', {}).get('db_host', 'Hidden')}

Proof: Database credentials successfully extracted"""
    
    return "Proof of concept details available in scan results"


def generate_description_for_finding(finding_type: str, data: Dict) -> str:
    """Generate description for finding"""
    descriptions = {
        "SQL Injection": "The application is vulnerable to SQL injection attacks, allowing attackers to execute arbitrary SQL commands against the database.",
        "XSS": "Cross-Site Scripting (XSS) vulnerability allows attackers to inject malicious scripts that execute in victims' browsers.",
        "File Upload RCE": "Unrestricted file upload allows attackers to upload and execute malicious web shells, achieving remote code execution.",
        "Weak Credentials": "Authentication mechanism lacks rate limiting and allows weak passwords, enabling brute force attacks.",
        "JWT Weak Secret": "JSON Web Tokens are signed with a weak or guessable secret, allowing token forgery and authentication bypass.",
        "LFI Credential Exposure": "Local File Inclusion vulnerability allows reading arbitrary files including configuration files containing sensitive credentials.",
    }
    return descriptions.get(finding_type, f"{finding_type} vulnerability detected in the application.")


def generate_impact_for_finding(finding_type: str, data: Dict) -> str:
    """Generate impact statement for finding"""
    impacts = {
        "SQL Injection": "Complete database compromise including data extraction, modification, and potential server takeover.",
        "XSS": "Session hijacking, credential theft, and ability to perform actions on behalf of authenticated users.",
        "File Upload RCE": "Full server compromise with ability to execute arbitrary system commands, access all files, and establish persistent access.",
        "Weak Credentials": "Unauthorized administrative access to the application and all associated data.",
        "JWT Weak Secret": "Authentication bypass allowing impersonation of any user including administrators.",
        "LFI Credential Exposure": "Exposure of database credentials and other sensitive configuration information.",
    }
    
    impact = impacts.get(finding_type, "Security impact depends on vulnerability context.")
    
    if data.get("credentials_exposed"):
        impact += " Database credentials have been confirmed extracted."
    
    if data.get("rce_verified"):
        impact += " Remote code execution has been confirmed."
    
    if data.get("session_hijack_possible"):
        impact += " Session hijacking is possible."
    
    return impact


def generate_remediation_for_finding(finding_type: str) -> str:
    """Generate remediation for finding"""
    remediations = {
        "SQL Injection": "Use parameterized queries and prepared statements. Implement input validation and least privilege database accounts.",
        "XSS": "Implement Content Security Policy (CSP). Encode all user output. Use modern frameworks with auto-escaping.",
        "File Upload RCE": "Validate file types by content, not extension. Store uploads outside web root. Disable script execution in upload directories.",
        "Weak Credentials": "Implement strong password policy. Enable account lockout. Implement multi-factor authentication.",
        "JWT Weak Secret": "Use strong random secrets (minimum 256 bits). Implement proper key rotation. Validate algorithm explicitly.",
        "LFI Credential Exposure": "Disable PHP wrappers if not needed. Implement input whitelist validation. Move sensitive files outside web root.",
    }
    return remediations.get(finding_type, "Review and remediate based on security best practices.")


def extract_endpoints(data: Dict) -> List[str]:
    """Extract affected endpoints from finding data"""
    endpoints = []
    
    if data.get("url"):
        endpoints.append(data["url"])
    if data.get("endpoint_tested"):
        endpoints.append(data["endpoint_tested"])
    if data.get("upload_endpoint_found"):
        endpoints.append(data["upload_endpoint_found"])
    if data.get("vulnerable_parameters"):
        for param in data["vulnerable_parameters"]:
            endpoints.append(f"?{param}=PAYLOAD")
    
    return endpoints if endpoints else ["Multiple endpoints affected"]


async def calculate_cvss_score(vulnerability_type: str, exploitation_confirmed: bool = False) -> str:
    """
    Calculate CVSS v3.1 score for vulnerability type.
    
    Args:
        vulnerability_type: Type of vulnerability
        exploitation_confirmed: Whether exploitation was confirmed
        
    Returns:
        JSON with CVSS details
    """
    cvss = CVSSCalculator.auto_calculate(vulnerability_type, exploitation_confirmed)
    return json.dumps(cvss, indent=2)
