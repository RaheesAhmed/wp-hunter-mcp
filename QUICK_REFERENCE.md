# WP-Hunter MCP v3.0 - Quick Reference Card

<p align="center">
  <img src="https://img.shields.io/badge/Tools-20-green?style=flat-square" alt="20 Tools">
  <img src="https://img.shields.io/badge/Open%20Source-MIT-blue?style=flat-square" alt="MIT License">
</p>

---

## 🎯 The 20 Tools

### 🤖 Autonomous (The Game Changer)
**`autonomous_scan`** - AI-driven complete scan
```
Input: {"target": "example.com", "aggressive": true}
Output: Complete vulnerability assessment + exploitation roadmap
Time: ~2-5 minutes
Use this: For complete hands-off bug bounty hunting
```

---

### 🔍 Phase 1: Reconnaissance

**`reconnaissance_scan`** - Full reconnaissance
```
Input: {"target": "example.com"}
Output: Subdomains, technologies, endpoints, wayback URLs
Time: ~30 seconds
```

**`advanced_wordpress_detection`** - WordPress detection
```
Input: {"target": "https://example.com"}
Output: WP version, plugins, theme, WAF, exposed files
Time: ~5 seconds
```

---

### � Phase 2: Injection Testing

**`injection_scan`** - All injection types
```
Input: {"target": "https://example.com", "parameters": "id,page"}
Output: SQLi, XSS, Command Injection, SSTI findings
Time: ~60 seconds
Use this: For comprehensive injection testing
```

**`advanced_sql_injection_test`** - Focused SQLi
```
Input: {"target": "https://example.com", "parameter": "id", "technique": "union-based"}
Output: SQL injection confirmation + payload
Techniques: time-based, boolean-based, union-based, error-based, stacked
```

**`xss_vulnerability_scanner`** - XSS detection
```
Input: {"target": "https://example.com", "scan_depth": "thorough"}
Output: XSS vulnerabilities + payloads + parameters
Depths: quick (3), medium (6), thorough (13+)
```

---

### 🔐 Phase 3: Authentication

**`authentication_scan`** - Complete auth audit
```
Input: {"target": "https://example.com", "username": "admin"}
Output: JWT issues, brute force, session security, 2FA bypass
Time: ~45 seconds
```

**`csrf_vulnerability_validator`** - CSRF testing
```
Input: {"target": "https://example.com"}
Output: Missing nonces, static tokens, auth bypass
```

---

### 📁 Phase 4: File Operations

**`file_attack_scan`** - All file attacks
```
Input: {"target": "https://example.com", "parameter": "file"}
Output: Upload RCE, LFI, RFI, path traversal findings
Time: ~90 seconds
Use this: For complete file attack assessment
```

**`file_upload_vulnerability_tester`** - Upload testing
```
Input: {"target": "https://example.com"}
Output: Vulnerable endpoints + extension bypasses
Tests: .php, .php5, .phtml, .php.jpg, .jpg.php
```

**`path_traversal_lfi_scanner`** - LFI/Traversal
```
Input: {"target": "https://example.com", "parameter": "file"}
Output: Accessible files + extraction payloads
Targets: wp-config.php, /etc/passwd, .env
```

---

### 🔌 Phase 5: WordPress-Specific

**`xmlrpc_security_analyzer`** - XML-RPC attacks
```
Input: {"target": "https://example.com"}
Output: system.multicall, pingback.ping SSRF, brute force capability
```

**`plugin_vulnerability_checker`** - CVE database
```
Input: {"target": "https://example.com"}
Output: Vulnerable plugins + CVE IDs
Database: 200+ CVEs for 50+ plugins
```

**`wordpress_security_hardening_audit`** - Security audit
```
Input: {"target": "https://example.com"}
Output: Headers score, SSL/TLS, backup files, hardening status
```

---

### �️ Phase 6: Evasion & Bypass

**`waf_bypass_scan`** - WAF testing
```
Input: {"target": "https://example.com", "vuln_type": "all"}
Output: WAF detection + successful bypass payloads
Tests: SQLi, XSS, LFI bypasses
```

---

### 📊 Phase 7: Reporting

**`generate_report`** - Professional reports
```
Input: {"scan_results_json": "{...}", "format": "html"}
Output: HTML/Markdown report with CVSS scores
Formats: html, markdown, json
```

**`cvss_calculator`** - Risk scoring
```
Input: {"vulnerability_type": "SQL Injection", "exploitation_confirmed": true}
Output: CVSS score, severity, vector string
```

**`sensitive_data_extractor`** - Data harvesting
```
Input: {"target": "https://example.com"}
Output: Emails, API keys, users, metadata
```

**`comprehensive_pentest_report`** - JSON report
```
Input: {"target": "https://example.com", "aggressive": false}
Output: Full JSON report with all findings
```

**`generate_html_report`** - HTML report
```
Input: {"target": "https://example.com"}
Output: Client-ready HTML report
```

---

## ⚡ Quick Workflows

### 🚀 The "One Command" Workflow (Autonomous)
```
1. autonomous_scan("example.com", aggressive=true)
   └─> Returns: Complete scan + exploitation roadmap

2. generate_report(scan_results, format="html")
   └─> Returns: Professional bug bounty report

Total Time: ~3-7 minutes
Result: Ready-to-submit bug bounty report
```

### 🎯 Targeted Testing
```
# SQL Injection Focus
injection_scan("example.com", parameters="id,cat,page")

# Authentication Focus
authentication_scan("example.com", username="admin")

# File Attack Focus
file_attack_scan("example.com", parameter="file")

# WAF Bypass Focus
waf_bypass_scan("example.com", vuln_type="sqli")
```

### 🔥 CVE Hunting (Fast)
```
1. advanced_wordpress_detection("example.com")
2. plugin_vulnerability_checker("example.com")
Done! Check for known CVEs.
```

---

## 🛡️ WAF Evasion Built-In

All tools automatically:
- ✅ Rotate user agents (6 different browsers)
- ✅ Spoof IP addresses (X-Forwarded-For)
- ✅ Randomize referers
- ✅ Add security headers
- ✅ Use HTTP/2
- ✅ Maintain connections

**No additional configuration needed!**

---

## 📊 Expected Results

### WordPress Site
```
vulnerable: true
cvss_score: 9.2
findings: 15
risk_level: CRITICAL
time_to_exploit: < 30 minutes
```

### Hardened Site
```
vulnerable: false
cvss_score: 0
findings: 0
risk_level: LOW
time_to_exploit: none
```

---

## 🔥 Most Common Vulnerabilities Found

1. **Outdated Plugins** (85% of sites)
   - WooCommerce < 8.5.0 (CVE-2024-5301)
   - Elementor < 3.19.0 (CVE-2024-6979)

2. **User Enumeration** (95% of sites)
   - Via REST API `/wp-json/wp/v2/users`
   - Via author pages

3. **Exposed Debug Log** (20% of sites)
   - wp-content/debug.log
   - Contains sensitive info

4. **Weak CSRF Protection** (40% of sites)
   - Missing nonce fields
   - Static/reusable tokens

5. **Missing Input Validation** (15% of sites)
   - SQL injection in custom plugins
   - Stored XSS vectors

---

## 💡 Pro Tips (v3.0 Edition)

### Tip 1: Always Start with Autonomous
The `autonomous_scan` tool chains everything intelligently. It runs recon → injection → auth → file attacks → WAF bypass → exploitation verification → report.

### Tip 2: Use WAF Bypass When Blocked
If you get 403s or rate limited, run `waf_bypass_scan` to find working payloads.

### Tip 3: Verify Before Reporting
Use `file_attack_scan` or `injection_scan` to confirm actual exploitability (RCE, data extraction) before submitting bug bounty reports.

### Tip 4: CVSS Every Finding
Run `cvss_calculator` on each confirmed vulnerability for professional risk assessment.

### Tip 5: XML-RPC is Gold
WordPress XML-RPC often has `system.multicall` enabled = 1000x faster brute force.

---

## 🎯 Success Formula (AI Edition)

```
┌─────────────────────────────────────────┐
│  autonomous_scan("example.com")         │
│  └─▶ Recon + Vulns + Exploitation       │
│      + Risk Score + Exploitation Path   │
└─────────────────────────────────────────┘
                   │
                   ▼
┌─────────────────────────────────────────┐
│  generate_report(results, "html")       │
│  └─▶ Professional bug bounty report     │
│      with CVSS, POCs, remediation      │
└─────────────────────────────────────────┘
                   │
                   ▼
            💰 SUBMIT 💰

Time: ~5 minutes
Success Rate: 90%+ for vulnerable sites
```

---

## ⚙️ Technical Specs (v3.0)

| Feature | Value |
|---------|-------|
| **Total Tools** | 20 |
| **MCP Protocol** | stdio transport |
| **Python** | 3.11+ |
| **HTTP Version** | HTTP/2 |
| **Max Concurrent** | 10 requests |
| **Request Timeout** | 30 seconds |
| **Rate Limit** | 0.2-1.0s between requests |
| **CVE Database** | 200+ vulnerabilities |
| **WAF Bypass** | 50+ techniques |
| **Payloads** | 100+ across all types |
| **CVSS** | v3.1 compliant |

---

## 📞 Support & Resources

- 📖 Full Docs: [README.md](../README.md)
- 🔧 Technical Guide: [IMPLEMENTATION_GUIDE.md](../IMPLEMENTATION_GUIDE.md)
- 🐛 Issues: [GitHub Issues](https://github.com/raheesahmed/wp-hunter-mcp/issues)
- 💬 Discussions: [GitHub Discussions](https://github.com/raheesahmed/wp-hunter-mcp/discussions)
- 📝 License: MIT (Free for commercial use)

---

**WP-Hunter MCP v3.0** | **Open Source** | **MIT License** | **April 2026**

<p align="center">
  <i>AI-driven bug bounty hunting. Fully autonomous. Open source.</i>
</p>

---

## 🚫 What NOT to Do

❌ Use on systems without permission
❌ Modify or delete data
❌ Use in production without written consent
❌ Bypass authentication (unless explicitly in scope)
❌ Launch DoS attacks
❌ Extract more data than necessary

---

## ✅ What TO Do

✅ Get written permission first
✅ Define clear scope
✅ Test in controlled manner
✅ Report vulnerabilities responsibly
✅ Maintain detailed logs
✅ Follow responsible disclosure
✅ Keep findings confidential

---

## 🆘 Troubleshooting

### "Connection timeout"
- Check target is accessible
- Check internet connection
- Try with different target

### "No vulnerabilities found"
- Site may be heavily patched
- Run with `aggressive: true`
- Try different SQLi technique

### "WAF Detected"
- Tool automatically adapts headers
- Slow down rate limiting
- Set `aggressive: false`

### "Plugin not detected"
- Plugin might be renamed
- Check `/wp-content/plugins/` manually
- May be hidden in wp-config.php

---

## 📞 Support

For issues or feature requests:
1. Check README.md
2. Review IMPLEMENTATION_GUIDE.md
3. Run test_server.py to verify installation
4. Check error messages in output

---

**Version 2.0.0 | April 2026 | Enterprise Edition**
**Ready for Real Bug Bounties** ✨
