# WP-Hunter MCP - Autonomous Bug Bounty Hunting MCP SERVER

<p align="center">
  <img src="https://img.shields.io/badge/MCP-Compatible-green?style=for-the-badge" alt="MCP Compatible">
  <img src="https://img.shields.io/badge/Python-3.11+-blue?style=for-the-badge" alt="Python 3.11+">
  <img src="https://img.shields.io/badge/Tools-20-red?style=for-the-badge" alt="20 Tools">
  <img src="https://img.shields.io/badge/License-MIT-yellow?style=for-the-badge" alt="MIT License">
</p>

**The first fully autonomous MCP server for WordPress bug bounty hunting.** AI-driven vulnerability discovery, exploitation verification, and professional report generation.

---

## Overview

WP-Hunter MCP is a comprehensive [Model Context Protocol (MCP)](https://modelcontextprotocol.io) server that enables AI agents to perform complete autonomous penetration testing on WordPress installations. It combines reconnaissance, vulnerability scanning, exploitation verification, and professional reporting into a single, powerful toolset.

### What Makes This Different

- **Fully Autonomous**: One command runs the entire workflow - recon → exploitation → reporting
- **Real Exploitation**: Actually verifies vulnerabilities (uploads shells, extracts data, steals cookies)
- **WAF Bypass Built-in**: 50+ encoding mutations and evasion techniques
- **CVSS Scoring**: Professional risk assessment for bug bounty submissions
- **20 Integrated Tools**: Everything from subdomain enumeration to JWT attacks

---

## Quick Start

```bash
# Clone the repository
git clone https://github.com/RaheesAhmed/wp-hunter-mcp.git
cd wp-hunter-mcp

# Install dependencies
pip install -r requirements.txt
# or
uv sync

# Activate virtual environment (Windows)
.\.venv\Scripts\activate
# or (Linux/Mac)
source .venv/bin/activate

# Run the MCP server
python wp_hunter_pro.py
```

## MCP Client Setup

Configure WP-Hunter with your favorite AI coding assistant:

### Claude Code (Anthropic)

Add to your Claude Code configuration (`~/.claude/config.json`):

```json
{
  "mcpServers": {
    "wp-hunter": {
      "command": "python",
      "args": ["/path/to/wp-hunter-mcp/wp_hunter_pro.py"],
      "env": {
        "PYTHONPATH": "/path/to/wp-hunter-mcp"
      }
    }
  }
}
```

**Usage in Claude Code:**
```
@wp-hunter autonomous_scan target="https://example.com" aggressive=true
```

### Cursor IDE

Add to Cursor MCP settings (`~/.cursor/mcp.json`):

```json
{
  "mcpServers": {
    "wp-hunter": {
      "type": "stdio",
      "command": "python",
      "args": ["C:\\path\\to\\wp-hunter-mcp\\wp_hunter_pro.py"],
      "env": {
        "PYTHONPATH": "C:\\path\\to\\wp-hunter-mcp"
      }
    }
  }
}
```

**Usage in Cursor:**
1. Open Cursor Settings → MCP
2. Click "Add MCP Server"
3. Select "Command" type
4. Enter: `python C:\path\to\wp-hunter-mcp\wp_hunter_pro.py`
5. Save and start chatting with the AI

### Cline (VS Code Extension)

Add to Cline MCP settings (VS Code Settings → Cline → MCP Servers):

```json
{
  "mcpServers": {
    "wp-hunter": {
      "command": "python",
      "args": ["${workspaceFolder}/wp-hunter-mcp/wp_hunter_pro.py"],
      "env": {
        "PYTHONPATH": "${workspaceFolder}/wp-hunter-mcp"
      }
    }
  }
}
```

### Generic MCP Client

For any MCP-compatible client, use this configuration:

```json
{
  "mcpServers": {
    "wp-hunter-mcp": {
      "type": "stdio",
      "command": "python",
      "args": ["/absolute/path/to/wp_hunter_pro.py"],
      "cwd": "/absolute/path/to/wp-hunter-mcp"
    }
  }
}
```

### Environment Variables

Optional environment variables for advanced configuration:

```bash
# Set custom rate limiting (seconds between requests)
export WP_HUNTER_DELAY=0.5

# Enable aggressive mode by default
export WP_HUNTER_AGGRESSIVE=false

# Set custom User-Agent
export WP_HUNTER_USER_AGENT="Custom-Agent"
```

## The 20 Tools

### Core Detection Tools
| Tool | Description | Autonomous |
|------|-------------|------------|
| `advanced_wordpress_detection` | WordPress version, plugins, themes, WAF detection | ✅ |
| `reconnaissance_scan` | Subdomain enum, tech fingerprint, endpoint discovery | ✅ |

### Injection Testing
| Tool | Description | Autonomous |
|------|-------------|------------|
| `injection_scan` | SQLi, XSS, Command Injection, SSTI combined | ✅ |
| `advanced_sql_injection_test` | Time-based, boolean, union, error-based, stacked | ✅ |
| `xss_vulnerability_scanner` | Reflected, stored, DOM-based XSS | ✅ |

### Authentication & Session
| Tool | Description | Autonomous |
|------|-------------|------------|
| `authentication_scan` | JWT attacks, brute force, session analysis, 2FA | ✅ |
| `csrf_vulnerability_validator` | CSRF nonce validation, static tokens | ✅ |

### File Operations
| Tool | Description | Autonomous |
|------|-------------|------------|
| `file_attack_scan` | Upload RCE, LFI, RFI, path traversal | ✅ |
| `file_upload_vulnerability_tester` | PHP execution via uploads | ✅ |
| `path_traversal_lfi_scanner` | wp-config.php extraction, /etc/passwd | ✅ |

### WordPress-Specific
| Tool | Description | Autonomous |
|------|-------------|------------|
| `xmlrpc_security_analyzer` | system.multicall brute force, pingback SSRF | ✅ |
| `plugin_vulnerability_checker` | CVE database (200+ vulnerabilities) | ✅ |
| `wordpress_security_hardening_audit` | Headers, SSL/TLS, backup files | ✅ |

### Data Extraction
| Tool | Description | Autonomous |
|------|-------------|------------|
| `sensitive_data_extractor` | Emails, API keys, user enumeration | ✅ |

### Evasion & Bypass
| Tool | Description | Autonomous |
|------|-------------|------------|
| `waf_bypass_scan` | WAF detection, encoding mutations, bypasses | ✅ |

### Reporting & Analysis
| Tool | Description | Autonomous |
|------|-------------|------------|
| `autonomous_scan` | **Complete AI-driven scan with exploitation roadmap** | ✅ |
| `generate_report` | Professional HTML/Markdown with CVSS | ✅ |
| `cvss_calculator` | CVSS v3.1 scoring | ✅ |
| `comprehensive_pentest_report` | JSON report with all findings | ✅ |
| `generate_html_report` | Client-ready HTML report | ✅ |

✅ **Critical Vulnerability Testing**
- **SQL Injection**: Time-based, Boolean-based, Union-based, Error-based, Stacked queries
- **Cross-Site Scripting (XSS)**: Reflected, Stored, DOM-based with 2026 evasion techniques
- **CSRF**: Nonce validation, static token detection, authentication bypass
- **File Upload RCE**: PHP execution, arbitrary file upload, shell deployment
- **Path Traversal / LFI**: Local file inclusion, wrapper injection, /etc/passwd extraction
- **Plugin Vulnerabilities**: Real CVE-2024/2025/2026 database matching

✅ **Advanced Exploitation Tools**
- Plugin CVE vulnerability checker with 100+ known vulnerabilities
- Sensitive data extraction (emails, API keys, credentials, metadata)
- Multi-threaded parallel scanning
- WAF evasion with IP spoofing and header manipulation
- Rate limit bypassing with intelligent delays
- PHP filter wrapper exploitation

✅ **Professional Reporting**
- Comprehensive JSON reports with CVSS scoring
- Production-grade HTML reports with risk visualization
- Executive summaries and technical details
- Actionable remediation guidance
- OWASP Top 10 mapping

## Installation

```bash
# Clone or navigate to repository
cd wp-hunter-mcp

# Install with uv (recommended)
uv sync

# Or with pip
pip install -r requirements.txt

# Activate virtual environment
.\.venv\Scripts\activate
```

## Available Tools

### 1. Advanced WordPress Detection
**Tool**: `advanced_wordpress_detection(target: str)`

Detects WordPress installations and gathers comprehensive intelligence.

```json
{
  "tool": "advanced_wordpress_detection",
  "target": "https://example.com"
}
```

**Returns**: WordPress version, plugins with versions, themes, exposed endpoints, WAF detection, sensitive files

---

### 2. Advanced SQL Injection Tester
**Tool**: `advanced_sql_injection_test(target: str, parameter: str, technique: str)`

Tests multiple SQL injection techniques simultaneously.

Supported techniques:
- `time-based` - SLEEP-based blind SQL injection
- `boolean-based` - True/false response based detection
- `union-based` - UNION SELECT data extraction
- `error-based` - Error message extraction
- `stacked` - Multiple statement execution

```json
{
  "tool": "advanced_sql_injection_test",
  "target": "https://example.com",
  "parameter": "id",
  "technique": "time-based"
}
```

**Returns**: Vulnerability status, payload details, response times, proof-of-concept

---

### 3. XSS Vulnerability Scanner
**Tool**: `xss_vulnerability_scanner(target: str, scan_depth: str)`

Comprehensive XSS testing across parameters and endpoints.

Scan depths:
- `quick` - Basic XSS payloads (3 payloads)
- `medium` - Standard testing (6 payloads)
- `thorough` - All payloads (13+ advanced payloads)

```json
{
  "tool": "xss_vulnerability_scanner",
  "target": "https://example.com",
  "scan_depth": "medium"
}
```

**Returns**: Reflected XSS findings, parameter mapping, payload details, severity scores

---

### 4. CSRF Vulnerability Validator
**Tool**: `csrf_vulnerability_validator(target: str)`

Tests for CSRF vulnerabilities and nonce validation weaknesses.

```json
{
  "tool": "csrf_vulnerability_validator",
  "target": "https://example.com"
}
```

**Returns**: Missing nonce tokens, static/reusable nonces, authentication bypass issues

---

### 5. File Upload Vulnerability Tester
**Tool**: `file_upload_vulnerability_tester(target: str)`

Identifies arbitrary file upload and RCE vulnerabilities.

```json
{
  "tool": "file_upload_vulnerability_tester",
  "target": "https://example.com"
}
```

**Returns**: Upload endpoints, bypassed extensions, directory listing issues, RCE potential

---

### 6. Path Traversal / LFI Scanner
**Tool**: `path_traversal_lfi_scanner(target: str, parameter: str)`

Tests for Local File Inclusion and directory traversal vulnerabilities.

```json
{
  "tool": "path_traversal_lfi_scanner",
  "target": "https://example.com",
  "parameter": "file"
}
```

**Returns**: LFI vulnerabilities, /etc/passwd extraction, wp-config.php access, PHP wrapper injection

---

### 7. Plugin Vulnerability Checker
**Tool**: `plugin_vulnerability_checker(target: str)`

Checks installed plugins against CVE database.

```json
{
  "tool": "plugin_vulnerability_checker",
  "target": "https://example.com"
}
```

**Returns**: Vulnerable plugins, CVE IDs, vulnerability types, version comparisons


---

### 8. Sensitive Data Extractor
**Tool**: `sensitive_data_extractor(target: str)`

Extracts sensitive information from WordPress installations.

```json
{
  "tool": "sensitive_data_extractor",
  "target": "https://example.com"
}
```

**Extracts**:
- Email addresses (users, comments, metadata)
- API keys and credentials
- User accounts and details
- Comments with author information
- WordPress version and metadata
- Open Graph data and metadata

---

### 9. Comprehensive Penetration Test Report
**Tool**: `comprehensive_pentest_report(target: str, aggressive: bool)`

Runs all scanning tools and generates a complete penetration test report.

```json
{
  "tool": "comprehensive_pentest_report",
  "target": "https://example.com",
  "aggressive": false
}
```

**Report includes**:
- All vulnerabilities found across all scanners
- CVSS scores for each finding
- Risk score (0-100)
- HTTP requests made
- Detailed remediation guidance
- Executive summary

---

### 10. HTML Report Generator
**Tool**: `generate_html_report(target: str)`

Generates professional HTML penetration test report.

```json
{
  "tool": "generate_html_report",
  "target": "https://example.com"
}
```

**Returns**: Professional HTML report with:
- Visual risk score dashboard
- Color-coded findings by severity
- Proof-of-concept details
- Remediation guidance
- Professional formatting for client delivery

---

## Usage Examples

### Example 1: Fully Autonomous Scan
```json
{
  "tool": "autonomous_scan",
  "arguments": {
    "target": "https://example.com",
    "aggressive": true
  }
}
```
**Output**: Complete vulnerability assessment with exploitation roadmap

### Example 2: Targeted SQL Injection
```json
{
  "tool": "injection_scan",
  "arguments": {
    "target": "https://example.com",
    "parameters": "id,page,cat"
  }
}
```
**Output**: SQLi, XSS, Command Injection, SSTI findings

### Example 3: WAF Bypass Testing
```json
{
  "tool": "waf_bypass_scan",
  "arguments": {
    "target": "https://example.com",
    "vuln_type": "all"
  }
}
```
**Output**: WAF detection and successful bypass payloads

### Example 4: Generate Bug Bounty Report
```json
{
  "tool": "generate_report",
  "arguments": {
    "scan_results_json": "{...scan results...}",
    "format": "html"
  }
}
```
**Output**: Professional HTML report with CVSS scores

## Technical Specifications

### Performance Optimizations
- ⚡ Async/await for concurrent requests
- 🔄 Connection pooling (10 simultaneous connections)
- 🚀 HTTP/2 support
- 🛡️ Intelligent rate limiting (0.2-1.0s between requests)
- 📦 Batch processing for payload testing

### WAF Evasion Techniques
- ✅ User-Agent rotation (6 modern browsers)
- ✅ X-Forwarded-For IP spoofing
- ✅ Referer randomization
- ✅ Security headers (Sec-Fetch-*, etc.)
- ✅ Custom header injection
- ✅ Cache control headers

### Detection Methods
- Regex pattern matching
- HTML parsing with BeautifulSoup
- JSON API analysis
- Header inspection
- Response timing analysis
- Error message parsing

## Security & Ethics

⚠️ **Legal Notice**: This tool is designed for authorized security testing only. Unauthorized access to computer systems is illegal. Always obtain written permission before testing any system you don't own.

Best practices:
- Only test systems you own or have explicit written permission to test
- Include scope and rules of engagement in bug bounty programs
- Report vulnerabilities responsibly to vendors
- Maintain detailed logs of all testing activities
- Use in isolated lab environments for learning

## Requirements

- Python 3.11+
- httpx[http2] >= 0.27.0
- beautifulsoup4 >= 4.12.0
- pydantic >= 2.0.0
- fastmcp >= 3.0.0

## Command Reference

| Command | Function | Parameters |
|---------|----------|-----------|
| `autonomous_scan` | **AI-driven complete scan** | `target`, `aggressive` |
| `reconnaissance_scan` | Subdomain & endpoint discovery | `target` |
| `injection_scan` | SQLi, XSS, SSTI, CMDi combined | `target`, `parameters` |
| `authentication_scan` | JWT, brute force, sessions | `target`, `username` |
| `file_attack_scan` | Upload RCE, LFI, traversal | `target`, `parameter` |
| `waf_bypass_scan` | WAF detection & bypass | `target`, `vuln_type` |
| `generate_report` | Professional report | `scan_results_json`, `format` |
| `cvss_calculator` | CVSS v3.1 scoring | `vulnerability_type`, `exploitation_confirmed` |
| `advanced_wordpress_detection` | Detect WP + plugins | `target` |
| `advanced_sql_injection_test` | Test SQL injection | `target`, `parameter`, `technique` |
| `xss_vulnerability_scanner` | Find XSS bugs | `target`, `scan_depth` |
| `csrf_vulnerability_validator` | Check CSRF tokens | `target` |
| `file_upload_vulnerability_tester` | Test file uploads | `target` |
| `path_traversal_lfi_scanner` | Test LFI/Path Traversal | `target`, `parameter` |
| `xmlrpc_security_analyzer` | XML-RPC attacks | `target` |
| `plugin_vulnerability_checker` | Check CVEs | `target` |
| `wordpress_security_hardening_audit` | Security headers audit | `target` |
| `sensitive_data_extractor` | Extract data | `target` |
| `comprehensive_pentest_report` | Full audit report | `target`, `aggressive` |
| `generate_html_report` | Professional HTML | `target` |

## Roadmap (2026+)

- [ ] Machine learning-based vulnerability classification
- [ ] Real-time WAF bypass using AI
- [ ] Automated exploit chain generation
- [ ] GraphQL API security testing
- [ ] Advanced deserialization exploits
- [ ] Supply chain vulnerability detection
- [ ] Zero-day payload generation
- [ ] Multi-stage exploitation automation

## Contributing

We welcome contributions! See [CONTRIBUTING.md](CONTRIBUTING.md) for guidelines.

### Quick Contribution Guide
1. Fork the repository
2. Create a feature branch (`git checkout -b feature/amazing-feature`)
3. Commit your changes (`git commit -m 'Add amazing feature'`)
4. Push to the branch (`git push origin feature/amazing-feature`)
5. Open a Pull Request

### Areas for Contribution
- Additional WAF bypass techniques
- New CVEs for plugin database
- GraphQL security testing
- Additional report templates
- Performance optimizations

---

## License

This project is licensed under the MIT License - see [LICENSE](LICENSE) file for details.

---

## Support

- 📖 Documentation: [IMPLEMENTATION_GUIDE.md](IMPLEMENTATION_GUIDE.md)
- 🚀 Quick Start: [QUICK_REFERENCE.md](QUICK_REFERENCE.md)
- 🐛 Issues: [GitHub Issues](https://github.com/RaheesAhmed/wp-hunter-mcp/issues)
- 💬 Discussions: [GitHub Discussions](https://github.com/RaheesAhmed/wp-hunter-mcp/discussions)

---

**WP-Hunter MCP v3.0** | Built for AI-Driven Bug Bounty Hunting | MIT License
