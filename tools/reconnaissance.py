"""
Advanced Reconnaissance & Discovery Suite
Subdomain enumeration, technology fingerprinting, endpoint discovery
"""

import asyncio
import json
import re
from typing import Dict, Any, List, Set
from urllib.parse import urljoin, urlparse
import httpx
from bs4 import BeautifulSoup


COMMON_SUBDOMAINS = [
    'www', 'mail', 'ftp', 'localhost', 'webmail', 'smtp', 'pop', 'ns1', 'webdisk',
    'ns2', 'cpanel', 'whm', 'autodiscover', 'autoconfig', 'ns3', 'm', 'imap',
    'test', 'ns', 'blog', 'pop3', 'dev', 'www2', 'admin', 'forum', 'news', 'vpn',
    'ns4', 'email', 'webmaster', 'support', 'mobile', 'www3', 'staging', 'api',
    'search', 'mx', 'help', 'secure', 'demo', 'webmaster', 'pay', 'store', 'beta',
    'wp', 'wordpress', 'old', 'new', 'shop', 'app', 'cdn', 'media', 'static',
    'portal', 'login', 'auth', 'members', 'dashboard', 'panel', 'control',
    'remote', 'git', 'svn', 'cvs', 'ci', 'jenkins', 'jira', 'confluence',
    'docker', 'kubernetes', 'k8s', 'kube', 'api-v1', 'api-v2', 'graphql',
    'admin-v1', 'admin-v2', 'wp-admin', 'wp-content', 'wp-includes', 'wp-json'
]

TECH_SIGNATURES = {
    'WordPress': ['/wp-content/', '/wp-includes/', 'wp-json', 'generator" content="WordPress'],
    'Drupal': ['/sites/default/', 'drupal.js', 'generator" content="Drupal'],
    'Joomla': ['/media/jui/', '/templates/', 'generator" content="Joomla'],
    'Laravel': ['laravel_session', 'csrf-token', '/vendor/laravel'],
    'Django': ['csrfmiddlewaretoken', '__debug__', 'static/admin/'],
    'Rails': ['csrf-param', 'csrf-token', 'action_cable', 'rails-controller'],
    'React': ['reactroot', 'data-react', '__reactLoadable'],
    'Angular': ['ng-app', 'ng-controller', 'angular.js', 'angular.min.js'],
    'Vue': ['__vue__', 'data-v-', 'vue.js', 'vue.min.js'],
    'jQuery': ['jquery.js', 'jquery.min.js'],
    'Bootstrap': ['bootstrap.css', 'bootstrap.min.css', 'bootstrap.js'],
    'Cloudflare': ['cf-ray', '__cfduid', 'cf-cache-status'],
    'AWS': ['x-amz-', 'aws', 's3.amazonaws.com'],
    'WooCommerce': ['woocommerce', 'wc-ajax', 'product-type'],
    'Elementor': ['/elementor/', 'elementor-frontend'],
    'Yoast SEO': ['yoast', 'yoast-seo'],
}


async def subdomain_enumerator(domain: str, wordlist: List[str] = None, threads: int = 50) -> Dict[str, Any]:
    """
    Enumerate subdomains using DNS resolution and HTTP probing.
    
    Args:
        domain: Base domain (e.g., example.com)
        wordlist: Custom wordlist or uses default
        threads: Number of concurrent requests
        
    Returns:
        Dict with discovered subdomains and their status
    """
    wordlist = wordlist or COMMON_SUBDOMAINS
    discovered = []
    
    async def check_subdomain(sub: str) -> Dict[str, Any]:
        subdomain = f"{sub}.{domain}"
        try:
            async with httpx.AsyncClient() as client:
                # Try HTTPS first
                try:
                    resp = await client.get(f"https://{subdomain}", timeout=5.0, follow_redirects=True)
                    return {
                        "subdomain": subdomain,
                        "status_code": resp.status_code,
                        "server": resp.headers.get('server', 'Unknown'),
                        "accessible": True,
                        "scheme": "https"
                    }
                except:
                    # Try HTTP
                    resp = await client.get(f"http://{subdomain}", timeout=5.0, follow_redirects=True)
                    return {
                        "subdomain": subdomain,
                        "status_code": resp.status_code,
                        "server": resp.headers.get('server', 'Unknown'),
                        "accessible": True,
                        "scheme": "http"
                    }
        except:
            return None
    
    # Run with semaphore for controlled concurrency
    semaphore = asyncio.Semaphore(threads)
    
    async def bounded_check(sub):
        async with semaphore:
            return await check_subdomain(sub)
    
    tasks = [bounded_check(sub) for sub in wordlist]
    results = await asyncio.gather(*tasks)
    
    discovered = [r for r in results if r and r.get("accessible")]
    
    return {
        "domain": domain,
        "total_tested": len(wordlist),
        "discovered_subdomains": discovered,
        "count": len(discovered),
        "interesting_targets": [
            d for d in discovered 
            if any(x in d["subdomain"] for x in ['admin', 'api', 'staging', 'dev', 'test', 'wp', 'dashboard'])
        ]
    }


async def technology_fingerprint(target: str) -> Dict[str, Any]:
    """
    Fingerprint technologies used by the target.
    
    Args:
        target: Target URL
        
    Returns:
        Dict with detected technologies and versions
    """
    base = target if target.startswith(('http://', 'https://')) else f"https://{target}"
    if not base.endswith('/'):
        base += '/'
    
    detected = {
        "technologies": [],
        "javascript_libraries": [],
        "server_software": None,
        "programming_language": None,
        "framework": None,
        "cms": None,
        "cms_version": None,
        "plugins": [],
        "waf": None,
        "cdn": None
    }
    
    try:
        async with httpx.AsyncClient() as client:
            resp = await client.get(base, timeout=15.0, follow_redirects=True)
            html_content = resp.text
            headers = resp.headers
            
            # Server detection
            detected["server_software"] = headers.get('server', 'Unknown')
            
            # WAF detection
            waf_headers = ['cf-ray', 'x-amz-cf-id', 'x-sucuri-id', 'x-waf-event', 'x-mod-security']
            for header in waf_headers:
                if header in headers:
                    detected["waf"] = header
                    break
            
            # CDN detection
            if 'cf-ray' in headers:
                detected["cdn"] = "Cloudflare"
            elif 'x-amz-cf-id' in headers:
                detected["cdn"] = "AWS CloudFront"
            elif 'x-akamai-transformed' in headers:
                detected["cdn"] = "Akamai"
            
            # Technology detection from HTML/headers
            for tech, signatures in TECH_SIGNATURES.items():
                for sig in signatures:
                    if sig.lower() in html_content.lower() or sig.lower() in str(headers).lower():
                        detected["technologies"].append(tech)
                        break
            
            # Remove duplicates
            detected["technologies"] = list(set(detected["technologies"]))
            
            # CMS specific detection
            if 'WordPress' in detected["technologies"]:
                detected["cms"] = "WordPress"
                # Extract version
                match = re.search(r'WordPress (\d+\.\d+\.?\d*)', html_content)
                if match:
                    detected["cms_version"] = match.group(1)
                
                # Extract plugins
                plugins = set(re.findall(r'/wp-content/plugins/([^/]+)/', html_content))
                detected["plugins"] = list(plugins)
            
            elif 'Drupal' in detected["technologies"]:
                detected["cms"] = "Drupal"
            elif 'Joomla' in detected["technologies"]:
                detected["cms"] = "Joomla"
            
            # JavaScript library detection
            js_patterns = {
                'jQuery': r'jquery[/-](\d+\.\d+\.?\d*)',
                'React': r'react[/-](\d+\.\d+\.?\d*)',
                'Angular': r'angular[/-](\d+\.\d+\.?\d*)',
                'Vue': r'vue[/-](\d+\.\d+\.?\d*)',
                'Bootstrap': r'bootstrap[/-](\d+\.\d+\.?\d*)',
            }
            
            for lib, pattern in js_patterns.items():
                matches = re.findall(pattern, html_content, re.I)
                if matches:
                    detected["javascript_libraries"].append(f"{lib} {matches[0]}")
            
            # Framework detection from cookies/headers
            cookies = resp.cookies
            if 'laravel_session' in str(cookies):
                detected["framework"] = "Laravel"
            elif 'django' in str(cookies).lower() or 'csrftoken' in str(cookies):
                detected["framework"] = "Django"
            elif 'rails' in str(cookies).lower():
                detected["framework"] = "Ruby on Rails"
            
            return detected
            
    except Exception as e:
        return {"error": str(e), **detected}


async def endpoint_discovery(target: str, wordlist: List[str] = None) -> Dict[str, Any]:
    """
    Discover hidden endpoints and directories.
    
    Args:
        target: Target URL
        wordlist: Custom wordlist or uses default common endpoints
        
    Returns:
        Dict with discovered endpoints
    """
    base = target if target.startswith(('http://', 'https://')) else f"https://{target}"
    if not base.endswith('/'):
        base += '/'
    
    common_endpoints = wordlist or [
        'admin', 'administrator', 'api', 'api/v1', 'api/v2', 'backup', 'config',
        'console', 'dashboard', 'debug', 'dev', 'env', 'git', 'graphql',
        'internal', 'jenkins', 'login', 'manage', 'panel', 'phpmyadmin',
        'secret', 'setup', 'staging', 'test', 'tmp', 'uploads', 'user',
        'wp-admin', 'wp-content', 'wp-json', 'xmlrpc.php', 'robots.txt',
        '.env', '.git', '.htaccess', '.htpasswd', 'sitemap.xml',
        'swagger', 'api-docs', 'graphql', 'wp-includes', 'vendor',
        'composer.json', 'package.json', 'README.md', 'LICENSE',
    ]
    
    discovered = []
    
    async def check_endpoint(endpoint: str) -> Dict[str, Any]:
        url = urljoin(base, endpoint)
        try:
            async with httpx.AsyncClient() as client:
                resp = await client.get(url, timeout=10.0, follow_redirects=True)
                
                # Interesting status codes
                if resp.status_code in [200, 201, 204, 301, 302, 307, 308, 401, 403, 405]:
                    return {
                        "endpoint": endpoint,
                        "url": url,
                        "status": resp.status_code,
                        "title": "",
                        "size": len(resp.content),
                        "interesting": resp.status_code in [200, 401, 403] or len(resp.content) > 0
                    }
        except:
            pass
        return None
    
    tasks = [check_endpoint(ep) for ep in common_endpoints]
    results = await asyncio.gather(*tasks)
    
    discovered = [r for r in results if r]
    
    # Sort by interestingness
    discovered.sort(key=lambda x: (0 if x["status"] == 200 else 1, -x["size"]))
    
    return {
        "target": base,
        "endpoints_tested": len(common_endpoints),
        "discovered_endpoints": discovered,
        "high_priority_targets": [d for d in discovered if d["status"] in [200, 401]],
        "count": len(discovered)
    }


async def wayback_url_discovery(domain: str) -> Dict[str, Any]:
    """
    Discover URLs from Wayback Machine.
    
    Args:
        domain: Domain to search
        
    Returns:
        Dict with discovered URLs
    """
    try:
        async with httpx.AsyncClient() as client:
            url = f"http://web.archive.org/cdx/search/cdx?url={domain}/*&output=json&collapse=urlkey"
            resp = await client.get(url, timeout=30.0)
            
            if resp.status_code == 200:
                data = resp.json()
                urls = [item[2] for item in data[1:]] if len(data) > 1 else []
                
                # Find interesting patterns
                interesting_patterns = [
                    '.env', 'backup', '.sql', '.zip', '.tar', '.gz',
                    'api/', 'admin/', 'config', 'debug', 'test',
                    'password', 'secret', 'token', 'key',
                ]
                
                interesting_urls = [u for u in urls if any(p in u.lower() for p in interesting_patterns)]
                
                return {
                    "domain": domain,
                    "total_urls": len(urls),
                    "interesting_urls": interesting_urls[:50],  # Limit to 50
                    "api_endpoints": list(set([u for u in urls if '/api/' in u]))[:20],
                    "admin_endpoints": list(set([u for u in urls if any(x in u for x in ['admin', 'manage', 'panel'])]))[:20]
                }
    except Exception as e:
        return {"error": str(e), "domain": domain}
    
    return {"domain": domain, "total_urls": 0, "note": "No data from Wayback"}


# MCP Tool Wrappers
async def full_reconnaissance_scan(target: str, subdomain_wordlist: List[str] = None) -> str:
    """
    Complete reconnaissance scan - subdomains, tech fingerprint, endpoints, wayback.
    
    Args:
        target: Target domain or URL
        subdomain_wordlist: Optional custom subdomain list
        
    Returns:
        JSON with complete recon data
    """
    # Extract domain from URL if needed
    if '://' in target:
        parsed = urlparse(target)
        domain = parsed.netloc
    else:
        domain = target
        target = f"https://{target}"
    
    results = await asyncio.gather(
        subdomain_enumerator(domain, subdomain_wordlist),
        technology_fingerprint(target),
        endpoint_discovery(target),
        wayback_url_discovery(domain)
    )
    
    return json.dumps({
        "scan_type": "Full Reconnaissance",
        "target_domain": domain,
        "target_url": target,
        "subdomains": results[0],
        "technology": results[1],
        "endpoints": results[2],
        "wayback_data": results[3],
        "summary": {
            "subdomains_found": results[0].get("count", 0),
            "technologies_detected": len(results[1].get("technologies", [])),
            "endpoints_discovered": results[2].get("count", 0),
            "attack_surface_rating": "High" if results[0].get("count", 0) > 10 or results[2].get("count", 0) > 20 else "Medium"
        }
    }, indent=2)
