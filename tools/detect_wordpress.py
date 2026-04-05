import re
from bs4 import BeautifulSoup
from typing import Optional
from models import DetectionResult
from utils import normalize_url, http

async def detect_wordpress(target: str) -> str:
    """
    Detect WordPress installation and gather intelligence.
    
    Args:
        target: Target URL (e.g., https://example.com)
    
    Returns:
        JSON with detection results, version, plugins, themes, exposed files
    """
    base = normalize_url(target)
    result = DetectionResult(is_wordpress=False, confidence="None")
    
    try:
        # Check homepage
        resp = await http.get(base)
        html = resp.text
        soup = BeautifulSoup(html, 'html.parser')
        
        # WordPress detection
        if 'wp-content' in html or 'wp-includes' in html:
            result.is_wordpress = True
            result.confidence = "High (wp-content paths found)"
        
        # Version from meta
        generator = soup.find('meta', attrs={'name': 'generator'})
        if generator and 'WordPress' in generator.get('content', ''):
            result.is_wordpress = True
            match = re.search(r'WordPress (\d+\.\d+\.?\d*)', generator['content'])
            if match:
                result.version = match.group(1)
        
        # Extract plugins
        result.plugins = list(set(re.findall(r'/wp-content/plugins/([^/]+)/', html)))
        
        # Extract themes
        themes = re.findall(r'/wp-content/themes/([^/]+)/', html)
        if themes:
            result.theme = themes[0]
        
        result.server_info = resp.headers.get('server', 'Unknown')
        
        # Check exposed endpoints
        endpoints = {
            'wp-login.php': f"{base}wp-login.php",
            'wp-json': f"{base}wp-json/",
            'xmlrpc.php': f"{base}xmlrpc.php",
            'wp-admin': f"{base}wp-admin/",
        }
        
        for name, url in endpoints.items():
            try:
                r = await http.get(url)
                if r.status_code == 200:
                    result.exposed_endpoints.append(name)
            except:
                pass
        
        # Check sensitive files
        sensitive = [
            ('wp-config.php.bak', 'Config Backup'),
            ('.env', 'Environment File'),
            ('wp-content/debug.log', 'Debug Log'),
            ('backup.zip', 'Backup Archive'),
        ]
        
        for file, desc in sensitive:
            try:
                r = await http.get(f"{base}{file}")
                if r.status_code == 200 and len(r.text) > 0:
                    result.interesting_files.append({
                        'file': file,
                        'type': desc,
                        'size': len(r.content)
                    })
            except:
                pass
        
        return result.model_dump_json(indent=2)
    
    except Exception as e:
        return f'{{"error": "Scan failed: {str(e)}"}}'
