import re
from typing import List, Dict, Any
from utils import normalize_url, http

async def enumerate_users(target: str) -> Dict[str, Any]:
    """
    Enumerate WordPress users via REST API and author pages.
    
    Args:
        target: Target URL
    
    Returns:
        Dict with user list and enumeration methods
    """
    base = normalize_url(target)
    users = []
    methods = []
    
    # Method 1: REST API
    try:
        resp = await http.get(f"{base}wp-json/wp/v2/users?per_page=100")
        if resp.status_code == 200:
            data = resp.json()
            for u in data:
                users.append({
                    'id': u.get('id'),
                    'username': u.get('slug'),
                    'name': u.get('name'),
                    'posts': u.get('posts', 0)
                })
            methods.append('REST API')
    except:
        pass
    
    # Method 2: Author pages
    if not users:
        for i in range(1, 11):
            try:
                resp = await http.get(f"{base}?author={i}")
                if '/author/' in str(resp.url):
                    match = re.search(r'/author/([^/]+)/', str(resp.url))
                    if match:
                        users.append({
                            'id': i,
                            'username': match.group(1),
                            'name': match.group(1)
                        })
            except:
                pass
        if users:
            methods.append('Author Pages')
    
    return {
        "enumeration_possible": len(users) > 0,
        "user_count": len(users),
        "users": users,
        "methods_used": methods,
        "severity": "Low" if users else "None",
        "note": "User enumeration enables targeted brute force attacks"
    }
