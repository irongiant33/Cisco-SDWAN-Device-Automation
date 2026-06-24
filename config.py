import os
import json

PROFILES_FILE = "sdwan_profiles.json"
CONFIG_GROUPS_CACHE_KEY = "config_groups_cache"
POLICY_GROUPS_CACHE_KEY = "policy_groups_cache"

def _profile_key(profiles, base_url):
    key = base_url.rstrip('/')
    if key in profiles:
        return key
    if base_url in profiles:
        return base_url
    return key

def load_profiles():
    """Reads saved environments and refresh tokens from the local JSON layer."""
    if os.path.exists(PROFILES_FILE):
        try:
            with open(PROFILES_FILE, 'r') as f:
                return json.load(f)
        except Exception:
            return {}
    return {}

def save_profiles(profiles):
    """Writes target metadata and refresh tokens securely back to local JSON."""
    try:
        with open(PROFILES_FILE, 'w') as f:
            json.dump(profiles, f, indent=4)
    except Exception as e:
        print(f"⚠️ Warning: Could not save profiles locally: {e}")

def get_vmanage_target():
    """Prompts user to select from known profiles or register a new target node."""
    profiles = load_profiles()
    
    print("\n" + "="*50)
    print("🌐 TARGET VMANAGE CONTROLLER MATRIX (JWT PROXY)")
    print("="*50)
    
    known_ips = list(profiles.keys())
    if known_ips:
        print("Discovered saved environment profiles:")
        for idx, ip in enumerate(known_ips, 1):
            print(f" [{idx}] {ip} (User: {profiles[ip].get('username')})")
        print(f" [{len(known_ips) + 1}] Connect to a new vManage Node IP")
        
        choice = input(f"\n👉 Select an environment (1-{len(known_ips) + 1}): ").strip()
        if choice.isdigit():
            c_idx = int(choice)
            if 1 <= c_idx <= len(known_ips):
                selected_ip = known_ips[c_idx - 1]
                return selected_ip, profiles[selected_ip]['username'], profiles[selected_ip]
            
    base_url = input("🌐 Enter new target vManage Base URL / IP: ").strip().rstrip('/')
    if base_url and not base_url.startswith("http://") and not base_url.startswith("https://"):
        base_url = f"https://{base_url}"
        
    username = input("👤 Enter RBAC Account Username: ").strip()
    return base_url, username, None

def get_cached_config_groups(base_url):
    """Return cached config groups for an environment, or None if never refreshed."""
    profiles = load_profiles()
    profile = profiles.get(_profile_key(profiles, base_url), {})
    if CONFIG_GROUPS_CACHE_KEY not in profile:
        return None
    return profile[CONFIG_GROUPS_CACHE_KEY]

def get_cached_policy_groups(base_url):
    """Return cached policy groups for an environment, or None if never refreshed."""
    profiles = load_profiles()
    profile = profiles.get(_profile_key(profiles, base_url), {})
    if POLICY_GROUPS_CACHE_KEY not in profile:
        return None
    return profile[POLICY_GROUPS_CACHE_KEY]

def save_config_groups_cache(base_url, groups):
    profiles = load_profiles()
    key = _profile_key(profiles, base_url)
    if key not in profiles:
        profiles[key] = {}
    profiles[key][CONFIG_GROUPS_CACHE_KEY] = groups
    save_profiles(profiles)

def save_policy_groups_cache(base_url, groups):
    profiles = load_profiles()
    key = _profile_key(profiles, base_url)
    if key not in profiles:
        profiles[key] = {}
    profiles[key][POLICY_GROUPS_CACHE_KEY] = groups
    save_profiles(profiles)

def update_profile_tokens(base_url, username, refresh_token):
    """Persist token rotation without clearing cached group lists."""
    profiles = load_profiles()
    key = _profile_key(profiles, base_url)
    if key not in profiles:
        profiles[key] = {}
    profiles[key]["username"] = username
    profiles[key]["refresh_token"] = refresh_token
    save_profiles(profiles)
