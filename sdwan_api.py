import time
import getpass
import urllib3
import requests
from config import load_profiles, save_profiles

urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

def get_xsrf_token(session, base_url):
    """Retrieves mandatory validation token."""
    try:
        token_url = f"{base_url}/dataservice/client/token"
        res = session.get(token_url, timeout=5)
        if res.status_code == 200 and res.text:
            return res.text.strip()
    except Exception:
        pass
    return None

def refresh_jwt_access(session, base_url, refresh_token):
    """Uses a long-lived token to request a short-lived JWT access token."""
    refresh_url = f"{base_url}/jwt/refresh"
    payload = {"refresh": refresh_token}
    try:
        res = session.post(refresh_url, json=payload, timeout=10)
        if res.status_code == 200:
            access_token = res.json().get("token")
            session.headers.update({
                'Authorization': f"Bearer {access_token}",
                'Content-Type': 'application/json'
            })
            xsrf = get_xsrf_token(session, base_url)
            if xsrf:
                session.headers.update({'X-XSRF-TOKEN': xsrf})
            return True
    except Exception:
        pass
    return False

def initialize_active_session(base_url, username, profile_data=None):
    """Establishes or reinstates a JWT session token pipeline."""
    session = requests.Session()
    session.verify = False
    
    if profile_data and 'refresh_token' in profile_data:
        print("🔄 Exchanging cached profile refresh token for short-lived JWT access...")
        if refresh_jwt_access(session, base_url, profile_data['refresh_token']):
            print("✨ Re-bound cleanly! Re-established Bearer Authorization.")
            return session
        print("⚠️ Stored refresh token expired. Prompting credentials...")

    password = getpass.getpass(f"🔑 Enter vManage password for user '{username}': ")
    login_url = f"{base_url}/jwt/login"
    payload = {"username": username, "password": password}
    
    try:
        res = session.post(login_url, json=payload, timeout=12)
        if res.status_code != 200:
            print(f"❌ Access denied. Status: {res.status_code}")
            return None
            
        data = res.json()
        session.headers.update({
            'Authorization': f"Bearer {data.get('token')}",
            'Content-Type': 'application/json'
        })
        
        xsrf = get_xsrf_token(session, base_url)
        if xsrf:
            session.headers.update({'X-XSRF-TOKEN': xsrf})
            
        profiles = load_profiles()
        profiles[base_url] = {"username": username, "refresh_token": data.get("refresh")}
        save_profiles(profiles)
        
        print("🔒 Session cache validated and refresh token pinned.")
        return session
    except Exception as e:
        print(f"❌ Handshake crash: {e}")
        return None

def fetch_devices(session, base_url):
    """Queries live nodes from inventory."""
    url = f"{base_url}/dataservice/device"
    res = session.get(url, timeout=15)
    if res.status_code == 200:
        return res.json().get('data', [])
    raise requests.exceptions.HTTPError(f"HTTP Rejected: {res.status_code}")

def fetch_config_groups(session, base_url):
    """Queries all Configuration Groups from SD-WAN Manager using corrected DevNet path."""
    url = f"{base_url}/dataservice/v1/config-group"
    res = session.get(url, timeout=15)
    if res.status_code == 200:
        return res.json().get('data', []) if isinstance(res.json(), dict) else res.json()
    raise requests.exceptions.HTTPError(f"HTTP Rejected ({res.status_code}): {res.text}")

def get_config_group_id(session, base_url, name):
    """Translates user-provided text name into vManage configuration group UUID."""
    try:
        groups = fetch_config_groups(session, base_url)
        for g in groups:
            if g.get('name') == name or g.get('configGroupName') == name:
                return g.get('id') or g.get('configGroupId')
    except Exception:
        pass
    return None

def associate_and_deploy_devices(session, base_url, group_id, devices_payload):
    """Binds device elements and triggers an execution task matching 26.1 specification."""
    
    # -------------------------------------------------------------------------
    # STEP 1: Associate devices with Configuration Group
    # -------------------------------------------------------------------------
    assoc_url = f"{base_url}/dataservice/v1/config-group/{group_id}/device/associate"
    assoc_payload = {"devices": [{"id": d["deviceId"]} for d in devices_payload]}
    
    assoc_res = session.post(assoc_url, json=assoc_payload, timeout=20)
    if not (200 <= assoc_res.status_code < 300):
        print(f"❌ Configuration Group association payload rejected (HTTP {assoc_res.status_code}): {assoc_res.text}")
        return None
        
    # -------------------------------------------------------------------------
    # STEP 2: Deploy config group to devices (DevNet 26.1 Fix)
    # -------------------------------------------------------------------------
    # CHANGED: Fixed path schema structure to match /device/deploy explicitly
    deploy_url = f"{base_url}/dataservice/v1/config-group/{group_id}/device/deploy"
    
    # CHANGED: Formatted payload to only match required list of device maps with 'id' key
    deploy_payload = {
        "devices": [{"id": d["deviceId"]} for d in devices_payload]
    }
    
    deploy_res = session.post(deploy_url, json=deploy_payload, timeout=20)
    
    if 200 <= deploy_res.status_code < 300:
        # Returns parentTaskId as outlined by the 26.1 deployment schema object response
        return deploy_res.json().get("parentTaskId") or deploy_res.json().get("id")
    else:
        print(f"❌ Deploy task allocation error (HTTP {deploy_res.status_code}): {deploy_res.text}")
        return None

def poll_task_status(session, base_url, task_id):
    """Asynchronous polling verification engine loop tracker."""
    status_url = f"{base_url}/dataservice/device/action/status/{task_id}"
    for _ in range(30): 
        try:
            task_res = session.get(status_url, timeout=10).json()
            status = task_res.get("summary", {}).get("status", "").lower()
            if status in ["success", "done", "completed"]:
                return True, "Success"
            if status in ["fail", "failed", "failure", "partial"]:
                return False, task_res.get("summary", {}).get("message", "vManage action task rejected.")
        except Exception:
            pass
        time.sleep(5)
    return False, "Deployment polling action timed out."
