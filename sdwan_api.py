import time
import getpass
import urllib3
import requests
from config import load_profiles, save_profiles
import re

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

def fetch_policy_groups(session, base_url):
    """Queries all Policy Groups from SD-WAN Manager."""
    url = f"{base_url}/dataservice/v1/policy-group"
    res = session.get(url, timeout=15)
    if res.status_code == 200:
        return res.json().get('data', []) if isinstance(res.json(), dict) else res.json()
    raise requests.exceptions.HTTPError(f"HTTP Rejected ({res.status_code}): {res.text}")

def fetch_policy_group_associations(session, base_url):
    """Queries all active device-to-policy-group association matrices."""
    url = f"{base_url}/dataservice/v1/config-group/policy-group/associations"
    try:
        res = session.get(url, timeout=15)
        if res.status_code == 200:
            return res.json().get('data', [])
    except Exception:
        pass
    return []

def _get_expected_variables(session, base_url, group_id):
    """Queries the exact device variables schema expected by the configuration group."""
    url = f"{base_url}/dataservice/v1/config-group/{group_id}/device/variables"
    try:
        res = session.get(url, timeout=30)
        if res.status_code == 200:
            data = res.json()
            # Extract the active variable name keys directly from the associated device array
            expected_names = set()
            for device in data.get("devices", []):
                for variable in device.get("variables", []):
                    if "name" in variable:
                        expected_names.add(variable["name"])
            
            if expected_names:
                return expected_names
                
            print("⚠️ [DEBUG] HTTP 200 OK received, but no variable tracking objects found inside device blocks.")
        else:
            print(f"❌ [DEBUG] Controller rejected request with HTTP status code: {res.status_code}")
            print(f"🔍 --- ERROR PAYLOAD RESPONSE --- \n{res.text}\n----------------------------------")
    except Exception as e:
        print(f"⚠️ Warning: Could not retrieve device variables schema: {e}")
        if res is not None and hasattr(res, 'text') and res.text:
            print(f"🔍 --- EXCEPTION RAW CONTEXT --- \n{res.text}\n----------------------------------")
    return set()

def associate_and_deploy_devices(session, base_url, group_id, devices_payload):
    """Binds devices, filters variables to match the schema definitions, and deploys the group."""
    # -------------------------------------------------------------------------
    # STEP 1: Associate devices with Configuration Group (DevNet 26.1 Schema Fix)
    # https://developer.cisco.com/docs/sd-wan/26-1/create-config-group-association/
    # -------------------------------------------------------------------------
    url = f"{base_url}/dataservice/v1/config-group/{group_id}/device/associate"
     
    assoc_devices = [{"id": d["deviceId"]} for d in devices_payload]
    payload = {"devices": assoc_devices}
    
    try:
        res = session.post(url, json=payload, timeout=15)
        res.raise_for_status()
        print("⏳ Association request accepted. Polling official association table to confirm database replication...")
        
        # Explicit Association Verification Polling Loop
        target_ids = {d["deviceId"] for d in devices_payload}
        verified = False
        check_url = f"{base_url}/dataservice/v1/config-group/{group_id}/device/associate"
        
        for attempt in range(12):  # Poll up to 60 seconds (12 * 5s)
            time.sleep(5)
            try:
                check_res = session.get(check_url, timeout=10)
                if check_res.status_code == 200:
                    associated_data = check_res.json().get("devices", [])
                    associated_ids = {dev.get("id") for dev in associated_data if dev.get("id")}
                    
                    if target_ids.issubset(associated_ids):
                        print("✅ Confirmed: All target devices are fully associated inside the group container backend.")
                        verified = True
                        break
            except Exception:
                pass
            print(f"⏳ Verification attempt {attempt + 1}/12: Devices missing from association table. Retrying...")
            
        if not verified:
            print("❌ Failure: Devices failed to reflect association within the 60-second execution window.")
            return None
            
    except Exception as e:
        print(f"❌ Structural layout binding rejected: {e}")
        if 'res' in locals() and hasattr(res, 'text') and res.text:
            print(f"🔍 --- CONTROLLER REJECTION DETAILS --- \n{res.text}\n----------------------------------")
        return None

    # Step 2: Associate individual device template configuration variables
    # https://developer.cisco.com/docs/sd-wan/26-1/create-config-group-device-variables/
    expected_vars = _get_expected_variables(session, base_url, group_id)
    if expected_vars:
        print(f"📋 Configuration Group schema requires variables: {list(expected_vars)}")
    var_url = f"{base_url}/dataservice/v1/config-group/{group_id}/device/variables"
    var_devices = []
    for d in devices_payload:
        # Sanitize keys: Only supply variables that the Configuration Group template is explicitly looking for
        sanitized_vars = {}
        for k, v in d["variables"].items():
            if k in ["raw_row"]: # this is for internal diagnostic only
                continue
            # Normalize CSV header key styles (e.g. "System IP" -> "system_ip", "Rollback Timer (sec)" -> "pseudo_commit_timer")
            normalized_key = k.lower().replace(" ", "_").replace("(", "").replace(")", "")
            if "rollback_timer" in normalized_key:
                normalized_key = "pseudo_commit_timer"

            # Enforce matching verification with the controller schema expectations
            if expected_vars and normalized_key in expected_vars:
                if v is not None and str(v).strip() != "":
                    sanitized_vars[normalized_key] = v

        # Nest the configuration parameters safely inside a "variables" dictionary
        var_devices.append({
            "device-id": d["deviceId"],
            "variables": sanitized_vars
        })
        
    # Include mandatory global solution parameter key
    var_payload = {
        "solution": "sdwan",
        "devices": var_devices
    }
    try:
        res = session.put(var_url, json=var_payload, timeout=15)
        res.raise_for_status()
        print("✅ Configuration variables cleanly associated with edge systems mapping grid.")
    except Exception as e:
        print(f"❌ Variable payload mapping rejected: {e}")
        if 'res' in locals() and hasattr(res, 'text') and res.text:
            print("\n🔍 --- SD-WAN MANAGER SERVER ERROR DETAILS ---")
            print(res.text)
            print("-----------------------------------------------\n")
        print("--------- var payload --------------")
        print(var_payload)
        print("----------------------------------------")
        print("----------devices payload---------------")
        print(devices_payload)
        print("----------------------------------------")
        return None

    # Step 3: Trigger the full Configuration Group orchestration deployment
    # https://developer.cisco.com/docs/sd-wan/26-1/deploy-config-group/
    deploy_url = f"{base_url}/dataservice/v1/config-group/{group_id}/deploy"
    try:
        res = session.post(deploy_url, json=payload, timeout=20)
        res.raise_for_status()
        return res.json().get("parentTaskId")
    except Exception as e:
        print(f"❌ Configuration deployment trigger failed: {e}")
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

def associate_policy_group(session, base_url, policy_group_id, device_ids):
    """
    Associates a list of device UUIDs with a specific Policy Group.
    
    :param session: Authenticated requests.Session object
    :param base_url: Base URL of your SD-WAN Manager (e.g., https://vmanage-ip)
    :param policy_group_id: The UUID of the target Policy Group
    :param device_ids: List of device UUIDs to associate
    """
    url = f"{base_url}/dataservice/v1/config-group/policy-group/{policy_group_id}/associate"
    
    # Structure payload according to Cisco's API Docs
    payload = {
        "devices": [
            {"id": device_id} for device_id in device_ids
        ]
    }
    
    headers = {
        'Content-Type': 'application/json'
    }
    
    try:
        response = session.post(url, json=payload, headers=headers, verify=False)
        response.raise_for_status()
        print(f"Successfully associated devices with Policy Group {policy_group_id}.")
        return response.json()
    except Exception as e:
        print(f"Error associating Policy Group: {e}")
        if 'response' in locals() and response.text:
            print(f"Details: {response.text}")
        return None
    
def deploy_policy_group(session, base_url, policy_group_id, device_ids):
    """
    Deploys the Policy Group for the associated devices.
    
    :param session: Authenticated requests.Session object
    :param base_url: Base URL of your SD-WAN Manager
    :param policy_group_id: The UUID of the target Policy Group
    :param device_ids: List of device UUIDs included in this deployment
    """
    url = f"{base_url}/dataservice/v1/config-group/policy-group/{policy_group_id}/deploy"
    
    # Payload maps the targeted devices to the action
    payload = {
        "devices": [
            {"id": device_id} for device_id in device_ids
        ]
    }
    
    headers = {
        'Content-Type': 'application/json'
    }
    
    try:
        response = session.post(url, json=payload, headers=headers, verify=False)
        response.raise_for_status()
        
        # This will return a dictionary containing the 'parentTaskId'
        task_info = response.json()
        task_id = task_info.get("parentTaskId")
        print(f"Deployment triggered successfully. Task ID: {task_id}")
        return task_id
        
    except Exception as e:
        print(f"Error deploying Policy Group: {e}")
        if 'response' in locals() and response.text:
            print(f"Details: {response.text}")
        return None