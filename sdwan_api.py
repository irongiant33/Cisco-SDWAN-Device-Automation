import time
import getpass
import urllib3
import requests
from config import (
    load_profiles,
    get_cached_config_groups,
    update_profile_tokens,
)
import re
from tabulate import tabulate

urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

def get_xsrf_token(session, base_url):
    # # https://developer.cisco.com/docs/sdwan/authentication/#authentication
    try:
        token_url = f"{base_url}/dataservice/client/token"
        res = session.get(token_url, timeout=5)
        if res.status_code == 200 and res.text:
            return res.text.strip()
    except Exception:
        pass
    return None

def refresh_jwt_access(session, base_url, refresh_token):
    # https://developer.cisco.com/docs/sdwan/authentication/#authentication
    refresh_url = f"{base_url}/jwt/refresh"
    payload = {"refresh": refresh_token}
    try:
        res = session.post(refresh_url, json=payload, timeout=10)
        if res.status_code == 200:
            data = res.json()
            access_token = data.get("token")
            new_refresh = data.get("refresh")
            session.headers.update({
                'Authorization': f"Bearer {access_token}",
                'Content-Type': 'application/json'
            })
            xsrf = get_xsrf_token(session, base_url)
            if xsrf:
                session.headers.update({'X-XSRF-TOKEN': xsrf})
            return new_refresh or refresh_token
    except Exception:
        pass
    return None

def initialize_active_session(base_url, username, profile_data=None):
    session = requests.Session()
    session.verify = False
    
    if profile_data and 'refresh_token' in profile_data:
        print("🔄 Exchanging cached profile refresh token for short-lived JWT access...")
        new_refresh = refresh_jwt_access(session, base_url, profile_data['refresh_token'])
        if new_refresh:
            print("✨ Re-bound cleanly! Re-established Bearer Authorization.")
            update_profile_tokens(base_url, username, new_refresh)
            return session
        print("⚠️ Stored refresh token expired. Prompting credentials...")

    # https://developer.cisco.com/docs/sdwan/authentication/#authentication
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
            
        update_profile_tokens(base_url, username, data.get("refresh"))
        
        print("🔒 Session cache validated and refresh token pinned.")
        return session
    except Exception as e:
        print(f"❌ Handshake crash: {e}")
        return None

def fetch_devices(session, base_url):
    # https://developer.cisco.com/docs/sdwan/getting-started/#get-the-list-of-devices
    url = f"{base_url}/dataservice/device"
    res = session.get(url, timeout=15)
    if res.status_code == 200:
        return res.json().get('data', [])
    raise requests.exceptions.HTTPError(f"HTTP Rejected: {res.status_code}")

def fetch_config_groups(session, base_url, debug=False):
    # https://developer.cisco.com/docs/sd-wan/26-1/get-config-group-by-solution/
    url = f"{base_url}/dataservice/v1/config-group"
    try:
        res = session.get(url, timeout=60)
        if res.status_code == 200:
            return res.json().get('data', []) if isinstance(res.json(), dict) else res.json()
        print(f"❌ Failed to fetch configuration groups (HTTP {res.status_code}).")
        try:
            err = res.json()
            msg = err.get("error", {}).get("message") or err.get("message")
            details = err.get("error", {}).get("details") or err.get("details")
            if msg:
                print(f"   Message: {msg}")
            if details:
                print(f"   Details: {details}")
        except Exception:
            if res.text:
                print(f"   Server response: {res.text}")
    except Exception as e:
        print(f"❌ Exception while fetching configuration groups: {e}")
    return []

def get_config_group_id(session, base_url, name, debug=False):
    cached = get_cached_config_groups(base_url)
    if cached is not None:
        for g in cached:
            if g.get('name') == name or g.get('configGroupName') == name:
                return g.get('id') or g.get('configGroupId')
            g_id = g.get('id') or g.get('configGroupId')
            if g_id == name:
                return g_id
    try:
        groups = fetch_config_groups(session, base_url, debug)
        if debug:
            print(f"{groups=}")
        for g in groups:
            if g.get('name') == name or g.get('configGroupName') == name:
                return g.get('id') or g.get('configGroupId')
    except Exception:
        pass
    return None

def fetch_policy_groups(session, base_url):
    # https://developer.cisco.com/docs/sd-wan/26-1/get-policy-group-by-solution/
    url = f"{base_url}/dataservice/v1/policy-group"
    res = session.get(url, timeout=15)
    if res.status_code == 200:
        return res.json().get('data', []) if isinstance(res.json(), dict) else res.json()
    raise requests.exceptions.HTTPError(f"HTTP Rejected ({res.status_code}): {res.text}")

def fetch_policy_group_associations(session, base_url, policy_group_id):
    url = f"{base_url}/dataservice/v1/{policy_group_id}/device/associate"
    try:
        res = session.get(url, timeout=15)
        if res.status_code == 200:
            return res.json().get('data', [])
    except Exception:
        print("⚠️ Could not fetch policy group associations")
    return []

def _get_expected_variables(session, base_url, group_id):
    # https://developer.cisco.com/docs/sd-wan/26-1/get-config-group-device-variables/
    # a device must be associated with the configuration group before a schema can be retrieved
    url = f"{base_url}/dataservice/v1/config-group/{group_id}/device/variables"
    try:
        res = session.get(url, timeout=30)
        if res.status_code == 200:
            data = res.json()
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
    except Exception as e:
        print(f"⚠️ Warning: Could not retrieve device variables schema: {e}")
    return set()

def _get_config_group_name(session, base_url, group_id):
    try:
        groups = fetch_config_groups(session, base_url)
        for g in groups:
            g_id = g.get('id') or g.get('configGroupId')
            if g_id == group_id:
                return g.get('name') or g.get('configGroupName')
    except Exception:
        pass
    return group_id

def dissociate_device_from_group(session, base_url, old_group_id, device_id):
    # https://developer.cisco.com/docs/sd-wan/26-1/delete-config-group-association/
    url = f"{base_url}/dataservice/v1/config-group/{old_group_id}/device/associate"
    payload = {"devices": [{"id": device_id}]}
    res = session.delete(url, json=payload, timeout=15)
    res.raise_for_status()

def parse_association_conflict(error_text):
    match = re.search(r'device\(s\)-group\(s\):\s*\{(.*?)\}', error_text)
    if not match:
        return {}
    pairs = match.group(1).split(',')
    conflicts = {}
    for pair in pairs:
        if '=' in pair:
            dev, grp = pair.split('=', 1)
            conflicts[dev.strip()] = grp.strip()
    return conflicts

def associate_devices(session, base_url, group_id, devices_payload):
    # https://developer.cisco.com/docs/sd-wan/26-1/create-config-group-association/
    url = f"{base_url}/dataservice/v1/config-group/{group_id}/device/associate"
    assoc_devices = [{"id": d["deviceId"]} for d in devices_payload]
    payload = {"devices": assoc_devices}
    
    try:
        res = session.post(url, json=payload, timeout=15)
        res.raise_for_status()
        print("⏳ Association request accepted. Polling official association table to confirm database replication...")
        
        target_ids = {d["deviceId"] for d in devices_payload}
        verified = False
        check_url = f"{base_url}/dataservice/v1/config-group/{group_id}/device/associate"
        
        for attempt in range(12):  
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
            print(f"⏳ Verification attempt {attempt + 1}/12: Sync pending in database roster. Retrying...")
        return verified
    except Exception as e:
        if 'res' in locals() and hasattr(res, 'text') and res.text:
            try:
                err_data = res.json()
                err_code = err_data.get("error", {}).get("code")
                err_details = err_data.get("error", {}).get("details", "")
                if err_code == "CFGRP0018":
                    conflicts = parse_association_conflict(err_details)
                    if conflicts:
                        proposed_group_name = _get_config_group_name(session, base_url, group_id)
                        table_data = []
                        for dev_id, cur_grp in conflicts.items():
                            table_data.append([dev_id, cur_grp, proposed_group_name])
                            
                        print("\n⚠️  DEVICE CONFIGURATION GROUP CONFLICTS DETECTED:")
                        print(tabulate(table_data, headers=["Device ID", "Current Group", "Proposed Group"], tablefmt="grid"))
                        
                        print("\nConflict Resolution Options:")
                        print(" [1] Stop association (abort)")
                        print(" [2] Associate all devices in the table with the new group (auto-override)")
                        print(" [3] Go device-by-device")
                        
                        while True:
                            choice = input("\n👉 Select conflict resolution option (1-3): ").strip()
                            if choice in ["1", "2", "3"]:
                                break
                            print("⚠️ Invalid entry. Please choose 1, 2, or 3.")
                        
                        if choice == "1":
                            print("❌ Association aborted by user choice.")
                            return False
                            
                        devices_to_associate = [d for d in devices_payload]
                        
                        if choice == "2":
                            for dev_id, cur_grp in conflicts.items():
                                cur_grp_id = get_config_group_id(session, base_url, cur_grp)
                                if cur_grp_id:
                                    print(f"🔄 Dissociating device {dev_id} from group {cur_grp}...")
                                    try:
                                        dissociate_device_from_group(session, base_url, cur_grp_id, dev_id)
                                    except Exception as diss_e:
                                        print(f"❌ Failed to dissociate {dev_id} from {cur_grp}: {diss_e}")
                                else:
                                    print(f"❌ Could not find group ID for '{cur_grp}'. Cannot dissociate device '{dev_id}'.")
                                    # Remove it from our retry list since we can't dissociate it
                                    devices_to_associate = [d for d in devices_to_associate if d["deviceId"] != dev_id]
                                    
                        elif choice == "3":
                            resolved_devices_to_associate = []
                            for dev in devices_payload:
                                dev_id = dev["deviceId"]
                                if dev_id in conflicts:
                                    cur_grp = conflicts[dev_id]
                                    while True:
                                        ans = input(f"\n👉 Move device '{dev_id}' from group '{cur_grp}' to '{proposed_group_name}'? (y/n): ").strip().lower()
                                        if ans in ['y', 'n']:
                                            break
                                        print("⚠️ Invalid entry. Enter 'y' or 'n'.")
                                        
                                    if ans == 'y':
                                        cur_grp_id = get_config_group_id(session, base_url, cur_grp)
                                        if cur_grp_id:
                                            print(f"🔄 Dissociating device {dev_id} from group {cur_grp}...")
                                            try:
                                                dissociate_device_from_group(session, base_url, cur_grp_id, dev_id)
                                                resolved_devices_to_associate.append(dev)
                                            except Exception as diss_e:
                                                print(f"❌ Failed to dissociate {dev_id} from {cur_grp}: {diss_e}")
                                        else:
                                            print(f"❌ Could not find group ID for '{cur_grp}'. Device '{dev_id}' cannot be moved.")
                                    else:
                                        print(f"ℹ️ Skipping device '{dev_id}' (retains group '{cur_grp}').")
                                else:
                                    resolved_devices_to_associate.append(dev)
                            devices_to_associate = resolved_devices_to_associate
                            
                        if not devices_to_associate:
                            print("ℹ️ No devices left to associate. Operation stopped.")
                            return False
                            
                        print(f"\n🚀 Retrying association for {len(devices_to_associate)} device(s) to group '{proposed_group_name}'...")
                        return associate_devices(session, base_url, group_id, devices_to_associate)
            except Exception as parse_e:
                # If anything fails during parsing or resolution, we let it fall through to generic error printing
                pass

        print(f"❌ Structural layout binding rejected: {e}")
        if 'res' in locals() and hasattr(res, 'text') and res.text:
            print(f"\n🔍 --- ERROR DETAILS --- \n{res.text}\n-----------------------")
        return False

def deploy_device_variables(session, base_url, group_id, devices_payload, custom_mappings=None, debug=False):
    custom_mappings = custom_mappings or {}
    expected_vars = _get_expected_variables(session, base_url, group_id)
    if expected_vars and debug:
        print(f"📋 Configuration Group schema requires variables: {list(expected_vars)}")
        
    # https://developer.cisco.com/docs/sd-wan/26-1/create-config-group-device-variables/
    var_url = f"{base_url}/dataservice/v1/config-group/{group_id}/device/variables"
    var_devices = []
    csv_to_schema_map = {csv_col: schema_var for schema_var, csv_col in custom_mappings.items()}

    # variables must match what is expected by the SD-WAN schema
    for d in devices_payload:
        sanitized_vars_list = []
        for k, v in d["variables"].items():
            if k in ["raw_row"]:
                continue
            val_str = str(v).strip()
            if v is None or val_str == "":
                continue

            matched_key = None
            if k in csv_to_schema_map and csv_to_schema_map[k] in expected_vars:
                matched_key = csv_to_schema_map[k]
            elif k in expected_vars:
                matched_key = k
            else:
                variants = [
                    k.lower().replace(" ", "_").replace("(", "").replace(")", ""),
                    k.lower().replace(" ", "-").replace("(", "").replace(")", ""),
                    "pseudo_commit_timer" if "Rollback Timer" in k else None
                ]
                for candidate in variants:
                    if candidate in expected_vars:
                        matched_key = candidate
                        break

            if matched_key:
                typed_value = val_str
                if val_str.lower() in ["true", "false"]:
                    typed_value = (val_str.lower() == "true")
                elif "," in val_str or matched_key in ["vpn1_svi1_dhcp_dns_servers", "vpn1_svi1_dhcp_exclude_range", "dhcp-server_dnsServers"]:
                    typed_value = [item.strip() for item in val_str.split(",") if item.strip()]
                elif matched_key in ["basic_consoleBaudRate", "consoleBaudRate"]:
                    typed_value = val_str
                else:
                    try:
                        if "." in val_str:
                            typed_value = float(val_str)
                        else:
                            typed_value = int(val_str)
                    except ValueError:
                        typed_value = val_str

                sanitized_vars_list.append({"name": matched_key, "value": typed_value})

        var_devices.append({
            "device-id": d["deviceId"],
            "variables": sanitized_vars_list
        })
        
    var_payload = {"solution": "sdwan", "devices": var_devices}
    try:
        res = session.put(var_url, json=var_payload, timeout=15)
        res.raise_for_status()
        print("✅ Configuration variables cleanly associated with edge systems mapping grid.")
    except Exception as e:
        print(f"❌ Variable payload mapping rejected: {e}")
        if 'res' in locals() and hasattr(res, 'text') and res.text:
            print(f"\n🔍 --- ERROR DETAILS --- \n{res.text}\n-----------------------")
        return None

    # https://developer.cisco.com/docs/sd-wan/26-1/deploy-config-group/
    deploy_url = f"{base_url}/dataservice/v1/config-group/{group_id}/device/deploy"
    assoc_devices = [{"id": d["deviceId"]} for d in devices_payload]
    deploy_payload = {"devices": assoc_devices}
    
    try:
        res = session.post(deploy_url, json=deploy_payload, timeout=20)
        res.raise_for_status()
        return res.json().get("parentTaskId")
    except Exception as e:
        print(f"❌ Configuration deployment trigger failed: {e}")
    return None

def poll_task_status(session, base_url, task_id):
    # https://developer.cisco.com/docs/sd-wan/26-1/find-status/
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
    # https://developer.cisco.com/docs/sd-wan/26-1/create-policy-group-association/
    url = f"{base_url}/dataservice/v1/policy-group/{policy_group_id}/device/associate"
    payload = {"devices": [{"id": device_id} for device_id in device_ids]}
    headers = {'Content-Type': 'application/json'}
    try:
        response = session.post(url, json=payload, headers=headers, verify=False)
        response.raise_for_status()
        print(f"Successfully associated devices with Policy Group {policy_group_id}.")
        return response
    except Exception as e:
        print(f"Error associating Policy Group: {e}")
        if 'response' in locals() and hasattr(response, 'text') and response.text:
            print(f"\n🔍 --- ERROR DETAILS --- \n{response.text}\n-----------------------")
        return None
    
def deploy_policy_group(session, base_url, policy_group_id, device_ids):
    # https://developer.cisco.com/docs/sd-wan/26-1/deploy-policy-group/
    url = f"{base_url}/dataservice/v1/policy-group/{policy_group_id}/device/deploy"
    payload = {"devices": [{"id": device_id} for device_id in device_ids]}
    headers = {'Content-Type': 'application/json'}
    try:
        response = session.post(url, json=payload, headers=headers, verify=False)
        response.raise_for_status()
        return response.json().get("parentTaskId")
    except Exception as e:
        print(f"Error deploying Policy Group: {e}")
        if 'response' in locals() and hasattr(response, 'text') and response.text:
            print(f"\n🔍 --- ERROR DETAILS --- \n{response.text}\n-----------------------")
        return None