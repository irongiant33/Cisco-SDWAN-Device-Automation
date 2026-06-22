import csv
import sys
import time
import json
import os
from tabulate import tabulate

from config import get_vmanage_target
from sdwan_api import (
    initialize_active_session, 
    fetch_devices, 
    fetch_config_groups, 
    get_config_group_id, 
    associate_devices,
    deploy_device_variables, 
    poll_task_status,
    fetch_policy_groups,
    fetch_policy_group_associations,
    associate_policy_group,
    deploy_policy_group,
    _get_expected_variables
)

MAPPINGS_FILE = "schema_mappings.json"

def load_local_mappings():
    """Reads persistent custom schema alignment structures from disk storage."""
    if os.path.exists(MAPPINGS_FILE):
        try:
            with open(MAPPINGS_FILE, 'r', encoding='utf-8') as f:
                return json.load(f)
        except Exception:
            return {}
    return {}

def save_local_mappings(mappings):
    """Writes custom alignment structures persistently back to a local JSON layer."""
    try:
        with open(MAPPINGS_FILE, 'w', encoding='utf-8') as f:
            json.dump(mappings, f, indent=4)
    except Exception as e:
        print(f"⚠️ Warning: Could not save layout schema mappings: {e}")

def test_connectivity(session, base_url):
    """CLI Option 1: Live connection diagnostics."""
    print("\n🔄 Interrogating node statistics from inventory directory matrix...")
    try:
        devices = fetch_devices(session, base_url)
        print(f"✅ JWT Bearer Active! Discovered {len(devices)} Edge systems.\n")
        table_data = [[d.get("host-name", "N/A"), d.get("managementIp", "N/A"), d.get("status", "N/A").upper()] for d in devices[:15]]
        print(tabulate(table_data, headers=["Hostname", "Management IP", "Status"], tablefmt="grid"))
    except Exception as e:
        print(f"❌ Exception caught during diagnostic token validation: {e}")

def show_config_groups(session, base_url):
    """CLI Option 2: Fetches and cleanly outputs all Configuration Groups."""
    print("\n📂 Fetching Configuration Groups list matrix from SD-WAN Manager...")
    try:
        groups = fetch_config_groups(session, base_url)
        if not groups:
            print("ℹ️ No configuration groups discovered on this target environment.")
            return
        print(f"✅ Successfully retrieved {len(groups)} Configuration Groups:\n")
        table_data = []
        for g in groups:
            name = g.get('name') or g.get('configGroupName', 'N/A')
            uuid = g.get('id') or g.get('configGroupId', 'N/A')
            solution = g.get('solution', 'N/A')
            devices_count = g.get('associatedDevicesCount', g.get('devicesCount', 'N/A'))
            table_data.append([name, solution, devices_count, uuid])
        print(tabulate(table_data, headers=["Group Name", "Solution Profile", "Associated Devices", "UUID Matrix Key"], tablefmt="grid"))
    except Exception as e:
        print(f"❌ Failed to parse configuration groups array: {e}")

def show_policy_groups(session, base_url):
    """CLI Option 3: Fetches and cleanly outputs all Policy Groups."""
    print("\n📂 Fetching Policy Groups matrix layer from SD-WAN Manager...")
    try:
        groups = fetch_policy_groups(session, base_url)
        if not groups:
            print("ℹ️ No Policy Groups discovered on this target environment.")
            return
        print(f"✅ Successfully retrieved {len(groups)} Policy Groups:\n")
        table_data = []
        for g in groups:
            name = g.get('name', 'N/A')
            uuid = g.get('id', 'N/A')
            desc = g.get('description', 'N/A')
            table_data.append([name, desc, uuid])
        print(tabulate(table_data, headers=["Policy Group Name", "Description", "UUID Matrix Key"], tablefmt="grid"))
    except Exception as e:
        print(f"❌ Failed to parse policy groups directory array: {e}")

def load_manifest_csv():
    """Shared Helper: Loads local target layout configuration files into active python environments."""
    csv_path = input("\n📂 Enter path to your Router Manifest CSV file (e.g., routers.csv): ").strip()
    try:
        with open(csv_path, mode='r', encoding='utf-8-sig') as f:
            reader = csv.DictReader(f)
            headers = reader.fieldnames
            rows = list(reader)
    except FileNotFoundError:
        print(f"❌ File not found at '{csv_path}'. Action canceled.")
        return None, None, None

    devices_payload = []
    for row in rows:
        device_id = row.get("Device ID") or row.get("device_id")
        if not device_id:
            continue
        variables = {}
        for key, value in row.items():
            if key not in ["Device ID", "device_id"] and value is not None:
                variables[key] = str(value).strip()
        devices_payload.append({
            "deviceId": device_id,
            "variables": variables,
            "raw_row": row
        })
    return devices_payload, headers, os.path.basename(csv_path)

def run_association_pipeline(session, base_url):
    """CLI Option 4: Structural layout group registration."""
    res = load_manifest_csv()
    if not res or not res[0]:
        return
    devices_payload, _, _ = res
        
    group_name = input("🏷️ Enter target Configuration Group Name: ").strip()
    group_id = get_config_group_id(session, base_url, group_name) or group_name
    
    print(f"\n🚀 Phase 1: Associating structural layout mappings for {len(devices_payload)} nodes...")
    success = associate_devices(session, base_url, group_id, devices_payload)
    if success:
        print("🎉 Devices successfully linked inside the configuration group roster.")
    else:
        print("❌ Association sequence rejected by controller framework.")

def test_fetch_expected_variables(session, base_url):
    """
    CLI Option 5: Audits expected template variables against CSV columns.
    Guides user step-by-step through any anomalies and logs resolutions to local JSON storage.
    """
    res = load_manifest_csv()
    if not res or not res[0]:
        return
    _, csv_headers, csv_filename = res

    target_input = input("🏷️ Enter Configuration Group Name or UUID: ").strip()
    if not target_input:
        print("❌ Invalid input provided.")
        return
    group_id = get_config_group_id(session, base_url, target_input) or target_input
    print(f"🔍 Fetching variable schema rules for Group: {group_id}...")
    
    expected_vars = _get_expected_variables(session, base_url, group_id)
    if not expected_vars:
        print("ℹ️ No expected variables found, or Configuration Group ID is invalid.")
        return

    print(f"\n✅ Successfully retrieved {len(expected_vars)} schema variables. Initiating alignment check...")
    
    # Analyze automatic formatting styles match variants
    missing_vars = []
    for var in sorted(expected_vars):
        matched = False
        if var in csv_headers:
            matched = True
        else:
            # Check internal naming translation conventions
            for header in csv_headers:
                normalized_header = header.lower().replace(" ", "_").replace("(", "").replace(")", "")
                if "rollback_timer" in normalized_header:
                    normalized_header = "pseudo_commit_timer"
                if normalized_header == var:
                    matched = True
                    break
        if not matched:
            missing_vars.append(var)

    if not missing_vars:
        print("🎉 Perfect Alignment! All expected template parameters automatically map cleanly to your CSV headers.")
        return

    print(f"\n⚠️ Schema Gap Detected! The following {len(missing_vars)} target template variable(s) were not found in the CSV:")
    for mv in missing_vars:
        print(f"  - {mv}")

    print("\n⏱️ Entering Interactive Schema Alignment Wizard...")
    print("For each target field, select the corresponding source index column number from your CSV file.")
    
    # Present option columns array grid index lists
    columns_list = list(csv_headers)
    all_saved_mappings = load_local_mappings()
    csv_specific_mapping = all_saved_mappings.get(csv_filename, {})

    for idx, col in enumerate(columns_list, 1):
        print(f" [{idx}] {col}")
    print(" [S] Skip mapping this specific field")

    for missing_var in missing_vars:
        while True:
            choice = input(f"\n👉 Which CSV column maps to expected schema variable '{missing_var}'? (1-{len(columns_list)} / S): ").strip()
            if choice.lower() == 's':
                print(f"⏭️ Skipping alignment resolution for variable: {missing_var}")
                break
            if choice.isdigit():
                c_idx = int(choice)
                if 1 <= c_idx <= len(columns_list):
                    mapped_column_name = columns_list[c_idx - 1]
                    csv_specific_mapping[missing_var] = mapped_column_name
                    print(f"✅ Mapped: '{missing_var}' <--- CSV Column: '{mapped_column_name}'")
                    break
            print("⚠️ Invalid entry. Choose a column digit or 'S' to skip.")

    all_saved_mappings[csv_filename] = csv_specific_mapping
    save_local_mappings(all_saved_mappings)
    print(f"\n💾 Variable mapping schemas stored successfully under reference index context: '{csv_filename}'")

def run_config_deployment_pipeline(session, base_url):
    """CLI Option 6: Sanitizes parameters, applies custom JSON schema maps, and pushes deployment task."""
    res = load_manifest_csv()
    if not res or not res[0]:
        return
    devices_payload, _, csv_filename = res
        
    group_name = input("🏷️ Enter target Configuration Group Name: ").strip()
    group_id = get_config_group_id(session, base_url, group_name) or group_name
    
    # Automatically retrieve any custom schema alignments recorded during Option 5
    all_saved_mappings = load_local_mappings()
    custom_mappings = all_saved_mappings.get(csv_filename, {})
    if custom_mappings:
        print(f"📋 Loaded {len(custom_mappings)} active custom layout column mapping rules from storage cache.")

    print(f"\n🚀 Phase 2: Processing and pushing variable deployment matrices...")
    task_id = deploy_device_variables(session, base_url, group_id, devices_payload, custom_mappings=custom_mappings)
    
    if task_id:
        print(f"⏳ Monitoring orchestration tracking action loop (ID: {task_id})...")
        success, message = poll_task_status(session, base_url, task_id)
        if success:
            print(f"✅ System group deployment confirmed successful!")
        else:
            print(f"❌ Execution failure flag context: {message}")
    else:
        print("❌ Automation failed to initialize deployment variables execution task.")

def run_policy_deployment_pipeline(session, base_url):
    """CLI Option 7: Validates target policy rules and schedules architecture changes."""
    res = load_manifest_csv()
    if not res or not res[0]:
        return
    devices_payload, _, _ = res
        
    device_ids = [d["deviceId"] for d in devices_payload]
    print("\n🔍 Checking existing Policy Group associations across the target edge pool...")
    all_assocs = fetch_policy_group_associations(session, base_url)
    existing_mappings = {}
    for record in all_assocs:
        p_id = record.get('id')
        for dev in record.get('devices', []):
            if dev.get('id') in device_ids:
                existing_mappings[dev.get('id')] = p_id

    devices_to_migrate = list(device_ids)
    if existing_mappings:
        print("\n⚠️  POLICING CONFLICTS DETECTED:")
        conflict_table = [[dev_id, p_id] for dev_id, p_id in existing_mappings.items()]
        print(tabulate(conflict_table, headers=["Device UUID", "Current Policy Group ID"], tablefmt="grid"))
        
        overwrite = input("\n👉 Do you want to change/overwrite these existing policy group associations? (y/n): ").strip().lower()
        if overwrite != 'y':
            devices_to_migrate = [d for d in device_ids if d not in existing_mappings]

    if not devices_to_migrate:
        print("ℹ️ Operation halted. All targeted devices preserved their current associations.")
        return

    policy_group_id = input("\n🏷️  Enter target Policy Group ID (UUID Matrix Key): ").strip()
    if not policy_group_id:
        print("❌ Invalid entry. Cancelling policy migration phase.")
        return

    print(f"\n🚀 Associating {len(devices_to_migrate)} systems with Policy Group ID: {policy_group_id}...")
    assoc_res = associate_policy_group(session, base_url, policy_group_id, devices_to_migrate)
    if not assoc_res:
        print("❌ Association failed at controller endpoint.")
        return

    print("⏳ Deploying updated security/routing policy architecture matrix changes...")
    task_id = deploy_policy_group(session, base_url, policy_group_id, devices_to_migrate)
    
    if task_id:
        success, msg = poll_task_status(session, base_url, task_id)
        if success:
            print(f"\n📊 POLICY SUMMARY: Successfully migrated {len(devices_to_migrate)} router(s) to Policy Group {policy_group_id}!")
        else:
            print(f"\n❌ Deployment failed: {msg}")
    else:
        print("❌ Failed to initiate asynchronous policy deploy application command on fabric.")

def main():
    base_url, username, profile_data = get_vmanage_target()
    if not base_url or not username:
        sys.exit(1)
        
    session = initialize_active_session(base_url, username, profile_data)
    if not session:
        sys.exit(1)
        
    while True:
        print("\n" + "-"*50)
        print("🎛️  OPERATIONS CONTROL DASHBOARD (CONFIG GROUPS V1)")
        print("-"*50)
        print(" [1] Run Inventory Verification Diagnostic (Test Connectivity)")
        print(" [2] Fetch & List All SD-WAN Configuration Groups")
        print(" [3] Fetch & List All SD-WAN Policy Groups")
        print(" [4] Associate Devices to Configuration Group")
        print(" [5] Audit & Interactively Map Expected Variables Schema")
        print(" [6] Deploy Configuration Group (Variables & Push)")
        print(" [7] Deploy Policy Group changes to Devices")
        print(" [8] Exit Utility")
        
        choice = input("\n👉 Select operational option (1-8): ").strip()
        if choice == "1":
            test_connectivity(session, base_url)
        elif choice == "2":
            show_config_groups(session, base_url)
        elif choice == "3":
            show_policy_groups(session, base_url)
        elif choice == "4":
            run_association_pipeline(session, base_url)
        elif choice == "5":
            test_fetch_expected_variables(session, base_url)
        elif choice == "6":
            run_config_deployment_pipeline(session, base_url)
        elif choice == "7":
            run_policy_deployment_pipeline(session, base_url)
        elif choice == "8":
            print("\n👋 Terminating operations processes. Goodbye.")
            break
        else:
            print("⚠️ Invalid entry. Please choose a value from 1 to 8.")

if __name__ == "__main__":
    main()