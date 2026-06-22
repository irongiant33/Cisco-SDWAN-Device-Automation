import csv
import sys
import time
from tabulate import tabulate

from config import get_vmanage_target
from sdwan_api import (
    initialize_active_session, 
    fetch_devices, 
    fetch_config_groups, 
    get_config_group_id, 
    associate_and_deploy_devices, 
    poll_task_status,
    fetch_policy_groups,
    fetch_policy_group_associations,
    associate_policy_group,
    deploy_policy_group,
    _get_expected_variables
)

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

def test_fetch_expected_variables(session, base_url):
    """CLI Option 5: Prompts for a Configuration Group and lists its expected variables schema."""
    target_input = input("\n🏷️ Enter Configuration Group Name or UUID: ").strip()
    if not target_input:
        print("❌ Invalid input provided.")
        return

    # Try to resolve Name to UUID first; if it returns None, assume user provided the UUID directly.
    group_id = get_config_group_id(session, base_url, target_input) or target_input
    print(f"🔍 Fetching variable schema rules for Group: {group_id}")
    
    expected_vars = _get_expected_variables(session, base_url, group_id)
    if expected_vars:
        print(f"\n✅ Successfully retrieved {len(expected_vars)} schema variables:")
        for var in sorted(expected_vars):
            print(f"  - {var}")
    else:
        print("ℹ️ No expected variables found, or Configuration Group ID is invalid.")


def run_migration_pipeline(session, base_url):
    """CLI Option 2: Loads target layout structures, configures systems, tracking errors."""
    csv_path = input("\n📂 Enter path to your Router Manifest CSV file (e.g., routers.csv): ").strip()
    try:
        with open(csv_path, mode='r', encoding='utf-8-sig') as f:
            reader = csv.DictReader(f)
            headers = reader.fieldnames
            rows = list(reader)
    except FileNotFoundError:
        print(f"❌ File not found at '{csv_path}'. Returning to dashboard.")
        return []

    group_name = input("🏷️ Enter target Configuration Group Name: ").strip()
    print("🔍 Fetching Configuration Group structural metadata definitions...")
    group_id = get_config_group_id(session, base_url, group_name)
    
    if not group_id:
        print(f"❌ Aborted: Configuration Group matching name '{group_name}' not discovered on environment.")
        return []

    devices_payload = []
    skipped_rows = []
    
    for row in rows:
        device_id = row.get("Device ID") or row.get("device_id")
        if not device_id:
            skipped_rows.append(row)
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

    if not devices_payload:
        print("❌ CSV does not contain records with valid device identifier tokens.")
        return []

    print(f"\n🚀 Bundling array mappings. Associating & deploying {len(devices_payload)} nodes...")
    task_id = associate_and_deploy_devices(session, base_url, group_id, devices_payload)
    
    migrated_device_ids = []

    success_count = 0
    failed_count = len(skipped_rows)
    failed_routers = list(skipped_rows)

    if task_id:
        print(f"⏳ Monitoring orchestration tracking action loop (ID: {task_id})...")
        success, message = poll_task_status(session, base_url, task_id)
        if success:
            print(f"✅ System group deployment confirmed successful!")
            success_count = len(devices_payload)
            migrated_device_ids = [d["deviceId"] for d in devices_payload]
        else:
            print(f"❌ Execution failure flag context: {message}")
            failed_count += len(devices_payload)
            for d in devices_payload:
                failed_routers.append(d["raw_row"])
    else:
        print("❌ Automation failed to initialize transactions on controller framework layer.")
        failed_count += len(devices_payload)
        for d in devices_payload:
            failed_routers.append(d["raw_row"])

    stats_table = [
        ["Manifest Targets Parsed", len(rows)],
        ["Successfully Configured", success_count],
        ["Failed / Rejected Lines", failed_count]
    ]
    print("\n📊 CONFIGURATION GROUP PIPELINE SUMMARY")
    print(tabulate(stats_table, headers=["Metric", "Count"], tablefmt="grid"))

    if failed_routers:
        failed_csv_name = f"failed_routers_{int(time.time())}.csv"
        with open(failed_csv_name, mode='w', newline='', encoding='utf-8') as f:
            writer = csv.DictWriter(f, fieldnames=headers)
            writer.writeheader()
            writer.writerows(failed_routers)
        print(f"\n💾 Exported unmigrated structured fallback data matrix to: '{failed_csv_name}'")
    else:
        print("\n🎉 Absolute execution confirmation. All nodes cleanly provisioned.")
    
    return migrated_device_ids

def run_policy_group_pipeline(session, base_url, device_ids):
    """Tracks policy overrides, prompts input ID, deploys and records failures to local CSV."""
    if not device_ids:
        print("⚠️ No valid devices available for policy operations.")
        return

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
            _write_policy_failures(devices_to_migrate, f"Task {task_id} Failed: {msg}")
    else:
        print("❌ Failed to initiate asynchronous policy deploy application command on fabric.")
        _write_policy_failures(devices_to_migrate, "Controller rejected policy deployment activation trigger.")

def _write_policy_failures(device_ids, reason):
    fail_file = f"failed_policy_migrations_{int(time.time())}.csv"
    with open(fail_file, mode='w', newline='', encoding='utf-8') as f:
        writer = csv.writer(f)
        writer.writerow(["Device ID", "Failure Reason"])
        for d in device_ids:
            writer.writerow([d, reason])
    print(f"💾 Local fallback error sheet generated: '{fail_file}'")

def show_policy_groups(session, base_url):
    """CLI Option 5: Fetches and cleanly outputs all Policy Groups."""
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

def show_config_groups(session, base_url):
    """CLI Option 3: Fetches and cleanly outputs all Configuration Groups."""
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
        print(" [2] Load Manifest CSV & Run Template Migration Pipeline")
        print(" [3] Fetch & List All SD-WAN Configuration Groups")
        print(" [4] Fetch & List All SD-WAN Policy Groups")
        print(" [5] Test Expected Variables Schema Lookup for a Group")
        print(" [6] Exit Utility")
        
        
        choice = input("\n👉 Select operational option (1-6): ").strip()
        if choice == "1":
            test_connectivity(session, base_url)
        elif choice == "2":
            migrated_routers = run_migration_pipeline(session, base_url)
            if migrated_routers:
                run_p = input("\n❓ Do you want to associate these routers to a policy group now? (y/n): ").strip().lower()
                if run_p == 'y':
                    run_policy_group_pipeline(session, base_url, migrated_routers)
        elif choice == "3":
            show_config_groups(session, base_url)
        elif choice == '4':
            show_policy_groups(session, base_url)
        elif choice == "5":
            test_fetch_expected_variables(session, base_url)
        elif choice == "6":
            print("\n👋 Terminating operations processes. Goodbye.")
            break
        else:
            print("⚠️ Invalid entry. Please choose a value from 1 to 6.")

if __name__ == "__main__":
    main()
