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
    poll_task_status
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
        return

    group_name = input("🏷️ Enter target Configuration Group Name: ").strip()
    print("🔍 Fetching Configuration Group structural metadata definitions...")
    group_id = get_config_group_id(session, base_url, group_name)
    
    if not group_id:
        print(f"❌ Aborted: Configuration Group matching name '{group_name}' not discovered on environment.")
        return

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
        return

    print(f"\n🚀 Bundling array mappings. Associating & deploying {len(devices_payload)} nodes...")
    task_id = associate_and_deploy_devices(session, base_url, group_id, devices_payload)
    
    success_count = 0
    failed_count = len(skipped_rows)
    failed_routers = list(skipped_rows)

    if task_id:
        print(f"⏳ Monitoring orchestration tracking action loop (ID: {task_id})...")
        success, message = poll_task_status(session, base_url, task_id)
        if success:
            print(f"✅ System group deployment confirmed successful!")
            success_count = len(devices_payload)
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
        print(" [4] Exit Utility")
        
        choice = input("\n👉 Select operational option (1-4): ").strip()
        if choice == "1":
            test_connectivity(session, base_url)
        elif choice == "2":
            run_migration_pipeline(session, base_url)
        elif choice == "3":
            show_config_groups(session, base_url)
        elif choice == "4":
            print("\n👋 Terminating operations processes. Goodbye.")
            break
        else:
            print("⚠️ Invalid entry. Please choose a value from 1 to 4.")

if __name__ == "__main__":
    main()
