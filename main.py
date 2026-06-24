import csv
import sys
import time
import json
import os
import cmd
import shlex
import glob
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
    if os.path.exists(MAPPINGS_FILE):
        try:
            with open(MAPPINGS_FILE, 'r', encoding='utf-8') as f:
                return json.load(f)
        except Exception:
            return {}
    return {}

def save_local_mappings(mappings):
    try:
        with open(MAPPINGS_FILE, 'w', encoding='utf-8') as f:
            json.dump(mappings, f, indent=4)
    except Exception as e:
        print(f"⚠️ Warning: Could not save layout schema mappings: {e}")

def test_connectivity(session, base_url):
    print("\n🔄 Interrogating node statistics from inventory directory matrix...")
    try:
        devices = fetch_devices(session, base_url)
        print(f"✅ JWT Bearer Active! Discovered {len(devices)} Edge systems.\n")
        table_data = [[d.get("host-name", "N/A"), d.get("managementIp", "N/A"), d.get("status", "N/A").upper()] for d in devices[:15]]
        print(tabulate(table_data, headers=["Hostname", "Management IP", "Status"], tablefmt="grid"))
    except Exception as e:
        print(f"❌ Exception caught during diagnostic token validation: {e}")

def show_config_groups(session, base_url):
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

def load_manifest_csv(csv_path=None):
    if not csv_path:
        csv_files = sorted(glob.glob("*.csv"))
        if csv_files:
            print("\n📂 Discovered CSV Manifest Files:")
            for idx, filename in enumerate(csv_files, 1):
                print(f" [{idx}] {filename}")
            
            while True:
                choice = input(f"\n👉 Select a CSV file (1-{len(csv_files)}) or enter a file path: ").strip()
                if not choice:
                    print("❌ Selection canceled.")
                    return None, None, None
                if choice.isdigit():
                    choice_idx = int(choice) - 1
                    if 0 <= choice_idx < len(csv_files):
                        csv_path = csv_files[choice_idx]
                        break
                    print(f"⚠️ Invalid entry. Please enter a number between 1 and {len(csv_files)} or type a file path.")
                else:
                    csv_path = choice
                    break
        else:
            print("ℹ️ No CSV files found in the local directory.")
            csv_path = input("📂 Enter path to your Router Manifest CSV file: ").strip()
            if not csv_path:
                print("❌ Selection canceled.")
                return None, None, None

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

def run_association_pipeline(session, base_url, csv_path=None, group_name=None):
    res = load_manifest_csv(csv_path)
    if not res or not res[0]:
        return
    devices_payload, _, _ = res
        
    if not group_name:
        group_name = input("🏷️ Enter target Configuration Group Name: ").strip()
    group_id = get_config_group_id(session, base_url, group_name)
    
    print(f"\n🚀 Phase 1: Associating structural layout mappings for {len(devices_payload)} nodes...")
    success = associate_devices(session, base_url, group_id, devices_payload)
    if success:
        print("🎉 Devices successfully linked inside the configuration group roster.")
    else:
        print("❌ Association sequence rejected by controller framework.")

def test_fetch_expected_variables(session, base_url, csv_path=None, target_input=None):
    """
    CLI Option 5: Audits expected template variables against CSV columns.
    Saves alignment resolutions and outputs a custom layout mapping overview block.
    """
    res = load_manifest_csv(csv_path)
    if not res or not res[0]:
        return
    devices_payload, csv_headers, csv_filename = res

    if not target_input:
        target_input = input("🏷️ Enter Configuration Group Name or UUID: ").strip()
    if not target_input:
        print("❌ Invalid input provided.")
        return
    group_id = get_config_group_id(session, base_url, target_input)
    print(f"🔍 Fetching variable schema rules for Group: {group_id}...")
    
    expected_vars = _get_expected_variables(session, base_url, group_id)
    if not expected_vars:
        print("ℹ️ No expected variables found, or Configuration Group ID is invalid.")
        return

    print(f"\n✅ Successfully retrieved {len(expected_vars)} schema variables. Checking layout maps...")
    
    missing_vars = []
    for var in sorted(expected_vars):
        matched = False
        if var in csv_headers:
            matched = True
        else:
            for header in csv_headers:
                normalized_header = header.lower().replace(" ", "_").replace("(", "").replace(")", "")
                if "rollback_timer" in normalized_header:
                    normalized_header = "pseudo_commit_timer"
                if normalized_header == var:
                    matched = True
                    break
        if not matched:
            missing_vars.append(var)

    all_saved_mappings = load_local_mappings()
    csv_specific_mapping = all_saved_mappings.get(csv_filename, {})

    if missing_vars:
        print(f"\n⚠️ Schema Gap Detected! {len(missing_vars)} target template variable(s) were not found in the CSV.")
        columns_list = list(csv_headers)
        for idx, col in enumerate(columns_list, 1):
            print(f" [{idx}] {col}")
        print(" [S] Skip mapping this specific field")

        for missing_var in missing_vars:
            while True:
                choice = input(f"\n👉 Which CSV column maps to expected schema variable '{missing_var}'? (1-{len(columns_list)} / S): ").strip()
                if choice.lower() == 's':
                    break
                if choice.isdigit():
                    c_idx = int(choice)
                    if 1 <= c_idx <= len(columns_list):
                        mapped_column_name = columns_list[c_idx - 1]
                        csv_specific_mapping[missing_var] = mapped_column_name
                        print(f"✅ Mapped: '{missing_var}' <--- CSV Column: '{mapped_column_name}'")
                        break
                print("⚠️ Invalid entry. Choose a column digit or 'S'.")

        all_saved_mappings[csv_filename] = csv_specific_mapping
        save_local_mappings(all_saved_mappings)

    # Invert custom mappings for rapid lookup identification
    csv_to_schema_map = {csv_col: schema_var for schema_var, csv_col in csv_specific_mapping.items()}

    # --- PRINT FULL DEPLOYMENT PREVIEW MAPPING LAYOUT ---
    print("\n" + "="*75)
    print(f"📊 LIVE VARIABLE MAPPING SUMMARY PREVIEW")
    print("="*75)
    
    sample_node = devices_payload[0]
    sample_vars = sample_node['variables']
    
    # Print leading reference key
    print(f"Device ID: {sample_node['deviceId']}")

    for idx, var in enumerate(sorted(expected_vars), 2):
        matched_csv_header = "❌ NOT MAPPED"
        raw_value = "⚠️ MISSING"

        if var in csv_specific_mapping:
            matched_csv_header = csv_specific_mapping[var]
            raw_value = sample_vars.get(matched_csv_header, raw_value)
        elif var in sample_vars:
            matched_csv_header = var
            raw_value = sample_vars[var]
        else:
            for k, v in sample_vars.items():
                normalized = k.lower().replace(" ", "_").replace("(", "").replace(")", "")
                if "rollback_timer" in normalized:
                    normalized = "pseudo_commit_timer"
                if csv_to_schema_map.get(k) == var or normalized == var:
                    matched_csv_header = k
                    raw_value = v
                    break

        # Wrap string rendering formatting criteria correctly
        if isinstance(raw_value, str) and raw_value != "⚠️ MISSING":
            # Add explicit quote marks for text strings
            if not raw_value.replace('.','',1).isdigit() and raw_value.lower() not in ['true', 'false'] and ',' not in raw_value:
                formatted_val = f'"{raw_value}"'
            else:
                formatted_val = raw_value
        else:
            formatted_val = raw_value

        print(f" [{idx}] {matched_csv_header} - {var} = {formatted_val}")
        
    print("\n💡 Verify the parameters above. If accurate, proceed to execute deployment.")

def run_config_deployment_pipeline(session, base_url, csv_path=None, group_name=None):
    res = load_manifest_csv(csv_path)
    if not res or not res[0]:
        return
    devices_payload, _, csv_filename = res
        
    if not group_name:
        group_name = input("🏷️ Enter target Configuration Group Name: ").strip()
    group_id = get_config_group_id(session, base_url, group_name)
    
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

def get_policy_group_id(session, base_url, name):
    """Translates user-provided text name into vManage policy group UUID."""
    try:
        groups = fetch_policy_groups(session, base_url)
        for g in groups:
            if g.get('name') == name:
                return g.get('id')
    except Exception:
        pass
    return None

def run_policy_deployment_pipeline(session, base_url, csv_path=None, policy_input=None):
    res = load_manifest_csv(csv_path)
    if not res or not res[0]:
        return
    devices_payload, _, _ = res

    if not policy_input:
        policy_input = input("\n🏷️ Enter target Policy Group Name or UUID: ").strip()
    if not policy_input:
        print("❌ Invalid entry. Cancelling policy migration phase.")
        return

    # Look up Policy Group Name to convert into the mandatory validation UUID string
    policy_group_id = get_policy_group_id(session, base_url, policy_input)
        
    device_ids = [d["deviceId"] for d in devices_payload]
    print("\n🔍 Checking existing Policy Group associations across the target edge pool...")
    all_assocs = fetch_policy_group_associations(session, base_url, policy_group_id)
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

class SDWANShell(cmd.Cmd):
    intro = (
        "\n" + "="*70 + "\n"
        "🎛️  SD-WAN DEVICE AUTOMATION INTERACTIVE SHELL (CONFIG GROUPS V1)\n"
        "======================================================================\n"
        " Type 'help' or '?' to list available commands.\n"
        " Commands support direct arguments (e.g., command <csv_path> <group>)\n"
        " or will prompt you interactively if arguments are missing.\n"
        " Tab-completion is supported for CSV file paths.\n"
        "======================================================================\n"
    )
    prompt = "sdwan> "

    def __init__(self, session, base_url):
        super().__init__()
        self.session = session
        self.base_url = base_url

    def emptyline(self):
        """Do nothing on empty input line."""
        pass

    def _complete_csv_files(self, text, line, begidx, endidx):
        import glob
        # We find arguments split by space up to the start of the current word being completed
        cmd_args = line[:begidx].split()
        # If we are completing the first argument to the command (cmd_args has length 1: the command name)
        if len(cmd_args) == 1:
            # Let's search for files matching text
            files = glob.glob(text + "*")
            return [f for f in files if f.endswith('.csv') or os.path.isdir(f)]
        return []

    def do_test_connectivity(self, arg):
        """Run Inventory Verification Diagnostic (Test Connectivity).
        Usage: test_connectivity
        """
        test_connectivity(self.session, self.base_url)

    def do_show_config_groups(self, arg):
        """Fetch & List All SD-WAN Configuration Groups.
        Usage: show_config_groups
        """
        show_config_groups(self.session, self.base_url)

    def do_show_policy_groups(self, arg):
        """Fetch & List All SD-WAN Policy Groups.
        Usage: show_policy_groups
        """
        show_policy_groups(self.session, self.base_url)

    def do_associate_devices(self, arg):
        """Associate Devices to Configuration Group.
        Usage: associate_devices [csv_path] [group_name]
        """
        args = shlex.split(arg)
        csv_path = args[0] if len(args) > 0 else None
        group_name = args[1] if len(args) > 1 else None
        run_association_pipeline(self.session, self.base_url, csv_path, group_name)

    def do_audit_variables(self, arg):
        """Audit & Interactively Map Expected Variables Schema.
        Usage: audit_variables [csv_path] [group_name_or_uuid]
        """
        args = shlex.split(arg)
        csv_path = args[0] if len(args) > 0 else None
        target_input = args[1] if len(args) > 1 else None
        test_fetch_expected_variables(self.session, self.base_url, csv_path, target_input)

    def do_deploy_config(self, arg):
        """Deploy Configuration Group (Variables & Push).
        Usage: deploy_config [csv_path] [group_name]
        """
        args = shlex.split(arg)
        csv_path = args[0] if len(args) > 0 else None
        group_name = args[1] if len(args) > 1 else None
        run_config_deployment_pipeline(self.session, self.base_url, csv_path, group_name)

    def do_deploy_policy(self, arg):
        """Deploy Policy Group changes to Devices.
        Usage: deploy_policy [csv_path] [policy_name_or_uuid]
        """
        args = shlex.split(arg)
        csv_path = args[0] if len(args) > 0 else None
        policy_input = args[1] if len(args) > 1 else None
        run_policy_deployment_pipeline(self.session, self.base_url, csv_path, policy_input)

    def do_clear(self, arg):
        """Clear the terminal output.
        Usage: clear
        """
        os.system('cls' if os.name == 'nt' else 'clear')

    def do_exit(self, arg):
        """Exit the interactive shell.
        Usage: exit
        """
        print("\n👋 Terminating operations processes. Goodbye.")
        return True

def main():
    base_url, username, profile_data = get_vmanage_target()
    if not base_url or not username:
        sys.exit(1)
        
    session = initialize_active_session(base_url, username, profile_data)
    if not session:
        sys.exit(1)
        
    SDWANShell(session, base_url).cmdloop()

if __name__ == "__main__":
    try:
        main()
    except KeyboardInterrupt:
        print("\n👋 Terminating operations processes. Goodbye.")
        sys.exit(0)