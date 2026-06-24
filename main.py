import csv
import sys
import time
import json
import os
import cmd
import shlex
import glob
import re
from collections import Counter
from tabulate import tabulate

from config import (
    get_vmanage_target,
    get_cached_config_groups,
    get_cached_policy_groups,
    save_config_groups_cache,
    save_policy_groups_cache,
)
from sdwan_api import (
    initialize_active_session, 
    fetch_devices, 
    fetch_config_groups, 
    associate_devices,
    deploy_device_variables, 
    poll_task_status,
    fetch_policy_groups,
    fetch_policy_group_associations,
    associate_policy_group,
    deploy_policy_group,
    _get_expected_variables,
    build_config_group_device_map,
    build_policy_group_device_map,
    build_device_inventory_map,
    lookup_inventory_record,
    lookup_group_record,
    normalize_sync_status,
    normalize_reachability,
)

MAPPINGS_FILE = "schema_mappings.json"
UUID_PATTERN = re.compile(
    r'^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$',
    re.I,
)

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
        save_config_groups_cache(base_url, groups)
        print("💾 Cached configuration groups locally in sdwan_profiles.json.")
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
        save_policy_groups_cache(base_url, groups)
        print("💾 Cached policy groups locally in sdwan_profiles.json.")
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

def _config_group_display_name(group):
    return group.get('name') or group.get('configGroupName', 'N/A')

def _policy_group_display_name(group):
    return group.get('name', 'N/A')

def _is_uuid(value):
    return bool(UUID_PATTERN.match(value))

def _find_config_group(groups, name_or_id):
    for g in groups:
        g_id = g.get('id') or g.get('configGroupId')
        g_name = _config_group_display_name(g)
        if name_or_id in (g_name, g_id):
            return g_id, g_name
    if _is_uuid(name_or_id):
        return name_or_id, name_or_id
    return None, None

def _find_policy_group(groups, name_or_id):
    for g in groups:
        g_id = g.get('id')
        g_name = _policy_group_display_name(g)
        if name_or_id in (g_name, g_id):
            return g_id, g_name
    if _is_uuid(name_or_id):
        return name_or_id, name_or_id
    return None, None

def _prompt_manual_config_group():
    print("\nℹ️ No cached Configuration Groups found for this environment.")
    print("   Run 'show_config_groups' to refresh the list from SD-WAN Manager,")
    print("   or enter a Configuration Group UUID manually below.")
    group_input = input("\n🏷️ Enter Configuration Group Name or UUID: ").strip()
    if not group_input:
        print("❌ Selection canceled.")
        return None, None
    if _is_uuid(group_input):
        return group_input, group_input
    print(f"❌ Cannot resolve configuration group name '{group_input}' without a local cache.")
    print("   Run 'show_config_groups' first, then retry.")
    return None, None

def _prompt_manual_policy_group():
    print("\nℹ️ No cached Policy Groups found for this environment.")
    print("   Run 'show_policy_groups' to refresh the list from SD-WAN Manager,")
    print("   or enter a Policy Group UUID manually below.")
    policy_input = input("\n🏷️ Enter Policy Group Name or UUID: ").strip()
    if not policy_input:
        print("❌ Selection canceled.")
        return None, None
    if _is_uuid(policy_input):
        return policy_input, policy_input
    print(f"❌ Cannot resolve policy group name '{policy_input}' without a local cache.")
    print("   Run 'show_policy_groups' first, then retry.")
    return None, None

def select_config_group(session, base_url, group_input=None):
    """
    Prompt for or resolve a configuration group using the local cache.
    Returns (group_id, group_name) or (None, None) on cancel/failure.
    """
    if group_input:
        group_input = group_input.strip()
        if not group_input:
            return None, None
        groups = get_cached_config_groups(base_url)
        if groups is None:
            if _is_uuid(group_input):
                return group_input, group_input
            print("\nℹ️ No cached Configuration Groups found for this environment.")
            print("   Run 'show_config_groups' to refresh the list from SD-WAN Manager.")
            print(f"❌ Cannot resolve configuration group name '{group_input}' without a local cache.")
            return None, None
        group_id, group_name = _find_config_group(groups, group_input)
        if not group_id:
            print(f"❌ Configuration group '{group_input}' not found in local cache.")
            print("   Run 'show_config_groups' to refresh the list, then retry.")
            return None, None
        return group_id, group_name

    groups = get_cached_config_groups(base_url)
    if groups is None:
        return _prompt_manual_config_group()

    if not groups:
        print("ℹ️ Cached configuration group list is empty for this environment.")
        return _prompt_manual_config_group()

    if len(groups) > 20:
        group_input = input(
            f"\n🏷️ {len(groups)} configuration groups in cache. Enter Configuration Group Name or UUID: "
        ).strip()
        if not group_input:
            print("❌ Selection canceled.")
            return None, None
        group_id, group_name = _find_config_group(groups, group_input)
        if not group_id:
            print(f"❌ Configuration group '{group_input}' not found in local cache.")
            print("   Run 'show_config_groups' to refresh the list, then retry.")
            return None, None
        return group_id, group_name

    print("\n📂 Available Configuration Groups (from local cache):")
    for idx, g in enumerate(groups, 1):
        name = _config_group_display_name(g)
        solution = g.get('solution', 'N/A')
        print(f" [{idx}] {name} ({solution})")

    while True:
        choice = input(
            f"\n👉 Select a Configuration Group (1-{len(groups)}) or enter a name/UUID: "
        ).strip()
        if not choice:
            print("❌ Selection canceled.")
            return None, None
        if choice.isdigit():
            choice_idx = int(choice) - 1
            if 0 <= choice_idx < len(groups):
                g = groups[choice_idx]
                return g.get('id') or g.get('configGroupId'), _config_group_display_name(g)
            print(f"⚠️ Invalid entry. Please enter a number between 1 and {len(groups)} or type a name/UUID.")
            continue
        group_id, group_name = _find_config_group(groups, choice)
        if group_id:
            return group_id, group_name
        print(f"⚠️ Configuration group '{choice}' not found in local cache. Try again or run 'show_config_groups'.")

def select_policy_group(session, base_url, policy_input=None):
    """
    Prompt for or resolve a policy group using the local cache.
    Returns (policy_group_id, policy_group_name) or (None, None) on cancel/failure.
    """
    if policy_input:
        policy_input = policy_input.strip()
        if not policy_input:
            return None, None
        groups = get_cached_policy_groups(base_url)
        if groups is None:
            if _is_uuid(policy_input):
                return policy_input, policy_input
            print("\nℹ️ No cached Policy Groups found for this environment.")
            print("   Run 'show_policy_groups' to refresh the list from SD-WAN Manager.")
            print(f"❌ Cannot resolve policy group name '{policy_input}' without a local cache.")
            return None, None
        group_id, group_name = _find_policy_group(groups, policy_input)
        if not group_id:
            print(f"❌ Policy group '{policy_input}' not found in local cache.")
            print("   Run 'show_policy_groups' to refresh the list, then retry.")
            return None, None
        return group_id, group_name

    groups = get_cached_policy_groups(base_url)
    if groups is None:
        return _prompt_manual_policy_group()

    if not groups:
        print("ℹ️ Cached policy group list is empty for this environment.")
        return _prompt_manual_policy_group()

    if len(groups) > 20:
        policy_input = input(
            f"\n🏷️ {len(groups)} policy groups in cache. Enter Policy Group Name or UUID: "
        ).strip()
        if not policy_input:
            print("❌ Selection canceled.")
            return None, None
        group_id, group_name = _find_policy_group(groups, policy_input)
        if not group_id:
            print(f"❌ Policy group '{policy_input}' not found in local cache.")
            print("   Run 'show_policy_groups' to refresh the list, then retry.")
            return None, None
        return group_id, group_name

    print("\n📂 Available Policy Groups (from local cache):")
    for idx, g in enumerate(groups, 1):
        name = _policy_group_display_name(g)
        desc = g.get('description', 'N/A')
        print(f" [{idx}] {name} ({desc})")

    while True:
        choice = input(
            f"\n👉 Select a Policy Group (1-{len(groups)}) or enter a name/UUID: "
        ).strip()
        if not choice:
            print("❌ Selection canceled.")
            return None, None
        if choice.isdigit():
            choice_idx = int(choice) - 1
            if 0 <= choice_idx < len(groups):
                g = groups[choice_idx]
                return g.get('id'), _policy_group_display_name(g)
            print(f"⚠️ Invalid entry. Please enter a number between 1 and {len(groups)} or type a name/UUID.")
            continue
        group_id, group_name = _find_policy_group(groups, choice)
        if group_id:
            return group_id, group_name
        print(f"⚠️ Policy group '{choice}' not found in local cache. Try again or run 'show_policy_groups'.")

def run_association_pipeline(session, base_url, csv_path=None, group_name=None):
    res = load_manifest_csv(csv_path)
    if not res or not res[0]:
        return
    devices_payload, _, _ = res

    group_id, group_name = select_config_group(session, base_url, group_name)
    if not group_id:
        return

    print(f"\n🚀 Phase 1: Associating structural layout mappings for {len(devices_payload)} nodes to '{group_name}'...")
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

    group_id, group_name = select_config_group(session, base_url, target_input)
    if not group_id:
        return
    print(f"🔍 Fetching variable schema rules for Group '{group_name}' ({group_id})...")
    
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

    group_id, group_name = select_config_group(session, base_url, group_name)
    if not group_id:
        return

    all_saved_mappings = load_local_mappings()
    custom_mappings = all_saved_mappings.get(csv_filename, {})
    if custom_mappings:
        print(f"📋 Loaded {len(custom_mappings)} active custom layout column mapping rules from storage cache.")

    print(f"\n🚀 Phase 2: Processing and pushing variable deployment matrices to '{group_name}'...")
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

def run_policy_deployment_pipeline(session, base_url, csv_path=None, policy_input=None):
    res = load_manifest_csv(csv_path)
    if not res or not res[0]:
        return
    devices_payload, _, _ = res

    policy_group_id, policy_group_name = select_policy_group(session, base_url, policy_input)
    if not policy_group_id:
        return
        
    device_ids = [d["deviceId"] for d in devices_payload]
    print(f"\n🔍 Checking existing Policy Group associations for '{policy_group_name}' across the target edge pool...")
    all_assocs = fetch_policy_group_associations(session, base_url, policy_group_id)
    existing_mappings = {}
    for dev in all_assocs:
        dev_id = dev.get('id') if isinstance(dev, dict) else dev
        if dev_id in device_ids:
            existing_mappings[dev_id] = policy_group_id

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

def _get_group_lists_for_status(session, base_url):
    config_groups = get_cached_config_groups(base_url)
    policy_groups = get_cached_policy_groups(base_url)

    if config_groups is None:
        print("\nℹ️ No cached Configuration Groups found.")
        print("   Run 'show_config_groups' to refresh the list. Fetching live from SD-WAN Manager now...")
        try:
            config_groups = fetch_config_groups(session, base_url)
        except Exception as e:
            print(f"❌ Failed to fetch configuration groups: {e}")
            config_groups = []

    if policy_groups is None:
        print("\nℹ️ No cached Policy Groups found.")
        print("   Run 'show_policy_groups' to refresh the list. Fetching live from SD-WAN Manager now...")
        try:
            policy_groups = fetch_policy_groups(session, base_url)
        except Exception as e:
            print(f"❌ Failed to fetch policy groups: {e}")
            policy_groups = []

    return config_groups, policy_groups

def _print_count_summary(title, counter):
    print(f"\n{title}")
    if not counter:
        print("  (none)")
        return
    for label, count in sorted(counter.items(), key=lambda item: (-item[1], str(item[0]))):
        print(f"  {label}: {count}")

def run_device_status_report(session, base_url, csv_path=None):
    res = load_manifest_csv(csv_path)
    if not res or not res[0]:
        return
    devices_payload, _, csv_filename = res
    target_device_ids = [d["deviceId"] for d in devices_payload]

    print(f"\n🔍 Checking status for {len(target_device_ids)} device(s) from '{csv_filename}'...")
    config_groups, policy_groups = _get_group_lists_for_status(session, base_url)

    print("🔄 Fetching device inventory...")
    try:
        inventory = fetch_devices(session, base_url)
    except Exception as e:
        print(f"❌ Failed to fetch device inventory: {e}")
        return
    inventory_map = build_device_inventory_map(inventory)

    print("🔄 Resolving configuration group associations...")
    config_group_map = build_config_group_device_map(
        session, base_url, config_groups, target_device_ids=target_device_ids
    )

    print("🔄 Resolving policy group associations...")
    policy_group_map = build_policy_group_device_map(
        session, base_url, policy_groups, target_device_ids=target_device_ids
    )

    rows = []
    config_group_counts = Counter()
    policy_group_counts = Counter()
    reachability_counts = Counter()
    sync_status_counts = Counter()

    for device_id in target_device_ids:
        _, config_record = lookup_group_record(config_group_map, device_id)
        _, policy_record = lookup_group_record(policy_group_map, device_id)
        inventory_record = lookup_inventory_record(inventory_map, device_id)

        config_group = config_record.get("config_group", "None") if config_record else "None"
        policy_group = policy_record.get("policy_group", "None") if policy_record else "None"
        association = config_record.get("association") if config_record else None
        reachability = normalize_reachability(inventory_record)
        sync_status = normalize_sync_status(association, inventory_record)

        rows.append([
            device_id,
            config_group,
            policy_group,
            reachability,
            sync_status,
        ])
        config_group_counts[config_group] += 1
        policy_group_counts[policy_group] += 1
        reachability_counts[reachability] += 1
        sync_status_counts[sync_status] += 1

    print("\n" + "=" * 90)
    print("📊 DEVICE STATUS REPORT")
    print("=" * 90)
    print(tabulate(
        rows,
        headers=["Device ID", "Config Group", "Policy Group", "Reachability", "Sync Status"],
        tablefmt="grid",
    ))

    print("\n" + "=" * 90)
    print("📈 SUMMARY")
    print("=" * 90)
    _print_count_summary("Configuration Groups:", config_group_counts)
    _print_count_summary("Policy Groups:", policy_group_counts)

    reachable = reachability_counts.get("Reachable", 0)
    unreachable = reachability_counts.get("Unreachable", 0)
    print("\nReachability:")
    print(f"  Reachable: {reachable}")
    print(f"  Unreachable: {unreachable}")
    unknown_reachability = len(target_device_ids) - reachable - unreachable
    if unknown_reachability:
        print(f"  Unknown: {unknown_reachability}")

    in_sync = sync_status_counts.get("In Sync", 0)
    out_of_sync = sync_status_counts.get("Out of Sync", 0)
    sync_pending = sync_status_counts.get("Sync Pending", 0)
    print("\nSync Status:")
    print(f"  In Sync: {in_sync}")
    print(f"  Out of Sync: {out_of_sync}")
    print(f"  Sync Pending: {sync_pending}")
    other_sync = len(target_device_ids) - in_sync - out_of_sync - sync_pending
    if other_sync:
        print(f"  Other/Unknown: {other_sync}")

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
        """Fetch & List All SD-WAN Configuration Groups. Stores a cached copy in sdwan_profiles.json.
        Usage: show_config_groups
        """
        show_config_groups(self.session, self.base_url)

    def do_show_policy_groups(self, arg):
        """Fetch & List All SD-WAN Policy Groups. Stores a cached copy in sdwan_profiles.json.
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

    def do_device_status(self, arg):
        """Check device status for routers listed in a CSV manifest.
        Usage: device_status [csv_path]
        """
        args = shlex.split(arg)
        csv_path = args[0] if len(args) > 0 else None
        run_device_status_report(self.session, self.base_url, csv_path)

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