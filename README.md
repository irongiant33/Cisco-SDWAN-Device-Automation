# Cisco Catalyst SD-WAN Configuration Group Automation Engine

This Python-based command-line interface (CLI) automation suite simplifies and speeds up deploying devices to **Configuration Groups** in Cisco Catalyst SD-WAN Manager (formerly vManage), matching the modern UX 2.0 / Release 26.x API specifications. Alternatively, you can consider the use of this tool: https://github.com/CiscoDevNet/sastre

Instead of configuring devices one by one in a web interface, this tool allows you to bulk-associate and bulk-deploy a matrix of system edge routers using a standard input CSV manifest file.

Cisco SD-WAN API Reference: https://developer.cisco.com/docs/sdwan/introduction/

---

## ✨ Features

- **JWT-Based Persistent Authentication**: Log in once with your RBAC password credentials. The script securely saves your long-lived refresh token locally, meaning subsequent sessions bypass password prompts until the token naturally expires.
- **No Cookies Required**: Completely modern token architecture (`Bearer` access structures combined with active `X-XSRF-TOKEN` validation tracking headers).
- **Dual-Step Deployment Lifecycle**: Automatically maps individual device identifiers, links them to your chosen target group, and schedules an asynchronous deployment transaction.
- **Automated Fallback Tracking**: Automatically collects metric status counts and creates an isolated, matching-format CSV spreadsheet of any failed or unconfigured entries for clean engineering fallbacks.
- **Network Verification Tool**: An option to quickly check active environment connectivity by querying live edge chassis assets.

---

## 📁 File Structure

Keep these files in the exact same execution directory folder:
```text
sdwan_automation/
├── config.py            # Handles loading/saving profiles and localized storage maps
├── sdwan_api.py         # Interrogates endpoints, manages tokens, and handles HTTP execution
├── main.py              # Houses the terminal display, processes CSV arrays, and handles metrics
└── sdwan_profiles.json  # Generated automatically on run to track saved environments
└── migration_csv.csv    # Spreadsheet containing variables for routers to configure
```

---

## 🛠️ Installation & Prerequisites

1. Ensure you have **Python 3.7+** installed on your workstation or management node.
2. Install the lightweight HTTP networking and console presentation libraries:

```bash
pip install -r requirements.txt
```

---

## 🚀 How to Run the Tool

Launch the main script entry point directly from your shell environment terminal:

```bash
python main.py
```

### 🎛️ Walkthrough Guide

1. **Authenticate & Log In**: Run the script with `python main.py` and authenticate. The script will save your session details and long-lived refresh token locally, enabling token rotation so you don't need to re-authenticate next time.
2. **Test Connectivity**: Run the `test` or `test_connectivity` command to verify that the discovered edge systems list and status are correct.
3. **Audit Variables**: Test a single router in a CSV spreadsheet first. Run the `audit [csv_path] [group_name]` (or `audit_variables`) command to audit the variables and ensure appropriate column/schema mapping with the target Configuration Group.
4. **Associate Routers**: Run the `associate [csv_path] [group_name]` (or `associate_devices`) command to associate the CSV routers with the configuration group. If conflicts are found, use the interactive resolution prompt.
5. **Deploy Configuration**: Run the `deploy [csv_path] [group_name]` (or `deploy_config`) command to push and deploy the variable configurations.
6. **Deploy Policy**: Run the `deploy_policy [csv_path] [policy_name_or_uuid]` command to deploy policy group changes to the devices.
7. **Repeat As Needed**: As needed, repeat steps 4 and 5 to update device associations and configurations.

---

## 📊 Input CSV Layout Schema Requirement

For associating devices to configuration groups and policy groups, and deploying variables, ensure your source spreadsheet is saved in standard CSV structure format using exact column naming logic. The engine uses **`Device ID`** to tie variables to a target router, while all remaining columns populate matching template keys:

```csv
Device ID,System IP,Host Name,Site Id,Dual Stack IPv6 Default,admin_username,admin_user_password
C8K-bee4a662,192.168.1.1,BR1-WAN-01,100,false,admin,C1sco123!
C8K-knt4aui2,192.168.1.2,BR2-WAN-01,200,false,admin,C1sco123!
```

Here is an example CSV header format for configuring device variables. Each subsequent line corresponds to values of a router you wish to migrate. You can add or remove variables as necessary, the script will only process what you give it. At a minimum, you need the `device_id` so the script can determine which devices to migrate

```
Device ID,Rollback Timer (sec),System IP,Host Name,Site Id,Dual Stack IPv6 Default,basic_consoleBaudRate
```

Alternatively, you can get a CSV by navigating to a configuration group in SD-WAN Manager's GUI, selecting the 3 dots next to the configuration group name, and selecting "Export". As long as there are some devices deployed, it will give you an idea of the example CSV format.


## ⚠️ Shortcomings & Current Limitations

1. **Scale Testing**: The engine has not been tested on multiple concurrent routers in the CSV manifest file yet.
2. **Policy Group Associations via CLI**: The CLI does not yet support switching or overriding arbitrary policy group associations outside of the conflict resolution/association prompts.

---

## TODO
- [ ] check schema mappings file when auditing variables. Ask if you want to preserve the mapping or change it.
- [ ] schema mappings should be per CSV per configuration group. Not just per CSV

## Done
- [x] add option at the end of the deployment stage to associate & deploy routers to a policy group
- [x] Sometimes I receive the error "Configuration Group matching name 'ITS_Demo_1101' not discovered on environment." even though the configuration group definitely exists. I've found that running option 3 to fetch all config groups and then re-running this gets rid of the error, but I should figure out why this error exists.
- [x] I should handle this error more gracefully because it is not really an error since the device already exists: ❌ Configuration Group association payload rejected (HTTP 400): {"error":{"message":"Config Group Association error","code":"CFGRP0018","details":"GenericGroup-ASSOCIATION validation : Device(s) already associated to group(s), device(s)-group(s): {IR1101-K9-FVH3002L7U6=ITS_Demo_1101}","type":"error"}}
- [x] just add a prompt for the user to ask whether to stop or skip and move on to the next step
- [x] add ability to up arrow and run old configuration options
- [x] Get JWT to work right. It seems to ask for my password every 2nd run of the script no matter what, but it should be time-based and I shouldn't need to enter password if I have a refresh key local

---

## 📚 Cisco Catalyst SD-WAN API References

The following Cisco Catalyst SD-WAN developer documentation and endpoints are referenced and utilized within this codebase:

| Component / Action | HTTP Method | API Endpoint | Documentation Link |
| :--- | :--- | :--- | :--- |
| **Authentication & Tokens** | POST | `/jwt/login` & `/jwt/refresh` | [API Docs](https://developer.cisco.com/docs/sdwan/authentication/#authentication) |
| **Device Inventory** | GET | `/dataservice/device` | [API Docs](https://developer.cisco.com/docs/sdwan/getting-started/#get-the-list-of-devices) |
| **Get Configuration Groups** | GET | `/dataservice/v1/config-group` | [API Docs](https://developer.cisco.com/docs/sd-wan/26-1/get-config-group-by-solution/) |
| **Get Policy Groups** | GET | `/dataservice/v1/policy-group` | [API Docs](https://developer.cisco.com/docs/sd-wan/26-1/get-policy-group-by-solution/) |
| **Get Group Expected Variables** | GET | `/dataservice/v1/config-group/{groupId}/device/variables` | [API Docs](https://developer.cisco.com/docs/sd-wan/26-1/get-config-group-device-variables/) |
| **Associate Config Group** | POST | `/dataservice/v1/config-group/{groupId}/device/associate` | [API Docs](https://developer.cisco.com/docs/sd-wan/26-1/create-config-group-association/) |
| **Dissociate Config Group** | DELETE | `/dataservice/v1/config-group/{groupId}/device/associate` | [API Docs](https://developer.cisco.com/docs/sd-wan/26-1/delete-config-group-association/) |
| **Create Device Variables** | POST | `/dataservice/v1/config-group/{groupId}/device/variables` | [API Docs](https://developer.cisco.com/docs/sd-wan/26-1/create-config-group-device-variables/) |
| **Deploy Config Group** | POST | `/dataservice/v1/config-group/{groupId}/device/deploy` | [API Docs](https://developer.cisco.com/docs/sd-wan/26-1/deploy-config-group/) |
| **Poll Task Status** | GET | `/dataservice/device/action/status/{taskId}` | [API Docs](https://developer.cisco.com/docs/sd-wan/26-1/find-status/) |
| **Associate Policy Group** | POST | `/dataservice/v1/policy-group/{groupId}/device/associate` | [API Docs](https://developer.cisco.com/docs/sd-wan/26-1/create-policy-group-association/) |
| **Deploy Policy Group** | POST | `/dataservice/v1/policy-group/{groupId}/device/deploy` | [API Docs](https://developer.cisco.com/docs/sd-wan/26-1/deploy-policy-group/) |