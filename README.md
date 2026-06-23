# Cisco Catalyst SD-WAN Configuration Group Automation Engine

This Python-based command-line interface (CLI) automation suite simplifies and speeds up deploying devices to **Configuration Groups** in Cisco Catalyst SD-WAN Manager (formerly vManage), matching the modern UX 2.0 / Release 26.x API specifications. 

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

1. **Select an Environment Profile**: 
   On start, the script checks your saved local settings. You can pick an environment from the menu list or register a brand new target controller IP/URL and username.
2. **Authenticate**: 
   Provide your password credentials if it is a new environment or if your refresh token expired.
3. **Verify Connectivity (Dashboard Options 1 - 3)**:
   Test your API access first. Option 3 pulls a clean table showing all active **Configuration Group Names**, **Policy Group Names**, and their UUID values.
4. **Execute Bulk Deployment (Dashboard Options 4 - 7)**:
   - Provide the path to your router CSV spreadsheet file (e.g., `routers.csv`).
   - Type in the target **Configuration Group Name**.
   - The automation system handles linking your devices, pushes the layout configurations, and polls the running task progress bar automatically.

---

## 📊 Input CSV Layout Schema Requirement

For options 4-7, ensure your source spreadsheet is saved in standard CSV structure format using exact column naming logic. The engine uses **`Device ID`** to tie variables to a target router, while all remaining columns populate matching template keys:

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


## TODO

## Done
- [x] add option at the end of the deployment stage to associate & deploy routers to a policy group
- [x] Sometimes I receive the error "Configuration Group matching name 'ITS_Demo_1101' not discovered on environment." even though the configuration group definitely exists. I've found that running option 3 to fetch all config groups and then re-running this gets rid of the error, but I should figure out why this error exists.
- [x] I should handle this error more gracefully because it is not really an error since the device already exists: ❌ Configuration Group association payload rejected (HTTP 400): {"error":{"message":"Config Group Association error","code":"CFGRP0018","details":"GenericGroup-ASSOCIATION validation : Device(s) already associated to group(s), device(s)-group(s): {IR1101-K9-FVH3002L7U6=ITS_Demo_1101}","type":"error"}}
❌ Automation failed to initialize transactions on controller framework layer.
    - [x] just add a prompt for the user to ask whether to stop or skip and move on to the next step
- [x] add ability to up arrow and run old configuration options
- [x] Get JWT to work right. It seems to ask for my password every 2nd run of the script no matter what, but it should be time-based and I shouldn't need to enter password if I have a refresh key local