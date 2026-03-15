<img width="400" src="https://github.com/user-attachments/assets/44bac428-01bb-4fe9-9d85-96cba7698bee" alt="Tor Logo with the onion and a crosshair on it"/>

# Threat Hunt Report: Unauthorized TOR Usage
- [Scenario Creation](./threat-hunting-scenario-tor-event-creation.md)

## Platforms and Languages Leveraged
- Windows 11 Virtual Machine (Microsoft Azure)
- EDR Platform: Microsoft Defender for Endpoint
- Kusto Query Language (KQL)
- TOR Browser

## Scenario

Management suspects that some employees may be using TOR browsers to bypass network security controls because recent network logs show unusual encrypted traffic patterns and connections to known TOR entry nodes. Additionally, there have been anonymous reports of employees discussing ways to access restricted sites during work hours. The goal is to detect any TOR usage and analyze related security incidents to mitigate potential risks. If any use of TOR is found, notify management.

### High-Level TOR-Related IoC Discovery Plan

- **Check `DeviceFileEvents`** for any `tor(.exe)` or `firefox(.exe)` file events.
- **Check `DeviceProcessEvents`** for any signs of installation or usage.
- **Check `DeviceNetworkEvents`** for any signs of outgoing connections over known TOR ports.

```kql
DeviceFileEvents
| top 20 by Timestamp desc
```
```kql
DeviceNetworkEvents
| top 20 by Timestamp desc
```
```kql
DeviceProcessEvents
| top 20 by Timestamp desc
```

---

## Steps Taken

### 1. Searched the `DeviceFileEvents` Table

Searched for any file containing the string `"tor"` associated with user `xerox_4123` on device `mde-test-03`. The query returned **67 items**, revealing that the user downloaded a TOR installer, which resulted in many TOR-related files being created on the Desktop, including the creation of a file called `tor-shopping-list.txt` on the Desktop at `Mar 14, 2026 9:01:21 AM`. These events began at `Mar 14, 2026 8:40 AM`.

**Query used to locate events:**

```kql
DeviceFileEvents
| where DeviceName == "mde-test-03"
| where InitiatingProcessAccountName contains "xerox"
| where FileName contains "tor"
| order by Timestamp desc
| project Timestamp, DeviceName, ActionType, FileName, FolderPath, SHA256, Account = InitiatingProcessAccountName
```

<img width="1132" height="670" alt="Image" src="https://github.com/user-attachments/assets/e3b43cd1-5f4e-4065-8c1f-423c07175225" />

---

### 2. Searched the `DeviceProcessEvents` Table

Searched for any `ProcessCommandLine` containing the string `"tor-browser-windows-x86_64-portable-15.0.7.exe"`. Based on the logs returned, at `Mar 14, 2026 8:40:45 AM`, user `xerox_4123` on device `mde-test-03` ran the TOR installer from their Downloads folder using a command that triggered a **silent installation**
**Query used to locate event:**

```kql
DeviceProcessEvents
| where DeviceName == "mde-test-03"
| where ProcessCommandLine contains "tor-browser-windows-x86_64-portable-15.0.7.exe"
| project Timestamp, DeviceName, AccountName, FileName, FolderPath, SHA256, ProcessCommandLine, ActionType
```

<img width="1160" height="601" alt="Image" src="https://github.com/user-attachments/assets/30cf8463-4f58-4ab8-9f35-c2bcfd4430e0" />

---

### 3. Searched the `DeviceProcessEvents` Table for TOR Browser Execution

Searched for any indication that user `xerox_4123` actually opened the TOR browser. The query returned **46 items**, confirming that TOR was launched at `Mar 14, 2026 8:46:20 AM`. There were 44 instances of `firefox.exe` (TOR's browser component) and 2 instances of `tor.exe` (the core routing service) spawned across two separate sessions.

**Query used to locate events:**

```kql
DeviceProcessEvents
| where DeviceName == "mde-test-03"
| where FileName has_any ("tor.exe", "firefox.exe", "tor-browser.exe")
| project Timestamp, DeviceName, AccountName, ActionType, FileName, FolderPath, SHA256, ProcessCommandLine
| order by Timestamp desc
```

<img width="1167" height="675" alt="Image" src="https://github.com/user-attachments/assets/8b3e5acc-62e1-4db4-a3a2-34bdd85db668" />

---

### 4. Searched the `DeviceNetworkEvents` Table for TOR Network Connections

Searched for any indication that the TOR browser was used to establish network connections over known TOR ports. The query returned **15 items**, all showing `ConnectionSuccess`. At `Mar 14, 2026 8:46:37 AM`, user `xerox_4123` on device `mde-test-03` successfully established a connection to remote IP `95.217.2.206` on **port 9001** (a known TOR Guard/Entry Node), confirming live TOR network routing. Additional connections were made over ports `443` (TOR Bridges) and `80` (TOR Directory servers), and `firefox.exe` connected to `127.0.0.1:9150` (the local TOR SOCKS proxy), confirming the full TOR circuit was active.

**Query used to locate events:**

```kql
DeviceNetworkEvents
| where DeviceName == "mde-test-03"
| where InitiatingProcessAccountName != "system"
| where InitiatingProcessFileName in ("tor.exe", "firefox.exe")
| where RemotePort in ("9001", "9030", "9040", "9050", "9051", "9150", "80", "443")
| project Timestamp, DeviceName, InitiatingProcessAccountName, ActionType, RemoteIP, RemotePort, RemoteUrl, InitiatingProcessFileName, InitiatingProcessFolderPath
| order by Timestamp desc
```

<img width="1156" height="668" alt="Image" src="https://github.com/user-attachments/assets/3cd7d77e-7d11-49c9-8538-6bbd97398ca6" />

---

### 5. Searched the `DeviceFileEvents` Table for the TOR Shopping List

Searched for any file containing `"shopping-list"` to determine whether the user documented their dark web activity. The query returned **2 items**. At `Mar 14, 2026 9:01:21 AM`, user `xerox_4123` created `tor-shopping-list.txt` on the Desktop during an active TOR session. A corresponding `.lnk` shortcut was automatically generated by Windows in AppData — meaning even if the `.txt` file is deleted, forensic evidence of its existence persists.

**Query used to locate events:**

```kql
DeviceFileEvents
| where DeviceName == "mde-test-03"
| where FileName contains "shopping-list"
| order by Timestamp desc
| project Timestamp, DeviceName, ActionType, FileName, FolderPath, Account = InitiatingProcessAccountName
```

<img width="1186" height="630" alt="Image" src="https://github.com/user-attachments/assets/e8f0ee1d-82bd-4203-bf94-17d13346a300" />

---

## Chronological Event Timeline

### 1. Silent Installation — TOR Browser Installed

- **Timestamp:** `Mar 14, 2026 8:40:45 AM`
- **Event:** User `xerox_4123` executed `tor-browser-windows-x86_64-portable-15.0.7.exe`  from the Downloads folder, triggering a background installation.
- **Action:** Process creation detected.
- **Command:** `tor-browser-windows-x86_64-portable-15.0.7.exe`
- **File Path:** `C:\Users\Xerox_4123\Downloads\tor-browser-windows-x86_64-portable-15.0.7.exe`
- **SHA256:** `958626901dbe17fc003ed671b61b3656375e6f0bc06c9dff60bd2f80d4ace21b`

### 2. TOR Files Appear on Disk

- **Timestamp:** `Mar 14, 2026 8:46 AM`
- **Event:** TOR-related files including `tor.exe`, `Tor Browser.lnk`, `torrc`, and browser databases (`storage.sqlite`, `storage-sync-v2.sqlite`) were created on disk, confirming successful installation.
- **Action:** Multiple `FileCreated` events detected.
- **File Path:** `C:\Users\Xerox_4123\Desktop\Tor Browser\Browser\TorBrowser\Tor\tor.exe`

### 3. TOR Browser Launched

- **Timestamp:** `Mar 14, 2026 8:46:20 AM`
- **Event:** User `xerox_4123` opened the TOR browser. The core `tor.exe` process was created, followed by 44 instances of `firefox.exe` (TOR's browser UI), confirming the browser launched successfully across two sessions.
- **Action:** Process creation of `tor.exe` and `firefox.exe` detected.
- **File Path:** `C:\Users\Xerox_4123\Desktop\Tor Browser\Browser\TorBrowser\Tor\tor.exe`

### 4. TOR Network Connection Established

- **Timestamp:** `Mar 14, 2026 8:46:37 AM`
- **Event:** A successful connection to remote IP `95.217.2.206` on port `9001` was established by `tor.exe`, confirming TOR Guard Node connection and live TOR network routing.
- **Action:** `ConnectionSuccess`
- **Process:** `tor.exe`
- **File Path:** `C:\Users\Xerox_4123\Desktop\Tor Browser\Browser\TorBrowser\Tor\tor.exe`

### 5. Additional TOR Network Connections

- **Timestamps:**
  - `Mar 14, 2026 8:46 AM` — Connected to `91.134.135.76` on port `443` (TOR Bridge)
  - `Mar 14, 2026 8:46 AM` — Local connection to `127.0.0.1` on port `9150` (firefox → TOR SOCKS proxy)
  - `Mar 14, 2026 8:47 AM` — Connected to `109.70.100.246` on port `80` (TOR Directory server)
  - `Mar 14, 2026 8:48 AM` — Connected to `213.239.213.190` on port `443` (TOR Bridge)
- **Event:** Multiple additional TOR connections confirmed, indicating sustained browsing activity through the TOR network.
- **Action:** Multiple `ConnectionSuccess` events detected.

### 6. TOR Shopping List Created

- **Timestamp:** `Mar 14, 2026 9:01:21 AM`
- **Event:** User `xerox_4123` created a file named `tor-shopping-list.txt` on the Desktop during an active TOR session, strongly suggesting documentation of dark web marketplace activity.
- **Action:** `FileCreated`
- **File Path:** `C:\Users\Xerox_4123\Desktop\tor-shopping-list.txt`

---

## Summary

User `xerox_4123` on device `mde-test-03` initiated and completed the installation of the TOR browser (v15.0.7). They proceeded to launch the browser, establish live connections within the TOR network — including a confirmed Guard Node connection on port `9001` — and created a file named `tor-shopping-list.txt` on their Desktop during an active TOR session. This sequence of activities confirms that the user actively installed, configured, and used the TOR browser for anonymous browsing, with the shopping list file indicating possible interaction with dark web marketplaces.

---

## Response Taken

TOR usage was confirmed on endpoint `mde-test-03` by user `xerox_4123`. The device was isolated, and the user's direct manager was notified.

---

## Related Queries

```kql
// Detect TOR-related file events
DeviceFileEvents
| where FileName startswith "tor"

// Detect silent TOR installation
DeviceProcessEvents
| where ProcessCommandLine contains "tor-browser-windows-x86_64-portable-15.0.7.exe"
| project Timestamp, DeviceName, ActionType, FileName, ProcessCommandLine

// Detect TOR files present on disk
DeviceFileEvents
| where FileName has_any ("tor.exe", "firefox.exe")
| project Timestamp, DeviceName, InitiatingProcessAccountName, ActionType, InitiatingProcessCommandLine

// Detect TOR browser or service execution
DeviceProcessEvents
| where ProcessCommandLine has_any ("tor.exe", "firefox.exe")
| project Timestamp, DeviceName, AccountName, ActionType, ProcessCommandLine

// Detect active TOR network connections
DeviceNetworkEvents
| where InitiatingProcessFileName in~ ("tor.exe", "firefox.exe")
| where RemotePort in (9001, 9030, 9040, 9050, 9051, 9150)
| project Timestamp, DeviceName, InitiatingProcessAccountName, InitiatingProcessFileName, RemoteIP, RemotePort, RemoteUrl
| order by Timestamp desc

// Detect shopping list file creation or deletion
DeviceFileEvents
| where FileName contains "shopping-list.txt"
```
