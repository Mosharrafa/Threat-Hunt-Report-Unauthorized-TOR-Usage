# Threat Event (Unauthorized TOR Usage)
**Unauthorized TOR Browser Installation and Use**

## Steps the "Bad Actor" Took to Create Logs and IoCs

1. Download the TOR browser installer: https://www.torproject.org/download/
2. Install it silently from the Downloads folder:
   ```
   tor-browser-windows-x86_64-portable-15.0.7.exe /S
   ```
3. Open the TOR browser from the Desktop folder
4. Connect to TOR and browse sites (e.g. .onion addresses)
5. Create a file on the Desktop called `tor-shopping-list.txt` with fake illicit items
6. Delete the file

---

## Tables Used to Detect IoCs

| **Parameter** | **Description** |
|---------------|-----------------|
| **Name** | DeviceFileEvents |
| **Info** | https://learn.microsoft.com/en-us/defender-xdr/advanced-hunting-devicefileevents-table |
| **Purpose** | Used for detecting TOR download and installation, as well as the shopping list creation and deletion. |

| **Parameter** | **Description** |
|---------------|-----------------|
| **Name** | DeviceProcessEvents |
| **Info** | https://learn.microsoft.com/en-us/defender-xdr/advanced-hunting-deviceprocessevents-table |
| **Purpose** | Used to detect the silent installation of TOR as well as the TOR browser and service launching. |

| **Parameter** | **Description** |
|---------------|-----------------|
| **Name** | DeviceNetworkEvents |
| **Info** | https://learn.microsoft.com/en-us/defender-xdr/advanced-hunting-devicenetworkevents-table |
| **Purpose** | Used to detect TOR network activity, specifically `tor.exe` and `firefox.exe` making connections over known TOR ports (9001, 9030, 9040, 9050, 9051, 9150). |

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

---

## Additional Notes
- TOR version used: `15.0.7`
- Device: `mde-test-03`
- User: `xerox_4123`
- Lab date: `March 14, 2026`

---

## Revision History

| **Version** | **Changes** | **Date** | **Modified By** |
|-------------|-------------|----------|-----------------|
| 1.0 | Initial draft | `March 2026` | — Mosharrafa
