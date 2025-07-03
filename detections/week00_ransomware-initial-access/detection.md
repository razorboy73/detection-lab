
# 🧪 Detection Narrative – Week 00: Ransomware Initial Access Detection

## 📌 Scenario Summary

As a SOC analyst for the MSSP *TryNotHackMe*, I was assigned to investigate a suspected ransomware event on Keegan’s workstation. While the system remained operational, several anomalous indicators were immediately present:

- Files with unusual extensions appeared
- The desktop wallpaper was altered
- A ransom note was discovered on disk

The objective was to determine the source, method, and impact of the intrusion using available Splunk logs, primarily sourced from Sysmon.

---

## 🎯 Investigation Objectives

- Identify the initial binary and its delivery method
- Detect privilege escalation and persistence mechanisms
- Trace outbound command and control (C2) activity
- Enumerate file-based IOCs such as dropped ransom notes and altered images
- Correlate key Sysmon EventCodes: 1, 3, 11, and 22

---

## 🔍 Detection Flow

### 1. Define Scope and Baseline

| Field            | Value                         |
|------------------|-------------------------------|
| Affected Host    | Keegan's workstation          |
| Incident Date    | Monday, May 16, 2022          |
| Suspicion        | Ransomware behavior           |
| Data Sources     | Splunk (Sysmon), Windows logs |

---


### 1. Define Scope and Baseline

| Field            | Value                         |
|------------------|-------------------------------|
| Affected Host    | Keegan's workstation          |
| Incident Date    | Monday, May 16, 2022          |
| Suspicion        | Ransomware behavior           |
| Data Sources     | Splunk (Sysmon), Windows logs |

---

### 2. Initial File Discovery – Sysmon Event ID 11

Query: [`01_file_creation.spl`](./queries/01_file_creation.spl)

This yielded a key file: `C:\Windows\Temp\OUTSTANDING_GUTTER.exe`.

---

### 3. Investigate Process Responsible – Sysmon Event ID 1

Query: [`02_process_lookup.spl`](./queries/02_process_lookup.spl)

This showed `powershell.exe -EncodedCommand ...` was used, confirming obfuscated PowerShell was involved.

---

### 4. Decode Encoded PowerShell

Manually decoded the Base64 command to reveal:
- Disabled Defender
- Downloaded a payload from Ngrok
- Created a scheduled task under SYSTEM context

---

### 5. Confirm Scheduled Task Creation – Event ID 1

Query: [`04_outstanding_gutter_cmdline.spl`](./queries/04_outstanding_gutter_cmdline.spl)

---

### 6. Investigate C2 Activity – DNS & Network

#### DNS (Event ID 22)

Query: [`06_dns_queries_by_binary.spl`](./queries/06_dns_queries_by_binary.spl)

Domains resolved: `9030-*.ngrok.io`, `886e-*.ngrok.io`

#### Network Connections (Event ID 3)

Query: [`05_network_connections_by_binary.spl`](./queries/05_network_connections_by_binary.spl)

| Destination IP   | Count | Notes                       |
|------------------|--------|-----------------------------|
| `3.17.7.232`     | 206    | Primary beacon destination  |
| `3.14.182.203`   | 76     | Secondary C2 activity       |
| `3.134.39.220`   | 4      | Sparse, but present         |
| `3.134.125.175`  | 3      | Sparse, but present         |
| `3.22.30.40`     | 2      | Sparse, but present         |

---

### 7. Find Related PowerShell Script

Query: [`07_find_dropped_ps1.spl`](./queries/07_find_dropped_ps1.spl)

Found: `C:\Windows\Temp\script.ps1`

---

### 8. Hash the Script

Query: [`08_extract_hash_from_ps1.spl`](./queries/08_extract_hash_from_ps1.spl)

---

### 9. Locate Ransom Note

Query: [`09_ransom_note_discovery.spl`](./queries/09_ransom_note_discovery.spl)

---

### 10. Wallpaper IOC – Event ID 11

Query: [`10_wallpaper_drop_discovery.spl`](./queries/10_wallpaper_drop_discovery.spl)

---

## 🧱 Indicators of Compromise (IOCs)

| Type         | Artifact / Pattern                        |
|--------------|-------------------------------------------|
| Binary       | OUTSTANDING_GUTTER.exe                    |
| Script       | script.ps1                                |
| File Drop    | BlackSun_README.txt, blacksun.jpg         |
| Persistence  | schtasks /RU SYSTEM                       |
| C2 Domain    | 886e*.ngrok.io, 9030*.ngrok.io            |
| C2 IP        | 3.134.125.175, 3.134.39.220, 3.14.182.203, 3.17.7.232, 3.22.30.40 |

---

## ✅ Summary of Detection Chain

| Step                | Sysmon Event | Key Field(s)                           |
|---------------------|---------------|----------------------------------------|
| File Written        | 11            | TargetFilename, Image, User            |
| Process Executed    | 1             | CommandLine, ParentImage, User         |
| Domain Queried      | 22            | QueryName, Image                       |
| Network Connected   | 3             | DestinationIp, Image                   |
| Persistence Created | 1             | CommandLine, Image                     |
