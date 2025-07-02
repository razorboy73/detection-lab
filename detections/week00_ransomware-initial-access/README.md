# 🛡️ Week 00 – Ransomware Initial Access Detection

This detection module investigates a simulated ransomware event in which a suspicious binary (`OUTSTANDING_GUTTER.exe`) was dropped, scheduled to persist, and communicated with an external Ngrok server.

## 🔍 Objectives 

- Detect initial payload delivery via PowerShellll
- Detect persistence via `schtasks.exe`
- Identify DNS and IP-based C2 communication
- Flag file and image IOCs (ransom note, wallpaper)
- Use EventCodes 1, 3, 11, and 22 from Sysmon and understand how they relate to underlying activity

## Learnings🧠 When to Use Which Codes?##
##Use Case##                                        ##Go To Event##
“What IP did this process connect to?”              EventCode=3
“What domain did this binary try to resolve?”       EventCode=22
“What command-line downloaded this?”                EventCode=1 (if logged)
“How did the binary arrive?”                        EventCode=11 (file creation) + 22/3 context

##Primary Event Codes to Monitor for File Downloads##
Event Code          Description                     Why It Matters
1                   Process Creation                Often shows tools used for download 
3                   Network Connection              Shows outbound connections
11                  File Create (mapped)            Fires when a file is created via a mapped section 
15                  File CreateStreamHash           Logs creation of alternate data streams 
13                  Registry Value Set              Can catch settings changed by malware download
7                   Image Load                      Detects dynamic loading of DLLs/execution of downloads file
22                  DNS Query                       Hostname lookup - domain names or beaconing


## 📂 Files
- [`detection.md`](./detection.md): Full narrative + detection logic
- [`queries/*.spl`](./queries): Modular SPL queries
- [`iocs/ioc_summary.json`](./iocs/ioc_summary.json): Structured IOC list
- [`reflection.md`](./reflection.md): Notes on detection logic, failure points, and improvements
