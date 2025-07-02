# Detection Narrative – Keegan Ransomware Case (Week 00)

## Scenario

As a SOC analyst for TryNotHackMe, I was tasked with investigating a potential ransomware attack on Keegan's machine. The workstation was functional, but several files had unfamiliar extensions and the wallpaper had been modified.


## Detection Flow

1. **Defined the Scope**
System Affected - Keegan's machine
Incident Date - Monday, May 16, 2022
Suspicion - Potential ransomware activity, weird file extensions
Objectives - Identify binary name, source URL, execution path, privilege escalation, IOCs

2. **Initial Orientation Questions**
 Which data sources are available?
 What are the target file types or behaviors?
 Focus on:
Binary drops: .exe, .dll, .msi


Scripts: .ps1, .bat, .vbs


Privilege escalation attempts: e.g., fodhelper.exe, schtasks, runas


Unusual file writes (ransomware often renames files)

 What logs or events are already suspect?
 What are the current Splunk indexes, sourcetypes, or fields?

 
1. **Download Detection**  
   Looked for EventCode=1 + 11 for `.exe` and `.ps1` dropped by PowerShell

2. **Persistence**  
   Tracked `schtasks /Create` with `/RU SYSTEM` and matching task names

3. **C2 Activity**  
   Used EventCode=22 (DNS) and 3 (NetConn) to flag outbound connections

4. **File Drops**  
   File creation logs showed IOCs in user folders: `.txt`, `.jpg` extensions



## Key Artifacts Found
- Suspicious binary: `OUTSTANDING_GUTTER.exe`
- Script: `script.ps1`
- Ransom note: `BlackSun_README.txt`
- Modified wallpaper: `blacksun.jpg`
- C2 Domains: `886e*.ngrok.io`, `9030*.ngrok.io`