# Executive Network Compromise & Data Exfiltration Detection - KQL Queries

Detection queries for the final phase of APT campaign targeting executive network, advanced reconnaissance, privilege escalation, and sensitive data exfiltration.

## Day 8: Advanced Reconnaissance Detection

### PowerView Advanced Enumeration:
```kql
process.command_line:*"powershell-import"* AND
process.command_line:*"PowerView.ps1"* OR (
  process.command_line:*"powerpick"* AND (
    process.command_line:*"Get-NetUser"* OR
    process.command_line:*"Get-NetGroup"* OR
    process.command_line:*"Get-NetComputer"*
  )
)
```

### Enterprise Admin Discovery:
```kql
process.command_line:*"powerpick"* AND (
  process.command_line:*"Enterprise Admins"* OR
  process.command_line:*"/domain"* OR
  process.command_line:*"net group"*
)
```

### Network Infrastructure Mapping:
```kql
process.command_line:("routeprint" OR "arp -a") OR (
  process.command_line:*"Get-NetComputer"* AND
  process.command_line:*"operatingsystem"* AND
  process.command_line:*"dnshostname"*
)
```

## Day 9: Executive Network Lateral Movement

### EXEC2 Lateral Movement:
```kql
process.command_line:*"jump psexec"* AND
process.command_line:*"SITE2-EXEC2"* OR (
  destination.ip:*"EXEC2"* AND
  network.protocol:"smb"
)
```

### Domain Admin Account Compromise:
```kql
user.name:"Abigail Howell" OR
user.name:"abigail.howell" OR
process.command_line:*"X#3$3#8R8AwP"* OR
process.command_line:*"42b94b2633e85cbabe92e6ec20ee25ed"*
```

### Executive Subnet Process Injection:
```kql
process.command_line:*"inject"* AND (
  host.name:*"EXEC"* OR
  network.subnet:*"exec"* OR
  user.name:"abigail.howell"
)
```

## Advanced Privilege Escalation Detection

### UAC Bypass with TCP Listeners:
```kql
process.command_line:*"runasadmin uac-cmstplua"* AND
process.command_line:*"oneliner x64 local-tcp"* OR (
  process.command_line:*"connect localhost"* AND
  network.transport:"tcp"
)
```

### Beacon Chain Establishment:
```kql
process.name:"dllhost.exe" AND (
  network.protocol:("http" OR "https") OR
  process.parent.name:"powershell.exe"
) AND user.name:"abigail.howell"
```

### Privilege Verification Commands:
```kql
process.command_line:*"getprivs"* AND
user.name:"abigail.howell" AND
process.token.elevation_type:"full"
```

## Day 10-11: Executive Network Reconnaissance

### Comprehensive System Information Gathering:
```kql
process.command_line:("uptime" OR "shell systeminfo" OR "ipconfig" OR "tasklist") AND
host.name:*"EXEC2"*
```

### Advanced Audit Policy Enumeration:
```kql
process.command_line:*"adv_audit_policies"* OR
process.command_line:*"auditpol"* OR
winlog.event_id:4719
```

### Executive Network Share Discovery:
```kql
process.command_line:*"netshares"* AND (
  host.name:*"EXEC"* OR
  user.name:"abigail.howell"
) AND process.command_line:*"\\\\"*
```

### Domain Enumeration on Executive Network:
```kql
process.command_line:*"domainenum"* AND
host.name:*"EXEC2"* AND
user.name:"abigail.howell"
```

## Sensitive Data Discovery Detection

### Executive Document Access:
```kql
file.path:"C:\\Users\\abigail.howell\\Documents\\*" AND (
  event.action:("file_access" OR "directory_list") OR
  process.command_line:*"ls Documents"*
)
```

### Sensitive File Enumeration:
```kql
process.command_line:*"cd C:\\Users\\*" AND
process.command_line:*"Documents"* AND
host.name:*"EXEC"*
```

### Executive User Profile Access:
```kql
file.path:"C:\\Users\\abigail.howell\\*" AND (
  event.action:"file_access" OR
  process.working_directory:"*abigail.howell*"
)
```

## Executive Network Persistence Detection

### Executive Subnet SharPersist Deployment:
```kql
process.command_line:*"execute-assembly"* AND
process.command_line:*"SharPersist.exe"* AND
host.name:*"EXEC2"*
```

### Executive Network Scheduled Task Creation:
```kql
winlog.event_id:4698 AND
winlog.event_data.TaskName:*"GoogleUpdateTaskClean"* AND
host.name:*"EXEC"*
```

### High-Value Target Persistence:
```kql
file.path:"C:\\Users\\abigail.howell\\AppData\\Local\\Temp\\*.exe" AND
event.action:"file_create" AND
process.command_line:*"timestomp"*
```

## Day 12-13: Data Exfiltration Detection

### Executive Document Downloads:
```kql
process.command_line:*"download"* AND
file.path:"C:\\Users\\abigail.howell\\*" AND (
  file.extension:("txt" OR "doc" OR "docx" OR "pdf") OR
  file.size > 100000
)
```

### Large File Transfers from Executive Network:
```kql
network.protocol:("http" OR "https") AND
network.bytes > 1000000 AND
source.ip:*"EXEC"* AND
user.name:"abigail.howell"
```

### Sensitive Data Staging:
```kql
process.command_line:*"copy"* AND
file.path:"C:\\Users\\abigail.howell\\*" AND
destination.path:"C:\\Windows\\Temp\\*"
```

### Repeated Exfiltration Activity:
```kql
process.command_line:*"download"* AND
@timestamp:[now-48h TO now] AND
host.name:*"EXEC2"* AND
user.name:"abigail.howell"
```

## Credential Harvesting from Executive Network

### Executive Network Credential Dumping:
```kql
process.command_line:*"logonpasswords"* AND
host.name:*"EXEC2"* AND
user.name:"abigail.howell"
```

### High-Value Account Access:
```kql
process.target.name:"lsass.exe" AND
process.access.mask:("PROCESS_ALL_ACCESS" OR "0x1F0FFF") AND
host.name:*"EXEC"*
```

### Domain Admin Credential Usage:
```kql
winlog.event_data.LogonType:9 AND
user.name:"abigail.howell" AND
winlog.event_data.ProcessName:*beacon*
```

## Long-Term Persistence Monitoring

### Multi-Day Beacon Activity:
```kql
network.protocol:("http" OR "https") AND
host.name:*"EXEC2"* AND (
  @timestamp:[now-24h TO now-23h] OR
  @timestamp:[now-48h TO now-47h] OR
  @timestamp:[now-72h TO now-71h]
)
```

### Persistent Scheduled Task Execution:
```kql
winlog.event_id:4688 AND
winlog.event_data.ProcessCommandLine:*"forfiles.exe"* AND
winlog.event_data.ProcessCommandLine:*"abigail.howell"*
```

### Executive Network Sleep Patterns:
```kql
process.command_line:*"sleep"* AND
host.name:*"EXEC"* AND
@timestamp:[now-7d TO now]
```

## Network Traffic Analysis

### Executive Subnet C2 Communications:
```kql
network.protocol:("http" OR "https") AND
source.ip:*"EXEC"* AND
destination.port:(80 OR 443) AND
@timestamp:[now-10m TO now-9m]
```

### SMB Lateral Movement to Executive Network:
```kql
network.protocol:"smb" AND
destination.ip:*"EXEC2"* AND
smb.command:"SMB2_TREE_CONNECT"
```

### Data Exfiltration Traffic Patterns:
```kql
network.protocol:("http" OR "https") AND
network.bytes_sent > 1000000 AND
source.ip:*"EXEC"* AND
user.name:"abigail.howell"
```

## Comprehensive Executive Campaign Detection

### High-Value Target Compromise Indicators:
```kql
(
  (process.command_line:*"SITE2-EXEC2"* AND process.command_line:*"jump psexec"*) OR
  (user.name:"abigail.howell" AND process.command_line:*"runasadmin uac-cmstplua"*) OR
  (process.command_line:*"Enterprise Admins"* AND process.command_line:*"powerpick"*) OR
  (file.path:"C:\\Users\\abigail.howell\\Documents\\*" AND event.action:"file_access") OR
  (process.command_line:*"download"* AND host.name:*"EXEC2"*) OR
  (winlog.event_data.TaskName:*"GoogleUpdateTaskClean"* AND host.name:*"EXEC"*) OR
  (network.bytes > 1000000 AND source.ip:*"EXEC"* AND user.name:"abigail.howell")
) AND @timestamp:[now-7d TO now]
```

## Behavioral Analysis Queries

### Executive Network Attack Progression:
```kql
(
  (@timestamp:[now-5d TO now-4d] AND process.command_line:*"Get-NetUser"*) AND
  (@timestamp:[now-4d TO now-3d] AND process.command_line:*"SITE2-EXEC2"*) AND
  (@timestamp:[now-3d TO now-2d] AND file.path:"*abigail.howell*Documents*") AND
  (@timestamp:[now-2d TO now] AND process.command_line:*"download"*)
)
```

### High-Privilege Account Activity Timeline:
```kql
user.name:"abigail.howell" AND (
  process.command_line:*"getprivs"* OR
  process.command_line:*"logonpasswords"* OR
  process.command_line:*"download"*
) AND @timestamp:[now-7d TO now]
```

## Key IOCs Summary

### Executive Network Indicators:
- **Target Host**: SITE2-EXEC2
- **Compromised Account**: Abigail Howell / abigail.howell
- **Credentials**: X#3$3#8R8AwP / 42b94b2633e85cbabe92e6ec20ee25ed
- **Data Location**: C:\Users\abigail.howell\Documents\

### Advanced Techniques:
- **Privilege Escalation**: UAC bypass with TCP listeners and beacon chaining
- **Reconnaissance**: PowerView with Enterprise Admin enumeration
- **Persistence**: SharPersist with GoogleUpdateTaskClean masquerading
- **Exfiltration**: Multi-day document downloads from executive user profile

### Network Patterns:
- **Lateral Movement**: SMB to executive subnet
- **C2 Communication**: HTTP/HTTPS with 10-minute intervals
- **Data Transfer**: Large outbound transfers from executive network

## Alert Thresholds

### Critical Executive Network Alerts:
- Any activity involving Abigail Howell account
- Lateral movement to SITE2-EXEC2
- Document access in abigail.howell\Documents
- Large data transfers from executive subnet
- Enterprise Admin enumeration activities

### Behavioral Thresholds:
- Multiple privilege escalation attempts on executive network
- Sustained data access over multiple days
- Daily persistence execution from executive hosts
- High-volume network traffic from executive subnet

## Visualization Recommendations

### Executive Compromise Timeline:
- X-axis: 7-day campaign timeline (Days 8-13)
- Y-axis: Attack progression (Recon → Movement → Escalation → Exfiltration)
- Focus: Executive network activities and high-value account usage

### Data Exfiltration Analysis:
- File access patterns in executive user profiles
- Network transfer volumes and timing
- Document types and sizes being exfiltrated
- Long-term persistence execution monitoring

### High-Value Target Monitoring:
- Executive network host activities
- Domain Admin account usage patterns
- Sensitive data access and movement
- Long-term campaign persistence indicators