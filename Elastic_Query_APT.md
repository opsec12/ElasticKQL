# Multi-Day APT Campaign Detection - KQL Queries

Detection queries for a sophisticated multi-day APT campaign involving lateral movement, privilege escalation, persistence, and data exfiltration.

## Day 1: Initial Lateral Movement Detection

### PSExec Lateral Movement:
```kql
process.command_line:*"jump psexec"* OR (
  process.name:"psexec.exe" OR
  process.command_line:*psexec* AND
  destination.ip:* AND
  network.protocol:"smb"
)
```

### Token Impersonation:
```kql
process.command_line:*"make_token"* AND (
  process.command_line:*"SITE2\\"* OR
  process.command_line:*"rev2self"*
)
```

### Credential Usage from DNS Server:
```kql
process.command_line:*"make_token"* AND
process.command_line:*"SITE2-TA13"* AND
winlog.event_data.LogonType:9
```

## Host Situational Awareness Detection

### PowerView Import and Usage:
```kql
process.command_line:*"powershell-import"* AND
process.command_line:*"PowerView.ps1"* OR (
  process.command_line:*"powerpick"* AND
  process.command_line:*"Domain Admins"*
)
```

### Network Enumeration Commands:
```kql
process.command_line:("arp -a" OR "arp -d") OR
process.command_line:*"Net computers"* OR
process.command_line:*"Netshares"* OR
process.command_line:*"netstat -antup"*
```

### File Server Enumeration:
```kql
process.command_line:*"netshares"* AND (
  process.command_line:*"\\\\172.17.2.4"* OR
  process.command_line:*"EngineeringDocs"* OR
  process.command_line:*"File Server"*
)
```

## Process Injection Detection

### User-Level Process Injection:
```kql
process.command_line:*"inject"* AND (
  process.command_line:*"User Process PID"* OR
  process.command_line:*"x64"* OR
  process.name:("svchost.exe" OR "explorer.exe")
)
```

### Specific User Account Targeting:
```kql
user.name:"Timothy Moore" OR
user.name:"Elizabeth.thompson" OR
process.command_line:*"I7@Q#7+rGa@3"*
```

## Day 2-3: Lateral Movement to Staff Network

### Staff Subnet Lateral Movement:
```kql
process.command_line:*"SITE2-STAFF05"* OR (
  process.command_line:*"jump psexec"* AND
  process.command_line:*"STAFF"*
)
```

### Directory Traversal Activity:
```kql
process.command_line:*"ls C:\\Users\\"* OR
process.command_line:*"cd C:\\Users\\"* OR (
  file.path:"C:\\Users\\*" AND
  event.action:("file_access" OR "directory_list")
)
```

### Engineering Documents Access Attempts:
```kql
process.command_line:*"\\\\172.17.2.4\\EngineeringDocs"* OR
network.protocol:"smb" AND
destination.ip:"172.17.2.4" AND
smb.path:"*EngineeringDocs*"
```

## Day 4: Privilege Escalation Detection

### Engineering Subnet Movement:
```kql
process.command_line:*"SITE2-ENG3"* OR (
  process.command_line:*"jump psexec"* AND
  process.command_line:*"ENG"*
)
```

### UAC Bypass Techniques:
```kql
process.command_line:*"runasadmin"* OR
process.command_line:*"uac-cmstplua"* OR
process.command_line:*"Runasadmin uac-cmstplua"*
```

### TCP Listener Setup:
```kql
process.command_line:*"oneliner"* AND
process.command_line:*"local-tcp"* OR (
  network.transport:"tcp" AND
  destination.port:[8000 TO 9000] AND
  source.ip:"127.0.0.1"
)
```

### Beacon Spawning and Linking:
```kql
process.command_line:*"spawn"* OR
process.command_line:*"connect localhost"* OR (
  process.name:"dllhost.exe" AND
  network.protocol:("http" OR "https")
)
```

### Domain Admin Verification:
```kql
process.command_line:*"whoami"* AND
user.name:"Elizabeth.thompson" AND
user.domain:"SITE2"
```

## Persistence Mechanisms Detection

### Repeated SharPersist Usage:
```kql
process.command_line:*"execute-assembly"* AND
process.command_line:*"SharPersist.exe"* AND (
  process.command_line:*"-t schtask"* AND
  process.command_line:*"-o daily"*
)
```

### GoogleUpdateTaskClean Scheduled Tasks:
```kql
winlog.event_id:4698 AND (
  winlog.event_data.TaskName:*"GoogleUpdateTaskClean"* OR
  winlog.event_data.TaskContent:*"forfiles.exe"*
)
```

### Multiple Persistence Across Subnets:
```kql
file.path:"C:\\Users\\*\\AppData\\Local\\Temp\\*.exe" AND
event.action:"file_create" AND
@timestamp:[now-7d TO now]
```

## Day 5-6: Data Discovery and Exfiltration

### Engineering Documents Discovery:
```kql
process.command_line:*"ls \\\\172.17.2.4\\EngineeringDocs"* OR (
  network.protocol:"smb" AND
  destination.ip:"172.17.2.4" AND
  smb.command:"SMB2_CREATE" AND
  smb.path:"*EngineeringDocs*"
)
```

### Data Staging Operations:
```kql
process.command_line:*"shell copy"* AND
process.command_line:*"\\\\172.17.2.4\\EngineeringDocs"* AND
process.command_line:*"C:\\Windows\\Temp\\"*
```

### File Copy to Staging Directory:
```kql
file.path:"C:\\Windows\\Temp\\*" AND
event.action:"file_create" AND (
  process.command_line:*"copy"* OR
  process.command_line:*"EngineeringDocs"*
)
```

### Data Exfiltration Detection:
```kql
process.command_line:*"download"* AND
process.command_line:*"\\\\172.17.2.4\\EngineeringDocs"* OR (
  network.protocol:("http" OR "https") AND
  file.size > 1000000 AND
  event.action:"file_transfer"
)
```

## Beacon Sleep Pattern Detection

### Overnight Sleep Patterns:
```kql
process.command_line:*"sleep"* AND (
  @timestamp:[now-24h TO now-16h] OR
  @timestamp:[now-48h TO now-40h] OR
  @timestamp:[now-72h TO now-64h]
)
```

### 10-Minute Beacon Callbacks:
```kql
network.protocol:("http" OR "https") AND (
  @timestamp:[now-10m TO now-9m] OR
  @timestamp:[now-20m TO now-19m] OR
  @timestamp:[now-30m TO now-29m]
) AND destination.port:(80 OR 443)
```

## Privilege Analysis

### SYSTEM Level Activities:
```kql
user.name:"SYSTEM" AND (
  process.command_line:*"logonpasswords"* OR
  process.command_line:*"getprivs"* OR
  process.command_line:*"domainenum"*
)
```

### Administrator Privilege Usage:
```kql
process.token.elevation_type:"full" AND (
  process.command_line:*"jump psexec"* OR
  network.protocol:"smb" OR
  process.command_line:*"make_token"*
)
```

## Network Infrastructure Targeting

### Specific Host Targeting:
```kql
destination.ip:("172.17.2.4" OR "SITE2-TA13" OR "SITE2-STAFF05" OR "SITE2-ENG3") OR
process.command_line:*("TA13" OR "STAFF05" OR "ENG3")*
```

### SMB Traffic to File Servers:
```kql
network.protocol:"smb" AND
destination.ip:"172.17.2.4" AND (
  smb.path:"*EngineeringDocs*" OR
  smb.command:("SMB2_CREATE" OR "SMB2_READ")
)
```

## Comprehensive Campaign Detection

### Multi-Day Campaign Indicators:
```kql
(
  (process.command_line:*"make_token SITE2"* AND process.command_line:*"jump psexec"*) OR
  (process.command_line:*"powershell-import"* AND process.command_line:*"PowerView"*) OR
  (process.command_line:*"netshares"* AND process.command_line:*"EngineeringDocs"*) OR
  (process.command_line:*"runasadmin uac-cmstplua"* AND process.command_line:*"oneliner"*) OR
  (process.command_line:*"download"* AND process.command_line:*"172.17.2.4"*) OR
  (user.name:("Timothy Moore" OR "Elizabeth.thompson") AND network.protocol:"smb") OR
  (winlog.event_data.TaskName:*"GoogleUpdateTaskClean"* AND @timestamp:[now-7d TO now])
) AND @timestamp:[now-7d TO now]
```

## Timeline Analysis Queries

### Day 1 Activities:
```kql
@timestamp:[now-6d TO now-5d] AND (
  process.command_line:*"SITE2-TA13"* OR
  process.command_line:*"Domain Admins"* OR
  process.command_line:*"PowerView"*
)
```

### Day 2-3 Activities:
```kql
@timestamp:[now-5d TO now-3d] AND (
  process.command_line:*"SITE2-STAFF05"* OR
  process.command_line:*"directory traversal"* OR
  file.path:"C:\\Users\\*" AND event.action:"file_access"
)
```

### Day 4-6 Activities:
```kql
@timestamp:[now-3d TO now] AND (
  process.command_line:*"SITE2-ENG3"* OR
  process.command_line:*"uac-cmstplua"* OR
  process.command_line:*"172.17.2.4\\EngineeringDocs"*
)
```

## Key IOCs Summary

### Network Indicators:
- **Target IPs**: 172.17.2.4 (File Server), SITE2-TA13, SITE2-STAFF05, SITE2-ENG3
- **Protocols**: SMB for lateral movement, HTTP/HTTPS for C2
- **Shares**: \\172.17.2.4\EngineeringDocs

### User Accounts:
- **Compromised**: Timothy Moore, Elizabeth.thompson
- **Credentials**: I7@Q#7+rGa@3 (Timothy Moore)
- **Domain**: SITE2

### File Locations:
- **Staging**: C:\Windows\Temp\, C:\Users\*\AppData\Local\Temp\
- **Tools**: SharPersist.exe, PowerView.ps1
- **Persistence**: GoogleUpdateTaskClean scheduled tasks

### Behavioral Patterns:
- **Multi-day progression**: DNS → TA → Staff → Engineering subnets
- **Daily persistence**: Scheduled tasks across multiple hosts
- **Data exfiltration**: Large file transfers from EngineeringDocs

## Alert Thresholds

### High-Confidence Campaign Indicators:
- Lateral movement to specific hostnames (TA13, STAFF05, ENG3)
- PowerView import and Domain Admin enumeration
- UAC bypass with TCP listeners and beacon spawning
- Data access and download from 172.17.2.4\EngineeringDocs

### Campaign Progression Alerts:
- Sequential subnet compromise over multiple days
- Persistence establishment on each compromised host
- Escalation from user to SYSTEM to Domain Admin privileges
- Culmination in sensitive data exfiltration

## Visualization Recommendations

### Campaign Timeline:
- X-axis: 7-day timeline
- Y-axis: Compromise progression (DNS → TA → Staff → Engineering)
- Layers: Lateral movement, persistence, privilege escalation, data access

### Network Topology Mapping:
- Subnet visualization showing movement path
- Host relationships and compromise sequence
- Data flow from EngineeringDocs to attacker infrastructure

### User Account Compromise:
- Timeline of credential harvesting and usage
- Privilege escalation chains
- Cross-subnet account utilization

These queries are designed to detect the sophisticated, multi-day campaign progression while correlating activities across different subnets and timeframes.