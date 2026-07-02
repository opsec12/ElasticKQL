# Domain Enumeration & Persistence Detection - KQL Queries

Detection queries for domain enumeration, credential harvesting, and scheduled task persistence using SharPersist and timestomping.

## Domain Enumeration Detection

### Domain Enumeration Commands:
```kql
process.command_line:*domainenum* OR
process.command_line:*"net group"* OR
process.command_line:*"net user /domain"* OR
process.command_line:*"nltest /domain_trusts"*
```

### Active Directory Reconnaissance:
```kql
process.command_line:*"dsquery"* OR
process.command_line:*"adfind"* OR
process.command_line:*"ldapsearch"* OR (
  process.command_line:*"net"* AND
  process.command_line:*"domain"*
)
```

### PowerShell Domain Enumeration:
```kql
process.command_line:*"Get-ADUser"* OR
process.command_line:*"Get-ADGroup"* OR
process.command_line:*"Get-ADComputer"* OR
process.command_line:*"Get-Domain"*
```

## Credential Harvesting Detection

### Logonpasswords Command:
```kql
process.command_line:*logonpasswords* OR
process.command_line:*"sekurlsa::logonpasswords"* OR
process.command_line:*"privilege::debug"*
```

### Mimikatz Execution:
```kql
process.name:"mimikatz.exe" OR
process.command_line:*mimikatz* OR
process.command_line:*"sekurlsa"* OR
process.command_line:*"lsadump"*
```

### LSASS Memory Access:
```kql
process.target.name:"lsass.exe" AND (
  event.action:"process_access" OR
  process.access.mask:("PROCESS_ALL_ACCESS" OR "0x1F0FFF")
)
```

## SharPersist Detection

### SharPersist Execution:
```kql
process.name:"SharPersist.exe" OR
process.command_line:*SharPersist* OR
file.name:"SharPersist.exe"
```

### Execute-Assembly with SharPersist:
```kql
process.command_line:*"execute-assembly"* AND
process.command_line:*SharPersist* AND (
  process.command_line:*"-t schtask"* OR
  process.command_line:*"-c"* OR
  process.command_line:*"forfiles.exe"*
)
```

### SharPersist Arguments:
```kql
process.command_line:*SharPersist* AND (
  process.command_line:*"-t schtask"* AND
  process.command_line:*"-m add"* AND
  process.command_line:*"-o daily"*
)
```

## Scheduled Task Persistence Detection

### Schtasks Query Commands:
```kql
process.command_line:*schtasks* AND (
  process.command_line:*"/query"* AND
  process.command_line:*"GoogleUpdateTaskClean"*
)
```

### Suspicious Scheduled Task Creation:
```kql
process.command_line:*schtasks* AND (
  process.command_line:*"/create"* OR
  process.command_line:*"forfiles.exe"* OR
  process.command_line:*"AppData\\Local\\Temp"*
)
```

### GoogleUpdateTaskClean Abuse:
```kql
process.command_line:*"GoogleUpdateTaskClean"* OR (
  process.command_line:*schtasks* AND
  process.command_line:*Google* AND
  process.command_line:*Update*
)
```

## Forfiles.exe Abuse Detection

### Forfiles Command Execution:
```kql
process.name:"forfiles.exe" AND (
  process.command_line:*"/p C:\\Windows\\System32"* OR
  process.command_line:*"/m cmd.exe"* OR
  process.command_line:*"AppData\\Local\\Temp"*
)
```

### Forfiles with Scheduled Tasks:
```kql
process.command_line:*forfiles* AND
process.command_line:*"/c"* AND
process.command_line:*"AppData\\Local\\Temp\\*.exe"
```

### Suspicious Forfiles Parameters:
```kql
process.name:"forfiles.exe" AND
process.command_line:*"/p C:\\Windows\\System32"* AND
process.command_line:*"/m cmd.exe"*
```

## File Upload and Staging Detection

### Temp Directory File Upload:
```kql
file.path:"C:\\Users\\*\\AppData\\Local\\Temp\\*.exe" AND (
  event.action:"file_create" OR
  event.action:"file_write"
)
```

### Beacon Upload Activity:
```kql
process.working_directory:"*\\AppData\\Local\\Temp*" AND (
  event.action:"file_create" OR
  file.extension:"exe"
)
```

### Payload Staging:
```kql
file.path:"*\\AppData\\Local\\Temp\\*" AND
file.extension:"exe" AND
event.action:"file_create" AND
file.size > 100000
```

## Timestomping Detection

### Timestomp Command Execution:
```kql
process.command_line:*timestomp* OR
process.command_line:*"timestomp"* AND
file.path:"*\\AppData\\Local\\Temp\\*.exe"
```

### File Timestamp Modification:
```kql
event.action:"file_change" AND
file.path:"*\\AppData\\Local\\Temp\\*.exe" AND (
  file.attributes:*modified* OR
  process.command_line:*"Google\\GoogleUpdater"*
)
```

### Google Directory Reference:
```kql
process.command_line:*timestomp* AND
process.command_line:*"Google\\GoogleUpdater"* AND
file.path:"*\\Temp\\*.exe"
```

## Cobalt Strike Beacon Detection

### Beacon Working Directory:
```kql
process.working_directory:"C:\\Users\\*\\AppData\\Local\\Temp" AND (
  process.command_line:*"cd"* OR
  process.command_line:*"upload"*
)
```

### Shell Command Execution:
```kql
process.command_line:*"shell"* AND
process.command_line:*schtasks* AND
process.command_line:*GoogleUpdateTaskClean*
```

### Execute-Assembly Usage:
```kql
process.command_line:*"execute-assembly"* AND (
  process.command_line:*SharPersist* OR
  process.command_line:*"-t schtask"*
)
```

## Persistence Verification Detection

### Scheduled Task Enumeration:
```kql
process.command_line:*schtasks* AND
process.command_line:*"/query"* AND
process.command_line:*"/tn"*
```

### Task Scheduler Service Activity:
```kql
process.name:"svchost.exe" AND
process.command_line:*"Schedule"* AND (
  network.protocol:("http" OR "https") OR
  event.action:"network_connection"
)
```

### Daily Task Execution:
```kql
winlog.event_id:4698 AND (
  winlog.event_data.TaskName:*Google* OR
  winlog.event_data.TaskContent:*forfiles* OR
  winlog.event_data.TaskContent:*"AppData\\Local\\Temp"*
)
```

## File System Artifacts

### SharPersist Binary:
```kql
file.name:"SharPersist.exe" AND (
  file.path:*cobaltstrike* OR
  file.path:*payloads* OR
  event.action:"file_create"
)
```

### Payload Files in Temp:
```kql
file.path:"C:\\Users\\*\\AppData\\Local\\Temp\\*.exe" AND
file.name:*schdtask* AND
event.action:"file_create"
```

### Google Updater Impersonation:
```kql
file.path:"*\\Google\\GoogleUpdater\\*" AND (
  event.action:"file_access" OR
  process.command_line:*timestomp*
)
```

## Network Indicators

### Beacon Callback Pattern:
```kql
network.protocol:("http" OR "https") AND
source.ip:* AND (
  @timestamp:[now-24h TO now-23h] OR
  @timestamp:[now-48h TO now-47h]
) AND destination.port:(80 OR 443)
```

### Daily Persistence Callback:
```kql
network.protocol:("http" OR "https") AND
@timestamp:[now-24h TO now] AND
process.parent.name:"forfiles.exe"
```

## Comprehensive Detection Query

### Combined Persistence Campaign Indicators:
```kql
(
  (process.command_line:*domainenum* OR process.command_line:*logonpasswords*) OR
  (process.name:"SharPersist.exe" OR process.command_line:*SharPersist*) OR
  (process.command_line:*schtasks* AND process.command_line:*GoogleUpdateTaskClean*) OR
  (process.command_line:*"execute-assembly"* AND process.command_line:*"-t schtask"*) OR
  (process.name:"forfiles.exe" AND process.command_line:*"AppData\\Local\\Temp"*) OR
  (process.command_line:*timestomp* AND file.path:"*\\Temp\\*.exe") OR
  (file.path:"C:\\Users\\*\\AppData\\Local\\Temp\\*.exe" AND event.action:"file_create") OR
  (process.command_line:*mimikatz* OR process.command_line:*sekurlsa*)
) AND @timestamp:[now-24h TO now]
```

## Behavioral Analysis

### Attack Chain Sequence:
```kql
(
  (process.command_line:*domainenum* AND @timestamp:[now-60m TO now-45m]) AND
  (process.command_line:*logonpasswords* AND @timestamp:[now-45m TO now-30m]) AND
  (process.command_line:*SharPersist* AND @timestamp:[now-30m TO now-15m]) AND
  (process.command_line:*timestomp* AND @timestamp:[now-15m TO now])
)
```

### Persistence Establishment Pattern:
```kql
(
  file.path:"*\\AppData\\Local\\Temp\\*.exe" AND
  event.action:"file_create" AND
  @timestamp:[now-30m TO now-20m]
) AND (
  process.command_line:*schtasks* AND
  @timestamp:[now-20m TO now-10m]
) AND (
  process.command_line:*timestomp* AND
  @timestamp:[now-10m TO now]
)
```

## Key IOCs to Monitor

### Process Indicators:
- **Tools**: SharPersist.exe, mimikatz, forfiles.exe
- **Commands**: domainenum, logonpasswords, schtasks
- **Arguments**: -t schtask, -m add, -o daily, GoogleUpdateTaskClean

### File Indicators:
- **Locations**: C:\Users\*\AppData\Local\Temp\*.exe
- **Names**: SharPersist.exe, *schdtask*.exe
- **Timestamps**: Modified to match Google\GoogleUpdater

### Network Indicators:
- **Timing**: Daily callbacks (24-hour intervals)
- **Protocols**: HTTP/HTTPS
- **Persistence**: Long-term beacon activity

## Alert Thresholds

### High-Confidence Alerts:
- SharPersist execution with schtask arguments
- Timestomping of files in Temp directory
- Scheduled task creation with forfiles.exe
- Execute-assembly with persistence tools

### Medium-Confidence Alerts:
- Domain enumeration commands
- Credential harvesting attempts
- File uploads to Temp directory
- GoogleUpdateTaskClean task queries

## Visualization Recommendations

### Persistence Timeline:
- X-axis: @timestamp
- Y-axis: Persistence stages (Upload → Schedule → Timestomp → Callback)
- Filter: User accounts and file paths

### Scheduled Task Analysis:
- Task creation events
- Daily execution patterns
- File system artifacts
- Network callback correlation

### Attack Progression:
- Initial enumeration → Credential harvest → Persistence setup
- Process parent-child relationships
- File creation and modification timeline
- Long-term monitoring for daily callbacks
