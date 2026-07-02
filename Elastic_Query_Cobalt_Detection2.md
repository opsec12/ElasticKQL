# Cobalt Strike Payload & Process Injection Detection - KQL Queries

Detection queries for Cobalt Strike payload generation, file hosting, initial access, and process injection techniques.

## Payload Generation Detection

### Cobalt Strike Payload Creation:
```kql
process.name:"cobaltstrike" OR
process.command_line:*cobaltstrike* AND (
  file.extension:"exe" OR
  process.command_line:*"stageless"* OR
  process.command_line:*"payload"*
)
```

### Windows EXE Payload Generation:
```kql
process.command_line:*"windows"* AND
process.command_line:*"exe"* AND (
  process.command_line:*"x64"* OR
  process.command_line:*"wininet"* OR
  process.command_line:*"indirect"*
)
```

### Teamserver Payload Activity:
```kql
process.name:"teamserver" AND (
  file.extension:"exe" AND
  event.action:"file_create" OR
  network.transport:"tcp" AND
  destination.port:80
)
```

## File Hosting Detection

### HTTP File Hosting on Port 80:
```kql
network.transport:"tcp" AND
destination.port:80 AND (
  url.path:"/download/*" OR
  url.path:*".exe" OR
  http.response.mime_type:"application/octet-stream"
)
```

### Suspicious Download URLs:
```kql
network.protocol:"http" AND (
  url.path:"/download/*" AND
  url.path:*".exe" OR
  http.request.method:"GET" AND
  file.extension:"exe"
)
```

### Teamserver IP File Hosting:
```kql
network.protocol:"http" AND
destination.port:80 AND (
  url.domain:* AND
  url.path:"/download/*" AND
  http.response.status_code:200
)
```

## Initial Access Detection

### Executable Download from Web:
```kql
network.protocol:"http" AND
event.action:"file_download" AND (
  file.extension:"exe" AND
  url.path:"/download/*" OR
  http.response.mime_type:"application/octet-stream"
)
```

### Suspicious File Downloads:
```kql
network.protocol:"http" AND
file.extension:"exe" AND (
  file.path:*"Downloads"* OR
  file.path:*"Temp"* OR
  file.path:*"AppData"*
) AND event.action:"file_create"
```

### Web-Delivered Executable Execution:
```kql
process.executable.path:*"Downloads"* AND
process.executable.extension:"exe" AND
network.protocol:"http" AND
@timestamp:[now-10m TO now]
```

## Scripted Web Delivery Detection

### PowerShell Web Delivery:
```kql
process.name:"powershell.exe" AND
process.command_line:*"IEX"* AND
process.command_line:*"Net.WebClient"* AND
process.command_line:*"DownloadString"*
```

### Encoded PowerShell Delivery:
```kql
process.command_line:*powershell* AND (
  process.command_line:*"-enc"* OR
  process.command_line:*"-e"* OR
  process.command_line:*"encodedCommand"*
) AND network.protocol:"http"
```

### Base64 Web Delivery Pattern:
```kql
process.command_line:*powershell* AND
process.command_line:*"frombase64string"* AND
process.command_line:*"webclient"*
```

## Process Injection Detection

### Beacon Process Injection:
```kql
process.name:"cobaltstrike" AND
process.command_line:*"inject"* AND (
  process.command_line:*"svchost"* OR
  process.command_line:*"x64"* OR
  process.command_line:*"https"*
)
```

### Suspicious Process Injection Patterns:
```kql
event.action:"process_injection" OR (
  process.name:("svchost.exe" OR "explorer.exe" OR "winlogon.exe") AND
  network.protocol:("http" OR "https") AND
  destination.port:(80 OR 443)
)
```

### Cross-Process Memory Operations:
```kql
event.action:("process_open" OR "process_access") AND
process.access.mask:("PROCESS_ALL_ACCESS" OR "0x1F0FFF") AND
process.target.name:("svchost.exe" OR "explorer.exe")
```

## Beacon Communication Detection

### 10-Minute Sleep Timer Pattern:
```kql
network.protocol:("http" OR "https") AND
@timestamp:[now-10m TO now-9m] AND
destination.port:(80 OR 443) AND
source.ip:*
```

### Beacon Callback Timing:
```kql
network.protocol:("http" OR "https") AND (
  @timestamp:[now-10m TO now-9m30s] OR
  @timestamp:[now-20m TO now-19m30s] OR
  @timestamp:[now-30m TO now-29m30s]
) AND destination.port:(80 OR 443)
```

### HTTPS Beacon Communication:
```kql
network.protocol:"https" AND
destination.port:443 AND (
  tls.client.ja3:* OR
  http.request.headers.user_agent:*
) AND @timestamp:[now-15m TO now]
```

## Process Privilege Detection

### SYSTEM/Administrator Process Injection:
```kql
process.name:("svchost.exe" OR "winlogon.exe" OR "lsass.exe") AND
user.name:("SYSTEM" OR "Administrator") AND (
  network.protocol:("http" OR "https") OR
  event.action:"network_connection"
)
```

### Elevated Process Network Activity:
```kql
process.token.elevation_type:"full" AND
network.protocol:("http" OR "https") AND
destination.port:(80 OR 443) AND
process.name:("svchost.exe" OR "explorer.exe")
```

## Beacon Management Detection

### Beacon Kill Commands:
```kql
process.command_line:*"beacon"* AND (
  process.command_line:*"kill"* OR
  process.command_line:*"exit"* OR
  process.command_line:*"terminate"*
)
```

### Multiple Beacon Sessions:
```kql
network.protocol:("http" OR "https") AND
destination.port:(80 OR 443) AND
source.ip:* AND
@timestamp:[now-5m TO now]
```

## File System Indicators

### Payload File Creation:
```kql
file.extension:"exe" AND (
  file.path:*"download"* OR
  file.name:*"obscure"* OR
  file.path:*"temp"*
) AND event.action:"file_create"
```

### Executable in Suspicious Locations:
```kql
file.extension:"exe" AND (
  file.path:*"\\AppData\\Local\\Temp\\*" OR
  file.path:*"\\Users\\*\\Downloads\\*" OR
  file.path:*"\\Windows\\Temp\\*"
) AND event.action:"file_create"
```

## Network Traffic Analysis

### HTTP GET Requests for Executables:
```kql
network.protocol:"http" AND
http.request.method:"GET" AND (
  url.path:*".exe" OR
  url.path:"/download/*"
) AND http.response.status_code:200
```

### Suspicious MIME Types:
```kql
network.protocol:"http" AND (
  http.response.mime_type:"application/octet-stream" OR
  http.response.mime_type:"application/x-msdownload" OR
  http.response.mime_type:"application/x-executable"
)
```

## Comprehensive Detection Query

### Combined Cobalt Strike Payload Indicators:
```kql
(
  (process.name:"cobaltstrike" AND file.extension:"exe") OR
  (network.protocol:"http" AND url.path:"/download/*" AND url.path:*".exe") OR
  (process.command_line:*"inject"* AND process.command_line:*"svchost"*) OR
  (process.name:"powershell.exe" AND process.command_line:*"IEX"* AND process.command_line:*"WebClient"*) OR
  (file.extension:"exe" AND file.path:*"temp"* AND event.action:"file_create") OR
  (process.name:"svchost.exe" AND network.protocol:"https" AND user.name:"SYSTEM") OR
  (network.protocol:("http" OR "https") AND @timestamp:[now-10m TO now-9m])
) AND @timestamp:[now-1h TO now]
```

## Behavioral Analysis

### Initial Access Chain:
```kql
(
  event.action:"file_download" AND file.extension:"exe"
) AND @timestamp:[now-30m TO now] AND (
  process.executable.path:*"Downloads"* OR
  process.executable.path:*"Temp"*
)
```

### Injection to Privilege Escalation:
```kql
process.name:("svchost.exe" OR "winlogon.exe") AND
user.name:("SYSTEM" OR "Administrator") AND
network.protocol:("http" OR "https") AND
@timestamp:[now-20m TO now]
```

## Key IOCs to Monitor

### Network Indicators:
- **Download URLs**: /download/[filename].exe
- **Ports**: 80 (HTTP), 443 (HTTPS)
- **MIME Types**: application/octet-stream
- **Timing**: 10-minute intervals

### Process Indicators:
- **Injection Targets**: svchost.exe, explorer.exe, winlogon.exe
- **Payload Types**: Windows x64 EXE
- **Execution Context**: SYSTEM/Administrator privileges

### File Indicators:
- **Locations**: Downloads, Temp, AppData folders
- **Extensions**: .exe files
- **Hosting**: Teamserver IP on port 80

## Alert Thresholds

### High-Confidence Alerts:
- Executable download followed by execution within 5 minutes
- Process injection into system processes with network activity
- Multiple beacons from same source with 10-minute intervals
- PowerShell web delivery with Base64 encoding

### Medium-Confidence Alerts:
- HTTP downloads of executable files
- Suspicious process network connections
- File creation in temporary directories
- Elevated process network activity

## Visualization Recommendations

### Attack Timeline:
- X-axis: @timestamp
- Y-axis: Attack stages (Download → Execute → Inject → C2)
- Filter: Source IP and target processes

### Process Injection Analysis:
- Parent-child process relationships
- Injection targets (svchost, explorer)
- Network connections per injected process
- Privilege levels and user contexts

### Network Flow Monitoring:
- Source/destination IP pairs
- Download patterns and timing
- Beacon communication intervals
- Protocol and port analysis