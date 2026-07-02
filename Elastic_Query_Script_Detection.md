# Automated Bash Attack Script Detection - KQL Queries

Detection queries for automated bash script performing nmap scanning, SSH brute force, and directory enumeration through proxychains.

## Bash Script Execution Detection

### Bash Script with Infinite Loop:
```kql
process.name:"bash" AND (
  process.command_line:*"while true"* OR
  process.command_line:*"#!/bin/bash"* OR
  file.extension:"sh" AND
  process.command_line:*"sleep"*
)
```

### Script File Execution:
```kql
process.name:"bash" AND (
  process.args:*".sh" OR
  file.extension:"sh" OR
  process.command_line:*"#!/bin/bash"*
) AND process.command_line:*proxychains*
```

### Long-Running Bash Process:
```kql
process.name:"bash" AND
process.uptime > 3600 AND (
  process.command_line:*"while"* OR
  process.command_line:*"for"* OR
  process.command_line:*"loop"*
)
```

## Proxychains Detection

### Proxychains Process Execution:
```kql
process.name:"proxychains" OR
process.command_line:*proxychains* OR
process.parent.name:"proxychains"
```

### Proxychains with Nmap:
```kql
process.command_line:*proxychains* AND
process.command_line:*nmap* AND (
  process.command_line:*"-A"* OR
  process.command_line:*"-p-"* OR
  process.command_line:*"--script"*
)
```

### SOCKS Proxy Configuration:
```kql
file.path:"*proxychains.conf*" OR
file.path:"*/etc/proxychains*" OR (
  process.command_line:*proxychains* AND
  network.transport:"tcp" AND
  destination.port:[1080 TO 1090]
)
```

## Nmap Aggressive Scan Detection

### Nmap Aggressive Mode (-A):
```kql
process.name:"nmap" AND (
  process.command_line:*"-A"* OR
  process.command_line:*"--aggressive"*
) AND process.command_line:*proxychains*
```

### Full Port Scan (-p-):
```kql
process.name:"nmap" AND (
  process.command_line:*"-p-"* OR
  process.command_line:*"1-65535"*
) AND process.command_line:*proxychains*
```

### Proxychained Nmap Execution:
```kql
process.parent.command_line:*proxychains* AND
process.name:"nmap" AND (
  process.command_line:*"-A"* OR
  process.command_line:*"-p-"*
)
```

## SSH Brute Force Detection

### SSH Brute Force Script Detection:
```kql
process.command_line:*nmap* AND
process.command_line:*"ssh-brute"* AND (
  process.command_line:*"userdb="* OR
  process.command_line:*"passdb="* OR
  process.command_line:*"users.lst"*
)
```

### SSH Script Arguments:
```kql
process.command_line:*"--script-args"* AND (
  process.command_line:*"ssh-brute"* OR
  process.command_line:*"timeout=4s"* OR
  process.command_line:*"userdb=users.lst"*
)
```

### Port 22 Targeting:
```kql
process.command_line:*nmap* AND
process.command_line:*"-p 22"* AND
process.command_line:*"--script"* AND
process.command_line:*proxychains*
```

## Network-Level SSH Brute Force Detection

### High Volume SSH Connection Attempts:
```kql
destination.port:22 AND
network.protocol:"tcp" AND
event.action:"connection_attempted" AND
@timestamp:[now-10m TO now]
```

### Failed SSH Authentication Patterns:
```kql
destination.port:22 AND (
  event.action:"authentication_failure" OR
  event.outcome:"failure"
) AND @timestamp:[now-10m TO now]
```

### SSH Brute Force from Single Source:
```kql
destination.port:22 AND
source.ip:* AND
event.action:("connection_attempted" OR "authentication_failure") AND
@timestamp:[now-10m TO now]
```

## Directory Brute Force Detection

### Dirb Process Execution:
```kql
process.name:"dirb" OR
process.command_line:*dirb* AND (
  process.command_line:*"http://"* OR
  process.command_line:*"common.txt"* OR
  process.command_line:*"/usr/share/dirb/wordlists/"*
)
```

### Proxychained Dirb:
```kql
process.command_line:*proxychains* AND
process.command_line:*dirb* AND
process.command_line:*"http://"*
```

### Directory Enumeration Wordlist:
```kql
process.command_line:*dirb* AND (
  process.command_line:*"common.txt"* OR
  process.command_line:*"/usr/share/dirb/"* OR
  process.command_line:*"wordlist"*
)
```

## Network-Level Directory Enumeration Detection

### High Volume HTTP Requests:
```kql
network.protocol:"http" AND
http.request.method:"GET" AND
@timestamp:[now-10m TO now] AND
source.ip:*
```

### HTTP 404 Response Pattern:
```kql
network.protocol:"http" AND
http.response.status_code:404 AND
@timestamp:[now-10m TO now] AND
source.ip:*
```

### Common Directory Enumeration Paths:
```kql
network.protocol:"http" AND
url.path:("/admin" OR "/test" OR "/backup" OR "/config" OR "/login" OR "/phpmyadmin")
```

## Sleep Pattern Detection

### Script Sleep Commands:
```kql
process.name:"sleep" AND (
  process.command_line:"1200" OR
  process.command_line:"600"
) AND process.parent.name:"bash"
```

### Timing Pattern Analysis:
```kql
process.name:"bash" AND (
  process.command_line:*"sleep 1200"* OR
  process.command_line:*"sleep 600"*
) AND process.command_line:*"while true"*
```

### 20-Minute Cycle Detection:
```kql
@timestamp:[now-20m TO now-19m] AND (
  process.command_line:*nmap* OR
  process.command_line:*dirb* OR
  process.command_line:*"ssh-brute"*
)
```

## Time-Based Correlation Detection

### Sequential Attack Pattern (20-minute cycles):
```kql
(
  (@timestamp:[now-20m TO now-19m] AND process.command_line:*nmap* AND process.command_line:*"-A"*) OR
  (@timestamp:[now-10m TO now-9m] AND process.command_line:*"ssh-brute"*) OR
  (@timestamp:[now-5m TO now] AND process.command_line:*dirb*)
) AND process.command_line:*proxychains*
```

### Attack Cycle Timing:
```kql
(
  process.command_line:*nmap* OR
  process.command_line:*"ssh-brute"* OR
  process.command_line:*dirb*
) AND process.command_line:*proxychains* AND
@timestamp:[now-30m TO now]
```

## File System Indicators

### Wordlist File Access:
```kql
file.path:"/usr/share/dirb/wordlists/common.txt" AND (
  event.action:"file_access" OR
  event.action:"file_read"
)
```

### User/Password List Files:
```kql
file.name:("users.lst" OR "pass.lst" OR "passwords.txt") AND
event.action:("file_access" OR "file_read")
```

### Script File Creation:
```kql
file.extension:"sh" AND
event.action:"file_create" AND (
  file.content:*"while true"* OR
  file.content:*"proxychains"* OR
  file.content:*"nmap"*
)
```

## Process Chain Analysis

### Bash → Proxychains → Attack Tools:
```kql
process.parent.name:"bash" AND
process.name:"proxychains" AND
process.args:("nmap" OR "dirb")
```

### Multiple Attack Tools from Same Parent:
```kql
process.parent.pid:* AND (
  process.name:("nmap" OR "dirb") OR
  process.command_line:*"ssh-brute"*
) AND @timestamp:[now-30m TO now]
```

## Comprehensive Detection Query

### Combined Automated Attack Indicators:
```kql
(
  (process.name:"bash" AND process.command_line:*"while true"* AND process.command_line:*"sleep"*) OR
  (process.command_line:*proxychains* AND process.command_line:*nmap* AND process.command_line:*"-A"*) OR
  (process.command_line:*"ssh-brute"* AND process.command_line:*"userdb=users.lst"*) OR
  (process.command_line:*proxychains* AND process.command_line:*dirb* AND process.command_line:*"common.txt"*) OR
  (process.name:"sleep" AND process.command_line:("1200" OR "600") AND process.parent.name:"bash") OR
  (destination.port:22 AND event.action:"authentication_failure" AND @timestamp:[now-10m TO now]) OR
  (network.protocol:"http" AND http.response.status_code:404 AND @timestamp:[now-10m TO now])
) AND @timestamp:[now-1h TO now]
```

## Behavioral Pattern Analysis

### Attack Loop Detection:
```kql
source.ip:* AND (
  (process.command_line:*nmap* AND @timestamp:[now-25m TO now-15m]) AND
  (destination.port:22 AND @timestamp:[now-15m TO now-5m]) AND
  (network.protocol:"http" AND @timestamp:[now-10m TO now])
)
```

### High-Frequency Scanning:
```kql
source.ip:* AND (
  destination.port:[1 TO 65535] AND
  event.action:"connection_attempted" AND
  @timestamp:[now-20m TO now]
)
```

## Key IOCs to Monitor

### Process Indicators:
- **Script Execution**: bash with while true loops
- **Proxy Usage**: proxychains with attack tools
- **Sleep Timing**: 1200s (20min) and 600s (10min) intervals
- **Tool Chain**: nmap → ssh-brute → dirb sequence

### Network Indicators:
- **Port Scanning**: Full range (1-65535) through proxy
- **SSH Attacks**: Port 22 brute force attempts
- **HTTP Enumeration**: Multiple 404 responses
- **Timing Pattern**: 20-minute attack cycles

### File Indicators:
- **Wordlists**: /usr/share/dirb/wordlists/common.txt
- **Credential Lists**: users.lst, pass.lst
- **Scripts**: .sh files with attack patterns

## Alert Thresholds

### High-Confidence Alerts:
- Proxychains + nmap + ssh-brute + dirb in sequence
- 100+ port connections in 20 minutes
- 50+ SSH authentication failures in 10 minutes
- 100+ HTTP 404 responses in 10 minutes

### Medium-Confidence Alerts:
- Bash script with infinite loop and sleep commands
- Proxychains usage with reconnaissance tools
- Directory enumeration with standard wordlists
- Regular timing patterns (20/10 minute intervals)

## Visualization Recommendations

### Attack Timeline:
- X-axis: @timestamp (5-minute intervals)
- Y-axis: Attack phases (Scan → SSH → Web enum)
- Filter: Source IP and attack tools

### Network Impact Analysis:
- Geographic mapping of source IPs
- Target port distribution
- Response code analysis for HTTP requests
- Connection attempt volumes over time

### Process Execution Flow:
- Parent-child relationships (bash → proxychains → tools)
- Command line argument analysis
- Resource utilization during attacks
- Timing correlation between processes