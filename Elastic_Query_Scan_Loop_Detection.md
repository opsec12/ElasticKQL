# Automated Attack Loop Detection - KQL Queries

Detection queries for the automated attack pattern involving nmap, SSH brute force, and directory enumeration.

## Nmap Aggressive Scan Detection

### Basic nmap detection:
```kql
network.protocol:"tcp" AND event.action:"connection_attempted" AND destination.port:[1 TO 65535] AND @timestamp:[now-20m TO now]
```

### Aggressive nmap scan detection:
```kql
process.command_line:*nmap* AND (
  process.command_line:*"-A"* OR
  process.command_line:*"-p-"* OR
  process.command_line:*"--script"*
) AND process.command_line:*proxychains*
```

### High-volume port scanning detection:
```kql
network.protocol:"tcp" AND 
event.action:"connection_attempted" AND
destination.port:[1 TO 65535] AND
@timestamp:[now-20m TO now]
```

## SSH Brute Force Detection

### SSH brute force script detection:
```kql
process.command_line:*nmap* AND (
  process.command_line:*"ssh-brute"* OR
  process.command_line:*"--script-args"* OR
  process.command_line:*"userdb="* OR
  process.command_line:*"passdb="*
)
```

### SSH connection attempts pattern:
```kql
destination.port:22 AND 
network.protocol:"tcp" AND
event.action:"connection_attempted" AND
@timestamp:[now-10m TO now]
```

### Failed SSH authentication detection:
```kql
event.action:"authentication_failure" AND
destination.port:22 AND
source.ip:* AND
@timestamp:[now-10m TO now]
```

## Directory Brute Force Detection

### Dirb/Dirbuster detection:
```kql
process.name:"dirb" OR 
process.command_line:*dirb* OR
process.command_line:*"/usr/share/dirb/wordlists/"*
```

### HTTP enumeration pattern:
```kql
network.protocol:"http" AND (
  url.path:*"/admin"* OR
  url.path:*"/test"* OR
  url.path:*"/backup"* OR
  url.path:*"/config"*
) AND http.response.status_code:[400 TO 404]
```

### High-volume HTTP requests:
```kql
network.protocol:"http" AND
event.action:"http_request" AND
@timestamp:[now-10m TO now] AND
source.ip:*
```

## Proxychains Detection

### Proxychains usage detection:
```kql
process.name:"proxychains" OR 
process.command_line:*proxychains* OR
process.parent.name:"proxychains"
```

### SOCKS proxy traffic patterns:
```kql
network.protocol:"tcp" AND
destination.port:[1080 TO 1090] AND
event.action:"connection_established"
```

## Automated Loop Pattern Detection

### Time-based correlation (20-minute intervals):
```kql
@timestamp:[now-40m TO now] AND (
  process.command_line:*nmap* OR
  destination.port:22 OR
  process.command_line:*dirb*
) AND source.ip:*
```

### Sequential attack pattern:
```kql
(
  (process.command_line:*nmap* AND process.command_line:*"-A"*) OR
  (destination.port:22 AND event.action:"connection_attempted") OR
  (process.command_line:*dirb* AND network.protocol:"http")
) AND @timestamp:[now-30m TO now]
```

## Comprehensive Detection Query

### Combined automated attack indicators:
```kql
(
  (process.command_line:*proxychains* AND process.command_line:*nmap* AND process.command_line:*"-A"*) OR
  (process.command_line:*proxychains* AND process.command_line:*nmap* AND process.command_line:*"ssh-brute"*) OR
  (process.command_line:*proxychains* AND process.command_line:*dirb*) OR
  (destination.port:22 AND event.action:"authentication_failure" AND @timestamp:[now-10m TO now]) OR
  (network.protocol:"http" AND http.response.status_code:404 AND @timestamp:[now-10m TO now])
) AND @timestamp:[now-1h TO now]
```

## Behavioral Analysis Queries

### Sleep pattern detection (1200s/600s intervals):
```kql
process.name:"sleep" AND (
  process.command_line:*1200* OR
  process.command_line:*600*
)
```

### Infinite loop detection:
```kql
process.command_line:*"while true"* OR
process.command_line:*"for(;;)"* OR
process.parent.command_line:*"while true"*
```

### Script execution detection:
```kql
process.name:"bash" AND (
  process.command_line:*".sh"* OR
  file.extension:"sh"
) AND process.command_line:*proxychains*
```

## Key Fields to Monitor

* @timestamp
* source.ip
* destination.ip
* destination.port
* process.name
* process.command_line
* process.parent.name
* network.protocol
* event.action
* http.response.status_code
* url.path
* user.name
* host.name

## Alert Thresholds

### High-confidence indicators:
- More than 100 TCP connections in 20 minutes from single source
- SSH authentication failures > 10 in 10 minutes
- HTTP 404 responses > 50 in 10 minutes from single source
- Proxychains + nmap + ssh-brute in same timeframe

### Time correlation windows:
- **Nmap scan**: Look for 20+ minute intervals
- **SSH brute force**: Look for 10+ minute intervals  
- **Directory enumeration**: Look for 10+ minute intervals
- **Overall pattern**: 30-40 minute cycles

## Visualization Recommendations

### Timeline visualization:
- X-axis: @timestamp (5-minute intervals)
- Y-axis: Count of events
- Split by: source.ip, event.action

### Geographic analysis:
- Map visualization showing source.ip locations
- Filter for proxychains usage

### Top attackers table:
- Rows: source.ip
- Metrics: Unique count of destination.ip, Count of events
- Time range: Last 2 hours

These queries will help identify the cyclical nature of this automated attack pattern and correlate the different phases of the attack loop.