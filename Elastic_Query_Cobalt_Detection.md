# APT40 Cobalt Strike Campaign Detection - KQL Queries

Detection queries for APT40 Cobalt Strike operations including C2 infrastructure, beacon communications, and persistence mechanisms.

## C2 Infrastructure Detection

### Web Protocol C2 Detection (T1071.001):
```kql
network.protocol:"http" AND (
  url.domain:"x.x.x.x" OR
  url.domain:"x.x.x.x" OR
  url.path:"/jquery-3.3.1.min.js" OR
  url.path:"/jquery-3.3.2.min.js" OR
  url.path:"/jquery-3.3.1.slim.min.js" OR
  url.path:"/jquery-3.3.2.slim.min.js"
)
```

### Suspicious jQuery C2 Traffic:
```kql
network.protocol:"http" AND (
  url.path:*jquery* AND
  http.request.headers.user_agent:"Mozilla/5.0 (Windows NT 6.3; Trident/7.0; rv:11.0) like Gecko"
)
```

### Microsoft Office Template Injection (T1221):
```kql
url.path:"/designs/MicrosoftOffice/*" OR (
  file.extension:"docx" AND
  network.protocol:"http" AND
  url.path:*template*
)
```

## DNS C2 Detection (T1071.004)

### DNS Beacon Communications:
```kql
dns.question.name:"analytics.siftscience.com" OR (
  network.protocol:"dns" AND
  dns.question.type:"TXT" AND
  dns.question.name:*siftscience*
)
```

### Suspicious DNS Queries:
```kql
network.protocol:"dns" AND (
  dns.question.name:*analytics* OR
  dns.response.code:"NXDOMAIN" AND
  dns.question.name:*.siftscience.com
)
```

### DNS Tunneling Detection:
```kql
network.protocol:"dns" AND (
  dns.question.name length > 50 OR
  dns.question.type:"TXT" AND
  dns.response.data length > 100
)
```

## SMB C2 Detection (T1071.002)

### Named Pipe Communications:
```kql
process.name:"*pipe*" OR (
  file.path:"*\\pipe\\mojo.5688.8052.18389493978708887720*" OR
  network.protocol:"smb" AND
  smb.path:"*mojo.5688.8052.18389493978708887720*"
)
```

### SMB Beacon Activity:
```kql
network.protocol:"smb" AND (
  smb.command:"SMB2_CREATE" AND
  smb.path:"*\\pipe\\*" AND
  smb.path:*mojo*
)
```

## Cobalt Strike Process Detection

### Teamserver Process Activity:
```kql
process.name:"teamserver" OR
process.command_line:*teamserver* OR (
  process.name:"java" AND
  process.command_line:*cobaltstrike* AND
  network.transport:"tcp" AND
  destination.port:50050
)
```

### Cobalt Strike Client Detection:
```kql
process.name:"cobaltstrike" OR
process.command_line:*cobaltstrike* OR (
  process.executable.path:*cobaltstrike* AND
  network.transport:"tcp" AND
  destination.port:50050
)
```

### Beacon Sleep Pattern Detection:
```kql
process.command_line:*sleep* AND (
  process.command_line:*600* OR
  process.command_line:*3600* OR
  process.command_line:*57600* OR
  process.command_line:*86400*
)
```

## Aggressor Script Detection

### Process Injection Detection:
```kql
process.name:*inject* OR
process.command_line:*processinject* OR (
  event.action:"process_creation" AND
  process.parent.name:"rundll32.exe" AND
  process.command_line:""
)
```

### Mimikatz Detection:
```kql
process.name:"mimikatz.exe" OR
process.command_line:*mimikatz* OR
process.command_line:*sekurlsa* OR (
  file.name:"mimikatz.exe" OR
  file.hash.sha256:"*mimikatz*"
)
```

### Situational Awareness BOF:
```kql
process.command_line:*whoami* OR
process.command_line:*netstat* OR
process.command_line:*tasklist* OR (
  process.name:"cmd.exe" AND
  process.command_line:*"/c"* AND
  process.parent.name:"rundll32.exe"
)
```

## Persistence Detection (SharPersist)

### SharPersist Execution:
```kql
process.name:"SharPersist.exe" OR
process.command_line:*SharPersist* OR
file.name:"SharPersist.exe"
```

### Scheduled Task Persistence:
```kql
process.command_line:*schtasks* AND (
  process.command_line:*/create* OR
  process.command_line:*/query* OR
  process.command_line:*persistence*
)
```

## Network Traffic Analysis

### High-Frequency Beacon Traffic:
```kql
network.protocol:"http" AND
url.path:*jquery* AND
@timestamp:[now-10m TO now] AND
source.ip:* AND
destination.ip:*
```

### C2 Traffic Timing Analysis:
```kql
(
  @timestamp:[now-10m TO now-9m] OR
  @timestamp:[now-60m TO now-59m] OR
  @timestamp:[now-16h TO now-15h59m]
) AND (
  url.path:*jquery* OR
  dns.question.name:*siftscience*
)
```

## Redirector Detection

### Apache Rewrite Module Activity:
```kql
process.name:"httpd" OR process.name:"apache2" AND (
  file.path:"*/.htaccess*" OR
  process.command_line:*RewriteEngine* OR
  process.command_line:*RewriteRule*
)
```

### Socat DNS Forwarding:
```kql
process.name:"socat" AND (
  process.command_line:*UDP4-RECVFROM:53* OR
  process.command_line:*UDP4-SENDTO* OR
  process.command_line:*fork* AND
  process.command_line:*53*
)
```

## Comprehensive Detection Query

### Combined APT40 Cobalt Strike Indicators:
```kql
(
  (url.path:*jquery* AND http.request.headers.user_agent:"*Windows NT 6.3*") OR
  (dns.question.name:"analytics.siftscience.com") OR
  (file.path:"*\\pipe\\mojo.5688.8052.18389493978708887720*") OR
  (process.name:"teamserver" OR process.name:"cobaltstrike") OR
  (process.name:"SharPersist.exe" OR process.command_line:*SharPersist*) OR
  (process.command_line:*mimikatz* OR process.command_line:*sekurlsa*) OR
  (process.name:"socat" AND process.command_line:*UDP4-RECVFROM:53*) OR
  (url.domain:"203.208.41.3" OR url.domain:"103.152.14.7")
) AND @timestamp:[now-24h TO now]
```

## Key IOCs to Monitor

### Network Indicators:
- **C2 Servers**: 203.208.41.3, 103.152.14.7
- **DNS Beacon**: analytics.siftscience.com
- **User Agent**: Mozilla/5.0 (Windows NT 6.3; Trident/7.0; rv:11.0) like Gecko
- **Named Pipe**: mojo.5688.8052.18389493978708887720

### File Indicators:
- **Payloads**: jquery-3.3.1.min.js, jquery-3.3.2.min.js
- **Templates**: /designs/MicrosoftOffice/*
- **Tools**: teamserver, cobaltstrike, SharPersist.exe

### Behavioral Indicators:
- Sleep intervals: 600s, 3600s, 57600s, 86400s
- Port 50050 communications
- DNS TXT record queries
- SMB named pipe communications

## Alert Thresholds

### High-Confidence Alerts:
- Any communication with known C2 IPs
- DNS queries to analytics.siftscience.com
- Named pipe creation with specific mojo string
- Teamserver/Cobaltstrike process execution

### Medium-Confidence Alerts:
- jQuery requests with specific User-Agent
- Multiple sleep commands with beacon intervals
- Socat DNS forwarding setup
- SharPersist execution

## Visualization Recommendations

### Timeline Analysis:
- X-axis: @timestamp (