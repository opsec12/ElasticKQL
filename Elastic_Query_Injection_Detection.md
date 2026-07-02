# Malicious Macro & Template Injection Detection - KQL Queries

Detection queries for malicious Office macros, AMSI bypasses, script block logging evasion, and remote template injection attacks.

## AMSI Bypass Detection

### Obfuscated AMSI Bypass Patterns:
```kql
process.command_line:*"l`o`AdwIThPa`Rti`AlnamE"* OR
process.command_line:*"g`E`TTYPE"* OR
process.command_line:*"seTVa`l`Ue"* OR
process.command_line:*"A`ss`Embly"* OR
process.command_line:*"AmsiInitFailed"*
```

### PowerShell AMSI Bypass Detection:
```kql
process.command_line:*"System.Management.Automation"* AND
process.command_line:*"amsi"* AND (
  process.command_line:*"InitFailed"* OR
  process.command_line:*"true"* OR
  process.command_line:*"SetValue"*
)
```

### Script Block Logging Bypass:
```kql
process.command_line:*"System.Diagnostics.Eventing.EventProvider"* OR
process.command_line:*"m_enabled"* OR
process.command_line:*"PSEtwLogProvider"* OR
process.command_line:*"etwProvider"*
```

## PowerShell Obfuscation Detection

### String Concatenation Obfuscation:
```kql
process.command_line:*"'+''"* OR
process.command_line:*'"{1}{0}"' OR
process.command_line:*"Get-varI`A`BLE"* OR
process.command_line:*"S`eT-It`em"*
```

### Backtick Obfuscation:
```kql
process.command_line:*"`"* AND (
  process.command_line:*"g`etf`iElD"* OR
  process.command_line:*"sE`T`VaLUE"* OR
  process.command_line:*"A`ss`Embly"* OR
  process.command_line:*"GET`TY`Pe"*
)
```

### PowerShell Execution with Hidden Window:
```kql
process.command_line:*powershell* AND (
  process.command_line:*"-nop"* AND
  process.command_line:*"-w hidden"* AND
  process.command_line:*"-enc"*
)
```

## Base64 Encoded PowerShell Detection

### Encoded Command Execution:
```kql
process.command_line:*"-enc"* AND
process.command_line:*"aQBlAHgA"* OR
process.command_line:*"SQBFAFgA"* OR
process.command_line:*"powershell"* AND
process.command_line length > 200
```

### Specific Base64 Pattern from Document:
```kql
process.command_line:*"aQBlAHgAIAAoAG4AZQB3AC0AbwBiAGoAZQBjAHQAIABuAGUAdAAuAHcAZQBiAGMAbABpAGUAbgB0ACkA"*
```

### IEX and DownloadString Pattern:
```kql
process.command_line:*"iex"* AND
process.command_line:*"new-object"* AND
process.command_line:*"net.webclient"* AND
process.command_line:*"downloadstring"*
```

## Template Injection Detection

### Remote Template URL Access:
```kql
network.protocol:"http" AND (
  url.domain:"gramarly.com" OR
  url.path:"/designs/MicrosoftOffice/press_release_template.dot" OR
  url.path:"/designs/MicrosoftOffice/starter" OR
  url.path:"/designs/MicrosoftOffice/template"
)
```

### Office Template File Downloads:
```kql
network.protocol:"http" AND
file.extension:"dot" AND (
  url.path:*template* OR
  url.path:*"MicrosoftOffice"*
)
```

### Remote Template Injection Tool Detection:
```kql
process.name:"remoteinjector.py" OR
process.command_line:*remoteinjector* OR
process.command_line:*"-w http"* AND
process.command_line:*".dot"*
```

## Office Macro Detection

### WMI Process Creation from Office:
```kql
process.parent.name:("winword.exe" OR "excel.exe" OR "powerpnt.exe") AND
process.command_line:*"winmgmts"* AND
process.command_line:*"Win32_Process"*
```

### AutoOpen Macro Execution:
```kql
process.parent.name:("winword.exe" OR "excel.exe") AND
process.name:"powershell.exe" AND
process.command_line:*"-nop"* AND
process.command_line:*"-w hidden"*
```

### Office Document with External Template:
```kql
file.extension:("docx" OR "xlsx" OR "pptx") AND
network.protocol:"http" AND
url.path:*template*
```

## Memory Stream and Compression Detection

### GZip Stream Decompression:
```kql
process.command_line:*"IO.MemoryStream"* OR
process.command_line:*"IO.Compression.GzipStream"* OR
process.command_line:*"FromBase64String"* OR
process.command_line:*"CompressionMode::Decompress"*
```

### Data Exfiltration Pattern:
```kql
process.command_line:*"%%DATA%%"* OR
process.command_line:*"New-Object IO.StreamReader"* AND
process.command_line:*"ReadToEnd"*
```

## File System Indicators

### Template File Creation:
```kql
file.extension:"dot" AND (
  file.path:*"AppData"* OR
  file.path:*"Temp"* OR
  event.action:"file_create"
)
```

### Office Template Directory Access:
```kql
file.path:"C:\\Program Files (x86)\\Microsoft Office\\Templates\\*" AND
event.action:("file_access" OR "file_modify")
```

### Suspicious Word Document Creation:
```kql
file.extension:"docx" AND
file.name:*"press_release"* AND
event.action:"file_create"
```

## Process Behavior Detection

### Office to PowerShell Chain:
```kql
process.parent.name:("winword.exe" OR "excel.exe") AND
process.name:"powershell.exe" AND
process.command_line:*"http"*
```

### WMI Process Spawning:
```kql
process.command_line:*"Win32_ProcessStartup"* OR
process.command_line:*"SpawnInstance_"* OR
process.command_line:*"impersonationLevel=impersonate"*
```

## Network Communication Patterns

### C2 Communication to gramarly.com:
```kql
network.protocol:"http" AND
url.domain:"gramarly.com" AND (
  url.path:"/designs/MicrosoftOffice/*" OR
  http.request.method:"GET"
)
```

### Template Download Pattern:
```kql
network.protocol:"http" AND
url.path:*".dot"* AND
http.response.status_code:200 AND
http.response.body.bytes > 1000
```

## Comprehensive Detection Query

### Combined Malicious Macro Indicators:
```kql
(
  (process.command_line:*"l`o`AdwIThPa`Rti`AlnamE"* OR process.command_line:*"AmsiInitFailed"*) OR
  (process.command_line:*powershell* AND process.command_line:*"-nop"* AND process.command_line:*"-w hidden"*) OR
  (process.command_line:*"aQBlAHgAIAAoAG4AZQB3AC0AbwBiAGoAZQBjAHQA"*) OR
  (url.domain:"gramarly.com" AND url.path:"/designs/MicrosoftOffice/*") OR
  (process.parent.name:("winword.exe" OR "excel.exe") AND process.command_line:*"winmgmts"*) OR
  (process.command_line:*"IO.MemoryStream"* AND process.command_line:*"GzipStream"*) OR
  (file.extension:"dot" AND network.protocol:"http")
) AND @timestamp:[now-24h TO now]
```

## Event Log Evasion Detection

### Script Block Logging Tampering:
```kql
winlog.event_id:4104 AND
winlog.event_data.ScriptBlockText:*"PSEtwLogProvider"* OR
winlog.event_data.ScriptBlockText:*"m_enabled"*
```

### Missing Expected PowerShell Logs:
```kql
NOT (winlog.event_id:4104) AND
process.name:"powershell.exe" AND
process.command_line length > 100
```

## Key IOCs to Monitor

### Network Indicators:
- **Malicious Domain**: gramarly.com
- **Template URLs**: /designs/MicrosoftOffice/press_release_template.dot
- **Payload URLs**: /designs/MicrosoftOffice/starter, /designs/MicrosoftOffice/template

### File Indicators:
- **Template Files**: template.dot, press_release_template.dot
- **Encoded Payload**: Base64 string starting with "aQBlAHgAIAAoAG4AZQB3AC0A"
- **Tools**: remoteinjector.py

### Process Indicators:
- PowerShell with -nop -w hidden -enc parameters
- WMI process creation from Office applications
- AMSI/ETW bypass techniques

## Alert Thresholds

### High-Confidence Alerts:
- AMSI bypass with obfuscated PowerShell
- Base64 encoded commands from Office processes
- Remote template downloads from gramarly.com
- WMI process creation from Office applications

### Medium-Confidence Alerts:
- PowerShell execution with hidden window
- Office documents accessing external templates
- Script block logging bypass attempts
- Unusual backtick obfuscation patterns

## Visualization Recommendations

### Attack Chain Timeline:
- X-axis: @timestamp
- Y-axis: Event types (Macro execution → AMSI bypass → Template download → C2 communication)
- Filter: Related process PIDs

### Network Flow Analysis:
- Source: Internal hosts
- Destination: gramarly.com
- Protocols: HTTP
- Data transfer patterns

### Process Execution Tree:
- Root: Office applications (winword.exe)
- Children: PowerShell processes
- Grandchildren: Network connections
- Command line analysis
