# Cobalt Strike Persistence Detection - KQL Queries

Here are KQL queries to detect Cobalt Strike persistence activity in Elasticsearch:

## File Upload/Creation Detection

### Temp directory file creation:
```kql
process.working_directory:"*\\AppData\\Local\\Temp*" AND (
  event.action:"file_create" OR
  file.name:*.exe OR
  process.name:"beacon*"
)
```

### SharPersist execution:
```kql
process.name:"SharPersist.exe" OR 
process.command_line:*SharPersist* OR 
file.name:"SharPersist.exe"
```

## Scheduled Task Detection

### Schtasks commands:
```kql
process.command_line:*schtasks* AND (
  process.command_line:*GoogleUpdateTaskClean* OR
  process.command_line:*/query* OR
  process.command_line:*/create*
)
```

### Suspicious scheduled task creation:
```kql
process.command_line:*schtasks* AND 
process.command_line:*forfiles.exe* AND 
process.command_line:*AppData\\Local\\Temp*
```

## Execute-Assembly Detection

### Assembly execution patterns:
```kql
process.command_line:*execute-assembly* OR (
  process.command_line:*"-t schtask"* AND
  process.command_line:*"-c"* AND
  process.command_line:*forfiles.exe*
)
```

## Timestomp Detection

### File timestamp modification:
```kql
event.action:"file_change" AND (
  process.command_line:*timestomp* OR
  file.path:"*\\AppData\\Local\\Temp\\*.exe"
) AND file.path:"*Google*"
```

## Comprehensive Detection Query

### Combined persistence indicators:
```kql
(
  (process.command_line:*schtasks* AND process.command_line:*forfiles.exe*) OR
  (process.name:"SharPersist.exe" OR process.command_line:*SharPersist*) OR
  (process.command_line:*execute-assembly* AND process.command_line:*schtask*) OR
  (process.command_line:*timestomp* AND file.path:"*\\Temp\\*.exe") OR
  (event.action:"file_create" AND file.path:"*\\AppData\\Local\\Temp\\*.exe")
) AND @timestamp:[now-24h TO now]
```

## Key Fields to Display in Discover

* @timestamp
* host.name
* user.name
* process.command_line
* process.name
* file.path
* file.name
* event.action

## Behavioral Patterns to Look For

### Sequential activity detection:
```kql
user.name:* AND (
  process.working_directory:"*\\Temp*" OR
  process.command_line:*GoogleUpdateTaskClean*
) | sort @timestamp
```

### Forfiles.exe abuse:
```kql
process.name:"forfiles.exe" AND 
process.command_line:*cmd.exe* AND 
process.command_line:"*\\AppData\\Local\\Temp\\*"
```

## Time-based Correlation

Look for these events occurring within a short timeframe (minutes):

1. File upload to Temp directory
2. Schtasks query commands
3. SharPersist execution
4. Timestomp operations

### Time correlation query:
```kql
@timestamp:[now-1h TO now] AND (
  process.command_line:*schtasks* OR
  process.name:"SharPersist.exe" OR
  process.command_line:*timestomp*
) | sort @timestamp
```