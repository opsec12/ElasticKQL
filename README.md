# elastickql

A Python CLI for managing and running Elastic Security KQL detection queries. Converted from [opsec12/ElasticKQL](https://github.com/opsec12/ElasticKQL) — 38 detection queries across 7 attack categories, each tagged with MITRE ATT&CK techniques.

## Features

- **38 detection queries** covering APT campaigns, Cobalt Strike, persistence, injection, exfiltration, scanning, and bash attack scripts
- **MITRE ATT&CK tagged** — every query maps to one or more technique IDs
- **Search** across query names, descriptions, body, and MITRE IDs
- **Export** to JSON, NDJSON, KQL, or CSV
- **Run** queries live against Elasticsearch via REST API
- **Zero dependencies** — stdlib only

## Usage

```bash
# List all query categories
python3 elastickql.py categories

# List all queries
python3 elastickql.py list

# Filter by category
python3 elastickql.py list --category cobalt

# Show a full query with KQL
python3 elastickql.py show 15

# Search by keyword, MITRE ID, or query body
python3 elastickql.py search "psexec"
python3 elastickql.py search "T1055"

# Export queries
python3 elastickql.py export --format kql --category scan
python3 elastickql.py export --format json
python3 elastickql.py export --format csv

# Run against a live Elasticsearch cluster
python3 elastickql.py run 15 \
  --es https://localhost:9200 \
  --index .ds-logs-* \
  --user elastic \
  --password changeme
```

## Categories

| Category | Queries | Coverage |
|----------|---------|----------|
| `apt` | 6 | Multi-day APT campaign: lateral movement, privilege escalation, exfiltration |
| `cobalt` | 9 | Cobalt Strike / APT40: C2 infrastructure, beacons, mimikatz, redirectors |
| `persistence` | 5 | SharPersist, scheduled tasks, forfiles.exe abuse, timestomp |
| `injection` | 6 | Malicious macros, AMSI bypass, template injection, Office→PowerShell chains |
| `exfil` | 4 | Executive network data theft, EngineeringDocs SMB staging, large transfers |
| `scan` | 4 | TCP port scanning, SSH brute force, HTTP directory enumeration |
| `script` | 4 | Automated bash attack scripts: proxychains, nmap, ssh-brute, dirb |

## Example Queries

### APT40 Cobalt Strike — Comprehensive (ID: 15)
```kql
(
  (url.path:*jquery* AND http.request.headers.user_agent:"*Windows NT 6.3*") OR
  (dns.question.name:"analytics.siftscience.com") OR
  (file.path:"*\\pipe\\mojo.5688.8052.18389493978708887720*") OR
  (process.name:"teamserver" OR process.name:"cobaltstrike") OR
  (process.name:"SharPersist.exe" OR process.command_line:*SharPersist*) OR
  (process.command_line:*mimikatz* OR process.command_line:*sekurlsa*) OR
  (process.name:"socat" AND process.command_line:*UDP4-RECVFROM:53*)
) AND @timestamp:[now-24h TO now]
```
MITRE: T1071.001 · T1071.004 · T1071.002 · T1055 · T1003.001 · T1090.001

### SSH Brute Force (ID: 33)
```kql
destination.port:22 AND (
  event.action:"authentication_failure" OR
  event.outcome:"failure"
) AND @timestamp:[now-10m TO now]
```
MITRE: T1110.001

### AMSI Bypass Detection (ID: 21)
```kql
process.command_line:*"l`o`AdwIThPa`Rti`AlnamE"* OR
process.command_line:*"AmsiInitFailed"* OR (
  process.command_line:*"System.Management.Automation"* AND
  process.command_line:*"amsi"* AND
  process.command_line:*"InitFailed"*
)
```
MITRE: T1562.001 · T1027

## Running Against Elasticsearch

```bash
# Point at your Elastic cluster and run query #7 (C2 jQuery Beacon)
python3 elastickql.py run 7 \
  --es https://my-elastic-cluster:9200 \
  --index .ds-logs-endpoint.events.process-* \
  --user elastic \
  --password $ES_PASSWORD \
  --size 50
```

The `run` command POSTs the KQL as an Elasticsearch `query_string` DSL query and prints the top hits sorted by `@timestamp` descending.

## Export Formats

| Format | Use case |
|--------|----------|
| `json` | Full structured query library |
| `ndjson` | Elastic bulk import / Kibana saved objects |
| `kql` | Copy-paste into Kibana Discover or Detection Rules |
| `csv` | Reporting, spreadsheet tracking |

## License

MIT — Eric Fong ([github.com/opsec12](https://github.com/opsec12))
