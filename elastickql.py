#!/usr/bin/env python3
"""
elastickql — Elastic Security KQL Detection Query Library & Runner
Converted from: github.com/opsec12/ElasticKQL

Usage:
    python3 elastickql.py list
    python3 elastickql.py list --category cobalt
    python3 elastickql.py show 5
    python3 elastickql.py search "psexec"
    python3 elastickql.py run 5 --es https://localhost:9200 --index .siem-signals-*
    python3 elastickql.py export --format json
    python3 elastickql.py categories

Zero dependencies for core use. Optional: ES API via stdlib urllib.
"""

import argparse
import json
import sys
import textwrap
import urllib.error
import urllib.parse
import urllib.request
from typing import List, Optional

# ── ANSI Colors ───────────────────────────────────────────────────────────────

RED    = "\033[91m"
YELLOW = "\033[93m"
GREEN  = "\033[92m"
CYAN   = "\033[96m"
MAGENTA= "\033[95m"
BOLD   = "\033[1m"
DIM    = "\033[2m"
RESET  = "\033[0m"

CAT_COLOR = {
    "apt":         MAGENTA,
    "cobalt":      RED,
    "persistence": YELLOW,
    "injection":   CYAN,
    "exfil":       RED,
    "scan":        GREEN,
    "script":      YELLOW,
}

# ── Query Library ─────────────────────────────────────────────────────────────
#
# Structure per query:
#   id       : unique int
#   category : short slug (apt | cobalt | persistence | injection | exfil | scan | script)
#   name     : query title
#   mitre    : MITRE ATT&CK technique IDs
#   desc     : plain-English what this detects
#   query    : the raw KQL string

QUERIES = [

    # ── APT Campaign ──────────────────────────────────────────────────────────

    {
        "id": 1,
        "category": "apt",
        "name": "PSExec Lateral Movement",
        "mitre": ["T1021.002", "T1570"],
        "desc": "Detects PSExec usage for lateral movement via SMB including Cobalt Strike 'jump psexec' command",
        "query": textwrap.dedent("""\
            process.command_line:*"jump psexec"* OR (
              process.name:"psexec.exe" OR
              process.command_line:*psexec* AND
              destination.ip:* AND
              network.protocol:"smb"
            )"""),
    },
    {
        "id": 2,
        "category": "apt",
        "name": "Token Impersonation (make_token)",
        "mitre": ["T1134.003"],
        "desc": "Detects Cobalt Strike make_token and rev2self credential impersonation commands",
        "query": textwrap.dedent("""\
            process.command_line:*"make_token"* AND (
              process.command_line:*"SITE2\\"* OR
              process.command_line:*"rev2self"*
            )"""),
    },
    {
        "id": 3,
        "category": "apt",
        "name": "PowerView Reconnaissance",
        "mitre": ["T1069.002", "T1087.002"],
        "desc": "Detects PowerView import and domain enumeration commands (Get-NetUser, Get-NetGroup, Domain Admins)",
        "query": textwrap.dedent("""\
            process.command_line:*"powershell-import"* AND
            process.command_line:*"PowerView.ps1"* OR (
              process.command_line:*"powerpick"* AND (
                process.command_line:*"Get-NetUser"* OR
                process.command_line:*"Get-NetGroup"* OR
                process.command_line:*"Get-NetComputer"* OR
                process.command_line:*"Domain Admins"*
              )
            )"""),
    },
    {
        "id": 4,
        "category": "apt",
        "name": "UAC Bypass (uac-cmstplua)",
        "mitre": ["T1548.002"],
        "desc": "Detects UAC bypass using CMSTPLUA COM interface, commonly used by Cobalt Strike runasadmin",
        "query": textwrap.dedent("""\
            process.command_line:*"runasadmin"* OR
            process.command_line:*"uac-cmstplua"* OR
            process.command_line:*"Runasadmin uac-cmstplua"*"""),
    },
    {
        "id": 5,
        "category": "apt",
        "name": "Data Staging in Windows Temp",
        "mitre": ["T1074.001"],
        "desc": "Detects file staging from network shares to Windows Temp for exfiltration preparation",
        "query": textwrap.dedent("""\
            process.command_line:*"shell copy"* AND
            process.command_line:*"\\\\172.17.2.4\\\\EngineeringDocs"* AND
            process.command_line:*"C:\\\\Windows\\\\Temp\\\\"*"""),
    },
    {
        "id": 6,
        "category": "apt",
        "name": "Multi-Day APT Campaign — Comprehensive",
        "mitre": ["T1021.002", "T1134.003", "T1069.002", "T1548.002", "T1074.001", "T1041"],
        "desc": "Broad composite query combining all indicators across a multi-day APT campaign (lateral movement, persistence, exfil)",
        "query": textwrap.dedent("""\
            (
              (process.command_line:*"make_token SITE2"* AND process.command_line:*"jump psexec"*) OR
              (process.command_line:*"powershell-import"* AND process.command_line:*"PowerView"*) OR
              (process.command_line:*"netshares"* AND process.command_line:*"EngineeringDocs"*) OR
              (process.command_line:*"runasadmin uac-cmstplua"* AND process.command_line:*"oneliner"*) OR
              (process.command_line:*"download"* AND process.command_line:*"172.17.2.4"*) OR
              (winlog.event_data.TaskName:*"GoogleUpdateTaskClean"* AND @timestamp:[now-7d TO now])
            ) AND @timestamp:[now-7d TO now]"""),
    },

    # ── Cobalt Strike ─────────────────────────────────────────────────────────

    {
        "id": 7,
        "category": "cobalt",
        "name": "C2 jQuery HTTP Beacon",
        "mitre": ["T1071.001"],
        "desc": "Detects APT40 Cobalt Strike HTTP C2 using fake jQuery file paths and IE11 user-agent",
        "query": textwrap.dedent("""\
            network.protocol:"http" AND (
              url.path:"/jquery-3.3.1.min.js" OR
              url.path:"/jquery-3.3.2.min.js" OR
              url.path:"/jquery-3.3.1.slim.min.js" OR
              url.path:"/jquery-3.3.2.slim.min.js"
            ) OR (
              network.protocol:"http" AND
              url.path:*jquery* AND
              http.request.headers.user_agent:"Mozilla/5.0 (Windows NT 6.3; Trident/7.0; rv:11.0) like Gecko"
            )"""),
    },
    {
        "id": 8,
        "category": "cobalt",
        "name": "DNS Beacon (siftscience.com)",
        "mitre": ["T1071.004"],
        "desc": "Detects DNS C2 beacon to analytics.siftscience.com including TXT record tunneling",
        "query": textwrap.dedent("""\
            dns.question.name:"analytics.siftscience.com" OR (
              network.protocol:"dns" AND
              dns.question.type:"TXT" AND
              dns.question.name:*siftscience*
            )"""),
    },
    {
        "id": 9,
        "category": "cobalt",
        "name": "SMB Named Pipe C2",
        "mitre": ["T1071.002", "T1090"],
        "desc": "Detects Cobalt Strike SMB beacon using mojo named pipe for peer-to-peer C2",
        "query": textwrap.dedent("""\
            file.path:"*\\\\pipe\\\\mojo.5688.8052.18389493978708887720*" OR (
              network.protocol:"smb" AND
              smb.path:"*mojo.5688.8052.18389493978708887720*"
            ) OR (
              network.protocol:"smb" AND
              smb.command:"SMB2_CREATE" AND
              smb.path:"*\\\\pipe\\\\*" AND
              smb.path:*mojo*
            )"""),
    },
    {
        "id": 10,
        "category": "cobalt",
        "name": "Cobalt Strike Teamserver / Client Process",
        "mitre": ["T1587.001"],
        "desc": "Detects teamserver or cobaltstrike process execution and port 50050 communications",
        "query": textwrap.dedent("""\
            process.name:"teamserver" OR
            process.name:"cobaltstrike" OR
            process.command_line:*cobaltstrike* OR (
              process.name:"java" AND
              process.command_line:*cobaltstrike* AND
              network.transport:"tcp" AND
              destination.port:50050
            )"""),
    },
    {
        "id": 11,
        "category": "cobalt",
        "name": "Cobalt Strike Beacon Sleep Patterns",
        "mitre": ["T1029"],
        "desc": "Detects sleep commands matching common Cobalt Strike beacon intervals (10min, 1h, 16h, 24h)",
        "query": textwrap.dedent("""\
            process.command_line:*sleep* AND (
              process.command_line:*600* OR
              process.command_line:*3600* OR
              process.command_line:*57600* OR
              process.command_line:*86400*
            )"""),
    },
    {
        "id": 12,
        "category": "cobalt",
        "name": "Process Injection Detection",
        "mitre": ["T1055"],
        "desc": "Detects processinject and inject commands, and suspicious rundll32 child processes with empty command lines",
        "query": textwrap.dedent("""\
            process.name:*inject* OR
            process.command_line:*processinject* OR (
              event.action:"process_creation" AND
              process.parent.name:"rundll32.exe" AND
              process.command_line:""
            )"""),
    },
    {
        "id": 13,
        "category": "cobalt",
        "name": "Mimikatz Credential Dumping",
        "mitre": ["T1003.001"],
        "desc": "Detects mimikatz and sekurlsa by process name, command line, and file hash",
        "query": textwrap.dedent("""\
            process.name:"mimikatz.exe" OR
            process.command_line:*mimikatz* OR
            process.command_line:*sekurlsa* OR
            process.command_line:*logonpasswords* OR
            file.name:"mimikatz.exe"
            """),
    },
    {
        "id": 14,
        "category": "cobalt",
        "name": "Socat DNS Forwarder (Redirector)",
        "mitre": ["T1090.001"],
        "desc": "Detects socat used as a DNS forwarding redirector for Cobalt Strike C2 infrastructure",
        "query": textwrap.dedent("""\
            process.name:"socat" AND (
              process.command_line:*UDP4-RECVFROM:53* OR
              process.command_line:*UDP4-SENDTO* OR (
                process.command_line:*fork* AND
                process.command_line:*53*
              )
            )"""),
    },
    {
        "id": 15,
        "category": "cobalt",
        "name": "APT40 Cobalt Strike — Comprehensive",
        "mitre": ["T1071.001", "T1071.004", "T1071.002", "T1055", "T1003.001", "T1090.001"],
        "desc": "Combined APT40 detection: C2 jQuery traffic, DNS beacon, named pipe, teamserver, SharPersist, mimikatz, socat",
        "query": textwrap.dedent("""\
            (
              (url.path:*jquery* AND http.request.headers.user_agent:"*Windows NT 6.3*") OR
              (dns.question.name:"analytics.siftscience.com") OR
              (file.path:"*\\\\pipe\\\\mojo.5688.8052.18389493978708887720*") OR
              (process.name:"teamserver" OR process.name:"cobaltstrike") OR
              (process.name:"SharPersist.exe" OR process.command_line:*SharPersist*) OR
              (process.command_line:*mimikatz* OR process.command_line:*sekurlsa*) OR
              (process.name:"socat" AND process.command_line:*UDP4-RECVFROM:53*) OR
              (url.domain:"203.208.41.3" OR url.domain:"103.152.14.7")
            ) AND @timestamp:[now-24h TO now]"""),
    },

    # ── Persistence ───────────────────────────────────────────────────────────

    {
        "id": 16,
        "category": "persistence",
        "name": "SharPersist Execution",
        "mitre": ["T1053.005"],
        "desc": "Detects SharPersist tool used for scheduled task persistence establishment",
        "query": textwrap.dedent("""\
            process.name:"SharPersist.exe" OR
            process.command_line:*SharPersist* OR
            file.name:"SharPersist.exe"
            """),
    },
    {
        "id": 17,
        "category": "persistence",
        "name": "GoogleUpdateTaskClean Scheduled Task",
        "mitre": ["T1053.005", "T1036.004"],
        "desc": "Detects fake GoogleUpdateTaskClean scheduled task used as masqueraded persistence by Cobalt Strike",
        "query": textwrap.dedent("""\
            winlog.event_id:4698 AND (
              winlog.event_data.TaskName:*"GoogleUpdateTaskClean"* OR
              winlog.event_data.TaskContent:*"forfiles.exe"*
            )"""),
    },
    {
        "id": 18,
        "category": "persistence",
        "name": "Forfiles.exe Abuse via Scheduled Task",
        "mitre": ["T1053.005", "T1218"],
        "desc": "Detects forfiles.exe used inside scheduled tasks to execute payloads from AppData Temp",
        "query": textwrap.dedent("""\
            process.name:"forfiles.exe" AND
            process.command_line:*cmd.exe* AND
            process.command_line:"*\\\\AppData\\\\Local\\\\Temp\\\\*"
            OR (
              process.command_line:*schtasks* AND
              process.command_line:*forfiles.exe* AND
              process.command_line:*AppData\\\\Local\\\\Temp*
            )"""),
    },
    {
        "id": 19,
        "category": "persistence",
        "name": "Timestomp Anti-Forensics",
        "mitre": ["T1070.006"],
        "desc": "Detects timestomp usage to alter file timestamps on executables in Temp directories",
        "query": textwrap.dedent("""\
            event.action:"file_change" AND (
              process.command_line:*timestomp* OR
              file.path:"*\\\\AppData\\\\Local\\\\Temp\\\\*.exe"
            ) AND file.path:"*Google*"
            OR (
              file.path:"C:\\\\Users\\\\*\\\\AppData\\\\Local\\\\Temp\\\\*.exe" AND
              event.action:"file_create" AND
              @timestamp:[now-7d TO now]
            )"""),
    },
    {
        "id": 20,
        "category": "persistence",
        "name": "Persistence — Comprehensive",
        "mitre": ["T1053.005", "T1036.004", "T1070.006", "T1218"],
        "desc": "Combined persistence detection: SharPersist, schtasks, execute-assembly, timestomp, Temp exe drops",
        "query": textwrap.dedent("""\
            (
              (process.command_line:*schtasks* AND process.command_line:*forfiles.exe*) OR
              (process.name:"SharPersist.exe" OR process.command_line:*SharPersist*) OR
              (process.command_line:*execute-assembly* AND process.command_line:*schtask*) OR
              (process.command_line:*timestomp* AND file.path:"*\\\\Temp\\\\*.exe") OR
              (event.action:"file_create" AND file.path:"*\\\\AppData\\\\Local\\\\Temp\\\\*.exe")
            ) AND @timestamp:[now-24h TO now]"""),
    },

    # ── Injection / Macro ─────────────────────────────────────────────────────

    {
        "id": 21,
        "category": "injection",
        "name": "AMSI Bypass (Obfuscated PowerShell)",
        "mitre": ["T1562.001", "T1027"],
        "desc": "Detects obfuscated AMSI bypass techniques using backtick obfuscation and AmsiInitFailed patterns",
        "query": textwrap.dedent("""\
            process.command_line:*"l`o`AdwIThPa`Rti`AlnamE"* OR
            process.command_line:*"g`E`TTYPE"* OR
            process.command_line:*"seTVa`l`Ue"* OR
            process.command_line:*"A`ss`Embly"* OR
            process.command_line:*"AmsiInitFailed"* OR (
              process.command_line:*"System.Management.Automation"* AND
              process.command_line:*"amsi"* AND (
                process.command_line:*"InitFailed"* OR
                process.command_line:*"SetValue"*
              )
            )"""),
    },
    {
        "id": 22,
        "category": "injection",
        "name": "Base64 Encoded PowerShell (IEX)",
        "mitre": ["T1059.001", "T1027"],
        "desc": "Detects base64-encoded IEX DownloadString payloads typically used in macro dropper chains",
        "query": textwrap.dedent("""\
            process.command_line:*"-enc"* AND
            process.command_line:*"aQBlAHgA"* OR
            process.command_line:*"SQBFAFgA"* OR (
              process.command_line:*"iex"* AND
              process.command_line:*"new-object"* AND
              process.command_line:*"net.webclient"* AND
              process.command_line:*"downloadstring"*
            )"""),
    },
    {
        "id": 23,
        "category": "injection",
        "name": "Remote Template Injection (gramarly.com)",
        "mitre": ["T1221"],
        "desc": "Detects remote template injection via HTTP to gramarly.com with MicrosoftOffice .dot template paths",
        "query": textwrap.dedent("""\
            network.protocol:"http" AND (
              url.domain:"gramarly.com" OR
              url.path:"/designs/MicrosoftOffice/press_release_template.dot" OR
              url.path:"/designs/MicrosoftOffice/starter" OR
              url.path:"/designs/MicrosoftOffice/template"
            ) OR (
              network.protocol:"http" AND
              file.extension:"dot" AND
              url.path:*template*
            )"""),
    },
    {
        "id": 24,
        "category": "injection",
        "name": "Office to PowerShell Process Chain",
        "mitre": ["T1566.001", "T1059.001"],
        "desc": "Detects Office application spawning PowerShell with hidden window and network connections — classic macro dropper",
        "query": textwrap.dedent("""\
            process.parent.name:("winword.exe" OR "excel.exe" OR "powerpnt.exe") AND
            process.name:"powershell.exe" AND (
              process.command_line:*"-nop"* AND
              process.command_line:*"-w hidden"*
            ) OR (
              process.parent.name:("winword.exe" OR "excel.exe") AND
              process.command_line:*"winmgmts"* AND
              process.command_line:*"Win32_Process"*
            )"""),
    },
    {
        "id": 25,
        "category": "injection",
        "name": "Script Block Logging Bypass",
        "mitre": ["T1562.001"],
        "desc": "Detects PowerShell ETW and script block logging bypass via PSEtwLogProvider and m_enabled field reflection",
        "query": textwrap.dedent("""\
            process.command_line:*"System.Diagnostics.Eventing.EventProvider"* OR
            process.command_line:*"m_enabled"* OR
            process.command_line:*"PSEtwLogProvider"* OR
            process.command_line:*"etwProvider"*"""),
    },
    {
        "id": 26,
        "category": "injection",
        "name": "Macro & Template Injection — Comprehensive",
        "mitre": ["T1566.001", "T1221", "T1059.001", "T1027", "T1562.001"],
        "desc": "Combined macro/injection query: AMSI bypass, base64 IEX, template injection, Office→PowerShell, ETW bypass",
        "query": textwrap.dedent("""\
            (
              (process.command_line:*"l`o`AdwIThPa`Rti`AlnamE"* OR process.command_line:*"AmsiInitFailed"*) OR
              (process.command_line:*powershell* AND process.command_line:*"-nop"* AND process.command_line:*"-w hidden"*) OR
              (process.command_line:*"aQBlAHgAIAAoAG4AZQB3AC0AbwBiAGoAZQBjAHQA"*) OR
              (url.domain:"gramarly.com" AND url.path:"/designs/MicrosoftOffice/*") OR
              (process.parent.name:("winword.exe" OR "excel.exe") AND process.command_line:*"winmgmts"*) OR
              (process.command_line:*"IO.MemoryStream"* AND process.command_line:*"GzipStream"*) OR
              (file.extension:"dot" AND network.protocol:"http")
            ) AND @timestamp:[now-24h TO now]"""),
    },

    # ── Exfiltration ──────────────────────────────────────────────────────────

    {
        "id": 27,
        "category": "exfil",
        "name": "Executive Document Downloads",
        "mitre": ["T1041", "T1005"],
        "desc": "Detects Cobalt Strike 'download' commands targeting executive user profile documents (abigail.howell)",
        "query": textwrap.dedent("""\
            process.command_line:*"download"* AND
            file.path:"C:\\\\Users\\\\abigail.howell\\\\*" AND (
              file.extension:("txt" OR "doc" OR "docx" OR "pdf") OR
              file.size > 100000
            )"""),
    },
    {
        "id": 28,
        "category": "exfil",
        "name": "Large File Transfer from Executive Subnet",
        "mitre": ["T1041"],
        "desc": "Detects high-volume outbound HTTP/HTTPS transfers from executive subnet hosts",
        "query": textwrap.dedent("""\
            network.protocol:("http" OR "https") AND
            network.bytes > 1000000 AND
            source.ip:*"EXEC"* AND
            user.name:"abigail.howell"
            OR (
              network.protocol:("http" OR "https") AND
              network.bytes_sent > 1000000 AND
              source.ip:*"EXEC"* AND
              user.name:"abigail.howell"
            )"""),
    },
    {
        "id": 29,
        "category": "exfil",
        "name": "EngineeringDocs SMB Access & Staging",
        "mitre": ["T1039", "T1074.001"],
        "desc": "Detects access and staging of sensitive EngineeringDocs share (172.17.2.4) to Windows Temp",
        "query": textwrap.dedent("""\
            process.command_line:*"ls \\\\\\\\172.17.2.4\\\\EngineeringDocs"* OR (
              network.protocol:"smb" AND
              destination.ip:"172.17.2.4" AND
              smb.command:"SMB2_CREATE" AND
              smb.path:"*EngineeringDocs*"
            ) OR (
              file.path:"C:\\\\Windows\\\\Temp\\\\*" AND
              event.action:"file_create" AND
              process.command_line:*"EngineeringDocs"*
            )"""),
    },
    {
        "id": 30,
        "category": "exfil",
        "name": "Exfiltration — Comprehensive",
        "mitre": ["T1041", "T1039", "T1074.001", "T1005"],
        "desc": "Combined exfiltration indicators: executive file downloads, large outbound transfers, EngineeringDocs access, domain admin credential usage",
        "query": textwrap.dedent("""\
            (
              (process.command_line:*"SITE2-EXEC2"* AND process.command_line:*"jump psexec"*) OR
              (user.name:"abigail.howell" AND process.command_line:*"runasadmin uac-cmstplua"*) OR
              (process.command_line:*"Enterprise Admins"* AND process.command_line:*"powerpick"*) OR
              (file.path:"C:\\\\Users\\\\abigail.howell\\\\Documents\\\\*" AND event.action:"file_access") OR
              (process.command_line:*"download"* AND host.name:*"EXEC2"*) OR
              (network.bytes > 1000000 AND source.ip:*"EXEC"* AND user.name:"abigail.howell")
            ) AND @timestamp:[now-7d TO now]"""),
    },

    # ── Scan / Recon ──────────────────────────────────────────────────────────

    {
        "id": 31,
        "category": "scan",
        "name": "TCP Port Scan Detection",
        "mitre": ["T1046"],
        "desc": "Detects high-volume TCP connection attempts indicative of network scanning",
        "query": textwrap.dedent("""\
            network.protocol:"tcp" AND
            event.action:"connection_attempted" AND
            @timestamp:[now-1h TO now]"""),
    },
    {
        "id": 32,
        "category": "scan",
        "name": "Full-Range Port Scan (1-65535)",
        "mitre": ["T1046"],
        "desc": "Detects nmap-style full port range scans through proxy with aggressive mode flags",
        "query": textwrap.dedent("""\
            source.ip:* AND (
              destination.port:[1 TO 65535] AND
              event.action:"connection_attempted" AND
              @timestamp:[now-20m TO now]
            )"""),
    },
    {
        "id": 33,
        "category": "scan",
        "name": "SSH Brute Force Attempts",
        "mitre": ["T1110.001"],
        "desc": "Detects high-volume SSH authentication failures indicating brute force attack",
        "query": textwrap.dedent("""\
            destination.port:22 AND (
              event.action:"authentication_failure" OR
              event.outcome:"failure"
            ) AND @timestamp:[now-10m TO now]"""),
    },
    {
        "id": 34,
        "category": "scan",
        "name": "HTTP Directory Enumeration (404 Pattern)",
        "mitre": ["T1083", "T1595.003"],
        "desc": "Detects web directory brute-force (dirb/gobuster) by high-volume HTTP 404 responses",
        "query": textwrap.dedent("""\
            network.protocol:"http" AND
            http.response.status_code:404 AND
            @timestamp:[now-10m TO now] AND
            source.ip:*
            OR (
              network.protocol:"http" AND
              url.path:("/admin" OR "/test" OR "/backup" OR "/config" OR "/login" OR "/phpmyadmin")
            )"""),
    },

    # ── Bash Script Attacks ───────────────────────────────────────────────────

    {
        "id": 35,
        "category": "script",
        "name": "Proxychains with Attack Tools",
        "mitre": ["T1090.001", "T1046", "T1110.001"],
        "desc": "Detects proxychains used to route nmap, ssh-brute, or dirb through SOCKS proxy",
        "query": textwrap.dedent("""\
            process.name:"proxychains" OR
            process.command_line:*proxychains* AND (
              process.command_line:*nmap* OR
              process.command_line:*"ssh-brute"* OR
              process.command_line:*dirb*
            ) OR (
              process.parent.command_line:*proxychains* AND
              process.name:("nmap" OR "dirb")
            )"""),
    },
    {
        "id": 36,
        "category": "script",
        "name": "Nmap SSH Brute Force Script",
        "mitre": ["T1110.001", "T1046"],
        "desc": "Detects nmap with ssh-brute NSE script and credential wordlists (users.lst, pass.lst)",
        "query": textwrap.dedent("""\
            process.command_line:*nmap* AND
            process.command_line:*"ssh-brute"* AND (
              process.command_line:*"userdb="* OR
              process.command_line:*"passdb="* OR
              process.command_line:*"users.lst"*
            ) OR (
              process.command_line:*"--script-args"* AND
              process.command_line:*"timeout=4s"* AND
              process.command_line:*"userdb=users.lst"*
            )"""),
    },
    {
        "id": 37,
        "category": "script",
        "name": "Bash Infinite Loop Attack Script",
        "mitre": ["T1059.004"],
        "desc": "Detects bash scripts with infinite while loops and sleep intervals used for automated attack cycling",
        "query": textwrap.dedent("""\
            process.name:"bash" AND (
              process.command_line:*"while true"* OR
              process.command_line:*"#!/bin/bash"*
            ) AND process.command_line:*proxychains*
            OR (
              process.name:"sleep" AND
              process.command_line:("1200" OR "600") AND
              process.parent.name:"bash"
            )"""),
    },
    {
        "id": 38,
        "category": "script",
        "name": "Automated Attack — Comprehensive",
        "mitre": ["T1059.004", "T1090.001", "T1046", "T1110.001", "T1083"],
        "desc": "Combined automated bash attack detection: infinite loop script, proxychains nmap, ssh-brute, dirb 404 bursts",
        "query": textwrap.dedent("""\
            (
              (process.name:"bash" AND process.command_line:*"while true"* AND process.command_line:*"sleep"*) OR
              (process.command_line:*proxychains* AND process.command_line:*nmap* AND process.command_line:*"-A"*) OR
              (process.command_line:*"ssh-brute"* AND process.command_line:*"userdb=users.lst"*) OR
              (process.command_line:*proxychains* AND process.command_line:*dirb* AND process.command_line:*"common.txt"*) OR
              (process.name:"sleep" AND process.command_line:("1200" OR "600") AND process.parent.name:"bash") OR
              (destination.port:22 AND event.action:"authentication_failure" AND @timestamp:[now-10m TO now]) OR
              (network.protocol:"http" AND http.response.status_code:404 AND @timestamp:[now-10m TO now])
            ) AND @timestamp:[now-1h TO now]"""),
    },
]

# ── Category Metadata ─────────────────────────────────────────────────────────

CATEGORIES = {
    "apt":         "Multi-Day APT Campaign (lateral movement, persistence, exfil)",
    "cobalt":      "Cobalt Strike / APT40 C2 Infrastructure",
    "persistence": "Persistence Mechanisms (SharPersist, scheduled tasks, timestomp)",
    "injection":   "Malicious Macro & Template Injection",
    "exfil":       "Data Exfiltration (executive network, EngineeringDocs)",
    "scan":        "Network Scan & Reconnaissance",
    "script":      "Automated Bash Attack Scripts (proxychains, nmap, dirb)",
}


# ── Lookup Helpers ────────────────────────────────────────────────────────────

def get_query(qid: int) -> Optional[dict]:
    for q in QUERIES:
        if q["id"] == qid:
            return q
    return None


def filter_queries(category: str = None, term: str = None) -> List[dict]:
    results = QUERIES
    if category:
        results = [q for q in results if q["category"] == category.lower()]
    if term:
        t = term.lower()
        results = [
            q for q in results
            if t in q["name"].lower()
            or t in q["desc"].lower()
            or t in q["query"].lower()
            or any(t in m.lower() for m in q["mitre"])
        ]
    return results


# ── Display Helpers ───────────────────────────────────────────────────────────

def cat_label(cat: str) -> str:
    color = CAT_COLOR.get(cat, CYAN)
    return f"{color}{cat.upper():<12}{RESET}"


def print_query_card(q: dict, show_full: bool = False):
    color = CAT_COLOR.get(q["category"], CYAN)
    mitre = "  ".join(q["mitre"])
    width = 72

    print(f"\n  {BOLD}[{q['id']:02d}] {q['name']}{RESET}")
    print(f"  {color}Category:{RESET} {q['category']}  {DIM}|{RESET}  {CYAN}MITRE:{RESET} {mitre}")
    print(f"  {DIM}{q['desc']}{RESET}")

    if show_full:
        print(f"\n  {'─' * width}")
        for line in q["query"].splitlines():
            print(f"  {GREEN}{line}{RESET}")
        print(f"  {'─' * width}")


# ── Commands ──────────────────────────────────────────────────────────────────

def cmd_categories(_args):
    print(f"\n{BOLD}  CATEGORIES{RESET}\n")
    for slug, desc in CATEGORIES.items():
        color = CAT_COLOR.get(slug, CYAN)
        count = len([q for q in QUERIES if q["category"] == slug])
        print(f"  {color}{slug:<14}{RESET} {count:2d} queries  —  {DIM}{desc}{RESET}")
    print()


def cmd_list(args):
    results = filter_queries(category=getattr(args, "category", None))
    if not results:
        print(f"\n{YELLOW}No queries found.{RESET}\n")
        return

    cat_header = f" [{args.category.upper()}]" if getattr(args, "category", None) else ""
    print(f"\n{BOLD}  ELASTIC KQL LIBRARY{cat_header}  ({len(results)} queries){RESET}\n")
    print(f"  {'─' * 72}")
    print(f"  {'ID':<5} {'CATEGORY':<14} {'MITRE':<22} NAME")
    print(f"  {'─' * 72}")

    for q in results:
        color = CAT_COLOR.get(q["category"], CYAN)
        mitre = q["mitre"][0] if q["mitre"] else ""
        extra = f"+{len(q['mitre'])-1}" if len(q["mitre"]) > 1 else ""
        print(f"  {q['id']:<5} {color}{q['category']:<14}{RESET} {mitre:<16}{DIM}{extra:<6}{RESET} {q['name']}")
    print()


def cmd_show(args):
    q = get_query(args.id)
    if not q:
        print(f"\n{RED}Query #{args.id} not found.{RESET}\n")
        sys.exit(1)
    print_query_card(q, show_full=True)
    print()


def cmd_search(args):
    results = filter_queries(term=args.term)
    if not results:
        print(f"\n{YELLOW}No results for '{args.term}'.{RESET}\n")
        return

    print(f"\n{BOLD}  SEARCH: '{args.term}'  ({len(results)} results){RESET}\n")
    for q in results:
        print_query_card(q, show_full=False)
    print()


def cmd_export(args):
    fmt     = getattr(args, "format", "json")
    cat     = getattr(args, "category", None)
    results = filter_queries(category=cat)

    if fmt == "json":
        print(json.dumps(results, indent=2))

    elif fmt == "ndjson":
        # Newline-delimited JSON — one query per line, ready for Elastic import
        for q in results:
            print(json.dumps(q))

    elif fmt == "kql":
        # Plain KQL — one query block per entry with comment header
        for q in results:
            print(f"// [{q['id']:02d}] {q['name']}  |  MITRE: {', '.join(q['mitre'])}")
            print(f"// {q['desc']}")
            print(q["query"])
            print()

    elif fmt == "csv":
        import csv
        writer = csv.DictWriter(
            sys.stdout,
            fieldnames=["id", "category", "name", "mitre", "desc", "query"],
        )
        writer.writeheader()
        for q in results:
            writer.writerow({**q, "mitre": "|".join(q["mitre"])})


def cmd_run(args):
    """
    Run a query against Elasticsearch via the KQL search API.
    Requires --es (Elasticsearch URL) and --index.
    Optionally --user / --password for basic auth.

    HOW IT WORKS:
    Elasticsearch exposes a REST API at /_search.
    The "kql" filter is a Kibana Query Language filter that translates to
    an Elasticsearch query_string query under the hood.
    We POST the query as JSON and print the hits.
    """
    q = get_query(args.id)
    if not q:
        print(f"\n{RED}Query #{args.id} not found.{RESET}\n")
        sys.exit(1)

    if not args.es:
        print(f"\n{RED}Error: --es <elasticsearch-url> required for run command.{RESET}")
        print(f"  Example: python3 elastickql.py run {args.id} --es https://localhost:9200\n")
        sys.exit(1)

    index = getattr(args, "index", ".ds-logs-*")
    url   = f"{args.es.rstrip('/')}/{index}/_search"

    # Build the Elasticsearch DSL query from KQL
    # KQL is sent as a query_string query (Elasticsearch's KQL-compatible syntax)
    payload = {
        "query": {
            "bool": {
                "must": [
                    {"query_string": {"query": q["query"], "default_field": "*"}}
                ]
            }
        },
        "size": getattr(args, "size", 20),
        "sort": [{"@timestamp": {"order": "desc"}}],
    }

    headers = {"Content-Type": "application/json"}
    data    = json.dumps(payload).encode("utf-8")
    req     = urllib.request.Request(url, data=data, headers=headers, method="POST")

    # Basic auth
    if getattr(args, "user", None) and getattr(args, "password", None):
        import base64
        creds = base64.b64encode(f"{args.user}:{args.password}".encode()).decode()
        req.add_header("Authorization", f"Basic {creds}")

    print(f"\n{BOLD}Running query #{q['id']}:{RESET} {q['name']}")
    print(f"{DIM}Endpoint: {url}{RESET}\n")

    try:
        with urllib.request.urlopen(req, timeout=15) as resp:
            result = json.loads(resp.read())
    except urllib.error.HTTPError as e:
        body = e.read().decode("utf-8", errors="replace")
        print(f"{RED}HTTP {e.code}: {body}{RESET}")
        sys.exit(1)
    except urllib.error.URLError as e:
        print(f"{RED}Connection error: {e.reason}{RESET}")
        sys.exit(1)

    hits  = result.get("hits", {})
    total = hits.get("total", {}).get("value", 0)
    items = hits.get("hits", [])

    print(f"{BOLD}Total hits: {total}{RESET}\n")

    if not items:
        print(f"{GREEN}No matches found.{RESET}\n")
        return

    for i, hit in enumerate(items, 1):
        src = hit.get("_source", {})
        ts  = src.get("@timestamp", "")
        host= src.get("host", {}).get("name", src.get("host.name", ""))
        cmd = src.get("process", {}).get("command_line",
              src.get("process.command_line", ""))
        user= src.get("user", {}).get("name", src.get("user.name", ""))

        print(f"  {CYAN}[{i:02d}]{RESET} {DIM}{ts}{RESET}  {BOLD}{host}{RESET}  {user}")
        if cmd:
            short = cmd[:120] + "…" if len(cmd) > 120 else cmd
            print(f"       {DIM}{short}{RESET}")
    print()


# ── Entry Point ───────────────────────────────────────────────────────────────

def main():
    parser = argparse.ArgumentParser(
        prog="elastickql",
        description="Elastic Security KQL Detection Query Library — github.com/opsec12/ElasticKQL",
    )
    sub = parser.add_subparsers(dest="command", required=True)

    # categories
    sub.add_parser("categories", help="List all query categories")

    # list
    p_list = sub.add_parser("list", help="List queries (optionally filter by category)")
    p_list.add_argument("--category", "-c", help="Filter by category slug (apt|cobalt|persistence|injection|exfil|scan|script)")

    # show
    p_show = sub.add_parser("show", help="Show full query by ID")
    p_show.add_argument("id", type=int, help="Query ID")

    # search
    p_search = sub.add_parser("search", help="Search queries by keyword")
    p_search.add_argument("term", help="Search term (name, desc, query body, MITRE ID)")

    # export
    p_export = sub.add_parser("export", help="Export queries to stdout")
    p_export.add_argument("--format", "-f", choices=["json", "ndjson", "kql", "csv"], default="json")
    p_export.add_argument("--category", "-c", help="Filter by category")

    # run
    p_run = sub.add_parser("run", help="Execute a query against Elasticsearch")
    p_run.add_argument("id", type=int, help="Query ID to run")
    p_run.add_argument("--es",       required=False, help="Elasticsearch URL (e.g. https://localhost:9200)")
    p_run.add_argument("--index",    default=".ds-logs-*", help="Index pattern (default: .ds-logs-*)")
    p_run.add_argument("--user",     help="Elasticsearch username")
    p_run.add_argument("--password", help="Elasticsearch password")
    p_run.add_argument("--size",     type=int, default=20, help="Max results to return (default: 20)")

    args = parser.parse_args()

    dispatch = {
        "categories": cmd_categories,
        "list":       cmd_list,
        "show":       cmd_show,
        "search":     cmd_search,
        "export":     cmd_export,
        "run":        cmd_run,
    }
    dispatch[args.command](args)


if __name__ == "__main__":
    main()
