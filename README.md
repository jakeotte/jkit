# jkit

Pentest toolkit. External recon and internal post-exploitation.

## Install

```
pip install -e .
git submodule update --init --recursive
```

## External

| Command | Description |
|---|---|
| `cloud-enum` | Multi-cloud asset enumeration (AWS, Azure, GCP, DO, CF, IBM, Oracle) |
| `emailscanner` | Email security audit — SPF, DKIM, DMARC, BIMI, MTA-STS, TLS-RPT |
| `subdtakeover` | Subdomain takeover scanner with CNAME chain fingerprinting |
| `viewstate-check` | ASP.NET ViewState MAC/encryption checker, weak key brute-force |
| `wcf-meta` | WCF metadata exposure scanner |
| `gh_org_map.py` | GitHub org member + repo enumeration with triage scoring |

## Internal

| Tool | Description |
|---|---|
| `comrecon.py` | COM hijack target + scheduled task recon via SMB C$ |
| `taskhijacker.py` | Hijack writable scheduled tasks via TSCH RPC, auto-restore |
| `find_entra_joined.py` | Enumerate hybrid/Entra-joined devices via LDAP cert parsing |
| [klist2ccache](internal/klist2ccache) | Windows `klist` → MIT ccache; remote TGT dump via Task Scheduler + SMB |
| [smbthief](internal/smbthief) | SMB share enumeration |
| [RustHound-CE](internal/RustHound-CE) | BloodHound LDAP collection with OPSEC obfuscation mode |
