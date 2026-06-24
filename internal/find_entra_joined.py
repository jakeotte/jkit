#!/usr/bin/env python3
"""
entra_enum.py — enumerate Entra/hybrid-joined devices via passive LDAP + DNS
No remote registry. No WMI. No endpoint connections.

Hybrid Entra-joined devices carry a userCertificate on their AD computer object
issued by MS-Organization-Access. That's the fingerprint.

Pure cloud-only Entra-joined devices don't exist in AD — use --graph for those
(requires an Entra token).

Usage:
    python entra_enum.py -d corp.local -u USER -p PASS
    python entra_enum.py -d corp.local -u USER -p PASS --dc 10.10.10.1
    python entra_enum.py -d corp.local -u USER -p PASS --all-computers   # slower, checks every cert
    python entra_enum.py -d corp.local -u USER -p PASS --out results.json
"""

import argparse
import ipaddress
import json
import socket
import sys
from dataclasses import asdict, dataclass, field
from typing import Optional

try:
    import ldap3
    from ldap3 import ALL_ATTRIBUTES, SUBTREE, Connection, Server, Tls
except ImportError:
    sys.exit("pip install ldap3")

try:
    from cryptography import x509
    from cryptography.hazmat.primitives.serialization import Encoding
except ImportError:
    sys.exit("pip install cryptography")

ENTRA_ISSUER_CN   = "MS-Organization-Access"
ENTRA_ISSUER_O    = "Microsoft Corporation"

# DS-Key-Credential-Link — populated on WHFB/device-reg objects, weaker signal but useful
MSDS_KEY_CRED     = "msDS-KeyCredentialLink"


# ---------------------------------------------------------------------------
# Data model
# ---------------------------------------------------------------------------

@dataclass
class Device:
    hostname: str
    dn: str
    os: str
    os_version: str
    entra_joined: bool          # confirmed via cert issuer
    key_cred_link: bool         # msDS-KeyCredentialLink present (weaker signal)
    device_id: str              # parsed from cert Subject CN if available
    cert_issuer: str
    last_logon: str
    ip: str = ""
    notes: list = field(default_factory=list)


# ---------------------------------------------------------------------------
# LDAP helpers
# ---------------------------------------------------------------------------

def build_server(dc: str, use_tls: bool) -> Server:
    port = 636 if use_tls else 389
    tls  = Tls(validate=0) if use_tls else None
    return Server(dc, port=port, use_ssl=use_tls, tls=tls, get_info=ldap3.ALL)


def connect(dc: str, domain: str, user: str, password: str,
            use_tls: bool) -> Connection:
    server = build_server(dc, use_tls)
    bind_user = f"{domain}\\{user}" if "\\" not in user and "@" not in user else user
    conn = Connection(
        server, user=bind_user, password=password,
        authentication=ldap3.NTLM, auto_bind=True,
    )
    return conn


def domain_to_basedn(domain: str) -> str:
    return ",".join(f"DC={part}" for part in domain.split("."))


def resolve_hostname(hostname: str) -> str:
    try:
        return socket.gethostbyname(hostname)
    except socket.gaierror:
        return ""


# ---------------------------------------------------------------------------
# Certificate parsing
# ---------------------------------------------------------------------------

def parse_cert(der_bytes: bytes) -> tuple[str, str, str]:
    """Returns (issuer_cn, issuer_o, subject_cn)."""
    try:
        cert = x509.load_der_x509_certificate(der_bytes)
        def get_attr(name, oid):
            try:
                return name.get_attributes_for_oid(oid)[0].value
            except IndexError:
                return ""
        issuer_cn  = get_attr(cert.issuer,  x509.NameOID.COMMON_NAME)
        issuer_o   = get_attr(cert.issuer,  x509.NameOID.ORGANIZATION_NAME)
        subject_cn = get_attr(cert.subject, x509.NameOID.COMMON_NAME)
        return issuer_cn, issuer_o, subject_cn
    except Exception:
        return "", "", ""


def is_entra_cert(issuer_cn: str, issuer_o: str) -> bool:
    return ENTRA_ISSUER_CN.lower() in issuer_cn.lower() or \
           ENTRA_ISSUER_O.lower()  in issuer_o.lower()


# ---------------------------------------------------------------------------
# Enumeration
# ---------------------------------------------------------------------------

COMPUTER_ATTRS = [
    "dNSHostName", "sAMAccountName", "operatingSystem",
    "operatingSystemVersion", "userCertificate",
    "msDS-KeyCredentialLink", "lastLogonTimestamp",
    "distinguishedName",
]


def filetime_to_iso(ft: int) -> str:
    if not ft or ft == 0:
        return ""
    try:
        # Windows FILETIME: 100ns intervals since 1601-01-01
        import datetime
        epoch_diff = 116444736000000000
        ts = (ft - epoch_diff) / 10_000_000
        return datetime.datetime.utcfromtimestamp(ts).strftime("%Y-%m-%d")
    except Exception:
        return ""


def query_computers(conn: Connection, base_dn: str,
                    cert_filter_only: bool) -> list:
    """
    Uses paged_search to bypass AD's default 1000-result cap.
    cert_filter_only=True  → pre-filter on userCertificate=* (only Entra-stamped machines)
    cert_filter_only=False → all computers, cert checked locally (recommended)
    """
    if cert_filter_only:
        ldap_filter = "(&(objectClass=computer)(userCertificate=*))"
    else:
        ldap_filter = "(objectClass=computer)"

    return list(conn.extend.standard.paged_search(
        search_base=base_dn,
        search_filter=ldap_filter,
        search_scope=SUBTREE,
        attributes=COMPUTER_ATTRS,
        paged_size=500,
        generator=False,
    ))


def attr(entry: dict, key: str, default=""):
    """Extract first value from paged_search result dict."""
    val = entry.get("attributes", {}).get(key)
    if val is None:
        return default
    if isinstance(val, list):
        return val[0] if val else default
    return val


def process_entry(entry: dict, resolve_dns: bool) -> Optional[Device]:
    attrs    = entry.get("attributes", {})
    hostname = str(attr(entry, "dNSHostName") or attr(entry, "sAMAccountName") or "")
    dn       = str(entry.get("dn", ""))
    os_name  = str(attr(entry, "operatingSystem") or "")
    os_ver   = str(attr(entry, "operatingSystemVersion") or "")
    has_kcl  = bool(attrs.get("msDS-KeyCredentialLink"))
    last_logon = ""
    try:
        ll = attr(entry, "lastLogonTimestamp")
        if isinstance(ll, int):
            last_logon = filetime_to_iso(ll)
        elif ll:
            last_logon = str(ll)[:10]
    except Exception:
        pass

    entra_joined = False
    device_id    = ""
    cert_issuer  = ""

    raw_certs = attrs.get("userCertificate", [])
    if not isinstance(raw_certs, list):
        raw_certs = [raw_certs]
    for cert_der in raw_certs:
        if isinstance(cert_der, str):
            continue  # skip if somehow a string
        issuer_cn, issuer_o, subject_cn = parse_cert(bytes(cert_der))
        if is_entra_cert(issuer_cn, issuer_o):
            entra_joined = True
            device_id    = subject_cn
            cert_issuer  = f"{issuer_cn} / {issuer_o}"
            break

    if not entra_joined and not has_kcl:
        return None

    ip = ""
    if resolve_dns and hostname:
        fqdn = hostname if "." in hostname else hostname
        ip   = resolve_hostname(fqdn)

    notes = []
    if has_kcl and not entra_joined:
        notes.append("msDS-KeyCredentialLink present (WHFB or device reg, unconfirmed Entra join)")

    return Device(
        hostname=hostname, dn=dn, os=os_name, os_version=os_ver,
        entra_joined=entra_joined, key_cred_link=has_kcl,
        device_id=device_id, cert_issuer=cert_issuer,
        last_logon=last_logon, ip=ip, notes=notes,
    )


# ---------------------------------------------------------------------------
# Output
# ---------------------------------------------------------------------------

def print_table(devices: list[Device]):
    confirmed = [d for d in devices if d.entra_joined]
    weak      = [d for d in devices if not d.entra_joined]

    def row(d: Device):
        ip_col = d.ip or "-"
        print(f"  {d.hostname:<40} {ip_col:<18} {d.os:<30} {d.last_logon:<12} {d.device_id}")

    if confirmed:
        print(f"\n  CONFIRMED ENTRA/HYBRID-JOINED ({len(confirmed)})")
        print(f"  {'HOSTNAME':<40} {'IP':<18} {'OS':<30} {'LAST LOGON':<12} DEVICE ID")
        print(f"  {'-'*40} {'-'*17} {'-'*29} {'-'*11} {'-'*36}")
        for d in sorted(confirmed, key=lambda x: x.hostname):
            row(d)

    if weak:
        print(f"\n  KEY-CRED-LINK ONLY (weaker signal, {len(weak)})")
        print(f"  {'HOSTNAME':<40} {'IP':<18} {'OS':<30} {'LAST LOGON':<12}")
        print(f"  {'-'*40} {'-'*17} {'-'*29} {'-'*11}")
        for d in sorted(weak, key=lambda x: x.hostname):
            print(f"  {d.hostname:<40} {(d.ip or '-'):<18} {d.os:<30} {d.last_logon:<12}")


# ---------------------------------------------------------------------------
# Main
# ---------------------------------------------------------------------------

def main():
    p = argparse.ArgumentParser(description="Enumerate Entra-joined devices via passive LDAP")
    p.add_argument("-d", "--domain",   required=True, help="Domain (e.g. corp.local)")
    p.add_argument("-u", "--user",     required=True, help="Username")
    p.add_argument("-p", "--password", required=True, help="Password")
    p.add_argument("--dc",             default="",    help="DC IP/hostname (default: auto from domain)")
    p.add_argument("--base-dn",        default="",    help="Base DN (default: derived from domain)")
    p.add_argument("--tls",            action="store_true", help="Use LDAPS (port 636)")
    p.add_argument("--cert-filter", action="store_true",
                   help="Pre-filter LDAP on userCertificate=* (faster but misses non-cert Entra signals)")
    p.add_argument("--no-resolve",     action="store_true", help="Skip DNS resolution")
    p.add_argument("--out",            default="",    help="Write JSON output to file")
    args = p.parse_args()

    dc      = args.dc or args.domain
    base_dn = args.base_dn or domain_to_basedn(args.domain)

    print(f"[*] Domain  : {args.domain}")
    print(f"[*] DC      : {dc}")
    print(f"[*] Base DN : {base_dn}")
    print(f"[*] Filter  : {'userCertificate=* only' if args.cert_filter else 'all computers'}")

    print("\n[1/3] Connecting...")
    try:
        conn = connect(dc, args.domain, args.user, args.password, args.tls)
        print(f"      Bound as {conn.extend.standard.who_am_i()}")
    except Exception as e:
        sys.exit(f"LDAP bind failed: {e}")

    print("\n[2/3] Querying computer objects...")
    entries = query_computers(conn, base_dn, cert_filter_only=args.cert_filter)
    # paged_search returns dicts, not Entry objects — filter out referrals
    entries = [e for e in entries if e.get("type") == "searchResEntry"]
    print(f"      Got {len(entries)} computer objects")

    print("\n[3/3] Processing...")
    devices = []
    for entry in entries:
        d = process_entry(entry, resolve_dns=not args.no_resolve)
        if d:
            devices.append(d)

    confirmed = sum(1 for d in devices if d.entra_joined)
    print(f"      Entra-joined (cert confirmed) : {confirmed}")
    print(f"      Key-cred-link only            : {len(devices) - confirmed}")

    print_table(devices)

    if args.out:
        with open(args.out, "w") as f:
            json.dump([asdict(d) for d in devices], f, indent=2)
        print(f"\n[*] JSON written to {args.out}")

    print()


if __name__ == "__main__":
    main()
