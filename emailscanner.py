#!/usr/bin/env python3
"""
Email Security Scanner
Usage: python3 email_security_scanner.py <domain>

Checks: SPF, DKIM, DMARC, MX, BIMI, MTA-STS, TLS-RPT, DNSSEC, SMTP TLS
Findings are categorized by severity: CRITICAL, HIGH, MEDIUM, LOW, INFO
"""

import sys
import socket
import ssl
import re
import json
import smtplib
import textwrap
from datetime import datetime, timezone
from dataclasses import dataclass, field
from typing import Optional
from enum import Enum

try:
    import dns.resolver
    import dns.dnssec
    import dns.query
    import dns.name
    import dns.rdatatype
    import dns.flags
except ImportError:
    print("ERROR: dnspython is required. Install with: pip3 install dnspython")
    sys.exit(1)

# ---------------------------------------------------------------------------
# Severity levels and finding data structure
# ---------------------------------------------------------------------------

class Severity(Enum):
    CRITICAL = 1
    HIGH     = 2
    MEDIUM   = 3
    LOW      = 4
    INFO     = 5

SEV_COLORS = {
    Severity.CRITICAL: "\033[1;31m",   # bold red
    Severity.HIGH:     "\033[31m",     # red
    Severity.MEDIUM:   "\033[33m",     # yellow
    Severity.LOW:      "\033[36m",     # cyan
    Severity.INFO:     "\033[37m",     # white
}
RESET = "\033[0m"
BOLD  = "\033[1m"

@dataclass
class Finding:
    category: str
    severity: Severity
    title: str
    detail: str
    recommendation: str = ""

# ---------------------------------------------------------------------------
# DNS helpers
# ---------------------------------------------------------------------------

def query_txt(name: str) -> list[str]:
    """Return a list of TXT record strings for *name*, or []."""
    try:
        answers = dns.resolver.resolve(name, "TXT", lifetime=8)
        return [b"".join(r.strings).decode(errors="replace") for r in answers]
    except Exception:
        return []

def query_mx(domain: str) -> list[tuple[int, str]]:
    """Return sorted list of (priority, hostname) MX records."""
    try:
        answers = dns.resolver.resolve(domain, "MX", lifetime=8)
        return sorted((r.preference, str(r.exchange).rstrip(".")) for r in answers)
    except Exception:
        return []

def query_a(name: str) -> list[str]:
    try:
        return [str(r) for r in dns.resolver.resolve(name, "A", lifetime=8)]
    except Exception:
        return []

def query_ptr(ip: str) -> Optional[str]:
    try:
        rev = dns.reversename.from_address(ip)
        answers = dns.resolver.resolve(rev, "PTR", lifetime=8)
        return str(answers[0]).rstrip(".")
    except Exception:
        return None

def check_dnssec(domain: str) -> Optional[bool]:
    """
    Return True if the domain has DNSSEC (DS/RRSIG records visible),
    False if explicitly unsigned, None if undetermined.
    """
    try:
        request = dns.message.make_query(domain, dns.rdatatype.DNSKEY, want_dnssec=True)
        response = dns.query.udp(request, "8.8.8.8", timeout=5)
        if response.flags & dns.flags.AD:
            return True
        # Check for DS record at parent
        request2 = dns.message.make_query(domain, dns.rdatatype.DS, want_dnssec=True)
        response2 = dns.query.udp(request2, "8.8.8.8", timeout=5)
        if response2.flags & dns.flags.AD:
            return True
        return False
    except Exception:
        return None

# ---------------------------------------------------------------------------
# SMTP / TLS helpers
# ---------------------------------------------------------------------------

def probe_smtp_tls(host: str, port: int = 25, timeout: int = 10) -> dict:
    """
    Connect to an MX host on port 25, attempt STARTTLS, and collect TLS info.
    Returns a dict with keys: connected, starttls, tls_version, cipher, cert_cn,
    cert_valid, cert_expiry, tls_error.
    """
    result = dict(connected=False, starttls=False, tls_version=None,
                  cipher=None, cert_cn=None, cert_valid=False,
                  cert_expiry=None, tls_error=None)
    try:
        with smtplib.SMTP(host, port, timeout=timeout) as smtp:
            result["connected"] = True
            code, _ = smtp.ehlo()
            if code != 250:
                smtp.helo()
            ctx = ssl.create_default_context()
            ctx.check_hostname = True
            ctx.verify_mode = ssl.CERT_REQUIRED
            try:
                smtp.starttls(context=ctx)
                result["starttls"] = True
                sock = smtp.sock
                if isinstance(sock, ssl.SSLSocket):
                    result["tls_version"] = sock.version()
                    result["cipher"] = sock.cipher()[0] if sock.cipher() else None
                    cert = sock.getpeercert()
                    if cert:
                        result["cert_valid"] = True
                        # Extract CN or SAN
                        sans = [v for t, v in cert.get("subjectAltName", []) if t == "DNS"]
                        if sans:
                            result["cert_cn"] = ", ".join(sans[:3])
                        else:
                            for part in cert.get("subject", []):
                                for k, v in part:
                                    if k == "commonName":
                                        result["cert_cn"] = v
                        # Expiry
                        not_after = cert.get("notAfter")
                        if not_after:
                            try:
                                expiry = datetime.strptime(not_after, "%b %d %H:%M:%S %Y %Z")
                                expiry = expiry.replace(tzinfo=timezone.utc)
                                result["cert_expiry"] = expiry.strftime("%Y-%m-%d")
                            except ValueError:
                                result["cert_expiry"] = not_after
            except ssl.SSLCertVerificationError as e:
                result["starttls"] = True
                result["cert_valid"] = False
                result["tls_error"] = str(e)
            except smtplib.SMTPException as e:
                result["tls_error"] = str(e)
    except (socket.timeout, ConnectionRefusedError, OSError) as e:
        result["tls_error"] = str(e)
    return result

def probe_smtp_plain(host: str, port: int = 25, timeout: int = 8) -> dict:
    """Quick connect check without full TLS handshake (for reachability)."""
    try:
        with smtplib.SMTP(host, port, timeout=timeout) as smtp:
            return {"connected": True, "banner": smtp.getwelcome().decode(errors="replace")}
    except Exception as e:
        return {"connected": False, "banner": str(e)}

# ---------------------------------------------------------------------------
# SPF checker
# ---------------------------------------------------------------------------

SPF_MECHANISMS_REQUIRING_LOOKUP = re.compile(
    r"\b(include|a|mx|ptr|exists|redirect)\s*:", re.I
)

def count_spf_lookups(record: str) -> int:
    """Count DNS-lookup-consuming mechanisms in an SPF record (limit is 10)."""
    mechanisms = re.findall(
        r"\b(include|a(?:/\d+)?|mx(?:/\d+)?|ptr|exists|redirect)\b",
        record, re.I
    )
    return len(mechanisms)

def check_spf(domain: str) -> list[Finding]:
    findings = []
    records = [r for r in query_txt(domain) if r.lower().startswith("v=spf1")]

    if not records:
        findings.append(Finding(
            category="SPF",
            severity=Severity.CRITICAL,
            title="No SPF record found",
            detail=f"No TXT record starting with 'v=spf1' exists for {domain}.",
            recommendation="Publish an SPF record. Example: 'v=spf1 mx -all'",
        ))
        return findings

    if len(records) > 1:
        findings.append(Finding(
            category="SPF",
            severity=Severity.HIGH,
            title="Multiple SPF records found",
            detail=f"Found {len(records)} SPF TXT records: {records}. Only one is allowed per RFC 7208.",
            recommendation="Remove duplicate SPF records; keep exactly one.",
        ))

    spf = records[0]
    findings.append(Finding(
        category="SPF", severity=Severity.INFO,
        title="SPF record", detail=spf,
    ))

    # Policy qualifier check
    spf_lower = spf.lower()
    if "-all" in spf_lower:
        findings.append(Finding(
            category="SPF", severity=Severity.INFO,
            title="SPF policy: hard fail (-all)",
            detail="Unauthorized senders will be hard-failed. Good.",
        ))
    elif "~all" in spf_lower:
        findings.append(Finding(
            category="SPF", severity=Severity.MEDIUM,
            title="SPF policy: soft fail (~all)",
            detail="Soft fail means non-compliant messages are tagged but not rejected.",
            recommendation="Consider upgrading to '-all' (hard fail) once you've confirmed all legitimate senders.",
        ))
    elif "?all" in spf_lower:
        findings.append(Finding(
            category="SPF", severity=Severity.HIGH,
            title="SPF policy: neutral (?all)",
            detail="Neutral policy provides no protection — any sender passes.",
            recommendation="Change to '-all' or at minimum '~all'.",
        ))
    elif "+all" in spf_lower:
        findings.append(Finding(
            category="SPF", severity=Severity.CRITICAL,
            title="SPF policy: +all (anyone can send)",
            detail="'+all' explicitly allows ANY host to send mail for this domain.",
            recommendation="This is extremely dangerous. Change immediately to '-all'.",
        ))
    else:
        findings.append(Finding(
            category="SPF", severity=Severity.HIGH,
            title="SPF record has no 'all' mechanism",
            detail="Without an 'all' at the end, the SPF record provides no catch-all policy.",
            recommendation="Append '-all' or '~all' to your SPF record.",
        ))

    # DNS lookup count
    lookup_count = count_spf_lookups(spf)
    if lookup_count > 10:
        findings.append(Finding(
            category="SPF", severity=Severity.HIGH,
            title=f"SPF exceeds 10 DNS lookup limit ({lookup_count} found)",
            detail="RFC 7208 mandates a maximum of 10 DNS lookups. Exceeding this causes SPF to permerror.",
            recommendation="Flatten SPF lookups using an SPF flattening tool, or reduce 'include:' entries.",
        ))
    elif lookup_count >= 8:
        findings.append(Finding(
            category="SPF", severity=Severity.MEDIUM,
            title=f"SPF is approaching the 10 DNS lookup limit ({lookup_count}/10)",
            detail="Adding more mail providers could push this over the limit.",
        ))

    # Record length
    if len(spf) > 450:
        findings.append(Finding(
            category="SPF", severity=Severity.LOW,
            title=f"SPF record is long ({len(spf)} chars)",
            detail="Very long SPF records can cause issues with some DNS implementations.",
        ))

    # ptr mechanism (deprecated)
    if re.search(r"\bptr\b", spf, re.I):
        findings.append(Finding(
            category="SPF", severity=Severity.LOW,
            title="SPF uses deprecated 'ptr' mechanism",
            detail="The 'ptr' mechanism is deprecated (RFC 7208 §5.5) and slow.",
            recommendation="Replace 'ptr' with 'a', 'mx', or 'ip4'/'ip6' mechanisms.",
        ))

    # exp= or redirect= present
    if "redirect=" in spf_lower:
        findings.append(Finding(
            category="SPF", severity=Severity.INFO,
            title="SPF uses redirect= modifier",
            detail=f"Redirects SPF lookup to another domain: {spf}",
        ))

    return findings

# ---------------------------------------------------------------------------
# DKIM checker
# ---------------------------------------------------------------------------

DKIM_SELECTORS = [
    "default", "mail", "google", "k1", "k2", "s1", "s2",
    "selector1", "selector2", "selector3",
    "dkim", "email", "smtp", "mx", "m1", "m2",
    "cm", "pm", "mandrill", "mailchimp", "sendgrid", "ses",
    "zoho", "protonmail", "fastmail", "mailgun",
    "mxvault", "sg", "yandex", "20161025", "20230601",
    "20210112", "20240101", "20221208",
]

def check_dkim(domain: str) -> list[Finding]:
    findings = []
    found_selectors = []

    for sel in DKIM_SELECTORS:
        name = f"{sel}._domainkey.{domain}"
        records = query_txt(name)
        for r in records:
            if "p=" in r or "v=DKIM1" in r:
                found_selectors.append((sel, r))

    if not found_selectors:
        findings.append(Finding(
            category="DKIM",
            severity=Severity.HIGH,
            title="No DKIM records found (common selectors checked)",
            detail=f"Checked {len(DKIM_SELECTORS)} common selectors. None returned a DKIM public key.",
            recommendation=(
                "Enable DKIM signing on your mail server and publish the public key as a TXT record "
                "at <selector>._domainkey.<domain>."
            ),
        ))
        return findings

    for sel, record in found_selectors:
        findings.append(Finding(
            category="DKIM", severity=Severity.INFO,
            title=f"DKIM record found: selector='{sel}'",
            detail=record[:200] + ("..." if len(record) > 200 else ""),
        ))

        # Key type
        key_type = "rsa"
        kt_match = re.search(r"\bk=(\w+)", record, re.I)
        if kt_match:
            key_type = kt_match.group(1).lower()
        if key_type == "rsa":
            # Extract public key and check length
            p_match = re.search(r"\bp=([A-Za-z0-9+/=]+)", record)
            if p_match:
                import base64
                try:
                    key_bytes = base64.b64decode(p_match.group(1))
                    # Estimate bit length from DER: rough heuristic
                    key_bits = (len(key_bytes) - 38) * 8  # offset for DER header
                    # More accurate: look for 0x02 0x82 near start
                    if len(key_bytes) > 5 and key_bytes[3] == 0x02:
                        key_bits = (key_bytes[4] * 256 + key_bytes[5]) * 8
                    elif len(key_bytes) >= 270:
                        key_bits = 2048
                    elif len(key_bytes) >= 140:
                        key_bits = 1024
                    else:
                        key_bits = len(key_bytes) * 8

                    if key_bits < 1024:
                        findings.append(Finding(
                            category="DKIM", severity=Severity.CRITICAL,
                            title=f"DKIM key too short for selector '{sel}' (~{key_bits} bits)",
                            detail="Keys shorter than 1024 bits are considered broken.",
                            recommendation="Rotate to a 2048-bit or larger RSA key.",
                        ))
                    elif key_bits < 2048:
                        findings.append(Finding(
                            category="DKIM", severity=Severity.MEDIUM,
                            title=f"DKIM key is 1024 bits for selector '{sel}'",
                            detail="1024-bit RSA keys are deprecated. 2048-bit is recommended.",
                            recommendation="Rotate to a 2048-bit RSA key.",
                        ))
                    else:
                        findings.append(Finding(
                            category="DKIM", severity=Severity.INFO,
                            title=f"DKIM key size for '{sel}': ~{key_bits} bits",
                            detail="Key size is acceptable.",
                        ))
                except Exception:
                    pass
            else:
                # Empty p= means the key is revoked
                findings.append(Finding(
                    category="DKIM", severity=Severity.HIGH,
                    title=f"DKIM key for selector '{sel}' is revoked (empty p=)",
                    detail="An empty 'p=' tag means this selector is intentionally revoked.",
                    recommendation="If mail is still being signed with this selector, update/replace the record.",
                ))

        # t=y means testing mode
        if re.search(r"\bt=y\b", record, re.I):
            findings.append(Finding(
                category="DKIM", severity=Severity.LOW,
                title=f"DKIM selector '{sel}' is in testing mode (t=y)",
                detail="Testing mode signals verifiers not to enforce DKIM failures.",
                recommendation="Remove 't=y' flag when DKIM is confirmed working.",
            ))

    return findings

# ---------------------------------------------------------------------------
# DMARC checker
# ---------------------------------------------------------------------------

def check_dmarc(domain: str) -> list[Finding]:
    findings = []
    records = query_txt(f"_dmarc.{domain}")

    if not records:
        findings.append(Finding(
            category="DMARC", severity=Severity.CRITICAL,
            title="No DMARC record found",
            detail=f"No TXT record at _dmarc.{domain}.",
            recommendation="Publish a DMARC record. Start with: 'v=DMARC1; p=none; rua=mailto:dmarc@yourdomain.com'",
        ))
        return findings

    dmarc_records = [r for r in records if r.lower().startswith("v=dmarc1")]
    if not dmarc_records:
        findings.append(Finding(
            category="DMARC", severity=Severity.CRITICAL,
            title="No valid DMARC record (v=DMARC1 not found)",
            detail=f"TXT records exist at _dmarc.{domain} but none start with 'v=DMARC1': {records}",
        ))
        return findings

    dmarc = dmarc_records[0]
    findings.append(Finding(
        category="DMARC", severity=Severity.INFO,
        title="DMARC record", detail=dmarc,
    ))

    # Policy
    p_match = re.search(r"\bp=(\w+)", dmarc, re.I)
    policy = p_match.group(1).lower() if p_match else None
    if policy == "none":
        findings.append(Finding(
            category="DMARC", severity=Severity.MEDIUM,
            title="DMARC policy is 'none' (monitoring only)",
            detail="p=none means DMARC failures are reported but not acted on.",
            recommendation="Move to p=quarantine, then p=reject once reporting confirms no legitimate mail is failing.",
        ))
    elif policy == "quarantine":
        findings.append(Finding(
            category="DMARC", severity=Severity.LOW,
            title="DMARC policy is 'quarantine'",
            detail="Failing messages are sent to spam. Good interim policy.",
            recommendation="Consider upgrading to p=reject for maximum protection.",
        ))
    elif policy == "reject":
        findings.append(Finding(
            category="DMARC", severity=Severity.INFO,
            title="DMARC policy is 'reject' (best)",
            detail="Failing messages are rejected outright. Highest protection.",
        ))
    else:
        findings.append(Finding(
            category="DMARC", severity=Severity.HIGH,
            title=f"DMARC policy is invalid or missing: '{policy}'",
            detail=f"Raw record: {dmarc}",
            recommendation="Set p=none (minimum), p=quarantine, or p=reject.",
        ))

    # Subdomain policy
    sp_match = re.search(r"\bsp=(\w+)", dmarc, re.I)
    if sp_match:
        sp = sp_match.group(1).lower()
        findings.append(Finding(
            category="DMARC", severity=Severity.INFO,
            title=f"DMARC subdomain policy (sp=): {sp}",
            detail="Subdomains inherit the parent 'p=' policy if 'sp=' is not set.",
        ))
    else:
        if policy in ("none", None):
            findings.append(Finding(
                category="DMARC", severity=Severity.LOW,
                title="No DMARC subdomain policy (sp=) set",
                detail="Subdomains will fall back to the parent p= policy.",
                recommendation="Add sp=reject if subdomains should not send mail.",
            ))

    # Reporting URI (rua)
    rua_match = re.search(r"\brua=([^\s;]+)", dmarc, re.I)
    if rua_match:
        findings.append(Finding(
            category="DMARC", severity=Severity.INFO,
            title="DMARC aggregate report URI (rua)",
            detail=f"Reports sent to: {rua_match.group(1)}",
        ))
    else:
        findings.append(Finding(
            category="DMARC", severity=Severity.MEDIUM,
            title="No DMARC aggregate reporting URI (rua) configured",
            detail="Without rua=, you won't receive aggregate reports about DMARC failures.",
            recommendation="Add rua=mailto:dmarc@yourdomain.com or use a DMARC reporting service.",
        ))

    # Forensic report URI (ruf)
    ruf_match = re.search(r"\bruf=([^\s;]+)", dmarc, re.I)
    if not ruf_match:
        findings.append(Finding(
            category="DMARC", severity=Severity.LOW,
            title="No DMARC forensic report URI (ruf) configured",
            detail="Forensic reports provide detailed samples of failing messages.",
            recommendation="Add ruf=mailto:dmarc@yourdomain.com (note: privacy implications).",
        ))

    # Percentage
    pct_match = re.search(r"\bpct=(\d+)", dmarc, re.I)
    if pct_match:
        pct = int(pct_match.group(1))
        if pct < 100:
            findings.append(Finding(
                category="DMARC", severity=Severity.LOW,
                title=f"DMARC pct={pct} (policy only applied to {pct}% of messages)",
                detail="pct < 100 means the policy is not fully enforced.",
                recommendation="Set pct=100 for full enforcement.",
            ))

    # Alignment modes
    adkim_match = re.search(r"\badkim=([rs])\b", dmarc, re.I)
    aspf_match  = re.search(r"\baspf=([rs])\b",  dmarc, re.I)
    adkim = adkim_match.group(1).lower() if adkim_match else "r"
    aspf  = aspf_match.group(1).lower()  if aspf_match  else "r"
    if adkim == "r":
        findings.append(Finding(
            category="DMARC", severity=Severity.INFO,
            title="DKIM alignment: relaxed (default)",
            detail="Relaxed alignment allows organizational domain matching.",
        ))
    else:
        findings.append(Finding(
            category="DMARC", severity=Severity.INFO,
            title="DKIM alignment: strict (adkim=s)",
            detail="Strict alignment requires exact From: domain match.",
        ))
    if aspf == "r":
        findings.append(Finding(
            category="DMARC", severity=Severity.INFO,
            title="SPF alignment: relaxed (default)",
            detail="Relaxed alignment allows organizational domain matching.",
        ))

    return findings

# ---------------------------------------------------------------------------
# MX checker
# ---------------------------------------------------------------------------

def check_mx(domain: str) -> list[Finding]:
    findings = []
    mx_records = query_mx(domain)

    if not mx_records:
        findings.append(Finding(
            category="MX", severity=Severity.CRITICAL,
            title="No MX records found",
            detail=f"Domain {domain} has no MX records. It cannot receive email.",
            recommendation="Add MX records pointing to your mail server(s).",
        ))
        return findings

    findings.append(Finding(
        category="MX", severity=Severity.INFO,
        title=f"MX records ({len(mx_records)} found)",
        detail="\n  ".join(f"Priority {p}: {h}" for p, h in mx_records),
    ))

    for priority, host in mx_records:
        ips = query_a(host)
        if not ips:
            findings.append(Finding(
                category="MX", severity=Severity.HIGH,
                title=f"MX host '{host}' does not resolve",
                detail=f"Priority {priority}: No A record found for {host}.",
                recommendation="Verify the MX hostname is correct and has an A record.",
            ))
            continue

        for ip in ips[:1]:  # Check first IP
            ptr = query_ptr(ip)
            if ptr:
                if not (host.lower().endswith("." + ptr.split(".", 1)[-1]) or
                        ptr.lower().endswith("." + host.split(".", 1)[-1]) or
                        host.lower() == ptr.lower()):
                    findings.append(Finding(
                        category="MX", severity=Severity.MEDIUM,
                        title=f"PTR/rDNS mismatch for MX host '{host}'",
                        detail=f"IP {ip} has PTR record '{ptr}' which does not match MX hostname.",
                        recommendation="Set the PTR record for the sending IP to match the MX hostname.",
                    ))
            else:
                findings.append(Finding(
                    category="MX", severity=Severity.MEDIUM,
                    title=f"No PTR (rDNS) record for MX host '{host}' ({ip})",
                    detail="Many mail servers reject email from IPs without valid reverse DNS.",
                    recommendation=f"Configure PTR record for {ip} to point to {host}.",
                ))

        # SMTP TLS probe (only for first MX to keep runtime reasonable)
        if host == mx_records[0][1]:
            tls = probe_smtp_tls(host)
            if not tls["connected"]:
                findings.append(Finding(
                    category="MX", severity=Severity.LOW,
                    title=f"Could not connect to MX host '{host}' on port 25",
                    detail=f"Error: {tls.get('tls_error', 'unknown')}",
                    recommendation="Verify the MX host is reachable on port 25. (Some ISPs block outbound port 25.)",
                ))
            else:
                if not tls["starttls"]:
                    findings.append(Finding(
                        category="MX", severity=Severity.HIGH,
                        title=f"MX host '{host}' does not support STARTTLS",
                        detail="Mail transmitted to this server will be unencrypted.",
                        recommendation="Enable STARTTLS on your mail server.",
                    ))
                else:
                    ver = tls.get("tls_version", "unknown")
                    cipher = tls.get("cipher", "unknown")
                    findings.append(Finding(
                        category="MX", severity=Severity.INFO,
                        title=f"STARTTLS supported on '{host}'",
                        detail=f"TLS version: {ver}, Cipher: {cipher}",
                    ))
                    if ver in ("TLSv1", "TLSv1.1", "SSLv3", "SSLv2"):
                        findings.append(Finding(
                            category="MX", severity=Severity.HIGH,
                            title=f"MX host '{host}' uses deprecated TLS version: {ver}",
                            detail=f"TLS 1.0 and 1.1 are deprecated (RFC 8996).",
                            recommendation="Configure the mail server to require TLS 1.2 or higher.",
                        ))
                    if not tls["cert_valid"]:
                        findings.append(Finding(
                            category="MX", severity=Severity.HIGH,
                            title=f"TLS certificate on '{host}' is invalid or untrusted",
                            detail=f"Error: {tls.get('tls_error', 'validation failed')}",
                            recommendation="Install a valid, trusted TLS certificate (e.g., Let's Encrypt).",
                        ))
                    else:
                        expiry = tls.get("cert_expiry")
                        if expiry:
                            findings.append(Finding(
                                category="MX", severity=Severity.INFO,
                                title=f"TLS certificate valid on '{host}', expires: {expiry}",
                                detail=f"Common Name / SANs: {tls.get('cert_cn', 'N/A')}",
                            ))
                            # Check expiry within 30 days
                            try:
                                exp_dt = datetime.strptime(expiry, "%Y-%m-%d").replace(tzinfo=timezone.utc)
                                days_left = (exp_dt - datetime.now(timezone.utc)).days
                                if days_left < 0:
                                    findings.append(Finding(
                                        category="MX", severity=Severity.CRITICAL,
                                        title=f"TLS certificate on '{host}' has EXPIRED",
                                        detail=f"Expired on {expiry} ({abs(days_left)} days ago).",
                                        recommendation="Renew the TLS certificate immediately.",
                                    ))
                                elif days_left < 14:
                                    findings.append(Finding(
                                        category="MX", severity=Severity.HIGH,
                                        title=f"TLS certificate on '{host}' expires in {days_left} days",
                                        detail=f"Expiry: {expiry}",
                                        recommendation="Renew the certificate immediately.",
                                    ))
                                elif days_left < 30:
                                    findings.append(Finding(
                                        category="MX", severity=Severity.MEDIUM,
                                        title=f"TLS certificate on '{host}' expires in {days_left} days",
                                        detail=f"Expiry: {expiry}",
                                        recommendation="Schedule certificate renewal soon.",
                                    ))
                            except ValueError:
                                pass

    return findings

# ---------------------------------------------------------------------------
# BIMI checker
# ---------------------------------------------------------------------------

def check_bimi(domain: str) -> list[Finding]:
    findings = []
    records = query_txt(f"default._bimi.{domain}")

    if not records:
        findings.append(Finding(
            category="BIMI", severity=Severity.INFO,
            title="No BIMI record found",
            detail="BIMI (Brand Indicators for Message Identification) is not configured.",
            recommendation="Optional: Implement BIMI to display your logo in supporting email clients.",
        ))
        return findings

    bimi = records[0]
    findings.append(Finding(
        category="BIMI", severity=Severity.INFO,
        title="BIMI record found", detail=bimi,
    ))

    l_match = re.search(r"\bl=([^\s;]+)", bimi, re.I)
    a_match = re.search(r"\ba=([^\s;]+)", bimi, re.I)

    if l_match and l_match.group(1):
        logo_url = l_match.group(1)
        findings.append(Finding(
            category="BIMI", severity=Severity.INFO,
            title="BIMI logo URL", detail=logo_url,
        ))

    if a_match and a_match.group(1) and a_match.group(1) != "":
        authority_url = a_match.group(1)
        findings.append(Finding(
            category="BIMI", severity=Severity.INFO,
            title="BIMI VMC (Verified Mark Certificate) URL", detail=authority_url,
        ))
    else:
        findings.append(Finding(
            category="BIMI", severity=Severity.LOW,
            title="No BIMI VMC (a=) set — logo won't show in Gmail/Yahoo",
            detail="Gmail and Yahoo require a VMC for full BIMI support.",
            recommendation="Obtain a Verified Mark Certificate from a CA like DigiCert or Entrust.",
        ))

    return findings

# ---------------------------------------------------------------------------
# MTA-STS checker
# ---------------------------------------------------------------------------

def check_mta_sts(domain: str) -> list[Finding]:
    findings = []
    records = query_txt(f"_mta-sts.{domain}")

    if not records:
        findings.append(Finding(
            category="MTA-STS", severity=Severity.MEDIUM,
            title="No MTA-STS DNS record found",
            detail=f"No TXT record at _mta-sts.{domain}.",
            recommendation=(
                "Implement MTA-STS to enforce TLS for inbound mail delivery. "
                "Publish a TXT record at _mta-sts.<domain> and host a policy file at "
                "https://mta-sts.<domain>/.well-known/mta-sts.txt"
            ),
        ))
        return findings

    sts_dns = records[0]
    findings.append(Finding(
        category="MTA-STS", severity=Severity.INFO,
        title="MTA-STS DNS record found", detail=sts_dns,
    ))

    # Fetch the policy file
    try:
        import urllib.request
        import urllib.error
        policy_url = f"https://mta-sts.{domain}/.well-known/mta-sts.txt"
        with urllib.request.urlopen(policy_url, timeout=8) as resp:
            policy_text = resp.read().decode(errors="replace")
        findings.append(Finding(
            category="MTA-STS", severity=Severity.INFO,
            title="MTA-STS policy file fetched",
            detail=policy_text[:500],
        ))
        if "mode: enforce" in policy_text.lower():
            findings.append(Finding(
                category="MTA-STS", severity=Severity.INFO,
                title="MTA-STS mode: enforce (best)",
                detail="Sending servers must deliver over valid TLS or fail.",
            ))
        elif "mode: testing" in policy_text.lower():
            findings.append(Finding(
                category="MTA-STS", severity=Severity.LOW,
                title="MTA-STS mode: testing (not enforcing)",
                detail="Policy is in testing mode — TLS failures are not rejected.",
                recommendation="Change mode to 'enforce' after validating delivery.",
            ))
        elif "mode: none" in policy_text.lower():
            findings.append(Finding(
                category="MTA-STS", severity=Severity.MEDIUM,
                title="MTA-STS mode: none (disabled)",
                detail="Policy is explicitly disabled.",
                recommendation="Set mode to 'enforce' to require TLS.",
            ))
    except Exception as e:
        findings.append(Finding(
            category="MTA-STS", severity=Severity.MEDIUM,
            title="Could not fetch MTA-STS policy file",
            detail=f"URL: https://mta-sts.{domain}/.well-known/mta-sts.txt — Error: {e}",
            recommendation="Ensure the policy file is hosted at the correct URL over HTTPS.",
        ))

    return findings

# ---------------------------------------------------------------------------
# TLS-RPT checker
# ---------------------------------------------------------------------------

def check_tls_rpt(domain: str) -> list[Finding]:
    findings = []
    records = query_txt(f"_smtp._tls.{domain}")

    if not records:
        findings.append(Finding(
            category="TLS-RPT", severity=Severity.LOW,
            title="No TLS-RPT record found",
            detail=f"No SMTP TLS Reporting (RFC 8460) record at _smtp._tls.{domain}.",
            recommendation=(
                "Add TLS-RPT to receive reports about TLS failures during mail delivery. "
                "Example: 'v=TLSRPTv1; rua=mailto:tlsrpt@yourdomain.com'"
            ),
        ))
        return findings

    rpt = records[0]
    findings.append(Finding(
        category="TLS-RPT", severity=Severity.INFO,
        title="TLS-RPT record found", detail=rpt,
    ))

    rua_match = re.search(r"\brua=([^\s;]+)", rpt, re.I)
    if rua_match:
        findings.append(Finding(
            category="TLS-RPT", severity=Severity.INFO,
            title="TLS-RPT reporting URI", detail=rua_match.group(1),
        ))

    return findings

# ---------------------------------------------------------------------------
# DNSSEC checker
# ---------------------------------------------------------------------------

def check_dnssec_findings(domain: str) -> list[Finding]:
    findings = []
    result = check_dnssec(domain)
    if result is True:
        findings.append(Finding(
            category="DNSSEC", severity=Severity.INFO,
            title="DNSSEC is enabled and validated",
            detail="DNS responses for this domain are cryptographically signed.",
        ))
    elif result is False:
        findings.append(Finding(
            category="DNSSEC", severity=Severity.MEDIUM,
            title="DNSSEC is not enabled",
            detail="DNS records for this domain are not signed with DNSSEC.",
            recommendation=(
                "Enable DNSSEC at your registrar and DNS provider to protect against "
                "DNS spoofing and cache poisoning attacks."
            ),
        ))
    else:
        findings.append(Finding(
            category="DNSSEC", severity=Severity.INFO,
            title="DNSSEC status could not be determined",
            detail="Could not query DNSSEC status (network error or unsupported resolver).",
        ))
    return findings

# ---------------------------------------------------------------------------
# Catch-all / subdomain spoofing check
# ---------------------------------------------------------------------------

def check_subdomain_spf(domain: str) -> list[Finding]:
    """
    Check if subdomains inherit SPF protection. If parent has SPF with -all,
    subdomains that don't have their own SPF records may still be spoofable
    unless DMARC sp= reject is set.
    """
    findings = []
    # Check a likely non-existent subdomain
    sub = f"noreply.{domain}"
    sub_spf = [r for r in query_txt(sub) if r.lower().startswith("v=spf1")]
    if not sub_spf:
        # Check DMARC for subdomain protection
        dmarc_recs = query_txt(f"_dmarc.{domain}")
        sp_protected = False
        for r in dmarc_recs:
            sp_match = re.search(r"\bsp=(quarantine|reject)\b", r, re.I)
            if sp_match:
                sp_protected = True
                break
        if not sp_protected:
            findings.append(Finding(
                category="Subdomain Spoofing",
                severity=Severity.MEDIUM,
                title="Subdomains may be spoofable (no DMARC sp= policy)",
                detail=(
                    f"'{sub}' has no SPF record and the parent DMARC record "
                    "does not set sp=quarantine or sp=reject."
                ),
                recommendation="Add sp=reject to your DMARC record to protect all subdomains.",
            ))
    return findings

# ---------------------------------------------------------------------------
# Report renderer
# ---------------------------------------------------------------------------

SEV_ORDER = [Severity.CRITICAL, Severity.HIGH, Severity.MEDIUM, Severity.LOW, Severity.INFO]
SEV_LABEL = {
    Severity.CRITICAL: "CRITICAL",
    Severity.HIGH:     "HIGH    ",
    Severity.MEDIUM:   "MEDIUM  ",
    Severity.LOW:      "LOW     ",
    Severity.INFO:     "INFO    ",
}

def render_report(domain: str, all_findings: list[Finding], use_color: bool = True) -> None:
    def c(sev: Severity, text: str) -> str:
        if use_color:
            return f"{SEV_COLORS[sev]}{text}{RESET}"
        return text

    def bold(text: str) -> str:
        return f"{BOLD}{text}{RESET}" if use_color else text

    width = 80
    now = datetime.now().strftime("%Y-%m-%d %H:%M:%S")

    print()
    print(bold("=" * width))
    print(bold(f"  Email Security Scan Report"))
    print(bold(f"  Domain : {domain}"))
    print(bold(f"  Time   : {now}"))
    print(bold("=" * width))

    # Summary counts
    counts = {s: 0 for s in SEV_ORDER}
    for f in all_findings:
        counts[f.severity] += 1

    print()
    print(bold("  SUMMARY"))
    print("  " + "-" * (width - 2))
    for sev in SEV_ORDER:
        if counts[sev]:
            print(f"  {c(sev, SEV_LABEL[sev])}  {counts[sev]}")
    print(f"  Total findings: {len(all_findings)}")
    print()

    # Group by severity then category
    by_sev: dict[Severity, list[Finding]] = {s: [] for s in SEV_ORDER}
    for f in all_findings:
        by_sev[f.severity].append(f)

    for sev in SEV_ORDER:
        group = by_sev[sev]
        if not group:
            continue
        label = SEV_LABEL[sev].strip()
        print(bold(f"  [{label}]") + "  " + "-" * (width - len(label) - 6))
        for f in group:
            cat_tag = f"[{f.category}]"
            print(f"\n  {c(sev, cat_tag)} {bold(f.title)}")
            if f.detail:
                for line in f.detail.splitlines():
                    wrapped = textwrap.wrap(line, width=width - 6)
                    for wl in (wrapped or [""]):
                        print(f"      {wl}")
            if f.recommendation:
                rec_lines = textwrap.wrap(f.recommendation, width=width - 16)
                print(f"      -> " + rec_lines[0])
                for rl in rec_lines[1:]:
                    print(f"         " + rl)
        print()

    print(bold("=" * width))
    print()

# ---------------------------------------------------------------------------
# Score / grade
# ---------------------------------------------------------------------------

def compute_score(findings: list[Finding]) -> tuple[int, str]:
    """Return (0-100 score, letter grade)."""
    deductions = {
        Severity.CRITICAL: 25,
        Severity.HIGH: 12,
        Severity.MEDIUM: 5,
        Severity.LOW: 2,
        Severity.INFO: 0,
    }
    score = 100
    for f in findings:
        if f.severity != Severity.INFO:
            score -= deductions[f.severity]
    score = max(0, score)
    if score >= 90: grade = "A"
    elif score >= 75: grade = "B"
    elif score >= 60: grade = "C"
    elif score >= 40: grade = "D"
    else: grade = "F"
    return score, grade

# ---------------------------------------------------------------------------
# Main
# ---------------------------------------------------------------------------

def main():
    if len(sys.argv) < 2:
        print(f"Usage: {sys.argv[0]} <domain>")
        print(f"Example: {sys.argv[0]} example.com")
        sys.exit(1)

    domain = sys.argv[1].lower().strip().rstrip(".")
    # Strip leading protocol if pasted from browser
    domain = re.sub(r"^https?://", "", domain).split("/")[0]

    use_color = sys.stdout.isatty()

    print(f"\nScanning email security for: {domain}")
    print("This may take 30-60 seconds...\n")

    all_findings: list[Finding] = []

    checks = [
        ("SPF",                check_spf),
        ("DKIM",               check_dkim),
        ("DMARC",              check_dmarc),
        ("MX / SMTP TLS",      check_mx),
        ("BIMI",               check_bimi),
        ("MTA-STS",            check_mta_sts),
        ("TLS-RPT",            check_tls_rpt),
        ("DNSSEC",             check_dnssec_findings),
        ("Subdomain Spoofing", check_subdomain_spf),
    ]

    for name, fn in checks:
        print(f"  Checking {name}...", end="", flush=True)
        try:
            results = fn(domain)
            all_findings.extend(results)
            print(f" {len(results)} finding(s)")
        except Exception as e:
            print(f" ERROR: {e}")
            all_findings.append(Finding(
                category=name, severity=Severity.INFO,
                title=f"Check failed with error", detail=str(e),
            ))

    render_report(domain, all_findings, use_color=use_color)

    score, grade = compute_score(all_findings)
    bold_str = lambda t: f"\033[1m{t}\033[0m" if use_color else t
    print(f"  Overall security score: {bold_str(str(score))}/100  (Grade: {bold_str(grade)})")
    print()

    # Optional: write JSON report
    if "--json" in sys.argv:
        out = {
            "domain": domain,
            "scanned_at": datetime.now().isoformat(),
            "score": score,
            "grade": grade,
            "findings": [
                {
                    "category": f.category,
                    "severity": f.severity.name,
                    "title": f.title,
                    "detail": f.detail,
                    "recommendation": f.recommendation,
                }
                for f in all_findings
            ],
        }
        json_path = f"{domain}_email_security.json"
        with open(json_path, "w") as jf:
            json.dump(out, jf, indent=2)
        print(f"  JSON report written to: {json_path}")
        print()

if __name__ == "__main__":
    main()
