#!/usr/bin/env python3
"""
viewstate_check.py — ASP.NET ViewState security checker

Checks for:
  - Encryption status (0xFF 0x01 header = encrypted)
  - MAC presence / algorithm (detected from trailing bytes)
  - Known/weak machine keys via badsecrets
  - Custom machine key list (--keys)

Background
  ASP.NET ViewState is a base64-encoded, serialized state blob stored in
  a hidden form field. Three independent protections exist:

  1. Encryption (viewStateEncryptionMode): AES-encrypts the payload.
     Disabled by default in many configs. Without it the raw serialized
     object graph is visible — and may contain sensitive values.

  2. MAC / HMAC (enableViewStateMac): HMAC appended to the payload.
     Disabled = anyone can tamper with the ViewState freely.
     On by default in .NET 4.5+, but sometimes disabled for perf.

  3. Machine key strength: if MAC is enabled but the validationKey is a
     known default, an attacker can forge a valid HMAC and submit a
     malicious ObjectStateFormatter payload → RCE via ysoserial.net.

Usage:
  viewstate-check <viewstate> -g CA0B0334
  viewstate-check <viewstate> -g CA0B0334 --keys machinekeys.txt
"""

import argparse
import base64
import hashlib
import hmac
import struct
import sys

from rich.console import Console
from rich.rule import Rule

console = Console(highlight=False)

# (hash constructor, digest length in bytes)
_ALGORITHMS: dict[str, tuple] = {
    "SHA1":      (hashlib.sha1,   20),
    "HMACSHA256":(hashlib.sha256, 32),
    "MD5":       (hashlib.md5,    16),
    "SHA256":    (hashlib.sha256, 32),
}


# ── helpers ───────────────────────────────────────────────────────────────────

def _decode(vs: str) -> bytes:
    vs = vs.strip().replace("%2B", "+").replace("%2F", "/").replace("%3D", "=")
    vs += "=" * ((-len(vs)) % 4)
    return base64.b64decode(vs)


def _gen_modifier(gen_hex: str) -> bytes:
    """Convert __VIEWSTATEGENERATOR hex to big-endian uint32 bytes."""
    if not gen_hex:
        return b""
    return struct.pack(">I", int(gen_hex, 16))


def _is_encrypted(data: bytes) -> bool:
    return len(data) >= 2 and data[0] == 0xFF and data[1] == 0x01


def _detect_mac(data: bytes) -> str | None:
    """
    Heuristic: check whether the data ends with a plausible HMAC block.
    LOS (Limited Object Serialization) payloads end with 0x65 (end marker).
    If byte at offset -(mac_len) == 0x65, trailing bytes are likely the MAC.
    Returns algorithm name or None if indeterminate.
    """
    for alg, (_, mac_len) in _ALGORITHMS.items():
        if len(data) > mac_len and data[-(mac_len + 1)] == 0x65:
            return alg
    return None


def _try_key(vs_bytes: bytes, key_hex: str, gen_hex: str) -> tuple[bool, str]:
    """Try all algorithms. Returns (matched, alg_name)."""
    try:
        key = bytes.fromhex(key_hex.strip())
    except ValueError:
        return False, ""

    modifier = _gen_modifier(gen_hex)

    for alg, (hash_fn, mac_len) in _ALGORITHMS.items():
        if len(vs_bytes) <= mac_len:
            continue
        payload     = vs_bytes[:-mac_len]
        claimed_mac = vs_bytes[-mac_len:]

        for suffix in (modifier, b""):
            h = hmac.new(key, payload + suffix, hash_fn)
            if hmac.compare_digest(h.digest(), claimed_mac):
                return True, alg

    return False, ""


def _badsecrets(vs_b64: str, gen_hex: str) -> dict | None:
    """
    Run badsecrets against known machine key list.
    Returns result dict, empty dict if no match, or None if not installed.
    """
    try:
        from badsecrets.base import check_all_modules            # type: ignore
    except ImportError:
        return None

    try:
        return check_all_modules(vs_b64, gen_hex) or {}
    except Exception:
        return {}


# ── main ──────────────────────────────────────────────────────────────────────

def main() -> None:
    ap = argparse.ArgumentParser(
        description="ASP.NET ViewState misconfiguration and weak key checker",
        formatter_class=argparse.RawDescriptionHelpFormatter,
    )
    ap.add_argument("viewstate",
                    help="Base64-encoded __VIEWSTATE value")
    ap.add_argument("-g", "--generator", default="", metavar="HEX",
                    help="__VIEWSTATEGENERATOR value (e.g. CA0B0334)")
    ap.add_argument("-k", "--keys", metavar="FILE",
                    help="File of validationKey values to test (hex, one per line)")
    args = ap.parse_args()

    console.print()
    console.print(Rule("[bold cyan]ViewState Security Check[/bold cyan]"))
    console.print()

    # Decode
    try:
        vs_bytes = _decode(args.viewstate)
    except Exception as e:
        console.print(f"[red]Decode failed: {e}[/red]")
        sys.exit(1)

    console.print(f"  Bytes     : {len(vs_bytes)}")
    console.print(f"  Header    : {vs_bytes[:8].hex()}")
    if args.generator:
        console.print(f"  Generator : {args.generator.upper()}")
    console.print()

    # ── 1. Encryption ─────────────────────────────────────────────────────────
    console.print(Rule("[dim]1 · Encryption[/dim]"))
    encrypted = _is_encrypted(vs_bytes)
    if encrypted:
        console.print("  [green][ENC][/green]  ViewState is encrypted (0xFF 0x01)")
        console.print("        MAC can only be checked after decryption.")
    else:
        console.print("  [yellow][!][/yellow]  ViewState is NOT encrypted")
        console.print("       Base64-decode and inspect for sensitive data.")
    console.print()

    # ── 2. MAC detection ──────────────────────────────────────────────────────
    console.print(Rule("[dim]2 · MAC Detection (heuristic)[/dim]"))
    if encrypted:
        console.print("  [dim]Skipped — payload is encrypted.[/dim]")
    else:
        detected_alg = _detect_mac(vs_bytes)
        if detected_alg:
            console.print(f"  [green][+][/green]  MAC likely present — trailing bytes match {detected_alg} length")
            console.print(f"       Tamper resistance: YES (but key may still be weak)")
        else:
            console.print("  [yellow][!][/yellow]  MAC not detected — MAC may be disabled")
            console.print("       If confirmed disabled: ViewState can be freely forged")
            console.print("       RCE path: ysoserial.net -p ViewState -g <generator> -c <cmd>")
    console.print()

    # ── 3. badsecrets ─────────────────────────────────────────────────────────
    console.print(Rule("[dim]3 · Known Machine Keys (badsecrets)[/dim]"))
    bs_results = _badsecrets(args.viewstate, args.generator)
    if bs_results is None:
        console.print("  [yellow]badsecrets not installed.[/yellow]  pip install badsecrets")
    elif bs_results:
        secret  = bs_results.get("secret", "?")
        details = bs_results.get("details", "")
        module  = bs_results.get("detecting_module", "")
        console.print(f"  [bold red][VULN][/bold red] {module}: {secret}")
        if details:
            console.print(f"         details: {details}")
    else:
        console.print("  [green][OK][/green]  No known machine keys matched")
    console.print()

    # ── 4. Custom key file ────────────────────────────────────────────────────
    if args.keys:
        console.print(Rule("[dim]4 · Custom Key File[/dim]"))
        try:
            with open(args.keys) as f:
                keys = [l.strip() for l in f
                        if l.strip() and not l.startswith("#")]
        except FileNotFoundError:
            console.print(f"  [red]File not found: {args.keys}[/red]")
            sys.exit(1)

        console.print(f"  Testing {len(keys)} keys …")
        found_any = False
        for key in keys:
            matched, alg = _try_key(vs_bytes, key, args.generator)
            if matched:
                console.print(f"  [bold red][MATCH][/bold red]  key={key}  alg={alg}")
                found_any = True
        if not found_any:
            console.print("  [green][OK][/green]  No keys matched")
        console.print()

    # ── Summary ───────────────────────────────────────────────────────────────
    console.print(Rule("[dim]Summary[/dim]"))
    issues = []
    if not encrypted:
        issues.append(("yellow", "Not encrypted → inspect plaintext for leaked data"))
    if not encrypted and not _detect_mac(vs_bytes):
        issues.append(("red", "MAC likely disabled → ViewState forgery / possible RCE"))
    if bs_results:
        issues.append(("red", "Known machine key found → forge ViewState → RCE"))

    if issues:
        for color, msg in issues:
            console.print(f"  [{color}][!][/{color}]  {msg}")
        if bs_results or (not encrypted and not _detect_mac(vs_bytes)):
            console.print()
            console.print("  [dim]ysoserial.net:[/dim]")
            console.print("  [dim]  ysoserial.exe -p ViewState -g TextFormattingRunProperties -c \"whoami\"[/dim]")
            console.print("  [dim]    --validationalg SHA1 --validationkey <key> --generator <gen>[/dim]")
    else:
        console.print("  [green]No obvious misconfigurations detected[/green]")
    console.print()


if __name__ == "__main__":
    main()
