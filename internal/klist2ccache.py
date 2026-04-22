#!/usr/bin/env python3
"""
klist2ccache.py  –  Convert Windows `klist tgt` output to MIT ccache format

Requirements: Python 3.6+, no dependencies

Session Key Note
  Running klist as a normal user zeroes out the session key. You must run
  as NT AUTHORITY\\SYSTEM and target the logon session with -li:

    klist tgt -li 0x<LogonId>

  The LogonId is shown in any `klist` output as "Current LogonId".
  Use `klist sessions` to list all active sessions.

Usage
  klist tgt -li 0x154333 > klist.txt
  python klist2ccache.py -i klist.txt
  python klist2ccache.py -i klist.txt -f jotte_tgt
  python klist2ccache.py -i klist.txt -K <hex key>
  python klist2ccache.py -i klist.txt --ref existing.ccache
"""

import argparse
import os
import re
import struct
import sys
from datetime import datetime, timezone


# ── ccache reader (key extraction from reference file) ────────────────────────

def _skip_counted(data: bytes, off: int) -> int:
    n = struct.unpack_from(">I", data, off)[0]
    return off + 4 + n


def _skip_principal(data: bytes, off: int) -> int:
    off += 4  # name-type
    count = struct.unpack_from(">I", data, off)[0]
    off += 4
    off = _skip_counted(data, off)  # realm
    for _ in range(count):
        off = _skip_counted(data, off)
    return off


def read_ccache_key(path: str) -> tuple:
    """Extract (etype, key_bytes) from the first credential in a ccache file."""
    with open(path, "rb") as f:
        data = f.read()

    off = 0
    version = struct.unpack_from(">H", data, off)[0]
    off += 2
    if version not in (0x0504, 0x0503, 0x0502):
        raise ValueError(f"Unrecognised ccache version: 0x{version:04x}")

    hdr_len = struct.unpack_from(">H", data, off)[0]
    off += 2 + hdr_len

    off = _skip_principal(data, off)  # default principal
    off = _skip_principal(data, off)  # cred client
    off = _skip_principal(data, off)  # cred server

    etype = struct.unpack_from(">H", data, off)[0]
    off += 2 + 2  # etype + etype2
    klen = struct.unpack_from(">H", data, off)[0]
    off += 2
    return etype, data[off:off + klen]


# ── klist text parser ──────────────────────────────────────────────────────────

def parse_klist(text: str) -> dict:
    """Parse the output of `klist tgt [-li 0x...]` into a credential dict."""

    def field(pat: str, default: str = "") -> str:
        m = re.search(pat, text, re.IGNORECASE)
        return m.group(1).strip() if m else default

    def parse_time(s: str) -> int:
        if not s:
            return 0
        for fmt in ("%m/%d/%Y %H:%M:%S", "%m/%d/%Y %H:%M"):
            try:
                return int(
                    datetime.strptime(s.strip(), fmt)
                    .replace(tzinfo=timezone.utc)
                    .timestamp()
                )
            except ValueError:
                pass
        return 0

    # Encoded ticket hex dump — lines like:
    #   0000  61 82 04 86 30 82 ...:.. XX XX  ........
    ticket_hex = []
    for m in re.finditer(
        r"^[0-9a-fA-F]{4}\s+((?:[0-9a-fA-F]{2}[\s:])+)", text, re.MULTILINE
    ):
        ticket_hex.append(re.sub(r"[^0-9a-fA-F]", "", m.group(1)))
    ticket_bytes = bytes.fromhex("".join(ticket_hex))

    # Session key — "KeyLength 32 - aa bb cc dd ..."
    raw = re.sub(
        r"\s+",
        "",
        field(r"KeyLength\s+\d+\s+-\s+([0-9a-fA-F][0-9a-fA-F ]*)"),
    )
    try:
        key_bytes = bytes.fromhex(raw) if raw else b"\x00" * 32
    except ValueError:
        key_bytes = b"\x00" * 32

    return {
        "client":     field(r"ClientName\s*:\s*(.+)"),
        "realm":      field(r"DomainName\s*:\s*(.+)"),
        "sname":      [
            field(r"ServiceName\s*:\s*(.+)"),
            field(r"TargetDomainName\s*:\s*(.+)"),
        ],
        "flags":      int(field(r"Ticket Flags\s*:\s*(0x[0-9a-fA-F]+)", "0x0"), 16),
        "key_type":   int(field(r"KeyType\s+(0x[0-9a-fA-F]+)", "0x12"), 16),
        "key_data":   key_bytes,
        "auth_time":  parse_time(field(r"StartTime\s*:\s*(.+?)\s*\(local\)")),
        "start_time": parse_time(field(r"StartTime\s*:\s*(.+?)\s*\(local\)")),
        "end_time":   parse_time(field(r"EndTime\s*:\s*(.+?)\s*\(local\)")),
        "renew_till": parse_time(field(r"RenewUntil\s*:\s*(.+?)\s*\(local\)")),
        "ticket_data": ticket_bytes,
    }


# ── ccache writer (MIT Kerberos credential cache v4) ──────────────────────────

def write_ccache(info: dict, path: str) -> None:
    """Write a MIT ccache v4 file from a parsed credential dict."""

    def p16(n: int) -> bytes:
        return struct.pack(">H", n)

    def p32(n: int) -> bytes:
        return struct.pack(">I", n)

    def cnt(b: bytes) -> bytes:
        """Counted octet string: uint32 length prefix + data."""
        return p32(len(b)) + b

    def principal(name: str, realm: str, ntype: int = 1) -> bytes:
        parts = name.split("/") if "/" in name else [name]
        out = p32(ntype) + p32(len(parts)) + cnt(realm.encode())
        for component in parts:
            out += cnt(component.encode())
        return out

    # File header: version=0x0504, delta-time tag
    # time_offset=0xffffffff signals no clock skew adjustment
    hdr = b"\x05\x04"
    tag = p16(1) + p16(8) + struct.pack(">I", 0xFFFFFFFF) + p32(0)
    hdr += p16(len(tag)) + tag

    default_p = principal(info["client"], info["realm"])

    cred = principal(info["client"], info["realm"])
    cred += principal("/".join(info["sname"]), info["realm"], 1)

    # Keyblock: etype(2) | etype2=0(2) | keylen(2) | keydata
    cred += p16(info["key_type"])
    cred += p16(0)
    cred += p16(len(info["key_data"])) + info["key_data"]

    # Timestamps: authtime, starttime, endtime, renew-till (4 × uint32 BE)
    cred += struct.pack(
        ">IIII",
        info["auth_time"],
        info["start_time"],
        info["end_time"],
        info["renew_till"],
    )

    cred += b"\x00"              # is_skey
    cred += p32(info["flags"])   # ticket_flags
    cred += p32(0)               # num_addresses
    cred += p32(0)               # num_authdata
    cred += cnt(info["ticket_data"])  # ticket
    cred += cnt(b"")             # second_ticket (empty)

    with open(path, "wb") as f:
        f.write(hdr + default_p + cred)

    print(f"[+] ccache written → {path}  ({os.path.getsize(path)} bytes)")


# ── debug dump ─────────────────────────────────────────────────────────────────

def debug_ccache(path: str) -> None:
    """Parse and pretty-print every field of a ccache file."""
    with open(path, "rb") as f:
        data = f.read()

    def p(label, val):
        print(f"  {label:<24} {val}")

    off = 0
    ver = struct.unpack_from(">H", data, off)[0]
    off += 2
    p("version", f"0x{ver:04x}")

    hlen = struct.unpack_from(">H", data, off)[0]
    off += 2
    p("header_len", hlen)
    hend = off + hlen
    while off < hend:
        tag = struct.unpack_from(">H", data, off)[0]
        off += 2
        tl = struct.unpack_from(">H", data, off)[0]
        off += 2
        val = data[off:off + tl]
        off += tl
        p(f"  tag={tag} len={tl}", val.hex())

    def read_princ(label: str) -> None:
        nonlocal off
        ntype = struct.unpack_from(">I", data, off)[0]
        off += 4
        count = struct.unpack_from(">I", data, off)[0]
        off += 4
        rlen = struct.unpack_from(">I", data, off)[0]
        off += 4
        realm = data[off:off + rlen].decode(errors="replace")
        off += rlen
        comps = []
        for _ in range(count):
            clen = struct.unpack_from(">I", data, off)[0]
            off += 4
            comps.append(data[off:off + clen].decode(errors="replace"))
            off += clen
        p(label, f"ntype={ntype} realm={realm} comps={comps}")

    read_princ("default_principal")
    read_princ("cred.client")
    read_princ("cred.server")

    etype = struct.unpack_from(">H", data, off)[0]
    off += 2
    etype2 = struct.unpack_from(">H", data, off)[0]
    off += 2
    klen = struct.unpack_from(">H", data, off)[0]
    off += 2
    key = data[off:off + klen]
    off += klen
    p("keyblock.etype", etype)
    p("keyblock.etype2", etype2)
    p("keyblock.klen", klen)
    p("keyblock.key", key.hex())

    auth, start, end, renew = struct.unpack_from(">IIII", data, off)
    off += 16
    p("time.authtime",  f"0x{auth:08x}  ({datetime.fromtimestamp(auth,  tz=timezone.utc)})")
    p("time.starttime", f"0x{start:08x} ({datetime.fromtimestamp(start, tz=timezone.utc)})")
    p("time.endtime",   f"0x{end:08x}  ({datetime.fromtimestamp(end,   tz=timezone.utc)})")
    p("time.renew_till",f"0x{renew:08x} ({datetime.fromtimestamp(renew, tz=timezone.utc)})")

    is_skey = data[off]
    off += 1
    flags = struct.unpack_from(">I", data, off)[0]
    off += 4
    p("is_skey", is_skey)
    p("ticket_flags", f"0x{flags:08x}")

    naddr = struct.unpack_from(">I", data, off)[0]
    off += 4
    p("num_addresses", naddr)
    nauth = struct.unpack_from(">I", data, off)[0]
    off += 4
    p("num_authdata", nauth)

    tlen = struct.unpack_from(">I", data, off)[0]
    off += 4
    p("ticket_len", tlen)
    p("ticket_first8", data[off:off + 8].hex())
    off += tlen

    s2len = struct.unpack_from(">I", data, off)[0]
    p("second_ticket_len", s2len)
    p("total_size", len(data))


# ── entry point ───────────────────────────────────────────────────────────────

def main() -> None:
    ap = argparse.ArgumentParser(
        description="Convert Windows klist TGT output to MIT ccache",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog=__doc__,
    )
    ap.add_argument(
        "-i", "--input", default="-",
        help="klist output file (default: stdin)",
    )
    ap.add_argument(
        "-f", "--filename", default=None,
        help="Output filename without extension (default: <user>@<realm>)",
    )
    ap.add_argument(
        "--ref", metavar="CCACHE",
        help="Extract session key from this existing ccache",
    )
    ap.add_argument(
        "-K", "--key", metavar="HEX",
        help="Session key as hex string (overrides --ref)",
    )
    ap.add_argument(
        "--debug", action="store_true",
        help="Print full ccache field dump after writing",
    )
    args = ap.parse_args()

    # Read klist input
    if args.input == "-":
        text = sys.stdin.read()
    else:
        with open(args.input, "r", errors="replace") as fh:
            text = fh.read()

    info = parse_klist(text)

    if not info["ticket_data"]:
        print("[-] Could not extract ticket bytes from input.", file=sys.stderr)
        sys.exit(1)

    # Resolve session key
    if args.key:
        info["key_data"] = bytes.fromhex(args.key.replace(" ", ""))
        print(f"[*] Using provided key ({len(info['key_data'])} bytes)")
    elif args.ref:
        etype, key = read_ccache_key(args.ref)
        info["key_data"] = key
        info["key_type"] = etype
        print(f"[*] Key extracted from {args.ref}  etype={etype}  ({len(key)} bytes)")
    elif all(b == 0 for b in info["key_data"]):
        print("[!] WARNING: session key is all-zeros — output will fail with BAD_INTEGRITY", file=sys.stderr)
        print("[!] Run klist as SYSTEM:  klist tgt -li 0x<LogonId>", file=sys.stderr)

    # Print parsed info
    key_display = "(all-zeros!)" if all(b == 0 for b in info["key_data"]) else info["key_data"].hex()
    print(f"\n[*] Parsed ticket:")
    print(f"    client     : {info['client']}@{info['realm']}")
    print(f"    server     : {'/'.join(info['sname'])}@{info['realm']}")
    print(f"    key_type   : {info['key_type']}")
    print(f"    key        : {key_display}")
    print(f"    flags      : 0x{info['flags']:08x}")
    print(f"    start_time : {datetime.fromtimestamp(info['start_time'], tz=timezone.utc) if info['start_time'] else 'N/A'}")
    print(f"    end_time   : {datetime.fromtimestamp(info['end_time'],   tz=timezone.utc) if info['end_time']   else 'N/A'}")
    print(f"    renew_till : {datetime.fromtimestamp(info['renew_till'], tz=timezone.utc) if info['renew_till'] else 'N/A'}")
    print(f"    ticket     : {len(info['ticket_data'])} bytes")

    # Write ccache
    print()
    out_base = args.filename or f"{info['client']}@{info['realm']}"
    out_path = out_base + ".ccache"
    write_ccache(info, out_path)

    if args.debug:
        print(f"\n[DEBUG] {out_path} structure:")
        debug_ccache(out_path)

    print(f"\n[*] Use with impacket:")
    print(f"    export KRB5CCNAME={out_path}")
    print(f"    smbclient.py -k -no-pass <domain>/<user>@<target>")


if __name__ == "__main__":
    main()
