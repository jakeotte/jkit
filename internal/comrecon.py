#!/usr/bin/env python3
"""comrecon.py — COM hijack target recon via SMB only (no RPC pipes)"""

import argparse
import io
import sys
import xml.etree.ElementTree as ET

from impacket.smbconnection import SMBConnection

TASK_NS   = 'http://schemas.microsoft.com/windows/2004/02/mit/task'
NS        = f'{{{TASK_NS}}}'
SHARE     = 'C$'
TASK_BASE = r'Windows\System32\Tasks'
STARTUP_ALLUSERS = r'ProgramData\Microsoft\Windows\Start Menu\Programs\StartUp'
USERS_BASE       = r'Users'
STARTUP_REL      = r'AppData\Roaming\Microsoft\Windows\Start Menu\Programs\Startup'


# ── auth ──────────────────────────────────────────────────────────────────────

def parse_args():
    p = argparse.ArgumentParser(
        description='COM hijack target recon — SMB only, no RPC pipes',
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog='''\
Examples:
  %(prog)s 192.168.1.10 -u admin -p 'P@ss' -d corp
  %(prog)s 192.168.1.10 -u admin -H :fc525c9683e8fe067095ba2ddc971889
  %(prog)s 192.168.1.10 -u admin -p pass --no-startup

Note: Run/RunOnce registry keys require winreg RPC (not used here).
      Resolve CLSIDs locally: Get-ItemProperty "HKLM:\\SOFTWARE\\Classes\\CLSID\\{GUID}\\InprocServer32"
''')
    p.add_argument('target')
    p.add_argument('-u', '--username', default='')
    p.add_argument('-p', '--password', default='')
    p.add_argument('-d', '--domain', default='WORKGROUP')
    p.add_argument('-H', '--hashes', default='', metavar='LM:NT')
    p.add_argument('--no-tasks',        action='store_true', help='Skip task file enumeration')
    p.add_argument('--no-startup',      action='store_true', help='Skip startup folder enumeration')
    p.add_argument('--include-windows', action='store_true',
                   help='Include \\Microsoft\\Windows\\* built-in tasks (hidden by default)')
    return p.parse_args()


def split_hashes(h):
    if not h:
        return '', ''
    parts = h.split(':')
    return (parts[0], parts[1]) if len(parts) == 2 else ('', parts[0])


# ── SMB helpers ───────────────────────────────────────────────────────────────

def smb_connect(target, user, passwd, domain, lm, nt):
    c = SMBConnection(target, target)
    c.login(user, passwd, domain, lm, nt)
    return c


def smb_ls(smb, path):
    """Yield (name, is_dir) for entries under path (skips . and ..)."""
    try:
        for e in smb.listPath(SHARE, path.rstrip('\\') + '\\*'):
            name = e.get_longname()
            if name in ('.', '..'):
                continue
            yield name, e.is_directory()
    except Exception:
        pass


def smb_read(smb, path):
    """Return file contents as bytes, or None on failure."""
    try:
        buf = io.BytesIO()
        smb.getFile(SHARE, path, buf.write)
        return buf.getvalue()
    except Exception:
        return None


# ── task file enumeration ─────────────────────────────────────────────────────

def enum_task_files(smb, base=TASK_BASE, skip_windows=True):
    r"""
    Walk C$\Windows\System32\Tasks recursively.
    Yield (task_scheduler_path, xml_str) for each task file found.
    Task scheduler path uses backslashes starting with \.
    """
    stack = [(base, '\\')]
    while stack:
        smb_dir, sched_dir = stack.pop()
        print(f'[*]   scanning {sched_dir:<60}', end='\r', flush=True)
        for name, is_dir in smb_ls(smb, smb_dir):
            smb_path   = smb_dir.rstrip('\\') + '\\' + name
            sched_path = sched_dir.rstrip('\\') + '\\' + name
            if is_dir:
                if skip_windows and sched_path.lower().startswith(r'\microsoft\windows'):
                    continue
                stack.append((smb_path, sched_path))
            else:
                data = smb_read(smb, smb_path)
                if not data:
                    continue
                try:
                    xml_str = data.decode('utf-16-le').lstrip('﻿')
                except UnicodeDecodeError:
                    try:
                        xml_str = data.decode('utf-8').lstrip('﻿')
                    except UnicodeDecodeError:
                        continue
                yield sched_path, xml_str
    print()  # clear progress line


# ── task XML parsing ──────────────────────────────────────────────────────────

def parse_task(xml_str):
    """Return dict: exec, com_handlers[], triggers[], run_as."""
    result = {'exec': None, 'com_handlers': [], 'triggers': [], 'run_as': '?'}
    try:
        root = ET.fromstring(xml_str)

        for el in root.iter(f'{NS}Exec'):
            cmd = el.find(f'{NS}Command')
            if cmd is not None:
                result['exec'] = cmd.text
            break

        for el in root.iter(f'{NS}ComHandler'):
            clsid_el = el.find(f'{NS}ClassId')
            data_el  = el.find(f'{NS}Data')
            if clsid_el is not None:
                result['com_handlers'].append({
                    'clsid': (clsid_el.text or '').strip(),
                    'data':  (data_el.text or '') if data_el is not None else '',
                })

        trigs = root.find(f'.//{NS}Triggers')
        if trigs is not None:
            for child in trigs:
                tag = child.tag.replace(NS, '').replace('Trigger', '') or 'Unknown'
                result['triggers'].append(tag)

        pr = root.find(f'.//{NS}Principal')
        if pr is not None:
            uid_el   = pr.find(f'{NS}UserId')
            group_el = pr.find(f'{NS}GroupId')
            uid = uid_el if uid_el is not None else group_el
            lvl = pr.find(f'{NS}RunLevel')
            user = uid.text if uid is not None else '?'
            hi   = lvl is not None and lvl.text == 'HighestAvailable'
            result['run_as'] = (user or '?') + (' (hi)' if hi else '')
    except ET.ParseError:
        pass
    return result


# ── startup folder enumeration ────────────────────────────────────────────────

def enum_startup_folders(smb):
    r"""
    Yield (label, filename) from:
      - All Users startup folder
      - Per-user startup folders (discovered by listing C$\Users\)
    """
    # All users
    for name, is_dir in smb_ls(smb, STARTUP_ALLUSERS):
        yield 'All Users Startup', name

    # Per-user: list C$\Users\ to get profile dirs
    for username, is_dir in smb_ls(smb, USERS_BASE):
        if not is_dir or username.lower() in ('public', 'default', 'default user', 'all users'):
            continue
        user_startup = USERS_BASE + '\\' + username + '\\' + STARTUP_REL
        for name, _ in smb_ls(smb, user_startup):
            yield f'Startup ({username})', name


# ── display ───────────────────────────────────────────────────────────────────

def trunc(s, n):
    s = str(s or '')
    return (s[:n - 1] + '…') if len(s) > n else s


def print_table(headers, rows, widths):
    hdr = '  '.join(h.ljust(widths[i]) for i, h in enumerate(headers))
    print(f'\n{hdr}')
    print('-' * len(hdr))
    for row in rows:
        print('  '.join(trunc(row[i], widths[i]).ljust(widths[i]) for i in range(len(headers))))


def print_exec_table(rows):
    """Two-line format: task/trigger/runas on line 1, full command indented on line 2."""
    W_TASK = 52
    W_TRIG = 18
    print(f'\n  {"Task Path":<{W_TASK}}  {"Trigger":<{W_TRIG}}  Run As')
    print('  ' + '-' * (W_TASK + W_TRIG + 35))
    for task, cmd, trig, run_as in rows:
        print(f'  {trunc(task, W_TASK):<{W_TASK}}  {trig:<{W_TRIG}}  {run_as}')
        print(f'    {cmd}')
        print()


# ── main ──────────────────────────────────────────────────────────────────────

def main():
    args = parse_args()
    lm, nt = split_hashes(args.hashes)

    print(f'[*] Target: {args.target}')

    try:
        smb = smb_connect(args.target, args.username, args.password, args.domain, lm, nt)
        print('[+] SMB OK')
    except Exception as e:
        sys.exit(f'[-] SMB failed: {e}')

    com_rows     = []
    exec_rows    = []
    startup_rows = []
    all_clsids   = set()

    # ── Tasks ─────────────────────────────────────────────────────────────────
    if not args.no_tasks:
        print(f'[*] Reading tasks from C$\\{TASK_BASE}...')
        count = 0
        for sched_path, xml_str in enum_task_files(smb, skip_windows=not args.include_windows):
            count += 1
            info = parse_task(xml_str)
            trig = ','.join(info['triggers'])[:16] or '-'

            for handler in info['com_handlers']:
                clsid = handler['clsid']
                all_clsids.add(clsid)
                com_rows.append([sched_path, clsid, trig, info['run_as']])

            if info['exec']:
                exec_rows.append([sched_path, info['exec'], trig, info['run_as']])

        suffix = '' if args.include_windows else '  (\\Microsoft\\Windows\\* skipped — use --include-windows)'
        print(f'[*] {count} task files read{suffix}')

    # ── Startup folders ───────────────────────────────────────────────────────
    if not args.no_startup:
        for label, fname in enum_startup_folders(smb):
            if fname.lower() == 'desktop.ini':
                continue
            startup_rows.append([label, fname])

    # ── Output ────────────────────────────────────────────────────────────────

    # Section 1: COM handler tasks
    print('\n── COM Handler Tasks ' + '─' * 60)
    print('   Tasks that invoke a COM object by CLSID instead of running an EXE.')
    print('   Hijack: plant HKCU\\Software\\Classes\\CLSID\\{guid}\\InprocServer32 -> your DLL.\n')
    if com_rows:
        print_table(
            ['Task Path',  'CLSID',  'Trigger', 'Run As'],
            com_rows,
            [52,            38,       16,         28]
        )
    else:
        print('   (none)')

    # Section 2: Exec tasks (taskhijacker.py targets)
    print('\n── Exec Tasks ' + '─' * 66)
    print('   Tasks running executables — targets for taskhijacker.py.\n')
    if exec_rows:
        print_exec_table(exec_rows)
    else:
        print('   (none)')

    # Section 3: Startup folder contents
    print('\n── Startup Folders ' + '─' * 61)
    print('   Files present in All Users and per-user startup directories.\n')
    if startup_rows:
        print_table(
            ['Source', 'File'],
            startup_rows,
            [25,        60]
        )
    else:
        print('   (empty — no non-desktop.ini items found)')

    # Section 4: CLSID resolution snippet
    if all_clsids:
        visible_clsids = {r[1] for r in com_rows}  # only show CLSIDs from visible rows
        if visible_clsids:
            print('\n── CLSID Resolution (run on target or similar host) ' + '─' * 28)
            print('   $clsids = @(')
            for clsid in sorted(visible_clsids):
                print(f'       "{clsid}",')
            print('   )')
            print('   $clsids | ForEach-Object {')
            print('       $p = "HKLM:\\SOFTWARE\\Classes\\CLSID\\$_\\InprocServer32"')
            print('       $r = Get-ItemProperty $p -EA SilentlyContinue')
            print('       [pscustomobject]@{ CLSID=$_; DLL=$r."(default)"; HKCU=(Test-Path "HKCU:\\Software\\Classes\\CLSID\\$_") }')
            print('   } | Format-Table -AutoSize')

    # ── Summary ───────────────────────────────────────────────────────────────
    print(f'\n[*] COM handler tasks: {len(com_rows)}')
    print(f'[*] Exec tasks:        {len(exec_rows)}')
    print(f'[*] Startup items:     {len(startup_rows)}')
    print('[*] No RPC pipes — C$ share access only.')

    smb.close()


if __name__ == '__main__':
    main()
