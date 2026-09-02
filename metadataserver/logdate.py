#!/usr/bin/env python3
"""
logdate.py - Reads metadata logs and determines BEGIN|END date and important markers as to status.

Author: Douglas Hunt (SAS domain expertise)
Developed with GitHub Copilot assistance
"""

import argparse
import os
import re
import csv
import html
import time
from datetime import datetime
from collections import defaultdict, deque, Counter

VERSION = '5.9.1'
LETTERS = 'abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789'
RESERVED = 14
TS = re.compile(r'(\d{4}-\d\d-\d\dT\d\d:\d\d:\d\d,\d{3})')
TID = re.compile(r'\[(\d+)\]')
METH = re.compile(r'OMI::([A-Za-z_]\w*)')
CAP = re.compile(r'reporting\s+cookie\s+jar\s+at\s+capacity\s+with\s+(\d+)\s+cookies', re.I)
GET = re.compile(r'GetCookie:\s*Task\s+CONTEXT\s+([0-9A-F]+)\s+getting\s+cookie\s+number\s+(\d+)', re.I)
PUT = re.compile(r'PutCookie:\s*Task\s+CONTEXT\s+([0-9A-F]+)\s+returning\s+cookie\s+number\s+(\d+)', re.I)
SAH = re.compile(r'\bSAH\s+Running\b', re.I)
SEP = '=' * 110
SUB = '-' * 110

def timestamp(s):
    m = TS.search(s)
    return datetime.strptime(m.group(1), '%Y-%m-%dT%H:%M:%S,%f') if m else None

def thread(s):
    m = TID.search(s)
    return m.group(1) if m else None

def method(s):
    m = METH.search(html.unescape(s))
    return m.group(1) if m else '?'

def short(t):
    return t.strftime('%H:%M:%S,%f')[:-3]

def full(t):
    return t.strftime('%Y-%m-%d %H:%M:%S,%f')[:-3]

def identity(s):
    m = re.search(r'\]\s+([^:\s]+):(\S+)\s+-\s+IOM CALL', s)
    if m:
        return m.group(1), m.group(2)
    m = re.search(r'\]\s*:(\S+)\s+-\s+IOM CALL', s)
    return (None, m.group(1)) if m else (None, None)

def median(v):
    v = sorted(v)
    n = len(v)
    return 0 if not n else v[n // 2] if n % 2 else (v[n // 2 - 1] + v[n // 2]) / 2

def percentile(v, p):
    v = sorted(v)
    return 0 if not v else v[min(len(v) - 1, max(0, (len(v) * p + 99) // 100 - 1))]

def lane_info(path, cpu):
    cap = None
    nums = set()
    evidence = None
    with open(path, errors='ignore') as f:
        for line in f:
            m = GET.search(line)
            if m:
                nums.add(int(m.group(2)))
            m = CAP.search(line)
            if m:
                cap = int(m.group(1))
                evidence = line.rstrip()
            if SAH.search(line):
                break
    if cap is not None:
        if cap <= RESERVED:
            raise ValueError(f'cookie capacity {cap} is not greater than {RESERVED}')
        return {'mode': 'COOKIE', 'capacity': cap, 'reserved': RESERVED, 'lanes': cap - RESERVED, 'observed': max(nums) + 1 if nums else None, 'evidence': evidence}
    if cpu is None:
        raise ValueError("cookie capacity not found before SAH Running; rerun with -cpu N")
    return {'mode': 'SYNTHETIC', 'capacity': None, 'reserved': 0, 'lanes': cpu, 'observed': None, 'evidence': None}

def parse(path, args):
    stacks = defaultdict(list)
    timeline = []
    events = []
    cycles = []
    gaps = []
    open_cycles = defaultdict(deque)
    seq = 0
    continuation = None
    first = last = None
    unmatched = 0
    previous_ts = None
    previous_line = None
    timestamped_lines = 0
    minor_ooo = 0
    significant_ooo = 0
    size = os.path.getsize(path)
    read = 0
    begun = time.time()
    progress = begun
    with open(path, errors='ignore') as f:
        for n, line in enumerate(f, 1):
            read += len(line.encode(errors='ignore'))
            now = time.time()
            if now - progress > .5:
                rate = read / (now - begun)
                eta = (size - read) / rate if rate else 0
                print(f'\r[PROGRESS] {n:,} lines | {100 * read / size:5.1f}% | ETA {time.strftime("%H:%M:%S", time.gmtime(max(0, eta)))}', end='', flush=True)
                progress = now
            when = timestamp(line)
            tid = thread(line)
            stripped = line.rstrip()
            if when:
                timestamped_lines += 1
                first = first or when
                last = when
                if previous_ts is not None:
                    delta = (when - previous_ts).total_seconds()
                    if delta > args.gap_threshold:
                        gaps.append({'start': previous_ts, 'end': when, 'duration': delta, 'start_line': previous_line, 'end_line': n})
                    elif delta < 0:
                        if delta < -1.0:
                            significant_ooo += 1
                        else:
                            minor_ooo += 1
                previous_ts = when
                previous_line = n
            if 'IOM CALL' in line and tid and when:
                proc, user = identity(line)
                call = {'tid': tid, 'method': method(line), 'start': when, 'depth': len(stacks[tid]) + 1, 'process': proc, 'user': user, 'line': stripped, 'cookie': None, 'ctx': None, 'get': None, 'put': None, 'cycle': None, 'context': []}
                stacks[tid].append(call)
                timeline.append({'ts': when, 'seq': seq, 'kind': 'CALL', 'call': call})
                seq += 1
                continuation = tid
                continue
            m = GET.search(line)
            if m and when:
                ctx, cookie = m.group(1).upper(), int(m.group(2))
                cycle = {'ctx': ctx, 'cookie': cookie, 'get': when, 'put': None, 'hold': None, 'wait': None, 'tid': tid, 'method': None, 'user': None}
                cycles.append(cycle)
                open_cycles[(ctx, cookie)].append(cycle)
                if tid and stacks[tid]:
                    call = stacks[tid][-1]
                    call.update(cookie=cookie, ctx=ctx, get=when, cycle=cycle)
                    cycle.update(wait=max(0, (when - call['start']).total_seconds()), method=call['method'], user=call['user'])
                    call['context'].append(stripped)
                continue
            m = PUT.search(line)
            if m and when:
                ctx, cookie = m.group(1).upper(), int(m.group(2))
                q = open_cycles[(ctx, cookie)]
                if q:
                    cycle = q.popleft()
                    cycle['put'] = when
                    cycle['hold'] = max(0, (when - cycle['get']).total_seconds())
                    for stack in stacks.values():
                        for call in reversed(stack):
                            if call.get('cycle') is cycle:
                                call['put'] = when
                                break
                continue
            if 'IOM RETURN' in line and tid and when:
                meth = method(line)
                stack = stacks[tid]
                idx = next((i for i in range(len(stack) - 1, -1, -1) if stack[i]['method'] == meth), None)
                if idx is None:
                    timeline.append({'ts': when, 'seq': seq, 'kind': 'BAD', 'tid': tid, 'method': meth})
                    seq += 1
                    unmatched += 1
                    continue
                call = stack.pop(idx)
                ev = {**call, 'end': when, 'dur': max(0, (when - call['start']).total_seconds()), 'missing': False, 'ooo': idx != len(stack)}
                events.append(ev)
                timeline.append({'ts': when, 'seq': seq, 'kind': 'RETURN', 'event': ev})
                seq += 1
                if not stack:
                    continuation = None
                continue
            if timestamp(line) is None and thread(line) is None and continuation and stacks[continuation] and len(stacks[continuation][-1]['context']) < args.context_lines:
                stacks[continuation][-1]['context'].append(stripped)
            elif when:
                continuation = None
    print()
    eof = last or datetime.now()
    for stack in stacks.values():
        for call in stack:
            ev = {**call, 'end': eof, 'dur': max(0, (eof - call['start']).total_seconds()), 'missing': True, 'ooo': False}
            events.append(ev)
            timeline.append({'ts': eof, 'seq': seq, 'kind': 'EOF', 'event': ev})
            seq += 1
    timeline.sort(key=lambda x: (x['ts'], x['seq']))
    gap_info = {'gaps': gaps, 'timestamped_lines': timestamped_lines, 'minor_ooo': minor_ooo, 'significant_ooo': significant_ooo}
    return events, timeline, cycles, first, last, unmatched, time.time() - begun, gap_info

def assign(events, timeline, info):
    fallback = {}
    nxt = 0

    def pick(tid, cookie):
        nonlocal nxt
        if info['mode'] == 'COOKIE' and cookie is not None and info['reserved'] <= cookie < info['capacity']:
            return cookie - info['reserved']
        if tid not in fallback:
            fallback[tid] = nxt % info['lanes']
            nxt += 1
        return fallback[tid]

    for e in events:
        e['lane'] = pick(e['tid'], e['cookie'])
    for x in timeline:
        x['lane'] = x['event']['lane'] if x['kind'] in ('RETURN', 'EOF') else pick(x['call']['tid'], x['call']['cookie']) if x['kind'] == 'CALL' else pick(x['tid'], None)

def marker(i, info):
    return LETTERS[(i + info['reserved']) % len(LETTERS)]

def timing(e):
    wait = max(0, (e['get'] - e['start']).total_seconds()) if e.get('get') else None
    hold = max(0, (e['put'] - e['get']).total_seconds()) if e.get('get') and e.get('put') else None
    eff = (100 * hold / e['dur']) if hold is not None and e['dur'] > 0 else (100.0 if hold == 0 and e['dur'] == 0 else None)
    return wait, hold, eff

def render(out, timeline, info, gap_info):
    active = [0] * info['lanes']

    def picture():
        a = ['_'] * info['lanes']
        for i, n in enumerate(active):
            if n:
                a[i] = marker(i, info)
        return ''.join(a)

    out.write(f"Lane Mode: {info['mode']} | Visible worker lanes: {info['lanes']}\nTiming: dur=CALL-to-RETURN wait=CALL-to-GetCookie hold=GetCookie-to-PutCookie eff=hold/dur\nGap markers: silence between adjacent timestamped log lines > {gap_info['threshold']:.3f} sec\nTHREAD        SWIM LANE             TIME          EVENT\n")
    gaps = iter(sorted(gap_info['gaps'], key=lambda g: g['end']))
    pending = next(gaps, None)
    for x in timeline:
        while pending is not None and pending['end'] <= x['ts']:
            active_events = [e for e in gap_info['events'] if e['start'] <= pending['start'] and e['end'] >= pending['end']]
            active_cookies = sorted({e.get('cookie') for e in active_events if e.get('cookie') is not None})
            cookies = ','.join(str(c) for c in active_cookies) if active_cookies else 'none'
            out.write(f"[GAP]       {picture()} {short(pending['end'])} *** LOG GAP {pending['duration']:.3f}s {short(pending['start'])}->{short(pending['end'])} active={len(active_events)} cookies={cookies} ***\n")
            pending = next(gaps, None)
        lane = x['lane']
        kind = x['kind']
        if kind == 'CALL':
            c = x['call']
            active[lane] += 1
            depth = f" depth={c['depth']}" if c['depth'] > 1 else ''
            cookie = f" cookie={c['cookie']}" if c['cookie'] is not None else ''
            out.write(f"[{c['tid']}] {picture()} {short(x['ts'])} {'  ' * (c['depth'] - 1)}+ CALL {c['method']}{depth}{cookie}\n")
        elif kind == 'RETURN':
            e = x['event']
            active[lane] = max(0, active[lane] - 1)
            wait, hold, eff = timing(e)
            depth = f" depth={e['depth']}" if e['depth'] > 1 else ''
            cookie = f" cookie={e['cookie']}" if e['cookie'] is not None else ' cookie=unknown'
            out.write(f"[{e['tid']}] {picture()} {short(x['ts'])} {'  ' * (e['depth'] - 1)}- RETURN {e['method']}{depth}{cookie} dur={e['dur']:.3f} wait={wait:.3f} hold={hold:.3f} eff={eff:.1f}%\n" if None not in (wait, hold, eff) else f"[{e['tid']}] {picture()} {short(x['ts'])} {'  ' * (e['depth'] - 1)}- RETURN {e['method']}{depth}{cookie} dur={e['dur']:.3f} wait={'unknown' if wait is None else f'{wait:.3f}'} hold={'unknown' if hold is None else f'{hold:.3f}'} eff={'unknown' if eff is None else f'{eff:.1f}%'}\n")
        elif kind == 'EOF':
            e = x['event']
            wait, hold, eff = timing(e)
            cookie = f" cookie={e['cookie']}" if e['cookie'] is not None else ' cookie=unknown'
            out.write(f"[{e['tid']}] {picture()} {short(x['ts'])} ! EOF OPEN {e['method']}{cookie} open={e['dur']:.3f} wait={'unknown' if wait is None else f'{wait:.3f}'} hold={'unknown' if hold is None else f'{hold:.3f}'} eff={'unknown' if eff is None else f'{eff:.1f}%'} [OPEN AT EOF]\n")
        else:
            out.write(f"[{x['tid']}] {picture()} {short(x['ts'])} ? RETURN {x['method']} [NO MATCHING CALL]\n")

def write_report_information(out, source, destination, events, cycles, info, unmatched, elapsed):
    completed = sum(not e['missing'] for e in events)
    open_eof = sum(e['missing'] for e in events)
    worker = [c for c in cycles if info['mode'] != 'COOKIE' or info['reserved'] <= c['cookie'] < info['capacity']]
    returned = sum(c['put'] is not None for c in worker)
    outstanding = len(worker) - returned
    out.write(f"{SEP}\nREPORT INFORMATION\n{SEP}\n")
    out.write(f"Tool Version           : m2tools v{VERSION}\n")
    out.write(f"Input Log              : {source}\n")
    out.write(f"Output File            : {destination}\n")
    out.write(f"Generated              : {full(datetime.now())}\n")
    out.write(f"Lane Mode              : {info['mode']}\n")
    if info['mode'] == 'COOKIE':
        out.write(f"Cookie Capacity        : {info['capacity']}\n")
        out.write(f"Reserved Cookie Slots  : {info['reserved']}\n")
    out.write(f"Visible Worker Lanes   : {info['lanes']}\n")
    out.write(f"Calls Found            : {len(events)}\n")
    out.write(f"Completed Calls        : {completed}\n")
    out.write(f"Open At EOF            : {open_eof}\n")
    out.write(f"Unmatched Returns      : {unmatched}\n")
    out.write(f"Worker GetCookie Count : {len(worker)}\n")
    out.write(f"Matched PutCookie Count: {returned}\n")
    out.write(f"Outstanding Cookies    : {outstanding}\n")
    if worker:
        out.write(f"Cookie Return Rate     : {100.0 * returned / len(worker):.2f}%\n")
    out.write(f"Processing Time        : {elapsed:.3f} sec\n")
    out.write("\n")

def connection_csv_path(path):
    root, ext = os.path.splitext(path)
    return root + '.connection-inventory.csv' if ext.lower() == '.log' else path + '.connection-inventory.csv'

def connection_value(pattern, line, default='<unknown>'):
    m = pattern.search(line)
    return m.group(1).strip() if m else default

def parse_connections(path, csv_path):
    conn_re = re.compile(r'New client connection\s*\(([^)]+)\)', re.I)
    accepted_re = re.compile(r'New client connection.*?\baccepted\b', re.I)
    rejected_re = re.compile(r'New client connection.*?\brejected\b', re.I)
    close_re = re.compile(r'Client connection\s*\(([^)]+)\).*?\bclosed\b|Client connection\s+([^\s]+).*?\bclosed\b', re.I)
    user_re = re.compile(r'\bfor\s+(.+?)\s+user\s+(.+?)(?=\.\s{2,}|\.\s+Encryption|$)', re.I)
    peer_re = re.compile(r'Peer IP address and port are\s+\[(?:[0-9a-f]+:)*([0-9.]+)\]:(\d+)', re.I)
    peer6_re = re.compile(r'Peer IP address and port are\s+\[([^\]]+)\]:(\d+)', re.I)
    server_port_re = re.compile(r'from server port\s+(\d+)', re.I)
    app_re = re.compile(r'\bAPPNAME\s*=\s*(.+?)(?:\.\s*$|$)', re.I)
    enc_re = re.compile(r'Encryption level is\s+(.+?)\s+using encryption algorithm\s+([^\s.]+)', re.I)
    fields = ['sequence', 'event', 'status', 'timestamp', 'line_number', 'thread', 'connection_id', 'user', 'auth_type', 'client_ip', 'client_port', 'server_port', 'appname', 'encryption_level', 'encryption_algorithm', 'open_count', 'raw_line']
    info = {'records': 0, 'opened': 0, 'accepted': 0, 'rejected': 0, 'closed': 0, 'redirects': 0, 'current': 0, 'peak': 0, 'peak_time': None, 'apps': Counter(), 'auth': Counter(), 'users': Counter(), 'ips': Counter(), 'server_ports': Counter(), 'encryption': Counter(), 'hourly': defaultdict(lambda: {'opened': 0, 'closed': 0, 'rejected': 0}), 'csv_path': csv_path}
    with open(csv_path, 'w', newline='', encoding='utf-8') as cf:
        writer = csv.DictWriter(cf, fieldnames=fields)
        writer.writeheader()
        seq = 0
        with open(path, errors='ignore') as f:
            for lineno, line in enumerate(f, 1):
                low = line.lower()
                when = timestamp(line)
                hour = when.strftime('%Y-%m-%dT%H') if when else '<unknown>'
                is_open = 'new client connection' in low
                is_close = 'client connection' in low and 'closed' in low
                is_redirect = 'redirect client in cluster' in low
                if not (is_open or is_close or is_redirect):
                    continue
                status = 'REDIRECTED'
                event = 'REDIRECT'
                cid = '<unknown>'
                if is_open:
                    event = 'OPEN'
                    cid = connection_value(conn_re, line)
                    rejected = bool(rejected_re.search(line))
                    accepted = bool(accepted_re.search(line))
                    status = 'REJECTED' if rejected else ('ACCEPTED' if accepted else 'OBSERVED')
                    info['opened'] += 1
                    info['hourly'][hour]['opened'] += 1
                    if rejected:
                        info['rejected'] += 1
                        info['hourly'][hour]['rejected'] += 1
                    else:
                        if accepted:
                            info['accepted'] += 1
                        info['current'] += 1
                        if info['current'] > info['peak']:
                            info['peak'] = info['current']
                            info['peak_time'] = when
                elif is_close:
                    event = 'CLOSE'
                    status = 'CLOSED'
                    m = close_re.search(line)
                    cid = (m.group(1) or m.group(2)) if m else '<unknown>'
                    info['closed'] += 1
                    info['hourly'][hour]['closed'] += 1
                    info['current'] = max(0, info['current'] - 1)
                else:
                    info['redirects'] += 1
                m = user_re.search(line)
                auth = m.group(1).strip().replace(' ', '_').upper() if m else '<unknown>'
                user = m.group(2) if m else '<unknown>'
                m = peer_re.search(line)
                if m:
                    client_ip, client_port = m.group(1), m.group(2)
                else:
                    m = peer6_re.search(line)
                    client_ip, client_port = (m.group(1), m.group(2)) if m else ('<unknown>', '<unknown>')
                    if client_ip.lower().startswith('::ffff:'):
                        client_ip = client_ip[7:]
                m = enc_re.search(line)
                enc_level, enc_alg = (m.group(1).strip(), m.group(2)) if m else ('<unknown>', '<unknown>')
                app = connection_value(app_re, line)
                seq += 1
                record = {'sequence': seq, 'event': event, 'status': status, 'timestamp': full(when) if when else '', 'line_number': lineno, 'thread': thread(line) or '<unknown>', 'connection_id': cid, 'user': user, 'auth_type': auth, 'client_ip': client_ip, 'client_port': client_port, 'server_port': connection_value(server_port_re, line), 'appname': app, 'encryption_level': enc_level, 'encryption_algorithm': enc_alg, 'open_count': info['current'], 'raw_line': line.rstrip()}
                writer.writerow(record)
                info['records'] += 1
                if is_open:
                    info['apps'][app] += 1
                    info['auth'][auth] += 1
                    info['users'][user] += 1
                    info['ips'][client_ip] += 1
                    info['server_ports'][record['server_port']] += 1
                    info['encryption'][f'{enc_level} / {enc_alg}'] += 1
    return info

def write_top(out, title, counter, topn):
    out.write(f"\n{title}\n{SUB}\n")
    if not counter:
        out.write('No values were found.\n')
        return
    for value, count in counter.most_common(topn):
        out.write(f'{count:8d}  {value}\n')

def write_connection_summary(out, c, args):
    if args.no_connections:
        return
    out.write(f"\n{SEP}\nCONNECTION SUMMARY\n{SEP}\n")
    out.write("Connection analysis and CSV inventory are enabled by default. Use --no-connections to suppress both.\n")
    out.write("Concurrent counts are modeled only from open/close records visible in this log.\n\n")
    out.write(f"New client connection records : {c['opened']}\nExplicitly accepted           : {c['accepted']}\nRejected                      : {c['rejected']}\nClient connection closes      : {c['closed']}\nCluster redirects             : {c['redirects']}\n")
    out.write(f"Modeled peak concurrent       : {c['peak']}\nPeak time                     : {full(c['peak_time']) if c['peak_time'] else '<not observed>'}\nModeled open at EOF           : {c['current']}\nOpen/close balance            : {c['opened'] - c['rejected'] - c['closed']:+d}\n")
    out.write(f"Connection inventory CSV      : {c['csv_path']}\nCSV records written           : {c['records']}\n")
    out.write(f"\nCONNECTION BUILDUP ANALYSIS\n{SUB}\n")
    rows = [(h, v) for h, v in sorted(c['hourly'].items()) if h != '<unknown>']
    if rows:
        out.write(f"{'HOUR':13} {'OPENED':>8} {'CLOSED':>8} {'REJECTED':>10} {'DELTA':>8}\n")
        for h, v in rows:
            out.write(f"{h:13} {v['opened']:8d} {v['closed']:8d} {v['rejected']:10d} {v['opened'] - v['rejected'] - v['closed']:+8d}\n")
    else:
        out.write('No timestamped connection activity was found.\n')
    write_top(out, 'CLIENT APPLICATIONS', c['apps'], args.top)
    write_top(out, 'AUTHENTICATION METHODS', c['auth'], args.top)
    write_top(out, 'TOP USERS', c['users'], args.top)
    write_top(out, 'TOP CLIENT IP ADDRESSES', c['ips'], args.top)
    write_top(out, 'SERVER PORT USAGE', c['server_ports'], args.top)
    write_top(out, 'ENCRYPTION USAGE', c['encryption'], args.top)

def write_log_gap_analysis(out, events, gap_info, args):
    gaps = gap_info['gaps']
    durations = [g['duration'] for g in gaps]
    out.write(f"\n{SEP}\nLOG GAP ANALYSIS\n{SEP}\n")
    out.write("A gap is silence between adjacent timestamped log lines.\n")
    out.write("Active requests are calls that began on or before the last line before the gap and did not return until the first line after the gap or later.\n")
    out.write("A gap is observational evidence of log silence; by itself it does not prove a server hang.\n\n")
    out.write(f"Gap threshold              : > {args.gap_threshold:.3f} sec\n")
    out.write(f"Timestamped lines          : {gap_info['timestamped_lines']}\n")
    out.write(f"Threshold-exceeding gaps   : {len(gaps)}\n")
    out.write(f"Significant out of order   : {gap_info['significant_ooo']} (< -1.000 sec)\n")
    out.write(f"Minor out of order         : {gap_info['minor_ooo']} (-1.000 to < 0 sec)\n")
    if durations:
        out.write(f"Average reported gap       : {sum(durations) / len(durations):.3f} sec\n")
        out.write(f"Median reported gap        : {median(durations):.3f} sec\n")
        out.write(f"95th percentile            : {percentile(durations, 95):.3f} sec\n")
        out.write(f"Maximum reported gap       : {max(durations):.3f} sec\n")
    else:
        out.write("No gaps exceeded the configured threshold.\n")

    out.write(f"\nTop {args.top} Log Gaps and Requests Active During Silence\n{SUB}\n")
    if not gaps:
        out.write("No threshold-exceeding gaps were found.\n")
        return
    for number, g in enumerate(sorted(gaps, key=lambda x: x['duration'], reverse=True)[:args.top], 1):
        active = [e for e in events if e['start'] <= g['start'] and e['end'] >= g['end']]
        out.write(f"\n[{number}] {g['duration']:.3f} sec  {full(g['start'])} -> {full(g['end'])}\n")
        out.write(f"    Log lines              : {g['start_line']} -> {g['end_line']}\n")
        out.write(f"    Active request count   : {len(active)}\n")
        if active:
            out.write(f"    {'THREAD':10} {'COOKIE':>8} {'METHOD':32} {'START':23} USER\n")
            for e in sorted(active, key=lambda x: x['start']):
                cookie = str(e.get('cookie') if e.get('cookie') is not None else 'unknown')
                user = e.get('user') or '<unknown>'
                out.write(f"    {e['tid']:10} {cookie:>8} {e['method'][:32]:32} {full(e['start']):23} {user}\n")
        else:
            out.write("    No parsed IOM request remained active across the complete gap.\n")

def write_authentication_summary(out, events, args):
    auth = [e for e in events if e.get('method') == 'InternalAuthentication']
    completed = [e for e in auth if not e.get('missing')]
    open_eof = [e for e in auth if e.get('missing')]
    durations = [e['dur'] for e in completed]
    warnings = [e for e in completed if e['dur'] > args.auth_threshold]

    out.write(f"\n{SEP}\nAUTHENTICATION SUMMARY\n{SEP}\n")
    out.write("Authentication duration is measured from IOM CALL InternalAuthentication to its matching IOM RETURN.\n")
    out.write("Only completed calls are included in duration statistics and threshold counts.\n\n")
    out.write(f"InternalAuthentication calls : {len(auth)}\n")
    out.write(f"Completed timing observations: {len(completed)}\n")
    out.write(f"Open at EOF                 : {len(open_eof)}\n")
    out.write(f"Warning threshold           : > {args.auth_threshold:.3f} sec\n")
    out.write(f"Threshold warnings          : {len(warnings)}\n")

    out.write(f"\nAuthentication Duration Statistics\n{SUB}\n")
    if durations:
        out.write(f"Average authentication time : {sum(durations) / len(durations):.3f} sec\n")
        out.write(f"Median authentication time  : {median(durations):.3f} sec\n")
        out.write(f"95th percentile             : {percentile(durations, 95):.3f} sec\n")
        out.write(f"Maximum authentication time : {max(durations):.3f} sec\n")
    else:
        out.write("No completed InternalAuthentication observations.\n")

    out.write(f"\nTop {args.top} Slowest InternalAuthentication Calls\n{SUB}\n")
    if completed:
        out.write(f"{'DURATION':>10}  {'START':23}  {'THREAD':10}  {'COOKIE':>8}  USER\n")
        for e in sorted(completed, key=lambda x: x['dur'], reverse=True)[:args.top]:
            cookie = str(e.get('cookie') if e.get('cookie') is not None else 'unknown')
            user = e.get('user') or '<unknown>'
            warning = ' [AUTH WARNING]' if e['dur'] > args.auth_threshold else ''
            out.write(f"{e['dur']:10.3f}  {full(e['start']):23}  {e['tid']:10}  {cookie:>8}  {user}{warning}\n")
    else:
        out.write("No completed InternalAuthentication calls were found.\n")

def report(out, events, cycles, info, unmatched, args):
    worker = [c for c in cycles if info['mode'] != 'COOKIE' or info['reserved'] <= c['cookie'] < info['capacity']]
    done = [c for c in worker if c['put']]
    leaked = [c for c in worker if not c['put']]
    waits = [c['wait'] for c in worker if c['wait'] is not None]
    holds = [c['hold'] for c in done if c['hold'] is not None]
    effs = []
    for e in events:
        wait, hold, eff = timing(e)
        if eff is not None:
            effs.append(eff)

    out.write(f"\n{SEP}\nCOOKIE TIMING SUMMARY\n{SEP}\n")
    out.write("wait measures CALL-to-GetCookie and indicates worker-slot contention.\n")
    out.write("hold measures GetCookie-to-PutCookie and indicates worker processing cost.\n")
    out.write("efficiency is hold divided by total IOM CALL-to-RETURN duration.\n\n")
    out.write(f"Worker GetCookie count  : {len(worker)}\n")
    out.write(f"Matched PutCookie count : {len(done)}\n")
    out.write(f"Outstanding lifecycles  : {len(leaked)}\n")
    if worker:
        out.write(f"Cookie return rate      : {100.0 * len(done) / len(worker):.2f}%\n")

    for name, values in [('Wait', waits), ('Hold', holds)]:
        out.write(f"\n{name} Time Statistics\n{SUB}\n")
        if values:
            out.write(f"Average {name.lower()} time       : {sum(values) / len(values):.3f} sec\n")
            out.write(f"Median {name.lower()} time        : {median(values):.3f} sec\n")
            out.write(f"95th percentile         : {percentile(values, 95):.3f} sec\n")
            out.write(f"Maximum {name.lower()} time       : {max(values):.3f} sec\n")
        else:
            out.write("No complete observations.\n")

    out.write(f"\nEfficiency Statistics (hold / total IOM duration)\n{SUB}\n")
    if effs:
        out.write(f"Average efficiency      : {sum(effs) / len(effs):.1f}%\n")
        out.write(f"Median efficiency       : {median(effs):.1f}%\n")
        out.write(f"Low efficiency (<50%)   : {sum(x < 50 for x in effs)}\n")
        out.write(f"Very low (<25%)         : {sum(x < 25 for x in effs)}\n")
    else:
        out.write("No complete observations.\n")

    out.write(f"\n{SEP}\nPOTENTIALLY LEAKED WORKER COOKIES\n{SEP}\n")
    out.write("Definition\n----------\n")
    out.write("These worker cookies have a GetCookie record but no matching PutCookie in this captured log.\n")
    out.write("This does NOT prove a leak. The matching PutCookie can be after this file or in another log.\n\n")
    out.write(f"Outstanding worker cookies: {len(leaked)}\n")
    if leaked:
        out.write(f"\n{'COOKIE':>6}  {'CONTEXT':10}  {'THREAD':10}  {'GETCOOKIE':23}  METHOD\n{SUB}\n")
        for c in sorted(leaked, key=lambda x: x['get']):
            out.write(f"{c['cookie']:6}  {c['ctx']:10}  {(c['tid'] or '<unknown>'):10}  {full(c['get']):23}  {c['method'] or '<unknown>'}\n")
    else:
        out.write("No potentially leaked worker cookies were found.\n")

    missing = sorted((e for e in events if e['missing']), key=lambda e: e['dur'], reverse=True)
    leaked_keys = {(c['ctx'], c['cookie']) for c in leaked}
    out.write(f"\n{SEP}\nMISSING IOM RETURNS\n{SEP}\n")
    out.write("Definition\n----------\n")
    out.write("No matching IOM RETURN was found before the captured log ended.\n")
    out.write("This does NOT prove the request was hung or that its worker cookie leaked.\n")
    out.write("A matching IOM RETURN or PutCookie can occur after this file or in a subsequent log.\n\n")
    out.write(f"Open At EOF                  : {len(missing)}\n")
    out.write(f"Unmatched return records     : {unmatched}\n")
    out.write(f"Potentially leaked cookies   : {sum((e.get('ctx'), e.get('cookie')) in leaked_keys for e in missing)}\n")

    out.write(f"\nSUMMARY OF OPEN REQUESTS\n{SUB}\n")
    if missing:
        out.write(f"{'THREAD':10} {'COOKIE':>8} {'METHOD':32} {'OPEN SEC':>12} {'WAIT SEC':>12} {'HOLD SEC':>12}\n")
        for e in missing:
            wait, hold, eff = timing(e)
            out.write(f"{e['tid']:10} {str(e.get('cookie') if e.get('cookie') is not None else 'unknown'):>8} {e['method'][:32]:32} {e['dur']:12.3f} {('unknown' if wait is None else f'{wait:.3f}'):>12} {('unknown' if hold is None else f'{hold:.3f}'):>12}\n")
    else:
        out.write("No requests were open at EOF.\n")

    for number, e in enumerate(missing, 1):
        wait, hold, eff = timing(e)
        put = e.get('put')
        potentially_leaked = (e.get('ctx'), e.get('cookie')) in leaked_keys
        out.write(f"\n{SEP}\n[{number}] THREAD {e['tid']}\n{SEP}\n")
        out.write("Request\n-------\n")
        out.write(f"Method              : {e['method']}\n")
        out.write(f"Nested depth        : {e['depth']}\n")
        out.write(f"User                : {e.get('user') or '<unknown>'}\n")
        out.write(f"Process             : {e.get('process') or '<unknown>'}\n")

        out.write("\nCookie Lifecycle\n----------------\n")
        out.write(f"Cookie Number       : {e.get('cookie') if e.get('cookie') is not None else '<unknown>'}\n")
        out.write(f"Context             : {e.get('ctx') or '<unknown>'}\n")
        out.write(f"GetCookie           : {full(e['get']) if e.get('get') else 'not found'}\n")
        out.write(f"PutCookie           : {full(put) if put else 'not found'}\n")
        out.write(f"Cookie Returned     : {'yes' if put else 'no'}\n")
        out.write(f"Cookie Wait Time    : {'unknown' if wait is None else f'{wait:.3f} sec'}\n")
        out.write(f"Cookie Hold Time    : {'unknown' if hold is None else f'{hold:.3f} sec'}\n")
        out.write(f"Efficiency          : {'unknown' if eff is None else f'{eff:.1f}%'}\n")

        out.write("\nRequest State\n-------------\n")
        out.write("Open At EOF         : yes\n")
        out.write(f"Start               : {full(e['start'])}\n")
        out.write(f"Log End             : {full(e['end'])}\n")
        out.write(f"Open Duration       : {e['dur']:.3f} sec\n")
        out.write(f"Potentially Cookie Leak: {'yes, within this captured log' if potentially_leaked else 'no'}\n")

        out.write("\nAssessment\n----------\n")
        out.write("The request remained open when the captured log ended. No matching IOM RETURN was found.\n")
        if put:
            out.write("A matching PutCookie was found, so the worker cookie was returned within this captured log.\n")
        elif e.get('cookie') is not None:
            out.write("No matching PutCookie was found, so the worker-cookie lifecycle is unresolved in this captured log.\n")
            out.write("This does NOT prove a leak; inspect later or adjacent Metadata Server logs for the matching PutCookie.\n")
        else:
            out.write("No worker-cookie association was found for this request.\n")

        fields = e.get('fields') or {}
        if fields:
            out.write("\nParsed Request Details\n----------------------\n")
            if fields.get('type'):
                out.write(f"Metadata Type       : {fields['type']}\n")
            if fields.get('id'):
                out.write(f"Metadata ID         : {fields['id']}\n")
            if fields.get('ns'):
                out.write(f"Namespace           : {fields['ns']}\n")
            if fields.get('flags'):
                out.write(f"Flags               : {fields['flags']}\n")
            if fields.get('search'):
                out.write(f"Search              : {fields['search']}\n")

        out.write("\nCall Line\n---------\n")
        out.write(e['line'] + "\n")
        out.write("\nRequest Context\n---------------\n")
        if e.get('context'):
            for i, line in enumerate(e['context'], 1):
                out.write(f"[{i:02d}] {line}\n")
        else:
            out.write("<no request-context lines captured>\n")
