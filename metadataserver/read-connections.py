#!/usr/bin/env python3
"""
read-connections.py - Summarize and search an m2tlog connection-inventory.csv file.

Author: Douglas Hunt (SAS domain expertise)
Developed with GitHub Copilot assistance
"""

import argparse,csv
from collections import Counter
from datetime import datetime
VERSION='1.1.0';UNKNOWN='<unknown>'
def dt(s):
 try:return datetime.strptime(s,'%Y-%m-%d %H:%M:%S,%f')
 except:return None
def main():
 p=argparse.ArgumentParser(description='Summarize and search an m2tlog connection-inventory.csv file.')
 p.add_argument('csvfile');p.add_argument('--top',type=int,default=10);p.add_argument('--user');p.add_argument('--app');p.add_argument('--auth');p.add_argument('--ip');p.add_argument('--connection-id');p.add_argument('--server-port');p.add_argument('--event',choices=['OPEN','CLOSE','REDIRECT']);p.add_argument('--status');p.add_argument('--show',type=int,default=0);p.add_argument('--raw',action='store_true');p.add_argument('--version',action='version',version=f'%(prog)s {VERSION}');a=p.parse_args()
 filters={'user':a.user,'appname':a.app,'auth_type':a.auth,'client_ip':a.ip,'connection_id':a.connection_id,'server_port':a.server_port,'event':a.event,'status':a.status}
 with open(a.csvfile,newline='',encoding='utf-8-sig') as f:
  rows=[r for r in csv.DictReader(f) if all(not v or v.lower() in r.get(k,'').lower() for k,v in filters.items())]
 def top(title,key):
  print(f'\n{title}\n'+('-'*len(title)));c=Counter(r.get(key) or UNKNOWN for r in rows)
  for value,count in c.most_common(a.top):print(f'{count:8d}  {value}')
 times=[dt(r.get('timestamp','')) for r in rows];times=[x for x in times if x]
 peaks=[]
 for r in rows:
  try:peaks.append((int(r.get('open_count',0)),r.get('timestamp','')))
  except:pass
 print(f'read-connections.py v{VERSION}\nFile                     : {a.csvfile}\nMatching records         : {len(rows)}')
 print(f'First timestamp          : {min(times) if times else UNKNOWN}\nLast timestamp           : {max(times) if times else UNKNOWN}')
 if peaks:
  peak=max(peaks);print(f'Max modeled open count   : {peak[0]} at {peak[1]}')
 ev=Counter(r.get('event') for r in rows);st=Counter(r.get('status') for r in rows)
 print(f'OPEN events              : {ev["OPEN"]}\nCLOSE events             : {ev["CLOSE"]}\nREDIRECT events          : {ev["REDIRECT"]}\nREJECTED records         : {st["REJECTED"]}')
 for title,key in [('Top Users','user'),('Top Applications','appname'),('Top Authentication Types','auth_type'),('Top Client IP Addresses','client_ip'),('Top Server Ports','server_port'),('Top Encryption Algorithms','encryption_algorithm')]:top(title,key)
 if a.show:
  print(f'\nMatching Records (up to {a.show})\n'+'-'*34)
  for r in rows[:a.show]:
   print(f"{r['timestamp']} {r['event']:8} {r['status']:9} open={r['open_count']:>5} conn={r['connection_id']} user={r['user']} auth={r['auth_type']} peer={r['client_ip']}:{r['client_port']} server={r['server_port']} app={r['appname']} enc={r['encryption_level']}/{r['encryption_algorithm']}")
   if a.raw:print('  '+r.get('raw_line',''))
 return 0
if __name__=='__main__':raise SystemExit(main())
