#!/usr/bin/env python3
"""Read-only JSONL collector. Durable offsets, rotation and partial-line handling."""
import argparse,json,os,sys,time
from pathlib import Path
sys.path.insert(0,str(Path(__file__).resolve().parents[1]))
from soc import Store

def collect(path,source,store,checkpoint):
    path=Path(path);checkpoint=Path(checkpoint);stat=path.stat()
    state=json.loads(checkpoint.read_text()) if checkpoint.exists() else {}
    key=str(path.resolve());old=state.get(key,{})
    offset=old.get('offset',0) if old.get('inode')==stat.st_ino and old.get('device')==stat.st_dev and stat.st_size>=old.get('offset',0) else 0
    records=[]
    with path.open('rb') as f:
        f.seek(offset)
        for _ in range(10000):
            start=f.tell();line=f.readline()
            if not line or not line.endswith(b'\n'):f.seek(start);break
            if line.strip():records.append(json.loads(line))
            offset=f.tell()
    result=store.ingest(source,records) # Failure leaves the checkpoint unchanged; fix/quarantine the bad line explicitly.
    state[key]={'inode':stat.st_ino,'device':stat.st_dev,'offset':offset}
    checkpoint.parent.mkdir(parents=True,exist_ok=True);tmp=checkpoint.with_suffix('.tmp');tmp.write_text(json.dumps(state));os.chmod(tmp,0o600);tmp.replace(checkpoint)
    return result
if __name__=='__main__':
    p=argparse.ArgumentParser();p.add_argument('--source',required=True,choices=['wazuh','suricata','zeek']);p.add_argument('--file',required=True);p.add_argument('--db',required=True);p.add_argument('--checkpoint',required=True);p.add_argument('--follow',action='store_true');a=p.parse_args()
    s=Store(a.db)
    while True:
        try:print(json.dumps(collect(a.file,a.source,s,a.checkpoint)),flush=True)
        except (ValueError,OSError) as e:
            print(f'Collector unhealthy: {e}',file=sys.stderr,flush=True)
            if not a.follow:sys.exit(1)
        if not a.follow:break
        time.sleep(2)
