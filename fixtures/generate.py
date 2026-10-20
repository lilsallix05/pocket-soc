"""Deterministic synthetic 30-day observations, never live telemetry."""
from pathlib import Path
import datetime as dt,json
root=Path(__file__).parent
logs={x:[] for x in ['zeek','wazuh','suricata']}
for day in range(30):
    t=dt.datetime(2026,9,1,tzinfo=dt.timezone.utc)+dt.timedelta(days=day,hours=1)
    for suffix,dest,size in [('backup','198.51.100.10',5000000),('review','203.0.113.70',2400000),('benign','203.0.113.5',300)]:
        logs['zeek'].append({'ts':t.timestamp(),'uid':f'synthetic-{day}-{suffix}','id.orig_h':'10.20.0.12','id.resp_h':dest,'orig_bytes':size,'resp_bytes':100,'proto':'tcp','synthetic':True})
    logs['wazuh'].append({'timestamp':t.isoformat(),'agent':{'name':'synthetic-clinic-pc','ip':'10.20.0.12'},'rule':{'id':'100101','level':8,'description':'Synthetic repeated authentication failures'},'data':{'srcip':'10.20.0.12'},'synthetic':True})
    logs['suricata'].append({'timestamp':t.isoformat(),'event_type':'alert','src_ip':'10.20.0.12','dest_ip':'203.0.113.70','alert':{'signature_id':1000001,'signature':'POCKET SOC synthetic marker','severity':2},'synthetic':True})
for name,items in logs.items():(root/f'{name}.jsonl').write_text(''.join(json.dumps(x)+'\n' for x in items))
