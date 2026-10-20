"""Pocket SOC: local evidence, triage and notification preparation. No outbound sends."""
import argparse, datetime as dt, hashlib, ipaddress, json, os, secrets, sqlite3, statistics, time, uuid
from contextlib import contextmanager
from pathlib import Path
UTC=dt.timezone.utc
ROOT=Path(__file__).resolve().parent
GUIDANCE='https://www.pdp.gov.my/ppdpv1/wp-content/uploads/2025/08/GP_DBN_ENG.pdf'
DEFAULT_POLICY={'zeek_bytes':1000000,'wazuh_level':7,'suricata_severity':2,'allow_destinations':[]}
HARM=['physical_financial','illegal','sensitive','identity']
LOCAL_NETS=tuple(ipaddress.ip_network(x) for x in ['10.0.0.0/8','172.16.0.0/12','192.168.0.0/16','127.0.0.0/8','169.254.0.0/16','::1/128','fc00::/7','fe80::/10'])
FIELDS={'data_types':'7.4.1.2','nature':'7.4.1.2','identification':'7.4.1.3','cause':'7.4.1.3','records':'7.4.1.5','systems':'7.4.1.6','consequences':'7.4.2 / 10.2.2','chronology':'7.4.3','containment':'7.4.4 / 10.2.3','subject_measures':'7.4.5 / 10.2.4','contact':'7.4.6 / 10.2.5','delay_reason':'7.7'}
def now():return dt.datetime.now(UTC).isoformat()
def stamp(value):
    if not value:raise ValueError('A timestamp with timezone is required')
    try:d=dt.datetime.fromisoformat(str(value).replace('Z','+00:00'))
    except (ValueError,TypeError):raise ValueError('Use an ISO timestamp with timezone')
    if d.tzinfo is None:raise ValueError('Timestamp must include a timezone, such as +08:00')
    return d.astimezone(UTC)
def digest(value):return hashlib.sha256(json.dumps(value,sort_keys=True,separators=(',',':')).encode()).hexdigest()
def textfield(v,name,required=False):
    if not isinstance(v,str) or len(v)>12000 or (required and not v.strip()):raise ValueError(f'{name}: enter valid text (maximum 12000 characters)')
    return v.strip()
def assess(a):
    if a.get('personal_data')!='yes':
        state='not-indicated' if a.get('personal_data')=='no' else 'undetermined'
        return {'commissioner':state,'subjects':state,'reasons':['Personal-data breach not confirmed'],'source':GUIDANCE}
    yes=[k for k in HARM if a.get(k)=='yes'];unknown=[k for k in HARM if a.get(k) not in ['yes','no']]
    count=a.get('count');scale=count is not None and count>1000
    return {'commissioner':'review-notify' if yes or scale else 'undetermined' if unknown or count is None else 'not-indicated','subjects':'review-notify' if yes else 'undetermined' if unknown else 'not-indicated','reasons':yes+(['more than 1000 affected people'] if scale else [])+(['unknown criteria remain'] if unknown or count is None else []),'source':GUIDANCE}
def clocks(i,current=None):
    current=stamp(current) if current else dt.datetime.now(UTC)
    anchor=i.get('anchor','awareness');a=i.get(anchor)
    due=stamp(a)+dt.timedelta(hours=72) if a else None
    n=stamp(i['notified']) if i.get('notified') else None
    return {'anchor':anchor,'commissioner_due':due.isoformat() if due else None,'remaining_hours':round((due-current).total_seconds()/3600,2) if due else None,'subjects_due':(n+dt.timedelta(days=7)).isoformat() if n else None,'phased_due':(n+dt.timedelta(days=30)).isoformat() if n else None,'confirmation_received':bool(i.get('confirmation'))}
def normalize(raw,source):
    if not isinstance(raw,dict):raise ValueError('Each log line must be a JSON object')
    for key in ['rule','agent','data','alert','flow']:
        if key in raw and not isinstance(raw[key],dict):raise ValueError(f'{key} must be a JSON object')
    e={'source':source,'raw':raw,'sha256':digest({'source':source,'raw':raw}),'bytes_out':0,'severity':0,'src':'','dst':''}
    try:
        if source=='suricata':
            e.update(timestamp=stamp(raw['timestamp']).isoformat(),kind=raw['event_type'],src=raw.get('src_ip',''),dst=raw.get('dest_ip',''),summary=raw.get('alert',{}).get('signature',raw['event_type']),severity=int(raw.get('alert',{}).get('severity',0)),bytes_out=int(raw.get('flow',{}).get('bytes_toserver',0)))
        elif source=='wazuh':
            r=raw['rule'];data=raw.get('data',{});e.update(timestamp=stamp(raw['timestamp']).isoformat(),kind='alert',severity=int(r['level']),summary=r['description'],src=data.get('srcip',raw.get('agent',{}).get('ip','')),dst=data.get('dstip',''))
        elif source=='zeek':
            e.update(timestamp=dt.datetime.fromtimestamp(float(raw['ts']),UTC).isoformat(),kind='connection',src=raw['id.orig_h'],dst=raw['id.resp_h'],bytes_out=int(raw.get('orig_bytes',0)),summary='Outbound connection '+str(raw.get('uid','')))
        else:raise ValueError('Unsupported format. Choose wazuh, suricata or zeek JSON lines')
        if e['bytes_out']<0 or e['severity']<0:raise ValueError('Negative event counters are invalid')
        for field in ['src','dst']:
            if e[field]:ipaddress.ip_address(e[field])
        return e
    except (KeyError,TypeError,OverflowError,OSError) as exc:raise ValueError(f'Invalid {source} record: missing or invalid {exc}') from exc

def policy_validate(p):
    if not isinstance(p,dict):raise ValueError('Policy must be an object')
    out=DEFAULT_POLICY|p
    for k,lo,hi in [('zeek_bytes',1,10**12),('wazuh_level',1,15),('suricata_severity',1,3)]:
        if type(out[k]) is not int or not lo<=out[k]<=hi:raise ValueError(f'{k} must be an integer from {lo} to {hi}')
    if not isinstance(out['allow_destinations'],list) or len(out['allow_destinations'])>100:raise ValueError('Allowlist must contain at most 100 IP addresses')
    for x in out['allow_destinations']:ipaddress.ip_address(x)
    return out

def detected(e,p):
    if e['dst'] in p['allow_destinations']:return False
    if e['source']=='wazuh':return e['severity']>=p['wazuh_level']
    if e['source']=='suricata':return e['kind']=='alert' and 0<e['severity']<=p['suricata_severity']
    if e['source']=='zeek':
        if not e['dst'] or not e['src']:return False
        src,dst=ipaddress.ip_address(e['src']),ipaddress.ip_address(e['dst'])
        return any(src in n for n in LOCAL_NETS) and not any(dst in n for n in LOCAL_NETS) and not dst.is_multicast and e['bytes_out']>=p['zeek_bytes']
    return False

def compare(events,policy):
    p=policy_validate(policy);baseline=[e for e in events if detected(e,DEFAULT_POLICY)];tuned=[e for e in events if detected(e,p)]
    daily={}
    for e in events:
        row=daily.setdefault(e['timestamp'][:10],{'date':e['timestamp'][:10],'baseline':0,'tuned':0});row['baseline']+=int(detected(e,DEFAULT_POLICY));row['tuned']+=int(detected(e,p))
    ids={e['sha256'] for e in tuned}
    return {'events':len(events),'baseline_alerts':len(baseline),'tuned_alerts':len(tuned),'suppressed':[{'sha256':e['sha256'],'summary':e['summary'],'dst':e['dst'],'reason':'destination allowlist' if e['dst'] in p['allow_destinations'] else 'threshold'} for e in baseline if e['sha256'] not in ids],'daily':sorted(daily.values(),key=lambda x:x['date']),'observed_days':len(daily),'policy':p,'policy_sha256':digest(p),'boundary':'Counts for imported records; unobserved days are missing, not zero. No false-positive claim without analyst labels.'}

class Store:
    def __init__(self,path):
        self.path=Path(path);self.path.parent.mkdir(parents=True,exist_ok=True)
        with self.connect() as c:
            c.executescript('CREATE TABLE IF NOT EXISTS incidents(id TEXT PRIMARY KEY,data TEXT NOT NULL);CREATE TABLE IF NOT EXISTS timeline(seq INTEGER PRIMARY KEY AUTOINCREMENT,incident TEXT NOT NULL,data TEXT NOT NULL,previous TEXT NOT NULL,hash TEXT NOT NULL);CREATE TABLE IF NOT EXISTS events(hash TEXT PRIMARY KEY,data TEXT NOT NULL);CREATE TABLE IF NOT EXISTS settings(key TEXT PRIMARY KEY,value TEXT);')
        os.chmod(self.path,0o600)
    @contextmanager
    def connect(self):
        """Commit (or roll back) the transaction, then always close the connection."""
        c=sqlite3.connect(self.path,timeout=15)
        try:
            with c:yield c
        finally:c.close()
    def _audit(self,c,i,actor,kind,body):
        old=c.execute('SELECT hash FROM timeline WHERE incident=? ORDER BY seq DESC LIMIT 1',(i,)).fetchone();prev=old[0] if old else '0'*64
        data={'at':now(),'actor':actor,'kind':kind,'body':body};h=digest({'previous':prev,'data':data})
        c.execute('INSERT INTO timeline(incident,data,previous,hash) VALUES(?,?,?,?)',(i,json.dumps(data),prev,h))
    def create(self,p):
        i={'id':uuid.uuid4().hex[:10],'created':now(),'title':textfield(p.get('title',''),'title',True),'owner':textfield(p.get('owner',''),'owner',True),'mode':p.get('mode','practice'),'org':textfield(p.get('org',''),'organisation'),'awareness':stamp(p.get('awareness')).isoformat(),'occurred':p.get('occurred',''),'anchor':'awareness','anchor_reason':'Review against guideline 6.1–6.2','notified':'','confirmation':'','status':'Investigating','assessment':{},'draft':{},'checklist':{},'roles':{},'exercise_step':0}
        if i['mode'] not in ['practice','live-record']:raise ValueError('Invalid mode')
        if i['occurred']:i['occurred']=stamp(i['occurred']).isoformat()
        with self.connect() as c:
            c.execute('INSERT INTO incidents VALUES(?,?)',(i['id'],json.dumps(i)));self._audit(c,i['id'],i['owner'],'opened',i)
        return self.detail(i['id'])
    def listing(self):
        with self.connect() as c:return [json.loads(r[0]) for r in c.execute('SELECT data FROM incidents ORDER BY rowid DESC')]
    def detail(self,i):
        with self.connect() as c:
            row=c.execute('SELECT data FROM incidents WHERE id=?',(i,)).fetchone()
            if not row:raise ValueError('Incident not found')
            result=json.loads(row[0]);result['timeline']=[json.loads(r[0])|{'previous':r[1],'hash':r[2]} for r in c.execute('SELECT data,previous,hash FROM timeline WHERE incident=? ORDER BY seq',(i,))]
        result['recommendation']=assess(result['assessment']);result['clocks']=clocks(result);result['chain_valid']=self.verify_chain(i)
        return result
    def verify_chain(self,i):
        prev='0'*64
        with self.connect() as c:
            for data,previous,h in c.execute('SELECT data,previous,hash FROM timeline WHERE incident=? ORDER BY seq',(i,)):
                if previous!=prev or h!=digest({'previous':prev,'data':json.loads(data)}):return False
                prev=h
        return True
    def update(self,i,p):
        allowed={'title','owner','org','awareness','occurred','anchor','anchor_reason','notified','confirmation','status','assessment','draft','checklist','roles','exercise_step'}
        if set(p)-allowed-{'actor'}:raise ValueError('Unknown incident fields')
        actor=textfield(p.get('actor',''),'actor',True)
        with self.connect() as c:
            c.execute('BEGIN IMMEDIATE');row=c.execute('SELECT data FROM incidents WHERE id=?',(i,)).fetchone()
            if not row:raise ValueError('Incident not found')
            d=json.loads(row[0]);patch={k:v for k,v in p.items() if k in allowed};d.update(patch)
            for k in ['title','owner','anchor_reason']:textfield(d[k],k,True)
            for k in ['org','confirmation']:textfield(d[k],k)
            for k in ['awareness','occurred','notified']:
                if d[k]:d[k]=stamp(d[k]).isoformat()
            if not d['awareness']:raise ValueError('Awareness time is required')
            if d['anchor'] not in ['awareness','occurred'] or not d[d['anchor']]:raise ValueError('Selected clock anchor needs a timestamp')
            if d['status'] not in ['Investigating','Contained','Recovering','Closed']:raise ValueError('Invalid status')
            for k in ['assessment','draft','checklist','roles']:
                if not isinstance(d[k],dict):raise ValueError(f'{k} must be an object')
            a=d['assessment']
            for k in HARM+['personal_data']:
                if k in a and a[k] not in ['yes','no','unknown']:raise ValueError('Assessment must be yes, no or unknown')
            if a.get('count') is not None and (type(a['count']) is not int or a['count']<0):raise ValueError('Affected people must be a nonnegative integer or unknown')
            for k,v in d['draft'].items():
                if k not in FIELDS:raise ValueError('Unknown notification field')
                textfield(v,k)
            if type(d['exercise_step']) is not int or not 0<=d['exercise_step']<=5:raise ValueError('Invalid exercise step')
            c.execute('UPDATE incidents SET data=? WHERE id=?',(json.dumps(d),i));self._audit(c,i,actor,'revision',patch)
        return self.detail(i)
    def note(self,i,p):
        self.detail(i);actor=textfield(p.get('actor',''),'actor',True);body=textfield(p.get('text',''),'note',True);kind=p.get('kind','note')
        if kind not in ['note','evidence','containment','decision','tabletop']:raise ValueError('Invalid note type')
        with self.connect() as c:self._audit(c,i,actor,kind,body)
        return self.detail(i)
    def ingest(self,source,raws):
        if not isinstance(raws,list) or len(raws)>10000:raise ValueError('Import up to 10000 JSON records per batch')
        start=time.perf_counter();events=[normalize(r,source) for r in raws];n=0
        with self.connect() as c:
            for e in events:n+=c.execute('INSERT OR IGNORE INTO events VALUES(?,?)',(e['sha256'],json.dumps(e))).rowcount
        return {'received':len(events),'inserted':n,'duplicates':len(events)-n,'elapsed_ms':round((time.perf_counter()-start)*1000,3),'boundary':'JSON normalization + SQLite insertion, excluding sensor acquisition and network transport'}
    def events(self):
        with self.connect() as c:return [json.loads(r[0]) for r in c.execute('SELECT data FROM events ORDER BY rowid DESC')]
    def policy(self,p=None):
        with self.connect() as c:
            if p is not None:c.execute('INSERT OR REPLACE INTO settings VALUES(?,?)',('policy',json.dumps(policy_validate(p))))
            r=c.execute('SELECT value FROM settings WHERE key=?',('policy',)).fetchone()
        return json.loads(r[0]) if r else DEFAULT_POLICY.copy()
    def export(self,i):
        d=self.detail(i);d['exported_at']=now();d['draft_mapping']=FIELDS;d['source']=GUIDANCE;d['notice']='Preparation record only. No notice has been sent by this application. Guideline v1.0 reviewed 2026-10-19. Preserve regulator confirmation separately.';return d

def benchmark():
    raw=json.loads((ROOT/'fixtures/zeek.jsonl').read_text().splitlines()[0]);times=[]
    for _ in range(200):
        t=time.perf_counter_ns();e=normalize(raw,'zeek');detected(e,DEFAULT_POLICY);times.append((time.perf_counter_ns()-t)/1e6)
    return {'runs':len(times),'fixture_sha256':digest(raw),'median_ms':statistics.median(times),'p95_ms':sorted(times)[189],'boundary':'in-process normalize + threshold evaluation of a synthetic Zeek connection; excludes live sensor, network and disk ingestion','live_detection_time_measured':False}

if __name__=='__main__':
    p=argparse.ArgumentParser();p.add_argument('--db',default=str(ROOT/'work/pocket-soc.sqlite'));sub=p.add_subparsers(dest='cmd',required=True)
    sub.add_parser('serve').add_argument('--port',type=int,default=8765)
    a=sub.add_parser('ingest');a.add_argument('--source',choices=['wazuh','suricata','zeek'],required=True);a.add_argument('file')
    sub.add_parser('benchmark');sub.add_parser('report-tuning')
    args=p.parse_args();s=Store(args.db)
    if args.cmd=='serve':
        from server import serve
        serve(s,args.port)
    elif args.cmd=='benchmark':print(json.dumps(benchmark(),indent=2))
    elif args.cmd=='ingest':print(json.dumps(s.ingest(args.source,[json.loads(x) for x in Path(args.file).read_text().splitlines() if x.strip()]),indent=2))
    elif args.cmd=='report-tuning':print(json.dumps(compare(s.events(),s.policy()),indent=2))
