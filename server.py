import json, mimetypes, secrets
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from urllib.parse import urlparse
from soc import ROOT, FIELDS, GUIDANCE, now, compare

INJECTS=[
 {'title':'An unusual upload','text':'The synthetic clinic workstation sends 2.4 MB to 203.0.113.70. Preserve logs, identify an incident commander and confirm whether patient data was involved.'},
 {'title':'Scope changes','text':'The practice records indicate 240 patients, including medical information. Assess significant harm independently of the volume threshold.'},
 {'title':'Processor update','text':'A mock processor says it saw access earlier. Record occurrence and awareness separately. Review the clock basis against paragraphs 6.1–6.2.'},
 {'title':'Notification review','text':'Prepare a draft with unknowns identified. Record who approves it. Do not send exercise notices. Discuss confirmation receipt and phased information.'},
 {'title':'Recovery and learning','text':'Revoke the test session, confirm restoration in the exercise narrative, and review whether allowlisting the destination would conceal the alert. Assign an improvement owner.'}
]
def serve(store,port):
    token=secrets.token_urlsafe(32)
    class Handler(BaseHTTPRequestHandler):
        def log_message(self,*args):pass
        def send(self,data,status=200,ctype='application/json'):
            blob=json.dumps(data).encode() if ctype=='application/json' else data if isinstance(data,bytes) else data.encode()
            self.send_response(status);self.send_header('Content-Type',ctype);self.send_header('Content-Length',str(len(blob)));self.send_header('Cache-Control','no-store');self.send_header('X-Content-Type-Options','nosniff');self.send_header('Content-Security-Policy',"default-src 'self'; script-src 'self'; style-src 'self' 'unsafe-inline'; img-src 'self' data:; object-src 'none'; base-uri 'none'; frame-ancestors 'none'");self.end_headers();self.wfile.write(blob)
        def valid_host(self):return self.headers.get('Host') in [f'127.0.0.1:{self.server.server_port}',f'localhost:{self.server.server_port}']
        def do_GET(self):
            if not self.valid_host():return self.send({'error':'Invalid local host'},403)
            path=urlparse(self.path).path
            try:
                if path=='/api/state':return self.send({'csrf':token,'incidents':store.listing(),'events':store.events(),'policy':store.policy(),'tuning':compare(store.events(),store.policy()),'injects':INJECTS,'fields':FIELDS,'guidance':GUIDANCE})
                if path=='/api/events/export':return self.send({'exported_at':now(),'observations':store.events(),'tuning':compare(store.events(),store.policy())})
                if path.startswith('/api/incidents/'):
                    parts=path.split('/');return self.send(store.export(parts[3]) if len(parts)>4 and parts[4]=='export' else store.detail(parts[3]))
                allowed={'/':'index.html','/app.js':'app.js','/style.css':'style.css'}
                if path not in allowed:return self.send({'error':'Not found'},404)
                f=ROOT/'static'/allowed[path];return self.send(f.read_bytes(),ctype=mimetypes.guess_type(f)[0] or 'text/plain')
            except ValueError as e:return self.send({'error':str(e)},404)
        def do_POST(self):
            expected=f'http://{self.headers.get("Host")}'
            if not self.valid_host() or self.headers.get('Origin') not in [None,expected] or self.headers.get('X-CSRF-Token')!=token:return self.send({'error':'Refresh the local page to establish a session'},403)
            try:
                n=int(self.headers.get('Content-Length','0'))
                if not 0<n<=8*1024*1024:raise ValueError('Request must be between 1 byte and 8 MiB')
                p=json.loads(self.rfile.read(n));path=urlparse(self.path).path
                if not isinstance(p,dict):raise ValueError('Request must be a JSON object')
                if path=='/api/incidents':r=store.create(p)
                elif path.startswith('/api/incidents/'):
                    parts=path.split('/');r=store.note(parts[3],p) if len(parts)>4 and parts[4]=='notes' else store.update(parts[3],p)
                elif path=='/api/ingest':r=store.ingest(p.get('source'),p.get('records'))
                elif path=='/api/policy':r=store.policy(p)
                elif path=='/api/exercise':
                    r=store.create({'title':'Clinic file transfer exercise','owner':'Exercise lead','org':'Synthetic clinic','awareness':now(),'mode':'practice'})
                    for source in ['zeek','wazuh','suricata']:store.ingest(source,[json.loads(x) for x in (ROOT/'fixtures'/f'{source}.jsonl').read_text().splitlines()])
                    store.note(r['id'],{'actor':'Facilitator','text':INJECTS[0]['text'],'kind':'tabletop'})
                else:return self.send({'error':'Not found'},404)
                return self.send(r)
            except (ValueError,TypeError,KeyError) as e:return self.send({'error':str(e)},400)
    http=ThreadingHTTPServer(('127.0.0.1',port),Handler)
    print(f'Pocket SOC running at http://127.0.0.1:{http.server_port}',flush=True);http.serve_forever()
