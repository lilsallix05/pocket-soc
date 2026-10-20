import json,subprocess,sys,tempfile,unittest,urllib.request,urllib.error
from pathlib import Path
ROOT=Path(__file__).resolve().parents[1]
class HttpTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.tmp=tempfile.TemporaryDirectory();cls.proc=subprocess.Popen([sys.executable,str(ROOT/'soc.py'),'--db',str(Path(cls.tmp.name)/'s.db'),'serve','--port','0'],stdout=subprocess.PIPE,text=True)
        cls.url=cls.proc.stdout.readline().strip().split()[-1]
        with urllib.request.urlopen(cls.url+'/api/state') as r:cls.token=json.load(r)['csrf']
    @classmethod
    def tearDownClass(cls):cls.proc.terminate();cls.proc.wait(timeout=10);cls.proc.stdout.close();cls.tmp.cleanup()
    def request(self,path,data,token=True,extra=None):
        h={'Content-Type':'application/json'}
        if token:h['X-CSRF-Token']=self.token
        h.update(extra or {})
        return urllib.request.urlopen(urllib.request.Request(self.url+path,json.dumps(data).encode(),h))
    def test_cross_origin_and_token_rejected(self):
        for token,extra in [(False,{}),(True,{'Origin':'https://untrusted.example'}),(True,{'Host':'untrusted.example'})]:
            with self.assertRaises(urllib.error.HTTPError) as x:self.request('/api/exercise',{},token,extra)
            self.assertEqual(x.exception.code,403);x.exception.close()
    def test_full_workflow_and_bad_shapes(self):
        with self.request('/api/exercise',{}) as r:i=json.load(r)
        with self.request('/api/incidents/'+i['id'],{'actor':'Test','assessment':{'personal_data':'yes','count':1001,'physical_financial':'no','illegal':'no','sensitive':'no','identity':'no'}}) as r:d=json.load(r)
        self.assertEqual(d['recommendation']['subjects'],'not-indicated')
        with urllib.request.urlopen(self.url+'/api/events/export') as r:self.assertEqual(len(json.load(r)['observations']),150)
        with self.assertRaises(urllib.error.HTTPError) as x:self.request('/api/ingest',{'source':'wazuh','records':[{'rule':[]}]})
        self.assertEqual(x.exception.code,400);x.exception.close()
        with urllib.request.urlopen(self.url+'/api/incidents/'+i['id']+'/export') as r:self.assertTrue(json.load(r)['chain_valid'])
