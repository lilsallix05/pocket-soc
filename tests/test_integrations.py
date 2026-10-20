import tempfile,unittest,json
from pathlib import Path
from soc import Store,normalize,detected,compare,DEFAULT_POLICY
from ops.tail_ingest import collect

class IntegrationTests(unittest.TestCase):
    def test_partial_rotation_and_duplicates(self):
        with tempfile.TemporaryDirectory() as tmp:
            root=Path(tmp);s=Store(root/'s.db');f=root/'eve.json';cp=root/'offset.json'
            row={'timestamp':'2026-10-19T01:00:00Z','event_type':'alert','alert':{'signature':'x','severity':1}}
            data=json.dumps(row);f.write_text(data)
            self.assertEqual(collect(f,'suricata',s,cp)['received'],0)
            with f.open('a') as h:h.write('\n')
            self.assertEqual(collect(f,'suricata',s,cp)['inserted'],1)
            self.assertEqual(collect(f,'suricata',s,cp)['received'],0)
            f.rename(root/'old');f.write_text(data+'\n')
            self.assertEqual(collect(f,'suricata',s,cp)['duplicates'],1)
    def test_tamper_detected(self):
        with tempfile.TemporaryDirectory() as tmp:
            s=Store(Path(tmp)/'s.db');i=s.create({'title':'X','owner':'Y','awareness':'2026-10-19T01:00:00Z'})
            with s.connect() as c:c.execute("UPDATE timeline SET data='{}'")
            self.assertFalse(s.verify_chain(i['id']))
    def test_duplicate_ingestion(self):
        with tempfile.TemporaryDirectory() as tmp:
            s=Store(Path(tmp)/'s.db');r={'timestamp':'2026-10-19T01:00:00Z','rule':{'level':7,'description':'x'}}
            self.assertEqual(s.ingest('wazuh',[r,r])['inserted'],1)
            self.assertEqual(s.ingest('wazuh',[r])['duplicates'],1)
    def test_private_destinations_not_outbound(self):
        for dest in ['10.1.2.3','192.168.1.5','172.16.1.5','127.0.0.1','::1','fe80::1','fc00::1']:
            e=normalize({'ts':1792371600,'id.orig_h':'10.0.0.2','id.resp_h':dest,'orig_bytes':2000000},'zeek')
            self.assertFalse(detected(e,DEFAULT_POLICY),dest)
    def test_bundled_fixture_policy_comparison(self):
        fixtures=Path(__file__).resolve().parents[1]/'fixtures'
        with tempfile.TemporaryDirectory() as tmp:
            s=Store(Path(tmp)/'s.db')
            for source in ['zeek','wazuh','suricata']:s.ingest(source,[json.loads(x) for x in (fixtures/f'{source}.jsonl').read_text().splitlines()])
            backup=compare(s.events(),{'allow_destinations':['198.51.100.10']})
            self.assertEqual((backup['events'],backup['observed_days'],backup['baseline_alerts'],backup['tuned_alerts'],len(backup['suppressed'])),(150,30,120,90,30))
            self.assertEqual({x['reason'] for x in backup['suppressed']},{'destination allowlist'})
            incident=compare(s.events(),{'allow_destinations':['203.0.113.70']})
            self.assertEqual((incident['tuned_alerts'],len(incident['suppressed'])),(60,60))
