import tempfile, unittest
from pathlib import Path
from soc import Store, assess, clocks, normalize, compare

class CoreTests(unittest.TestCase):
    def test_scale_is_not_subject_harm(self):
        r=assess({'personal_data':'yes','count':1001,'physical_financial':'no','illegal':'no','sensitive':'no','identity':'no'})
        self.assertEqual(r['commissioner'],'review-notify')
        self.assertEqual(r['subjects'],'not-indicated')
    def test_boundary_and_unknown(self):
        r=assess({'personal_data':'yes','count':1000,'physical_financial':'no','illegal':'no','sensitive':'no','identity':'no'})
        self.assertEqual(r['commissioner'],'not-indicated')
        self.assertEqual(assess({'personal_data':'unknown'})['commissioner'],'undetermined')
    def test_clocks_timezone_and_anchor(self):
        r=clocks({'awareness':'2026-10-19T09:00:00+08:00','occurred':'2026-10-18T09:00:00+08:00','anchor':'awareness','notified':'2026-10-20T01:00:00Z'},'2026-10-19T01:00:00Z')
        self.assertEqual(r['commissioner_due'],'2026-10-22T01:00:00+00:00')
        self.assertEqual(r['subjects_due'],'2026-10-27T01:00:00+00:00')
        with self.assertRaises(ValueError): clocks({'awareness':'2026-10-19T09:00:00','anchor':'awareness'})
    def test_sensor_normalization(self):
        e=normalize({'ts':1792371600,'uid':'x','id.orig_h':'10.0.0.2','id.resp_h':'203.0.113.9','orig_bytes':2000000},'zeek')
        self.assertEqual(e['bytes_out'],2000000)
        with self.assertRaises(ValueError):normalize({'oops':1},'suricata')
    def test_durable_chain_and_import_atomicity(self):
        with tempfile.TemporaryDirectory() as d:
            s=Store(Path(d)/'test.db')
            i=s.create({'title':'Exercise','mode':'practice','awareness':'2026-10-19T01:00:00Z','owner':'Test'})
            s.note(i['id'],{'actor':'Test','text':'Preserved log','kind':'evidence'})
            self.assertTrue(s.verify_chain(i['id']))
            self.assertEqual(len(Store(Path(d)/'test.db').detail(i['id'])['timeline']),2)
            with self.assertRaises(ValueError):s.ingest('suricata',[{'event_type':'alert','timestamp':'2026-10-19T01:00:00Z','alert':{'severity':1,'signature':'test'}},{'bad':1}])
            self.assertEqual(s.events(),[])
    def test_tuning_records_suppression_and_deduplicates(self):
        e=normalize({'ts':1792371600,'uid':'x','id.orig_h':'10.0.0.2','id.resp_h':'203.0.113.9','orig_bytes':2000000},'zeek')
        r=compare([e],{'zeek_bytes':1000000,'allow_destinations':['203.0.113.9'],'wazuh_level':7,'suricata_severity':2})
        self.assertEqual(r['baseline_alerts'],1)
        self.assertEqual(r['tuned_alerts'],0)
        self.assertEqual(len(r['suppressed']),1)

if __name__=='__main__':unittest.main()
