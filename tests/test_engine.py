import unittest
from windows_baseline_snapshot import analyze
from windows_baseline_snapshot.engine import load_policy, compare
from windows_baseline_snapshot.common import InputError

class WindowsTests(unittest.TestCase):
    def good(self,name='machine'):
        return {'baseline':name,'observations':{r['ID']:{'state':'measured','method':r['Method'],'value':r['RecommendedValue']} for r in load_policy(name)}}
    def test_all_machine_rows(self):
        r=analyze(self.good());self.assertEqual(r['status'],'PASS');self.assertEqual(r['counts']['PASS'],418)
    def test_all_user_rows(self):
        r=analyze(self.good('user'));self.assertEqual(r['status'],'PASS');self.assertEqual(r['counts']['PASS'],56)
    def test_missing_not_default(self):
        s=self.good();s['observations'].pop('1000');self.assertEqual(analyze(s)['status'],'OPEN')
    def test_not_configured(self):
        s=self.good();s['observations']['1000']={'state':'not_configured'};self.assertEqual(analyze(s)['status'],'OPEN')
    def test_method_mismatch(self):
        s=self.good();s['observations']['1000']['method']='Registry';self.assertEqual(analyze(s)['status'],'OPEN')
    def test_inequality_boundaries(self):
        self.assertTrue(compare('15','15','>='));self.assertFalse(compare('14','15','>='));self.assertTrue(compare('10','10','<='));self.assertFalse(compare('11','10','<='))
    def test_exact_token_contains(self):
        self.assertTrue(compare('Enabled;Disabled','Disabled','contains'));self.assertFalse(compare('NotDisabled','Disabled','contains'))
    def test_unordered_casefold_equal(self):self.assertTrue(compare('Admin;USER','user;admin','='))
    def test_unknown_measurement_type(self):
        s=self.good();s['observations']['1000']['value']=True
        with self.assertRaises(InputError):analyze(s)
    def test_oversized_number_open(self):self.assertIsNone(compare('9'*5000,'10','>='))
    def test_extra_observation(self):
        s=self.good();s['observations']['unknown']={};self.assertEqual(analyze(s)['status'],'OPEN')
    def test_unknown_baseline(self):
        with self.assertRaises(InputError):analyze({'baseline':'all'})
