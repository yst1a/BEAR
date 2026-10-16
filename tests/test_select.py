import unittest
from bear.select import select

class Selection(unittest.TestCase):
    def p(self,v,a,e=None):
        return dict(variant=v,area=a,status='PASS',budget_delay_ps=500,D=100,dynamic_pJ_per_cycle=e)
    def test_unknown_cannot_replace(self):
        d=select([self.p('original',100),self.p('T_cs',60)],[1000],proofs={'T_cs':{'status':'UNKNOWN'}})[0]
        self.assertEqual(d['selected']['variant'],'original')
    def test_warmup_pass_cannot_replace(self):
        d=select([self.p('original',100),self.p('T_cs',60)],[1000],proofs={'T_cs':{'status':'PASS'}})[0]
        self.assertEqual(d['selected']['variant'],'original')
    def test_equal_area_energy_secondary(self):
        d=select([self.p('original',100,2),self.p('T_cs',100,1)],[1000],proofs={'T_cs':{'status':'PASS','scope_status':'FULL_PREFIX'}})[0]
        self.assertEqual(d['selected']['variant'],'T_cs')
    def test_area_precedes_energy(self):
        d=select([self.p('original',99,2),self.p('T_cs',100,1)],[1000],proofs={'T_cs':{'status':'PASS','scope_status':'FULL_PREFIX'}})[0]
        self.assertEqual(d['selected']['variant'],'original')
    def test_no_feasible_preserves_input(self):
        d=select([self.p('original',100)],[100])[0]
        self.assertIsNone(d['selected']);self.assertEqual(d['fallback_reason'],'NO_FEASIBLE_PROVEN_POINT')

if __name__=='__main__':unittest.main()

