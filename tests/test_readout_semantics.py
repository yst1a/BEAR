import unittest
from pathlib import Path
from unittest.mock import patch
from bear.select import apply_readout_semantics, point_feasible, readout_options, select, sta


class ReadoutSemantics(unittest.TestCase):
    def point(self,variant='original',area=100):
        return dict(status='PASS',variant=variant,area=area,D=100,
                    paths_ps=dict(RR=700,IR=800,RO=2300,IO=None),budget_delay_ps=2300,period_ps=800)

    def sampled(self,point=None,ports=('y',),all_outputs=('y',)):
        return apply_readout_semantics(point or self.point(),readout='on-readout',readout_ports=ports,
                                      readout_budget_ps=2500,readout_contract='Hold state after the last accumulation and allow 2500 ps before readout',
                                      all_output_ports=all_outputs)

    def test_every_cycle_retains_full_output_cost(self):
        p=apply_readout_semantics(self.point())
        self.assertFalse(point_feasible(p,1000))
        self.assertEqual(p['budget_delay_ps'],2300)

    def test_independent_readout_budget_is_enforced(self):
        p=self.sampled()
        self.assertTrue(point_feasible(p,1000))
        p['readout_semantics']['budget_ps']=2000
        self.assertFalse(point_feasible(p,1000))

    def test_internal_consumer_remains_in_rr_budget(self):
        p=self.point();p['paths_ps']['RR']=2600
        self.assertFalse(point_feasible(self.sampled(p),1000))

    def test_missing_protocol_or_budget_rejected(self):
        with self.assertRaises(ValueError):readout_options('on-readout',('y',),2500)
        with self.assertRaises(ValueError):readout_options('on-readout',('y',),float('inf'),'protocol')
        with self.assertRaises(ValueError):readout_options('every-cycle',('y',),2500,'protocol')
        with self.assertRaises(ValueError):readout_options('on-readout',('*',),2500,'protocol')

    def test_mixed_ports_old_aggregate_is_unknown(self):
        p=self.sampled(all_outputs=('y','forward'))
        self.assertEqual(p['status'],'UNKNOWN_READOUT_TIMING')
        self.assertFalse(point_feasible(p,1000))

    def test_mixed_ports_split_preserves_forward_output(self):
        p=self.point();p['paths_ps'].update(RO_READOUT=2300,IO_READOUT=None,RO_EVERY=1200,IO_EVERY=900)
        p=self.sampled(p,all_outputs=('y','forward'))
        self.assertEqual(p['budget_delay_ps'],1200)
        self.assertFalse(point_feasible(p,1000))
        self.assertTrue(point_feasible(p,1500))

    def test_select_cannot_mix_observation_contracts(self):
        with self.assertRaises(ValueError):select([self.point(),self.sampled(self.point('T_cs',70))],[1000])

    def test_proof_still_required_on_readout(self):
        points=[self.sampled(),self.sampled(self.point('T_cs',70))]
        self.assertEqual(select(points,[1000],proofs={'T_cs':{'status':'UNKNOWN'}})[0]['selected']['variant'],'original')

    def test_sta_expands_bus_and_does_not_remove_internal_paths(self):
        writes={}
        log=''.join('=='+k+'==\n'+s+' slack\n' for k,s in
                    [('IO','7.7'),('RR','9.3'),('IR','9.2'),('RO','7.7'),
                     ('IO_READOUT','7.7'),('IO_EVERY','8.8'),('RO_READOUT','7.7'),('RO_EVERY','8.8')])
        with patch.object(Path,'mkdir'), patch.object(Path,'read_text',return_value='output [14:0] y;'),\
             patch.object(Path,'write_text',lambda p,s,*a,**k:writes.update({str(p):s})),\
             patch('bear.select.run_guarded',return_value=dict(status='PASS',stdout=log,log='fake')):
            p=sta('fake.v','X','fake',readout='on-readout',readout_ports=('y',),readout_budget_ps=2500,
                  readout_contract='Extend the final cycle')
        tcl=writes[str(Path('fake').resolve()/'sta.tcl')]
        self.assertIn('^y(\\[[0-9]+\\])?$',tcl)
        self.assertIn('-to [all_registers -data_pins]',tcl)
        self.assertIn('set every_outputs [delete_from_list [all_outputs] $readout_ports]',tcl)
        self.assertEqual(p['budget_delay_ps'],1200)
        self.assertEqual(p['readout_delay_ps'],2300)


if __name__=='__main__':unittest.main()

