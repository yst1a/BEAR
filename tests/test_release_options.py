"""Small regressions for block encoding, fastest selection and output delay."""
import os
import tempfile
import unittest
from pathlib import Path

from bear.reencode import block_accumulator_rtl, rewrite_design
from bear.select import select
from bear.cli import characterize_library, library_specs
from bear.extract import detect_design
from bear._pipeline import rewrite_pipe_design
from bear.verify import prove
from bear.runtime import NATIVE

ROOT=Path(__file__).resolve().parents[1]


class ReleaseOptions(unittest.TestCase):
    def test_block_generator_matches_source(self):
        for q in (2,4):
            for k in (0,8):
                with self.subTest(q=q,k=k):
                    expected=(ROOT/'tests'/'fixtures'/f'block_q{q}_k{k}.v').read_bytes()
                    self.assertEqual(block_accumulator_rtl('accumulator',q,k).encode('utf-8'),expected)

    def test_fastest_selects_proven_delay_then_area(self):
        def p(v,a,d):return dict(variant=v,area=a,budget_delay_ps=d,status='PASS')
        points=[p('original',80,500),p('quick',120,300),p('compact',100,300),p('unknown',1,100)]
        proofs={v:dict(status='PASS',scope_status='FULL_PREFIX') for v in ('quick','compact')}
        self.assertEqual(select(points,proofs=proofs,objective='fastest')[0]['selected']['variant'],'compact')
        self.assertEqual(select(points,[1000],proofs=proofs)[0]['selected']['variant'],'original')
        self.assertEqual(select(points,proofs={},objective='fastest')[0]['selected']['variant'],'original')
        points.append(p('original',90,200))
        self.assertEqual(select(points,proofs=proofs,objective='fastest')[0]['selected']['variant'],'original')

    def example(self,root):
        certs=characterize_library(library_specs(ROOT/'examples'/'adders.json'),root/'certs')
        detection=detect_design([ROOT/'examples'/'loa_accumulator.v'],'loa_accumulator',certs,root/'detect')
        self.assertEqual(detection['status'],'PASS')
        return certs,detection

    @unittest.skipUnless(os.getenv('BEAR_INTEGRATION'),'Requires the optional integration toolchain')
    def test_block_reencode_proof(self):
        root=Path(tempfile.mkdtemp(prefix='block_',dir=NATIVE))
        certs,detection=self.example(root)
        for q in (2,4):
            result=rewrite_design(detection,certs,root/f'q{q}',f'T_blk_q{q}')
            self.assertEqual(result['status'],'GENERATED',result)
            proof=prove(ROOT/'examples'/'loa_accumulator.v',result['rtl'],'loa_accumulator',root/f'proof{q}',
                        refinement=result['refinement'],cycles=1000,formal_engine='yosys_sat',timeout=90)
            self.assertEqual(proof['status'],'PASS',proof.get('refinement_skipped'))

    @unittest.skipUnless(os.getenv('BEAR_INTEGRATION'),'Requires the optional integration toolchain')
    def test_pipeline_aligned_two_clocks(self):
        root=Path(tempfile.mkdtemp(prefix='pipeline_',dir=NATIVE))
        certs,detection=self.example(root)
        candidate=rewrite_pipe_design(detection,certs,root/'candidate',pipe_l=3)
        self.assertEqual(candidate['status'],'GENERATED',candidate)
        self.assertEqual(candidate['latency'],2)
        for d,expected in ((2,'PASS'),(1,'FAIL')):
            proof=prove(ROOT/'examples'/'loa_accumulator.v',candidate['rtl'],'loa_accumulator',root/f'proof{d}',
                        refinement=candidate['refinement'],latency=d,cycles=1000,formal_engine='yosys_sat',timeout=90)
            self.assertEqual(proof['status'],expected,proof.get('refinement_skipped'))
            if d==2:
                self.assertEqual(proof['scope_status'],'FULL_PREFIX')
                self.assertEqual(proof['formal']['status'],'PASS')
                self.assertEqual(proof['simulation']['status'],'PASS')


if __name__=='__main__':unittest.main()
