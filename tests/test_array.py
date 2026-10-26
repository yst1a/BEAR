"""Small array readout end-to-end and adversarial actual-RTL checks."""
import json
import os
from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch

from bear.array import build_array, readout_rtl, reuse_pe, selection_valid
from bear.runtime import NATIVE

MUX = Path(__file__).resolve().parents[1]/'examples/array_mux.sv'


class ArrayTests(unittest.TestCase):
    def test_selection_contract(self):
        self.assertEqual([v for v in range(16) if selection_valid(v,4,'onehot0')], [0,1,2,4,8])
        self.assertEqual([v for v in range(16) if selection_valid(v,4,'onehot')], [1,2,4,8])
        self.assertFalse(selection_valid(3,4,'onehot0'))
        self.assertFalse(selection_valid(16,4,'onehot0'))

    def test_generation_and_invalid_parameters(self):
        text=readout_rtl(4,8,2,'array_mux',segments=3)
        self.assertIn('select_carry',text)
        self.assertIn('if(!rst_n)',text)
        self.assertIn('tag_out=t1',text)
        self.assertNotIn('enable',text)
        for n,w,k,l in [(0,8,2,1),(4,8,8,1),(4,8,2,7)]:
            with self.assertRaises(ValueError):readout_rtl(n,w,k,'array_mux',segments=l)
        with self.assertRaises(ValueError):readout_rtl(4,8,2,'array_mux',default=(4,0,0))

    def test_staged_groups_and_validation(self):
        from bear.array import selector_groups
        for m,groups in ((1,[8]),(2,[4,4]),(3,[3,3,2])):
            self.assertEqual(selector_groups(256,m),groups)
            rtl=readout_rtl(256,8,2,'array_mux',selector_stages=m,selector_group_bits=groups)
            self.assertIn(f'select_tag_{m-1}',rtl)
        for m,groups in ((-1,None),(2,[2]),(2,[2,2]),(0,[2]),(2,[-1,3])):
            with self.assertRaises(ValueError):readout_rtl(4,8,2,'array_mux',selector_stages=m,selector_group_bits=groups)

    def test_incomplete_pe_proof_rejected(self):
        NATIVE.mkdir(parents=True,exist_ok=True)
        root=Path(tempfile.mkdtemp(prefix='array_invalid_',dir=NATIVE))
        record=root/'record.json';record.write_text('{"status":"UNKNOWN"}',encoding='utf-8')
        with self.assertRaisesRegex(ValueError,'completed'):reuse_pe(record,[],8,2)


@unittest.skipUnless(os.getenv('BEAR_INTEGRATION'),'Requires the optional integration toolchain')
class ArrayIntegrationTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        from bear.extract import detect_design
        from bear.reencode import rewrite_design
        from bear.verify import prove
        from test_extract_reencode import RTL, loa_certificate
        NATIVE.mkdir(parents=True,exist_ok=True)
        cls.root=Path(tempfile.mkdtemp(prefix='array_e2e_',dir=NATIVE))
        original=cls.root/'pe.v';original.write_text(RTL,encoding='utf-8')
        cert=loa_certificate()
        detection=detect_design([original],'natural',[cert],cls.root/'detect')
        rewrite=rewrite_design(detection,[cert],cls.root/'rewrite',variant='T_cs')
        if rewrite['status']!='GENERATED':raise AssertionError(rewrite)
        cls.pe=[rewrite['rtl']]
        proof=prove([original],cls.pe,'natural',cls.root/'pe_proof',
                    refinement=rewrite['refinement'],cycles=1000,formal_engine='yosys_sat',timeout=120)
        if proof['status']!='PASS':raise AssertionError('PE proof: '+str(cls.root/'pe_proof/receipt.json'))
        cls.proof=cls.root/'pe_proof/receipt.json'

    def run_array(self,name,mux=MUX,**kwargs):
        # Any accidental PE re-proof is an error; the existing verify record is reused.
        with patch('bear.verify.prove',side_effect=AssertionError('PE proof must be reused')):
            return build_array(self.pe,self.proof,[mux],'array_mux',4,8,2,self.root/name,**kwargs)

    def test_end_to_end_pipeline_and_repeated_reset(self):
        for segments in (1,2,3):
            result=self.run_array('good'+str(segments),segments=segments)
            self.assertEqual(result['status'],'PASS',result)
            self.assertEqual(result['pe']['status'],'REUSED')
            self.assertEqual(result['latency'],segments-1)
            script=(self.root/('good'+str(segments))/'commutation.ys').read_text(encoding='utf-8')
            self.assertEqual(sum(line.startswith('sat ') for line in script.splitlines()),1)

    def test_different_component_select_fails(self):
        wrong=self.root/'wrong.sv'
        wrong.write_text(MUX.read_text(encoding='utf-8').replace('if(sel==i)',
            'if((WIDTH==6 ? (sel ^ 1) : sel)==i)'),encoding='utf-8')
        result=self.run_array('wrong',wrong)
        self.assertEqual(result['commutation']['status'],'FAIL',result)

    def test_mismatched_default_fails(self):
        result=self.run_array('default_wrong',default=(1,0,0))
        self.assertEqual(result['commutation']['status'],'FAIL',result)

    def test_nonzero_default_and_non_power_of_two(self):
        result=build_array(self.pe,self.proof,[MUX],'array_mux',3,8,2,self.root/'n3',
                           default=(1,2,3),original_default=21,segments=2)
        self.assertEqual(result['status'],'PASS',result)

    def test_or_mux_requires_selection_contract(self):
        mux=self.root/'or_mux.sv'
        mux.write_text('''module array_mux #(parameter WIDTH=8,N=4,SEL_WIDTH=4)
(input [SEL_WIDTH-1:0] sel,input [N*WIDTH-1:0] data,
input [WIDTH-1:0] default_value,output reg [WIDTH-1:0] y);
integer i;
always @* begin y=0;for(i=0;i<N;i=i+1) y=y | ({WIDTH{sel[i]}} & data[i*WIDTH +: WIDTH]);
if(sel==0)y=default_value;end
endmodule
''',encoding='utf-8')
        result=self.run_array('or_onehot0',mux,mode='onehot0',segments=2)
        self.assertEqual(result['status'],'PASS',result)
        self.assertEqual(result['selection']['status'],'CONDITIONAL')
        # Interpreting the same RTL as an unconstrained binary mux must fail.
        self.assertEqual(self.run_array('or_binary',mux)['commutation']['status'],'FAIL')

    def test_stale_pe_and_decoder_mismatch_rejected(self):
        bad=self.root/'different_pe.v';bad.write_text('module different;endmodule',encoding='utf-8')
        with self.assertRaisesRegex(ValueError,'differs'):reuse_pe(self.proof,[bad],8,2)
        with self.assertRaisesRegex(ValueError,'requested'):reuse_pe(self.proof,self.pe,8,3)

    def test_actual_selection_producer_checked(self):
        good=self.root/'selector.sv'
        good.write_text('module controller(input [2:0] control,output [3:0] sel);'
                        "assign sel=(control<4)?(4'b1<<control):4'b0;endmodule\n",encoding='utf-8')
        # Binary mux source is deliberately adapted to onehot priority selection.
        mux=self.root/'priority.sv'
        mux.write_text(MUX.read_text(encoding='utf-8').replace('if(sel==i)','if(sel[i])'),encoding='utf-8')
        result=self.run_array('producer_good',mux,mode='onehot0',selector_files=[good],
                              selector_top='controller',control_width=3)
        self.assertEqual(result['status'],'PASS',result)
        self.assertEqual(result['selection']['status'],'PROVEN_PRODUCER')
        bad=self.root/'selector_bad.sv'
        bad.write_text('module controller(input [3:0] control,output [3:0] sel);'
                       'assign sel=control;endmodule\n',encoding='utf-8')
        result=self.run_array('producer_bad',mux,mode='onehot0',selector_files=[bad],
                              selector_top='controller',control_width=4)
        self.assertEqual(result['selection']['producer_check']['status'],'FAIL',result)
        self.assertEqual(result['status'],'FAIL')


    def test_staged_selector_combinations(self):
        for m in (1,2,3):
            for l in (1,2,3):
                with self.subTest(M=m,L=l):
                    result=self.run_array(f'staged_m{m}l{l}',selector_stages=m,segments=l)
                    self.assertEqual(result['status'],'PASS',result)
                    self.assertEqual(result['latency'],m+l-1)
                    self.assertEqual(sum(result['selector_group_bits']),2)

    def test_staged_nonzero_default_and_onehot(self):
        result=build_array(self.pe,self.proof,[MUX],'array_mux',5,8,2,self.root/'staged_n5',
                           default=(1,2,3),original_default=21,selector_stages=2,
                           selector_group_bits=[1,2],segments=3)
        self.assertEqual(result['status'],'PASS',result)
        mux=self.root/'staged_priority.sv'
        mux.write_text(MUX.read_text(encoding='utf-8').replace('if(sel==i)','if(sel[i])'),encoding='utf-8')
        for mode in ('onehot','onehot0'):
            result=self.run_array('staged_'+mode,mux,mode=mode,selector_stages=2,segments=2)
            self.assertEqual(result['status'],'PASS',result)

    def test_staged_selection_bits_negative_control(self):
        from bear.array import _alignment, _sat, _write
        out=self.root/'negative_selection_bits'
        out.mkdir()
        good=readout_rtl(4,8,2,'array_mux',selector_stages=2)
        bad=good.replace('select_bits_0[0:0]', 'select_index[1:1]')
        self.assertNotEqual(good,bad)
        _write(out/'bad.sv',bad)
        _write(out/'ref.sv',readout_rtl(4,8,2,'array_mux').replace('module bear_array_readout(', 'module bear_array_reference('))
        _write(out/'miter.sv',_alignment(4,8,2,3,2))
        result=_sat(out,'negative',[MUX,out/'bad.sv',out/'ref.sv',out/'miter.sv'],
                    'array_alignment','sat -seq 7 -prove-asserts -set-assumes -show-inputs -dump_json counterexample.json',120)
        self.assertEqual(result['status'],'FAIL',result)
        self.assertTrue((out/'counterexample.json').exists())

    def test_three_nonempty_selector_levels(self):
        # N=8 consumes a real bit at all three levels (N=4 also tests zero-bit levels).
        for segments in (1,2,3):
            result=build_array(self.pe,self.proof,[MUX],'array_mux',8,8,2,
                               self.root/f'three_nonempty_l{segments}',selector_stages=3,
                               selector_group_bits=[1,1,1],segments=segments)
            self.assertEqual(result['status'],'PASS',result)
            self.assertEqual(result['latency'],segments+2)


if __name__=='__main__':unittest.main()
