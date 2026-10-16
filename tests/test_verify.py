"""Test test prove."""
import json
import os
from pathlib import Path
import tempfile
import unittest

from bear.verify import prove, make_testbench
from bear.runtime import NATIVE


class ProveTests(unittest.TestCase):
    def test_wide_boundary_stimulus_and_dump_scope(self):
        ports={'clk':{'direction':'input','bits':[1]},
               'rst_n':{'direction':'input','bits':[2]},
               'x':{'direction':'input','bits':list(range(3,99))},
               'y':{'direction':'output','bits':list(range(100,196))}}
        text=make_testbench(ports,True,4096,20261007,dump_path='activity.vcd',candidate_instance='dut')
        self.assertIn('apx_candidate dut',text)
        self.assertIn('$dumpvars(0,tb)',text)
        self.assertIn('$urandom,$urandom,$urandom',text)
        self.assertIn('BEAR_MISMATCH',text)

    @unittest.skipUnless(os.getenv('BEAR_INTEGRATION'),'Requires the optional integration toolchain')
    def test_combinational_identity_and_real_counterexample(self):
        root=Path(tempfile.mkdtemp(prefix='prove_',dir=NATIVE))
        original=root/'original.v'
        original.write_text('module top(input [7:0] a,b,output [7:0] y); assign y=a+b; endmodule\n', encoding='utf-8')
        same=root/'same.v'
        same.write_text('module top(input [7:0] a,b,output [7:0] y); assign y=b+a; endmodule\n', encoding='utf-8')
        wrong=root/'wrong.v'
        wrong.write_text('module top(input [7:0] a,b,output [7:0] y); assign y=a+b+1; endmodule\n', encoding='utf-8')
        a=prove(original,same,'top',root/'same_proof',timeout=60)
        b=prove(original,wrong,'top',root/'wrong_proof',timeout=60)
        self.assertEqual(a['formal']['status'],'PASS')
        self.assertEqual(a['simulation']['cycles_or_vectors'],100000)
        self.assertEqual(b['formal']['status'],'FAIL')
        self.assertEqual(b['simulation']['status'],'FAIL')

    @unittest.skipUnless(os.getenv('BEAR_INTEGRATION'),'Requires the optional integration toolchain')
    def test_sequential_reset_induction(self):
        root=Path(tempfile.mkdtemp(prefix='prove_seq_',dir=NATIVE))
        text='''module top(input clk,rst_n,start,input [7:0] x,output reg [7:0] y);
always @(posedge clk or negedge rst_n) if(!rst_n)y<=0; else if(start)y<=x; else y<=y+x;
endmodule
'''
        o=root/'original.v';t=root/'same.v';o.write_text(text, encoding='utf-8');t.write_text(text, encoding='utf-8')
        r=prove(o,t,'top',root/'proof',timeout=90)
        self.assertEqual(r['formal']['status'],'PASS')
        self.assertEqual(r['simulation']['status'],'PASS')
        self.assertEqual(r['simulation']['cycles_or_vectors'],100000)

    @unittest.skipUnless(os.getenv('BEAR_INTEGRATION'),'Requires the optional integration toolchain')
    def test_initial_prefix_mismatch_is_rejected(self):
        root=Path(tempfile.mkdtemp(prefix='prove_prefix_',dir=NATIVE))
        o=root/'original.v';t=root/'wrong_prefix.v'
        o.write_text('''module top(input clk,rst_n,input [7:0] x,output reg [7:0] y);
always @(posedge clk or negedge rst_n) if(!rst_n)y<=0; else y<=x;
endmodule
''', encoding='utf-8')
        t.write_text('''module top(input clk,rst_n,input [7:0] x,output [7:0] y);
reg [7:0] q; reg [1:0] age=0;
always @(posedge clk) if(age<3)age<=age+1;
always @(posedge clk or negedge rst_n) if(!rst_n)q<=0; else q<=x;
// Change only the first three outputs to test initial-prefix coverage.
assign y=(age<3)?(q^8'h01):q;
endmodule
''', encoding='utf-8')
        r=prove(o,t,'top',root/'proof',timeout=90)
        self.assertEqual(r['formal']['status'],'FAIL')
        self.assertEqual(r['simulation']['status'],'FAIL')
        self.assertIn('i=0',r['simulation']['execution']['stdout'])

    @unittest.skipUnless(os.getenv('BEAR_INTEGRATION'),'Requires the optional integration toolchain')
    def test_no_reset_arbitrary_initial_state_correspondence(self):
        root=Path(tempfile.mkdtemp(prefix='prove_norst_',dir=NATIVE))
        text='''module top(input clk,input [7:0] x,output [7:0] y);
reg [7:0] a,b;
always @(posedge clk) begin a<=x;b<=a;end
assign y=b;
endmodule
'''
        o=root/'original.v';t=root/'same.v';o.write_text(text, encoding='utf-8');t.write_text(text, encoding='utf-8')
        r=prove(o,t,'top',root/'proof',timeout=90)
        self.assertEqual(r['scope_status'],'FULL_PREFIX')
        self.assertEqual(r['initial_consistency']['status'],'PASS')
        self.assertEqual(r['formal']['status'],'PASS')
        self.assertEqual(r['simulation']['cycles_or_vectors'],100000)

    @unittest.skipUnless(os.getenv('BEAR_INTEGRATION'),'Requires the optional integration toolchain')
    def test_no_reset_candidate_initial_constant_cannot_shrink_domain(self):
        root=Path(tempfile.mkdtemp(prefix='prove_init_domain_',dir=NATIVE))
        o=root/'original.v';t=root/'initial_constant.v'
        o.write_text('module top(input clk,input [7:0] x,output reg [7:0] y); always @(posedge clk)y<=x; endmodule\n', encoding='utf-8')
        t.write_text('module top(input clk,input [7:0] x,output reg [7:0] y=0); always @(posedge clk)y<=x; endmodule\n', encoding='utf-8')
        r=prove(o,t,'top',root/'proof',timeout=90)
        # test test prove implementation.
        self.assertEqual(r['scope_status'],'INITIAL_DOMAIN_NOT_COVERED')
        self.assertNotEqual(r['status'],'PASS')


if __name__=='__main__':
    unittest.main()

