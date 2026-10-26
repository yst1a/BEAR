"""Signed product boundaries, certificate domain checks, and end-to-end proofs."""
import importlib.util
import os
from pathlib import Path
import tempfile
import unittest

from bear.input_interface import product_interface, accumulator_interface_rtl
from bear.extract import NetGraph, detect_design
from bear.reencode import block_accumulator_rtl, rewrite_design
from bear.runtime import NATIVE, run_guarded, tool
from bear.verify import prove


def certificate(width=8, k=2):
    B = 1 << k
    return dict(module="arith_cell", status="PASS", width=width,
                output_width=width, input_widths=[width,width],
                input_ports=["a","b"], output_port="y", low_local=True, k=k,
                phi=[[a|b for b in range(B)] for a in range(B)],
                kappa=[[(a&b)>>(k-1) for b in range(B)] for a in range(B)])


ADDER = """module arith_cell(input [7:0] a,b,output [7:0] y);
wire [5:0] high=a[7:2]+b[7:2]+(a[1]&b[1]);
assign y={high,(a[1:0]|b[1:0])}; endmodule
"""


class SignedInputTests(unittest.TestCase):
    def test_interface_rejects_inconsistent_or_truncated_contracts(self):
        for kw in (dict(width=15),dict(mode="BAD"),dict(mode="ACC",weight_signed=True),
                   dict(mode="MAC",product_signed=True),
                   dict(mode="MAC",weight_signed=True),dict(product_signed=1)):
            with self.subTest(kw=kw),self.assertRaises(ValueError):
                product_interface(**kw)
        with self.assertRaises(ValueError):accumulator_interface_rtl("bad;name","adder")

    def test_elaborated_sign_extension_is_distinguished_from_zero_extension(self):
        p=[2,3,4,5]
        g=NetGraph(dict(ports={"prod_in":dict(direction="input",bits=p)},cells={}),[])
        self.assertEqual(g.operand_interface(p+[5]*4)["extension"],"sign")
        self.assertEqual(g.operand_interface(p+["0"]*4)["extension"],"zero")
        self.assertEqual(g.operand_interface(p+[4]*4)["extension"],"bit_vector")

    @unittest.skipUnless(importlib.util.find_spec("torch"),"Optional PyTorch export dependency")
    def test_signed_product_model_all_bit_patterns_and_wrap(self):
        import torch
        from bear.export.cert_runtime import CertificateAccumulator
        mod=CertificateAccumulator(certificate())
        # All 256 states x all 16 narrow products, including both signs.
        a=torch.arange(256,dtype=torch.int32)[:,None]
        bits=torch.arange(16,dtype=torch.int32)[None,:]
        signed=torch.where(bits>=8,bits-16,bits)
        for flag in (False,True):
            p=(signed if flag else bits).long()&255
            expected=(4*((a.long()>>2)+(p>>2)+((a.long()&p)>>1&1))|((a.long()|p)&3))&255
            expected=torch.where(expected>=128,expected-256,expected).int()
            got=mod.product_step(a,bits,4,signed_input=flag)
            self.assertTrue(torch.equal(got,expected))
        self.assertTrue(torch.equal(mod.product_step(a,bits,4,signed_input=True),
                                    mod.product_step(a,signed,4,signed_input=True)))
        self.assertFalse(torch.equal(mod.product_step(a,bits,4,signed_input=True),
                                     mod.product_step(a,bits,4,signed_input=False)))

    @unittest.skipUnless(importlib.util.find_spec("torch"),"Optional PyTorch export dependency")
    def test_product_model_does_not_silently_change_certificate_domain(self):
        import torch
        from bear.export.cert_runtime import CertificateAccumulator, UnsupportedCertificate
        c=certificate();c["input_widths"]=[8,4]
        mod=CertificateAccumulator(c);v=torch.tensor([0],dtype=torch.int32)
        with self.assertRaises(UnsupportedCertificate):mod.product_step(v,v,4,signed_input=True)
        mod=CertificateAccumulator(certificate())
        for w in (0,9,True):
            with self.assertRaises(ValueError):mod.product_step(v,v,w)

    @unittest.skipUnless(os.getenv("BEAR_INTEGRATION"),"Requires the optional integration toolchain")
    def test_signed_acc_and_mac_reencoding_full_prefix(self):
        root=Path(tempfile.mkdtemp(prefix="signed_proof_",dir=NATIVE))
        cert=certificate()
        for mode in ("ACC","MAC"):
            source=root/(mode+".v")
            source.write_text(ADDER+accumulator_interface_rtl("top","arith_cell",8,2,
                              mode=mode,product_signed=True,weight_signed=(mode=="MAC")),encoding="utf-8")
            detection=detect_design([source],"top",[cert],root/(mode+"_detect"))
            self.assertEqual(detection["status"],"PASS")
            extensions=[v["extension"] for s in detection["stages"] for v in s["operand_interfaces"]]
            self.assertIn("sign",extensions)
            for variant in ("T_cs","T_cs_pp","T_cs_sel","T_blk_q2","T_blk_q4"):
                with self.subTest(mode=mode,variant=variant):
                    generated=rewrite_design(detection,[cert],root/(mode+"_"+variant),variant)
                    self.assertEqual(generated["status"],"GENERATED",generated)
                    result=prove(source,generated["rtl"],"top",root/(mode+"_"+variant+"_proof"),
                                 refinement=generated["refinement"],cycles=1000,formal_engine="yosys_sat",timeout=90)
                    self.assertEqual(result["status"],"PASS",result.get("refinement_skipped"))
                    self.assertEqual(result["scope_status"],"FULL_PREFIX")

    @unittest.skipUnless(os.getenv("BEAR_INTEGRATION"),"Requires the optional integration toolchain")
    def test_signed_and_unsigned_product_interfaces_are_not_equivalent(self):
        root=Path(tempfile.mkdtemp(prefix="signed_negative_",dir=NATIVE))
        a=root/"signed.v";b=root/"unsigned.v"
        a.write_text(ADDER+accumulator_interface_rtl("top","arith_cell",8,2,product_signed=True),encoding="utf-8")
        b.write_text(ADDER+accumulator_interface_rtl("top","arith_cell",8,2),encoding="utf-8")
        result=prove(a,b,"top",root/"proof",cycles=1000,formal_engine="yosys_sat",timeout=90)
        self.assertEqual(result["formal"]["status"],"FAIL")
        self.assertEqual(result["simulation"]["status"],"FAIL")

    @unittest.skipUnless(os.getenv("BEAR_INTEGRATION"),"Requires the optional integration toolchain")
    def test_standalone_signed_block_preserves_negative_updates_and_resets(self):
        root=Path(tempfile.mkdtemp(prefix="signed_block_",dir=NATIVE))
        for q in (2,4):
            rtl=root/f"q{q}.v";rtl.write_text(block_accumulator_rtl("top",q,2,8,4,signed_input=True),encoding="utf-8")
            vectors=[];state=0
            for i in range(272):
                bits=(i*7)&15;reset=(i%37!=0);value=bits-16 if bits>=8 else bits
                b=value&255
                state=(4*((state>>2)+(b>>2)+((state&b)>>1&1))|((state|b)&3))&255 if reset else 0
                vectors.append(f"rst_n=1'b{int(reset)};x=4'd{bits};#5;clk=1;#5;if(y!==8'd{state})$fatal(1,\"cycle {i}\");clk=0;")
            tb=root/f"tb{q}.v"
            tb.write_text("module tb;reg clk=0,rst_n=1;reg [3:0] x=0;wire [7:0] y;top dut(clk,rst_n,x,y);initial begin\n"+
                          "\n".join(vectors)+"\n$display(\"SIGNED_BLOCK_PASS\");$finish;end endmodule\n",encoding="utf-8")
            build=run_guarded([tool("iverilog"),"-g2012","-s","tb","-o",root/f"q{q}.vvp",rtl,tb],cwd=root,log=root/f"compile{q}.log")
            self.assertEqual(build["returncode"],0,build["stdout"])
            sim=run_guarded([tool("vvp"),root/f"q{q}.vvp"],cwd=root,log=root/f"sim{q}.log")
            self.assertEqual(sim["returncode"],0,sim["stdout"])
            self.assertIn("SIGNED_BLOCK_PASS",sim["stdout"])


if __name__ == "__main__":unittest.main()
