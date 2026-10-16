"""Test test detect rewrite."""
import json
from pathlib import Path
import tempfile
import unittest
from bear.extract import analyze_netlist, detect_design, NetGraph
from bear.reencode import rewrite_design, _low_function, _unsigned_bound, Unsupported


def loa_certificate(width=8, k=2):
    B = 1 << k
    return {"module": "arith_cell", "width": width, "output_width": width,
            "input_ports": ["lhs", "rhs"], "output_port": "result", "low_local": True, "k": k,
            "phi": [[a | b for b in range(B)] for a in range(B)],
            "kappa": [[((a >> (k-1)) & (b >> (k-1))) for b in range(B)] for a in range(B)],
            "t1": {"associative": True, "commutative": True}, "t2": {"row_quotient_m": B}}


RTL = r'''module arith_cell(input [7:0] lhs,rhs,output [7:0] result);
assign result={((lhs[7:2]+rhs[7:2])+(lhs[1]&rhs[1])),(lhs[1:0]|rhs[1:0])};
endmodule
module natural(input clk,rst_n,clear,load,en,horner,input [7:0] x,y,z,output [7:0] acc_out,pipe_out,comb_out);
reg [7:0] accumulated,stage0,stage1;
wire [7:0] shifted=horner?{accumulated[6:0],1'b0}:accumulated;
wire [7:0] nacc,ns0,ns1,c0;
arith_cell aa(.lhs(shifted),.rhs(x),.result(nacc));
arith_cell p0(.lhs(x),.rhs(y),.result(ns0));
arith_cell p1(.lhs(stage0),.rhs(z),.result(ns1));
arith_cell c_first(.lhs(x),.rhs(y),.result(c0));
arith_cell c_last(.lhs(c0),.rhs(z),.result(comb_out));
always @(posedge clk or negedge rst_n)
 if(!rst_n) accumulated<=0;
 else if(clear) accumulated<=0;
 else if(load) accumulated<=y;
 else if(en) accumulated<=nacc;
always @(posedge clk or negedge rst_n)
 if(!rst_n) begin stage0<=0;stage1<=0;end
 else if(en) begin stage0<=ns0;stage1<=ns1;end
assign acc_out=accumulated;assign pipe_out=stage1;
endmodule
'''


class DetectRewriteTests(unittest.TestCase):
    def test_low_tables_reject_multi_bit_carry(self):
        cert = loa_certificate()
        cert["kappa"][0][0] = 2
        with self.assertRaisesRegex(ValueError, "MULTIBIT"):
            _low_function(cert)

    def test_register_name_has_no_effect(self):
        q, y, x = list(range(2, 10)), list(range(10, 18)), list(range(18, 26))
        net = {"modules": {"top": {"cells": {
            "unrelated_opaque_name": {"type": "$dff", "parameters": {"CLK_POLARITY": "1"},
                                      "port_directions": {"Q": "output", "D": "input", "CLK": "input"},
                                      "connections": {"Q": q, "D": y, "CLK": [1]}},
            "not_named_accumulator": {"type": "arith_cell", "parameters": {},
                                      "port_directions": {"lhs": "input", "rhs": "input", "result": "output"},
                                      "connections": {"lhs": q, "rhs": x, "result": y}}}, "netnames": {}}}}
        d = analyze_netlist(net, "top", [loa_certificate()])
        self.assertEqual([s["kind"] for s in d["structures"]], ["ACC"])
        self.assertTrue(d["structures"][0]["rewritable"])
        bad = loa_certificate()
        bad["low_local"] = False
        self.assertFalse(analyze_netlist(net, "top", [bad])["structures"][0]["rewritable"])

    def test_horner_concat_and_conditional_mux(self):
        q = list(range(2, 10))
        shifted = list(range(10, 18))
        module = {"cells": {
            "reg": {"type": "$dff", "connections": {"Q": q, "D": shifted, "CLK": [1]},
                    "port_directions": {"Q": "output", "D": "input", "CLK": "input"}},
            "mux": {"type": "$mux", "connections": {"Y": shifted, "A": q, "B": ["0"]+q[:-1], "S": [20]},
                    "port_directions": {"Y": "output", "A": "input", "B": "input", "S": "input"}}}}
        path = NetGraph(module, []).state_path(shifted)
        self.assertEqual(path["kind"], "mux")
        self.assertEqual(path["b"]["shift"], 1)

    def test_parametric_certificate_is_bound_to_actual_widths(self):
        q,y,x=list(range(2,10)),list(range(10,18)),list(range(18,22))
        cert={**loa_certificate(),'module':'wrapper','match_module':'base','input_ports':['a','b'],
              'output_port':'y','input_widths':[4,8],'parameters':{'LEFT':4,'RIGHT':8}}
        module={'cells':{'r':{'type':'$dff','parameters':{},'connections':{'Q':q,'D':y,'CLK':[1]},
                             'port_directions':{'Q':'output','D':'input','CLK':'input'}},
                         'c':{'type':'$paramod$base','parameters':{},'connections':{'a':x,'b':q,'c':y},
                              'port_directions':{'a':'input','b':'input','c':'output'}}},'netnames':{}}
        metadata={'$paramod$base':{'attributes':{'hdlname':'base'},
                                  'parameter_default_values':{'LEFT':'00000100','RIGHT':'00001000'}}}
        d=analyze_netlist({'modules':{'top':module,**metadata}},'top',[cert])
        self.assertEqual(d['adder_count'],1)
        self.assertTrue(d['structures'][0]['rewritable'])
        cert['parameters']['LEFT']=5
        self.assertEqual(analyze_netlist({'modules':{'top':module,**metadata}},'top',[cert])['adder_count'],0)

    def test_signed_narrow_shift_bound_is_not_unsigned_60(self):
        p=list(range(2,6));y=list(range(6,14));z=list(range(14,22))
        module={'cells':{'shift':{'type':'$sshl','parameters':{'A_SIGNED':'1'},
                                 'connections':{'A':p,'B':['0','1'],'Y':y},
                                 'port_directions':{'A':'input','B':'input','Y':'output'}},
                         'consumer':{'type':'$add','parameters':{},
                                     'connections':{'A':y,'B':['1']+['0']*7,'Y':z},
                                     'port_directions':{'A':'input','B':'input','Y':'output'}}}}
        graph=NetGraph(module,[])
        self.assertGreaterEqual(_unsigned_bound(graph,y),252)
        self.assertGreaterEqual(_unsigned_bound(graph,z),253)


def integration(out_dir):
    from bear.runtime import run_guarded, tool
    out = Path(out_dir)
    out.mkdir(parents=True, exist_ok=True)
    original = out / "natural.v"
    original.write_text(RTL, encoding='utf-8')
    certificate = loa_certificate()
    detection = detect_design([original], "natural", [certificate], out / "detect")
    assert detection["status"] == "PASS", detection
    kinds = [s["kind"] for s in detection["structures"]]
    assert kinds.count("ACC") == 1 and kinds.count("PIPE") == 2 and kinds.count("CHAIN") == 1, kinds
    results = {}
    for variant in ("T_cs", "T1", "T2"):
        result = rewrite_design(detection, [certificate], out / variant, variant)
        assert result["status"] == "GENERATED", result
        candidate = Path(result["rtl"]).read_text(encoding='utf-8').replace("module natural(", "module candidate(", 1)
        (out / (variant + "_pair.v")).write_text(RTL + candidate, encoding='utf-8')
        tb = r'''module tb;
reg clk=0,rst_n=1,clear=0,load=0,en=0,horner=0;reg [7:0] x=0,y=0,z=0;
wire [7:0] a,b,c,aa,bb,cc;
natural refdut(clk,rst_n,clear,load,en,horner,x,y,z,a,b,c);
candidate newdut(clk,rst_n,clear,load,en,horner,x,y,z,aa,bb,cc);
integer i;integer seed=20261007;
initial begin #1;rst_n=0;#1;rst_n=1;
for(i=0;i<100128;i=i+1) begin
 clk=0;en=$random(seed);horner=$random(seed);load=(i%19==0);clear=(i%137==0);
 x=$random(seed);y=$random(seed);z=$random(seed);
 if(i<256)begin x=i;y=255-i;z=(1<<(i%8))-1;end
 if(i%1013==0)begin rst_n=0;#1;rst_n=1;end
 #2;clk=1;#2;
 if({a,b,c}!=={aa,bb,cc})begin $display("FIRST_FAIL cycle=%0d original=%h candidate=%h",i,{a,b,c},{aa,bb,cc});$fatal(1);end
end
$display("SIM_PASS cycles=%0d",i);$finish;end
endmodule
'''
        tbfile = out / (variant + "_tb.v")
        tbfile.write_text(tb, encoding='utf-8')
        exe = out / (variant + ".vvp")
        compile = run_guarded([tool("iverilog"), "-g2012", "-s", "tb", "-o", exe, out / (variant + "_pair.v"), tbfile], out,
                              log=out / (variant + "_compile.log"), timeout=120)
        assert compile["returncode"] == 0, compile
        sim = run_guarded([tool("vvp"), exe], out, log=out / (variant + "_sim.log"), timeout=120)
        assert sim["returncode"] == 0 and "SIM_PASS" in sim["stdout"], sim
        results[variant] = {"rewrite": result, "simulation": sim}
    (out / "INTEGRATION.json").write_text(json.dumps({"detection": detection, "results": results}, ensure_ascii=False, indent=2), encoding='utf-8')
    return results


if __name__ == "__main__":
    import sys
    if len(sys.argv) > 1 and sys.argv[1] == "integration":
        print(json.dumps(integration(sys.argv[2]), ensure_ascii=False, indent=2))
    else:
        unittest.main()

