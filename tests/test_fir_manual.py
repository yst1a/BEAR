"""Test test fir manual."""
from pathlib import Path
import random
import sys
import unittest


def manual_fir_rtl(top, taps=16, width=12, k=4, fused_output=False):
    """Test test fir manual."""
    if not (taps >= 3 and 0 < k < width):
        raise ValueError("Require taps>=3 and 0<k<width")
    h = width-k
    L = [f"module {top}(input clk,rst_n,input [{width-1}:0] x,output [{width-1}:0] y);"]
    for i in range(taps):
        L.append(f"wire [{width-1}:0] p{i}=x*{i%7+1};")
    for i in range(taps-2):
        L += [f"reg [{h-1}:0] S{i},C{i};", f"reg [{k-1}:0] l{i};"]
    tail = taps-2
    L.append(f"reg [{width-1}:0] tail;")
    for i in range(taps-2):
        if i == taps-3:
            aa, bb, ll = f"tail[{width-1}:{k}]", f"{h}'b0", f"tail[{k-1}:0]"
        else:
            aa, bb, ll = f"S{i+1}", f"C{i+1}", f"l{i+1}"
        product = f"p{i+1}"
        L += [f"wire [{k-1}:0] nl{i}={ll}|{product}[{k-1}:0];",
              f"wire kap{i}={ll}[{k-1}] & {product}[{k-1}];" if i != taps-3 else
              f"wire kap{i}=tail[{k-1}] & {product}[{k-1}];",
              f"wire [{h-1}:0] ns{i}=({aa})^({bb})^{product}[{width-1}:{k}];",
              f"wire [{h-1}:0] maj{i}=(({aa})&({bb}))|(({aa})&{product}[{width-1}:{k}])|(({bb})&{product}[{width-1}:{k}]);",
              f"wire [{h-1}:0] nc{i}={{maj{i}[{h-2}:0],kap{i}}};" if h>1 else
              f"wire [0:0] nc{i}=kap{i};",
              f"always @(posedge clk or negedge rst_n) if(!rst_n) begin l{i}<=0;S{i}<=0;C{i}<=0;end else begin l{i}<=nl{i};S{i}<=ns{i};C{i}<=nc{i};end"]
    L.append(f"always @(posedge clk or negedge rst_n) if(!rst_n) tail<=0;else tail<=p{taps-1};")
    L += [f"wire [{k-1}:0] out_l=l0|p0[{k-1}:0];", f"wire out_kap=l0[{k-1}]&p0[{k-1}];"]
    if fused_output:
        L += [f"wire [{h-1}:0] out_s=S0^C0^p0[{width-1}:{k}];",
              f"wire [{h-1}:0] out_m=(S0&C0)|(S0&p0[{width-1}:{k}])|(C0&p0[{width-1}:{k}]);",
              f"wire [{h-1}:0] out_c={{out_m[{h-2}:0],out_kap}};" if h>1 else
              "wire [0:0] out_c=out_kap;",
              f"wire [{h-1}:0] out_h=out_s+out_c;"]
    else:
        L += [f"wire [{h-1}:0] decoded=S0+C0;",
              f"wire [{h-1}:0] out_h=decoded+p0[{width-1}:{k}]+out_kap;"]
    L += ["assign y={out_h,out_l};", "endmodule"]
    return '\n'.join(L)+'\n'


def loa(a, b, width, k):
    mask=(1<<k)-1
    return ((((a>>k)+(b>>k)+((a&b)>>(k-1)&1))<<k)|((a|b)&mask))&((1<<width)-1)


class FirManualTests(unittest.TestCase):
    def test_csa_matches_loa_for_all_small_redundant_states(self):
        w,k=5,2
        hm=(1<<(w-k))-1
        for s in range(hm+1):
            for c in range(hm+1):
                for low in range(1<<k):
                    for p in range(1<<w):
                        q=(((s+c)&hm)<<k)|low
                        high=p>>k
                        kap=((low&p)>>(k-1))&1
                        ns=s^c^high
                        nc=(((s&c)|(s&high)|(c&high))<<1|kap)&hm
                        represented=(((ns+nc)&hm)<<k)|((low|p)&((1<<k)-1))
                        self.assertEqual(represented,loa(p,q,w,k))

    def test_transposed_fir_latency_and_asynchronous_reset(self):
        rng=random.Random(20261007)
        for m,w,k in ((4,5,2),(16,12,4),(64,16,4)):
            hm=(1<<(w-k))-1
            q=[0]*(m-1)
            states=[(0,0,0)]*(m-2)
            tail=0
            for cycle in range(2048):
                x=rng.randrange(1<<w)
                if cycle%127==0:
                    q=[0]*(m-1);states=[(0,0,0)]*(m-2);tail=0
                p=[(x*(i%7+1))&((1<<w)-1) for i in range(m)]
                s,c,l=states[0]
                self.assertEqual(loa(p[0],q[0],w,k),loa(p[0],(((s+c)&hm)<<k)|l,w,k))
                nq=[loa(p[i+1],q[i+1],w,k) for i in range(m-2)]+[p[-1]]
                updated=[]
                for i in range(m-2):
                    s,c,l=states[i+1] if i<m-3 else (tail>>k,0,tail&((1<<k)-1))
                    a=p[i+1]>>k
                    kap=((l&p[i+1])>>(k-1))&1
                    updated.append((s^c^a,(((s&c)|(s&a)|(c&a))<<1|kap)&hm,(l|p[i+1])&((1<<k)-1)))
                states,tail,q=updated,p[-1],nq


def integration(out):
    """Test test fir manual."""
    from bear.runtime import run_guarded, tool
    out=Path(out);out.mkdir(parents=True,exist_ok=True)
    ref='''module reference(input clk,rst_n,input [11:0] x,output [11:0] y);
reg [11:0] q[0:14];wire [11:0] p[0:15];wire [11:0] n[0:14];genvar j;
function [11:0] add(input [11:0] a,b);reg [7:0] hi;begin hi=a[11:4]+b[11:4]+(a[3]&b[3]);add={hi,a[3:0]|b[3:0]};end endfunction
generate for(j=0;j<16;j=j+1)begin assign p[j]=x*(j%7+1);end
for(j=0;j<15;j=j+1)begin assign n[j]=add(p[j],q[j]);end endgenerate
integer z;always @(posedge clk or negedge rst_n)if(!rst_n)for(z=0;z<15;z=z+1)q[z]<=0;else begin for(z=0;z<14;z=z+1)q[z]<=n[z+1];q[14]<=p[15];end
assign y=n[0];endmodule
'''
    tb='''module tb;reg clk=0,rst_n=1;reg [11:0] x=0;wire [11:0] yr,ym,yf;
reference a(clk,rst_n,x,yr);manual b(clk,rst_n,x,ym);fused c(clk,rst_n,x,yf);
integer i,seed=20261007;task check;begin #1;if(yr!==ym || yr!==yf)begin $display("FIRST_FAIL i=%d ref=%h manual=%h fused=%h",i,yr,ym,yf);$fatal(1);end end endtask
initial begin #1;rst_n=0;check;rst_n=1;
for(i=0;i<100128;i=i+1)begin clk=0;x=$random(seed);if(i<4096)x=i;check;
if(i%1013==0)begin rst_n=0;check;rst_n=1;check;end
clk=1;check;x=$random(seed);check;end
$display("SIM_PASS 100128 cycles; two observations per cycle; asynchronous reset");$finish;end endmodule
'''
    rtl=out/'fir_pair.v';rtl.write_text(ref+manual_fir_rtl('manual')+manual_fir_rtl('fused',fused_output=True)+tb, encoding='utf-8')
    exe=out/'fir.vvp'
    rec=run_guarded([str(tool('iverilog')),'-g2012','-s','tb','-o',str(exe),str(rtl)],cwd=out,log=out/'compile.log',timeout=60)
    if rec['returncode']!=0:raise RuntimeError(rec)
    rec=run_guarded([str(tool('vvp')),str(exe)],cwd=out,log=out/'simulation.log',timeout=120)
    if rec['returncode']!=0:raise RuntimeError(rec)
    print((out/'simulation.log').read_text(encoding='utf-8'))


if __name__=='__main__':
    if len(sys.argv)>1 and not sys.argv[1].startswith('-'):
        integration(sys.argv[1])
    else:
        unittest.main()

