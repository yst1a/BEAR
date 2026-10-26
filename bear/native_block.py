"""Native-leaf block recoding with named state refinement."""
import re,json,time
from pathlib import Path
from .runtime import run_guarded,tool,sha
from .extract import _quote

def save(p,x):
    p=Path(p);p.parent.mkdir(parents=True,exist_ok=True);q=p.with_name(p.name+'.tmp')
    q.write_text(x if isinstance(x,str) else json.dumps(x,ensure_ascii=False,indent=2),encoding='utf-8',newline='\n');q.replace(p)

def strip_top(text,top):
    return re.sub(r'\bmodule\s+'+re.escape(top)+r'\b.*?endmodule','',text,flags=re.S)

def ff_blk_text(top,leaf,ks,b,o_text,needs_first):
    w=32;h=w-ks
    text=strip_top(o_text,top)
    lines=[f'module {top}(input clk,rst_n,input [15:0] prod_in,output [31:0] y);','wire [15:0] prod=prod_in;','wire [31:0] x={{16{prod[15]}},prod};',
           f'reg [{h-1}:0] S;',f'wire [{h-1}:0] xh=x[{w-1}:{ks}];',f'reg [{ks-1}:0] l;','wire [31:0] native_low;',
           f"{leaf} low_impl(.a({{{32-ks}'d0,l}}),.b({{{32-ks}'d0,x[{ks-1}:0]}}),.y(native_low));",
           f'wire [{ks-1}:0] next_l=native_low[{ks-1}:0];',f'wire kappa=native_low[{ks}];']
    if needs_first:lines.append('reg first;')
    n=(h+b-1)//b
    lines+=[f'reg [{n-1}:0] cb;',f'wire [{h-1}:0] Cw;']
    updates=[]
    for j in range(n):
        lo=j*b;hi=min(h,lo+b)-1;bw=hi-lo+1;cin='kappa' if not j else f'cb[{j}]'
        lines+=[f"wire [{bw}:0] t_{j}={{1'b0,S[{hi}:{lo}]}}+{{1'b0,xh[{hi}:{lo}]}}+{cin};",f"assign Cw[{lo}]="+("1'b0;" if not j else f'cb[{j}];')]
        if bw>1:lines+=[f"assign Cw[{hi}:{lo+1}]='0;"]
        updates+=[f'S[{hi}:{lo}]<=t_{j}[{bw-1}:0];']
        if j<n-1:updates+=[f'cb[{j+1}]<=t_{j}[{bw}];']
    updates+=["cb[0]<=1'b0;",'l<=next_l;']
    if needs_first:
        lines+=['always @(posedge clk or negedge rst_n) begin',f"if(!rst_n) begin S<='0; cb<='0; l<='0; first<=1'b1; end else begin",
                "first<=1'b0;",f"if(first) begin S<=xh; cb<='0; l<=x[{ks-1}:0]; end else begin"]+updates+['end','end end']
    else:
        lines+=['always @(posedge clk or negedge rst_n) begin',f"if(!rst_n) begin S<='0; cb<='0; l<='0; end else begin"]+updates+['end end']
    lines+=[f'wire [{h-1}:0] decoded=S+Cw;','assign y={decoded,l};','endmodule']
    return text+'\n'+'\n'.join(lines)+'\n'


def rewrite_native_block(detection,certificates,out_dir,variant,runner=None,yosys=None):
    started=time.monotonic();out=Path(out_dir).resolve();out.mkdir(parents=True,exist_ok=True)
    runner=runner or run_guarded;yosys=yosys or tool('yosys');top=detection['top']
    def skip(reason):return dict(status='SKIPPED',variant=variant,reason=reason)
    if detection.get('status')!='PASS':return skip('Extraction did not pass')
    stages=[s for s in detection.get('structures',[]) if s['kind']=='ACC' and s.get('rewritable')]
    if len(stages)!=1:return skip('Native block recoding requires one certified accumulator')
    text='\n'.join(Path(p).read_text(encoding='utf-8') for p in detection.get('sources',[]))
    topm=re.search(r'\bmodule\s+'+re.escape(top)+r'\b.*?endmodule',text,re.S)
    if not topm:return skip('Native source top is unavailable')
    body=topm[0]
    # This port implements the evaluated 32-bit signed-product ACC interface.
    net=json.loads(Path(detection['elaborated_json']).read_text(encoding='utf-8'))
    ports=net['modules'][top]['ports']
    expected={'clk':('input',1),'rst_n':('input',1),'prod_in':('input',16),'y':('output',32)}
    if {n:(p['direction'],len(p['bits'])) for n,p in ports.items()}!=expected:
        return skip('Native block recoding requires clk/rst_n/prod_in[15:0]/y[31:0]')
    leafm=re.search(r'(\w+)\s+\w+\s*\(\s*\.a\(acc\)',body)
    if not leafm:return skip('Native accumulator leaf binding is unsupported')
    leaf=leafm[1];cert=next((c for c in certificates if c.get('module')==leaf),None)
    if cert is None or not cert.get('low_local') or cert.get('status','PASS')!='PASS':return skip('No passing native leaf certificate')
    k=int(cert.get('k',cert.get('k_min',0)))
    # Preserve the implementation split, which may exceed the minimal certified split.
    leaftext=strip_top(text,top)
    splits=re.findall(r'IMPRECISE_PART\((\d+)\)',leaftext)
    if not splits:splits=[str(int(m)+1) for m in re.findall(r'wire\s+\[(\d+):0\]\s+g\s*=',leaftext)]
    if not splits:
        lm=re.search(r'_k(\d+)(?:_|$)',leaf)
        if lm:splits=[lm[1]]
    if splits and len(set(splits))==1:k=max(k,int(splits[0]))
    if not 0<k<32:return skip('No nonempty certified high region')
    needs_first=bool(re.search(r'\bfirst\b',body))
    rtl=out/'candidate.v';save(rtl,ff_blk_text(top,leaf,k,int(variant[-1]),text,needs_first))
    check=out/'check.ys';save(check,'read_verilog -sv '+_quote(rtl)+'\nhierarchy -check -top '+top+'\nproc\ncheck -assert\n')
    rec=runner([str(yosys),'-Q','-s',str(check)],cwd=out,log=out/'check.log',timeout=300)
    result=dict(status='GENERATED' if rec['returncode']==0 else rec['status'],variant=variant,rtl=str(rtl),
        rtl_sha256=sha(rtl),latency=0,readout_ports=[],needs_first=needs_first,split=k,tool=rec,
        refinement=[dict(original_q_name='acc',width=32,k=k,state_names=dict(os='S',oc='Cw',ol='l'))],
        elapsed_s=time.monotonic()-started,proof_status='NOT_ASSESSED')
    save(out/'REWRITE.json',result);return result
