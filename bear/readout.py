"""Balanced readout with explicit delayed output metadata."""
import json,re,time
from pathlib import Path
from .runtime import run_guarded,tool,sha
from .native_block import save

def load(p):return json.loads(Path(p).read_text(encoding='utf-8'))

def newbits(m,w,name):
 allb=[b for v in m['netnames'].values() for b in v['bits'] if isinstance(b,int)]+[b for v in m['ports'].values() for b in v['bits'] if isinstance(b,int)]
 start=max(allb+[1])+1;bits=list(range(start,start+w));m['netnames'][name]={'hide_name':0,'bits':bits,'attributes':{}};return bits

def binding(m,readouts):
 for n,v in m['netnames'].items():
  if not (n=='S' or n.endswith('.S')):continue
  pre=n[:-1];s=v['bits'];cv=m['netnames'].get(pre+'C') or m['netnames'].get(pre+'Cw')
  if cv is None:continue
  cb=cv['bits'];lv=m['netnames'].get(pre+'l') or m['netnames'].get(pre+'s') or m['netnames'].get(pre+'lo') or m['netnames'].get(pre+'low');lb=lv['bits'] if lv else []
  if len(s)!=len(cb):continue
  candidates=[m['netnames'].get(pre+x,{}).get('bits',[]) for x in ('decoded_hi','decoded','q','final_hi')]
  for ro in readouts:
   out=m['ports'][ro]['bits']
   if len(out)!=len(s)+len(lb):continue
   if lb and out[:len(lb)]!=lb:continue
   # Optimized prefix/select adders may fold the decoded_hi name.
   # Matching low bits and widths propose a binding; arbitrary-state SAT validates it.
   if (lb and out[:len(lb)]==lb) or any(out[len(lb):]==b[:len(s)] or out==b[:len(out)] for b in candidates):return {'port':ro,'S':s,'C':cb,'low':lb,'prefix':pre,'h':len(s),'k':len(lb)}
 raise ValueError('UNKNOWN_NON_DIRECT_READOUT_BINDING')


def readout_module(h,k,L,name='r2_readout',areset=0,breset=0,lreset=0,formal=False,resettable=True):
 w=h+k
 lines=[f'module {name}(input clk,rst_n,input [{h-1}:0] a,b,'+(f'input [{k-1}:0] low,' if k else '')+f'output [{w-1}:0] y);']
 resets=[];updates=[]
 for i in range(L):
  lo=(h*i+L-1)//L;hi=(h*(i+1)+L-1)//L;nb=hi-lo
  lines += [f'reg [{h-1}:0] ap{i},bp{i},sum{i}; reg cy{i};']
  if k:lines += [f'reg [{k-1}:0] lp{i};']
  aa='a' if i==0 else f'ap{i-1}';bb='b' if i==0 else f'bp{i-1}'
  ci="1'b0" if i==0 else f'cy{i-1}'
  prior=f"{h}'d0" if i==0 else f'sum{i-1}'
  if nb:
   lines += [f"wire [{nb}:0] t{i}={{1'b0,{aa}[{hi-1}:{lo}]}}+{{1'b0,{bb}[{hi-1}:{lo}]}}+{ci};"]
   expr=f'({prior} & {h}\'d{(1<<lo)-1}) | ({{{h-nb}\'d0,t{i}[{nb-1}:0]}} << {lo})' if h>nb else f't{i}[{nb-1}:0]'
   carry=f't{i}[{nb}]'
  else:expr=prior;carry=ci
  updates += [f'ap{i}<={aa}; bp{i}<={bb}; sum{i}<={expr}; cy{i}<={carry};']
  resets += [f"ap{i}<={h}'d{areset}; bp{i}<={h}'d{breset}; sum{i}<={h}'d{(areset+breset)&((1<<hi)-1)}; cy{i}<=1'd{(((areset&((1<<hi)-1))+(breset&((1<<hi)-1)))>>hi)&1};"]
  if k:
   updates += [f'lp{i}<='+('low' if i==0 else f'lp{i-1}')+';'];resets += [f"lp{i}<={k}'d{lreset};"]
 lines += (['always @(posedge clk or negedge rst_n) begin if(!rst_n) begin',*resets,'end else begin',*updates,'end end'] if resettable else ['always @(posedge clk) begin',*updates,'end'])
 lines += [f'assign y='+('{'+f'sum{L-1},lp{L-1}'+'};' if k else f'sum{L-1};')]
 if formal:
  # History stages share the pipeline reset semantics; induction constrains actual registers.
  for i in range(L):
   hi=(h*(i+1)+L-1)//L
   lines += [f'reg [{h-1}:0] ha{i},hb{i};']
   if k:lines += [f'reg [{k-1}:0] hl{i};']
   srca='a' if i==0 else f'ha{i-1}';srcb='b' if i==0 else f'hb{i-1}'
   body=f'ha{i}<={srca};hb{i}<={srcb};'+(f'hl{i}<='+('low' if i==0 else f'hl{i-1}')+';' if k else '')
   reset=f"ha{i}<={h}'d{areset};hb{i}<={h}'d{breset};"+(f"hl{i}<={k}'d{lreset};" if k else '')
   lines += [f'always @(posedge clk or negedge rst_n) if(!rst_n) begin {reset} end else begin {body} end' if resettable else f'always @(posedge clk) begin {body} end']
   lines += [f'wire [{hi}:0] hs{i}='+f"{{1'b0,ha{i}[{hi-1}:0]}}+{{1'b0,hb{i}[{hi-1}:0]}};"]
   valid='valid' if resettable else f'valid{i}'
   lines += [f'always @* if({valid}) begin assert(ap{i}==ha{i});assert(bp{i}==hb{i});assert(sum{i}[{hi-1}:0]==hs{i}[{hi-1}:0]);assert(cy{i}==hs{i}[{hi}]);'+(f'assert(lp{i}==hl{i});' if k else '')+'end']
  if resettable:lines += ["reg valid=0; always @(posedge clk) begin if(!valid) assume(!rst_n);valid<=1;end"]
  else:
   for i in range(L):lines += [f'reg valid{i}=0;always @(posedge clk) valid{i}<='+ ("1'b1;" if i==0 else f'valid{i-1};')]
  valid='valid' if resettable else f'valid{L-1}'
  lines += [f'wire [{h-1}:0] full=ha{L-1}+hb{L-1};',f'always @* if({valid}) assert(y=='+('{'+f'full,hl{L-1}'+'}' if k else 'full')+');']
 return '\n'.join(lines+['endmodule',''])


def pipeline_candidate(base,top,L,out_dir,*,variant=None,readout_ports=('y',),runner=None,yosys=None):
    if L not in (2,3,4):raise ValueError('balanced readout latency must be 2, 3, or 4')
    if list(readout_ports)!=['y']:raise ValueError('balanced readout currently supports the explicit y output')
    runner=runner or run_guarded;yosys=yosys or tool('yosys');d=Path(out_dir).resolve();d.mkdir(parents=True,exist_ok=True)
    # Local callbacks avoid global state and permit independent candidate generation.
    def runys(script,out,label):
        p=Path(out)/(label+'.ys');save(p,script)
        rec=runner([str(yosys),'-Q','-s',str(p)],cwd=out,log=Path(out)/(label+'.log'),timeout=300)
        if rec['returncode']:raise RuntimeError(rec['log'])
        return rec
    started=time.monotonic();gp=d/'graph.json'
    runys(f'read_verilog -sv "{base}"\nhierarchy -check -top {top}\nproc\nflatten\nopt_clean\nwrite_json "{gp}"',d,'graph')
    g=load(gp);m=g['modules'][top]
    if any(n not in m['ports'] for n in ('clk','rst_n','y')):
        raise ValueError('Balanced readout requires the clk/rst_n/y interface')
    b=binding(m,['y'])
    out=newbits(m,b['h']+b['k'],'diag_pipeline_y');m['ports']['y']['bits']=out;m['netnames']['y']['bits']=out
    con=dict(clk=m['ports']['clk']['bits'],rst_n=m['ports']['rst_n']['bits'],a=b['S'],b=b['C'],y=out)
    if b['k']:con['low']=b['low']
    m['cells']['diag_pipe']={'hide_name':0,'type':'diag_readout','parameters':{},'attributes':{},
        'port_directions':{n:'output' if n=='y' else 'input' for n in con},'connections':con}
    jp=d/'candidate.json';save(jp,g);hp=d/'candidate_helpers.v';save(hp,readout_module(b['h'],b['k'],L,name='diag_readout'))
    rtl=d/'candidate.v'
    runys(f'read_json "{jp}"\nread_verilog -sv "{hp}"\nhierarchy -check -top {top}\nproc\nflatten\nopt_clean\ncheck -assert\nwrite_verilog -noattr "{rtl}"',d,'candidate_emit')
    # The base metadata describes original state names, retained by flattening.
    result={**base_metadata(base,top,b), 'status':'GENERATED','variant':variant or f'pipe_L{L}',
        'rtl':str(rtl),'rtl_sha256':sha(rtl),'latency':L,'readout_ports':['y'],'elapsed_s':time.monotonic()-started,
        'proof_status':'NOT_ASSESSED','readout':'balanced','binding':b}
    save(d/'REWRITE.json',result);return result

def base_metadata(base,top,b):
    pre=b['prefix'];return dict(refinement=[dict(original_q_name='acc',width=b['h']+b['k'],k=b['k'],
        state_names=dict(os=pre+'S',oc=pre+('Cw' if 'Cw' in Path(base).read_text(encoding='utf-8') else 'C'),ol=pre+'l'))])

BASE_VARIANTS=('T_cs','T_csf','T_cs_pp','T_csf_pp','T_cs_sel','B_pp','B_sel','T1','T2','T_blk_q2','T_blk_q4','R_blk_b2','R_blk_b4')
PIPE_BASE_VARIANTS=('T_cs','T_csf','T_cs_pp','T_csf_pp','T_cs_sel','T_blk_q2','T_blk_q4','R_blk_b2','R_blk_b4')
DEFAULT_VARIANTS=BASE_VARIANTS+tuple(f'{v}_pipeL{L}' for v in PIPE_BASE_VARIANTS for L in (2,3,4))

def generate_candidates(detection,certificates,out_dir,*,runner=None,yosys=None,variants=None):
    from .reencode import rewrite_design
    out=Path(out_dir);results={}
    selected=DEFAULT_VARIANTS if variants is None else variants
    for variant in selected:
        if '_pipeL' not in variant:
            results[variant]=rewrite_design(detection,certificates,out/variant,variant,runner=runner,yosys=yosys)
            continue
        base,L=variant.rsplit('_pipeL',1)
        if base not in results:results[base]=rewrite_design(detection,certificates,out/base,base,runner=runner,yosys=yosys)
        generated=results[base]
        if generated.get('status')!='GENERATED':
            results[variant]={**generated,'variant':variant};continue
        try:
            result=pipeline_candidate(generated['rtl'],detection['top'],int(L),out/variant,
                variant=variant,runner=runner,yosys=yosys)
            result['refinement']=generated.get('refinement',[])
            save(out/variant/'REWRITE.json',result);results[variant]=result
        except ValueError as exc:results[variant]=dict(status='SKIPPED',variant=variant,reason=str(exc))
    return results
