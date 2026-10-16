"""Single-design command-line flow."""
from __future__ import annotations
import argparse, json, re, time
from pathlib import Path
from .runtime import tool
from .characterize import characterize
from .extract import detect_design
from .reencode import rewrite_design
from .select import synthesize, select, point_feasible, readout_options

def load(path):
    return json.loads(Path(path).read_text(encoding='utf-8-sig'))

def save(path,obj):
    Path(path).parent.mkdir(parents=True,exist_ok=True)
    Path(path).write_text(json.dumps(obj,ensure_ascii=False,indent=2)+'\n',encoding='utf-8')

def _file(base,path):
    p=Path(path)
    return p if p.is_absolute() else base/p

def library_specs(path):
    path=Path(path)
    if path.is_file() and path.suffix=='.json':
        data=load(path);base=path.parent
        specs=data.get('adders',data.get('adder_specs',[])) if isinstance(data,dict) else data
        return [{**s,'files':[str(_file(base,p)) for p in s['files']]} for s in specs]
    if path.is_dir() and (path/'manifest.json').exists():
        return library_specs(path/'manifest.json')
    files=sorted(path.glob('*.v'))+sorted(path.glob('*.sv')) if path.is_dir() else [path]
    specs=[]
    for f in files:
        for module in re.findall(r'\bmodule\s+(\w+)',f.read_text(encoding='utf-8',errors='replace')):
            specs.append(dict(module=module,files=[str(f)]))
    return specs

def characterize_library(specs,out):
    out=Path(out).resolve();out.mkdir(parents=True,exist_ok=True)
    certs=[]
    for spec in specs:
        files=spec['files'];module=spec.get('top',spec['module'])
        cache=out/('adder_'+str(len(certs)))
        try:
            c=characterize(files,module,cache,input_ports=spec.get('input_ports'),output_port=spec.get('output_port'),yosys=tool('yosys'))
        except Exception as exc:
            c=dict(module=module,status='UNKNOWN',low_local=False,error=repr(exc))
            save(cache/'FIRST_FAILURE.json',c)
        c={**c,'characterized_module':module,'module':spec.get('match_module',spec['module'])}
        for k in ('input_ports','output_port','parameter_values','port_widths','domain_restrictions','match_module','parameters','input_widths'):
            if k in spec: c[k]=spec[k]
        if 'parameters' in spec:c['parameter_values']=spec['parameters']
        if 'match_output_port' in spec:c['output_port']=spec['match_output_port']
        certs.append(c);save(out/(re.sub(r'\W','_',spec['module'])+'.json'),c)
    return certs

def run_design(files,top,adder_specs,out,*,D=(100,2000),budgets=(1000,2000),objective='area@budget',
               certificates=None,prove_enabled=True,heavy=False,energy_enabled=False,
               readout='every-cycle',readout_ports=(),readout_budget_ps=None,readout_contract=None,formal_engine='sby',
               pipeline_stages=None, block_size=None):
    from .verify import prove
    if energy_enabled:
        raise ValueError('Energy proxy collection is not included in this package')
    readout_semantics=readout_options(readout,readout_ports,readout_budget_ps,readout_contract)
    started=time.monotonic();out=Path(out).resolve();out.mkdir(parents=True,exist_ok=True)
    times={};t=time.monotonic()
    certs=certificates or characterize_library(adder_specs,out/'certificates')
    times['characterize_s']=time.monotonic()-t;t=time.monotonic()
    detection=detect_design(files,top,certs,out/'detect')
    times['detect_s']=time.monotonic()-t;t=time.monotonic()
    candidates={}
    for variant in ('T_cs','T_csf','T_cs_pp','T_csf_pp','T1','T2'):
        r=rewrite_design(detection,certs,out/'rewrite'/variant,variant=variant)
        candidates[variant]=r
    if block_size:
        variant=f'T_blk_q{block_size}'
        candidates[variant]=rewrite_design(detection,certs,out/'rewrite'/variant,variant=variant)
    if pipeline_stages:
        from ._pipeline import rewrite_pipe_design
        r=rewrite_pipe_design(detection,certs,out/'rewrite'/'pipeline',pipeline_stages)
        candidates[r['variant']]=r
    times['rewrite_s']=time.monotonic()-t
    ppa=[];proofs={};ptime=0;synthtime=0
    for variant,sources in [('original',files)]+[(v,[r['rtl']]) for v,r in candidates.items() if r.get('status')=='GENERATED']:
        if variant!='original':
            t=time.monotonic()
            if prove_enabled:
                try:
                    proofs[variant]=prove(files,[candidates[variant]['rtl']],top,out/'proof'/variant,
                                           refinement=candidates[variant].get('refinement'),cycles=100000,
                                           latency=candidates[variant].get('latency',0),
                                           memory_mb=8192 if heavy else 3072,formal_engine=formal_engine)
                except Exception as exc:
                    proofs[variant]=dict(status='UNKNOWN',error=repr(exc));save(out/'proof'/variant/'FIRST_FAILURE.json',proofs[variant])
            else: proofs[variant]=dict(status='NOT_ASSESSED')
            ptime+=time.monotonic()-t
        for budgetD in D:
            t=time.monotonic();p=synthesize(sources,top,out/'ppa'/variant/f'D{budgetD}',D=budgetD,heavy=heavy,
                                          readout=readout,readout_ports=readout_ports,
                                          readout_budget_ps=readout_budget_ps,readout_contract=readout_contract)
            p['variant']=variant;ppa.append(p);synthtime+=time.monotonic()-t
    times.update(prove_s=ptime,synth_s=synthtime,total_s=time.monotonic()-started)
    decisions=select(ppa,budgets,proofs=proofs,objective=objective)
    energies=[]
    times['total_s']=time.monotonic()-started
    chosen=decisions[-1]['selected'] if decisions else None
    selected=chosen['variant'] if chosen else 'original'
    if selected=='original':
        rtl='\n'.join(Path(p).read_text(encoding="utf-8") for p in files)
    else: rtl=Path(candidates[selected]['rtl']).read_text(encoding='utf-8')
    (out/'rewritten.v').write_text(rtl,encoding='utf-8')
    result=dict(schema='BEAR_RUN_V1',top=top,status='RUN_COMPLETED' if detection.get('status')=='PASS' else 'UNKNOWN',
                objective=objective,certificates=certs,detection=detection,candidates=candidates,
                readout_semantics=readout_semantics,
                proofs=proofs,ppa=ppa,decisions=decisions,selected_variant=selected,
                rewritten_rtl=str(out/'rewritten.v'),timings=times,
                energies=energies,energy_scope='NOT_ASSESSED')
    save(out/'RUN.json',result)
    table=['# BEAR report', '', f'Top: `{top}`. Selected candidate: `{selected}`.', '',
           '| Budget (ps) | Selected | Fallback reason |', '|---:|---|---|']
    for decision in decisions:
        point=decision.get('selected')
        table.append(f"|{decision['budget_ps']}|{point['variant'] if point else 'original'}|{decision['fallback_reason']}|")
    (out/'REPORT.md').write_text('\n'.join(table)+'\n', encoding='utf-8')
    return result


def main(argv=None):
    parser=argparse.ArgumentParser(prog='bear',description='Bit-exact accumulator re-encoding')
    sub=parser.add_subparsers(dest='cmd',required=True)
    for name in ('run','extract','characterize'):
        p=sub.add_parser(name)
        p.add_argument('files',nargs='+');p.add_argument('--top',required=True);p.add_argument('--out',required=True)
        if name!='characterize':p.add_argument('--adders',required=True)
        if name=='run':
            p.add_argument('--objective',default='area@budget',choices=['area@budget','fastest'])
            p.add_argument('--pipeline-stages',type=int,choices=[2,3])
            p.add_argument('--block-size',type=int,choices=[2,4])
            p.add_argument('--D',default='100,2000');p.add_argument('--budgets',default='1000,2000')
            p.add_argument('--heavy',action='store_true',help='Accepted for compatibility; no resource scheduling')
            p.add_argument('--liberty');p.add_argument('--constraints')
            p.add_argument('--readout',default='every-cycle',choices=['every-cycle','on-readout'])
            p.add_argument('--readout-ports',default='')
            p.add_argument('--readout-budget-ps',type=float);p.add_argument('--readout-contract')
            p.add_argument('--formal-engine',default='sby',choices=['sby','yosys_sat'])
    p=sub.add_parser('reencode')
    p.add_argument('detection');p.add_argument('--certificates',required=True)
    p.add_argument('--variant',default='T_cs');p.add_argument('--out',required=True)
    p.add_argument('--pipeline-stages',type=int,choices=[2,3])
    p.add_argument('--block-size',type=int,choices=[2,4])
    p=sub.add_parser('verify')
    p.add_argument('original');p.add_argument('candidate');p.add_argument('--top',required=True);p.add_argument('--out',required=True)
    p.add_argument('--refinement',help='Candidate metadata JSON or a named refinement list')
    p.add_argument('--latency',type=int,help='Extra candidate output delay in clocks (d)')
    p.add_argument('--readout-ports',default='',help='Comma-separated delayed outputs; default: all outputs')
    p.add_argument('--formal-engine',default='sby',choices=['sby','yosys_sat'])
    p=sub.add_parser('select')
    p.add_argument('points',help='JSON list of technology-mapped timing/area points')
    p.add_argument('--proofs',required=True,help='JSON proof records keyed by candidate variant')
    p.add_argument('--budgets');p.add_argument('--out',required=True)
    p.add_argument('--objective',default='area@budget',choices=['area@budget','fastest'])
    p=sub.add_parser('export');p.add_argument('certificate');p.add_argument('output')
    args=parser.parse_args(argv)
    if args.cmd=='export':
        from .export import export
        result=export(args.certificate,args.output)
        print(json.dumps(result));return
    if args.cmd=='characterize':
        result=characterize(args.files,args.top,args.out,yosys=tool('yosys'))
    elif args.cmd in ('run','extract'):
        specs=library_specs(args.adders)
        if args.cmd=='run':
            from .select import configure
            configure(args.liberty,args.constraints)
            result=run_design(args.files,args.top,specs,args.out,D=list(map(int,args.D.split(','))),
                              budgets=list(map(float,args.budgets.split(','))),objective=args.objective,heavy=args.heavy,
                              readout=args.readout,readout_ports=[p.strip() for p in args.readout_ports.split(',') if p.strip()],
                              readout_budget_ps=args.readout_budget_ps,readout_contract=args.readout_contract,
                              pipeline_stages=args.pipeline_stages,block_size=args.block_size,
                              formal_engine=args.formal_engine)
        else:result=detect_design(args.files,args.top,characterize_library(specs,Path(args.out)/'certificates'),args.out)
    elif args.cmd=='reencode':
        certs=load(args.certificates)
        if isinstance(certs,dict):certs=certs.get('certificates',[certs])
        if args.pipeline_stages and args.block_size:
            parser.error('Choose either --pipeline-stages or --block-size')
        if args.pipeline_stages:
            from ._pipeline import rewrite_pipe_design
            result=rewrite_pipe_design(load(args.detection),certs,args.out,args.pipeline_stages)
        else:result=rewrite_design(load(args.detection),certs,args.out,f'T_blk_q{args.block_size}' if args.block_size else args.variant)
    elif args.cmd=='verify':
        from .verify import prove
        refinement=load(args.refinement) if args.refinement else None
        metadata=refinement if isinstance(refinement,dict) else {}
        if 'refinement' in metadata:refinement=metadata['refinement']
        latency=args.latency if args.latency is not None else metadata.get('latency',0)
        result=prove(args.original,args.candidate,args.top,args.out,refinement=refinement,formal_engine=args.formal_engine,
                     latency=latency,readout_ports=[p.strip() for p in args.readout_ports.split(',') if p.strip()])
    else:
        points=load(args.points)
        if args.objective=='area@budget' and not args.budgets:parser.error('area@budget requires --budgets')
        result=select(points,list(map(float,args.budgets.split(','))) if args.budgets else [],proofs=load(args.proofs),objective=args.objective)
        save(args.out,result)
        print(json.dumps({'decisions':len(result),'out':args.out}));return
    print(json.dumps({'status':result.get('status'),'out':args.out}))
