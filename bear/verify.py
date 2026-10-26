"""Verify."""
from __future__ import annotations

import hashlib
import json
import re
import time
from pathlib import Path

from .runtime import run_guarded, tool

IMPLEMENTATION_SHA256=hashlib.sha256(Path(__file__).read_bytes()).hexdigest()


def _quote(path):
    return '"' + str(Path(path).resolve()).replace('\\', '/') + '"'


def _id(name):
    return '\\' + name + ' '


def _width(width):
    return f'[{width-1}:0] ' if width > 1 else ''


def _sources(first, others=None):
    if isinstance(first, (tuple, list)):
        paths = list(first)
    else:
        paths = [first]
    paths += list(others or [])
    return list(dict.fromkeys(str(Path(p).resolve()) for p in paths))


def _flatten(files, top, name, out, timeout, memory_mb):
    inc = ' '.join('-I' + _quote(Path(p).parent) for p in files)
    script = (f'read_verilog -sv {inc} ' + ' '.join(_quote(p) for p in files) +
              f'\nhierarchy -check -top {top}\nproc\nflatten\nsetattr -set keep 1 w:bear_*_low w:bear_*_sum w:bear_*_carry\nopt_clean\n'
              f'rename {top} {name}\nwrite_json {_quote(out/(name+".json"))}\n'
              f'write_verilog -norename {_quote(out/(name+".v"))}\n')
    ys = out / (name + '.ys')
    ys.write_text(script, encoding='utf-8')
    record = run_guarded([tool('yosys'), '-s', ys], cwd=out,
                         log=out/(name+'.log'), timeout=timeout, memory_mb=memory_mb)
    if record['returncode'] or not (out/(name+'.json')).exists():
        return record, None
    module = json.loads((out/(name+'.json')).read_text(encoding='utf-8'))['modules'][name]
    return record, module


def _controls(inputs):
    clock = next((p for p in inputs if p.lower() in ('clk', 'clock', 'ap_clk')), None)
    resets = {p: 0 if p.lower().endswith(('_n', 'n')) else 1 for p in inputs
              if p.lower() in ('rst', 'reset', 'rst_n', 'reset_n', 'resetn', 'ap_rst', 'ap_rst_n')}
    initials = {p: 1 for p in inputs if p.lower() in ('start', 'clear')}
    return clock, resets, initials


def _harness(ports, sequential, warmup=4):
    inputs = {p: len(v['bits']) for p, v in ports.items() if v['direction'] == 'input'}
    outputs = {p: len(v['bits']) for p, v in ports.items() if v['direction'] == 'output'}
    clock, resets, initials = _controls(inputs)
    head = f'module formal(input {_id(clock)});' if sequential and clock else 'module formal;'
    lines = [head]
    for p, w in inputs.items():
        if p != clock or not sequential:
            lines.append(f'(* anyseq *) reg {_width(w)}{_id(p)};')
    for p, w in outputs.items():
        lines += [f'wire {_width(w)}{_id("o_"+p)};', f'wire {_width(w)}{_id("t_"+p)};']
    for inst, mod in [('o', 'apx_original'), ('t', 'apx_candidate')]:
        binds = [f'.{_id(p)}({_id(p if p in inputs else inst+"_"+p)})' for p in ports]
        lines.append(f'{mod} {inst} (' + ','.join(binds) + ');')
    checks = [f'assert({_id("o_"+p)} == {_id("t_"+p)});' for p in outputs]
    if sequential and clock:
        lines.append('(* keep *) wire bear_initial = $initstate;')
        lines.append('always @* if ($initstate) begin')
        for p, active in resets.items():
            lines.append(f'assume({_id(p)} == {inputs[p]}\'d{active});')
        lines += ['end', 'always @* begin'] + checks + ['end']
    else:
        lines += ['always @* begin'] + checks + ['end']
    lines.append('endmodule')
    return '\n'.join(lines)+'\n'


def _testbench(ports, sequential, count, seed, warmup=8, dump_path=None,
               candidate_instance='t', original_instance='o', half_period_ps=5000):
    inputs = {p: len(v['bits']) for p, v in ports.items() if v['direction'] == 'input'}
    outputs = {p: len(v['bits']) for p, v in ports.items() if v['direction'] == 'output'}
    clock, resets, initials = _controls(inputs)
    lines = ['`timescale 1ps/1ps', 'module tb;', 'integer i, j; integer rnd; integer checked=0;']
    for p, w in inputs.items():
        lines.append(f'reg {_width(w)}{_id(p)} = 0;')
    for p, w in outputs.items():
        lines += [f'wire {_width(w)}{_id("o_"+p)};', f'wire {_width(w)}{_id("t_"+p)};']
    for inst, mod, prefix in [(original_instance,'apx_original','o'), (candidate_instance,'apx_candidate','t')]:
        binds = [f'.{_id(p)}({_id(p if p in inputs else prefix+"_"+p)})' for p in ports]
        lines.append(f'{mod} {inst} (' + ','.join(binds) + ');')
    lines += ['initial begin']
    if dump_path is not None:
        lines += [f'$dumpfile("{str(dump_path)}"); $dumpvars(0,tb);']
    lines += [f'rnd={seed}; rnd=$urandom(rnd);', f'for(i=0;i<{count};i=i+1) begin']
    if sequential and clock:
        lines.append(f'{_id(clock)}=0;')
    for p, w in inputs.items():
        if p == clock:
            continue
        if p in resets:
            lines.append(f'{_id(p)}=(i<2 || i%997==0) ? {resets[p]} : {1-resets[p]};')
        elif p in initials:
            lines.append(f'{_id(p)}=(i<2 || i%257==0) ? 1 : ($urandom%31==0);')
        else:
            random_word = '{' + ','.join('$urandom' for _ in range((w+31)//32)) + '}'
            lines.append(f'{_id(p)}={random_word};')
            lines.append(f'case(i%257) 0:{_id(p)}=0; 1:{_id(p)}={{ {w}{{1\'b1}} }}; '
                         f'2:{_id(p)}={w}\'h'+hex(int('10'*((w+1)//2),2)&((1<<w)-1))[2:]+'; '
                         f'3:{_id(p)}={w}\'d1 << (i%{w}); endcase')
    lines.append(f'#{int(half_period_ps)};')
    if sequential and clock:
        lines.append(f'{_id(clock)}=1; #{int(half_period_ps)};')
    else:
        lines.append(f'#{int(half_period_ps)};')
    lines.append('begin')
    for p in outputs:
        lines.append(f'if({_id("o_"+p)} !== {_id("t_"+p)}) begin '
                     f'$display("BEAR_MISMATCH i=%0d port={p} original=%h candidate=%h", i,'
                     f'{_id("o_"+p)},{_id("t_"+p)}); $fatal(1); end')
    lines += ['checked=checked+1;', 'end', 'end',
              '$display("BEAR_SIM_PASS checked=%0d",checked); $finish;', 'end','endmodule']
    return '\n'.join(lines)+'\n'


make_testbench = _testbench


_REGTYPES={'$dff','$adff','$dffe','$adffe','$sdff','$sdffe','$sdffce','$_DFF_P_','$_DFF_N_'}


def _init_bits(module):
    known={}
    for n in module.get('netnames',{}).values():
        init=n.get('attributes',{}).get('init')
        if init is None:continue
        text=str(init)[::-1]
        for b,v in zip(n['bits'],text):
            if v in ('0','1'):known[b]=v
    return known


def _q_bits(module):
    return {b for c in module.get('cells',{}).values() if c['type'] in _REGTYPES
            for b in c.get('connections',{}).get('Q',[]) if isinstance(b,int)}


def _identity_initial_domain(original_bits,candidate_bits,om,tm):
    """Verify."""
    oi,ti,tq=_init_bits(om),_init_bits(tm),_q_bits(tm)
    if len(original_bits) != len(candidate_bits):
        return 'INITIAL_DOMAIN_NOT_COVERED'
    assigned={}
    for a,b in zip(original_bits,candidate_bits):
        ov=oi.get(a,a if isinstance(a,str) and a in ('0','1') else None)
        tv=ti.get(b,b if isinstance(b,str) and b in ('0','1') else None)
        if tv is not None:
            if ov is None or ov!=tv:
                return 'INITIAL_DOMAIN_NOT_COVERED'
        elif b not in tq:
            return 'INITIAL_DOMAIN_UNKNOWN'
        else:
            required=('constant',ov) if ov is not None else ('original',a)
            if b in assigned and assigned[b]!=required:
                return 'INITIAL_DOMAIN_NOT_COVERED'
            assigned[b]=required
    return 'PASS'


def _csa_initial_domain(item,om,tm):
    """Verify."""
    q=om['netnames'][item['original_q_name']]['bits']
    names=item.get('state_names',{})
    try:
        s=tm['netnames'][names['os']]['bits'];c=tm['netnames'][names['oc']]['bits']
        low=tm['netnames'][names['ol']]['bits'] if item.get('k') else []
    except KeyError:
        return 'INITIAL_DOMAIN_UNKNOWN'
    ti,tq=_init_bits(tm),_q_bits(tm)
    low_status=_identity_initial_domain(q[:len(low)],low,om,tm)
    if low_status!='PASS':return low_status
    def free(row,other):
        return (len(set(row))==len(row) and not (set(row)&set(other+low))
                and all(isinstance(b,int) and b in tq and b not in ti for b in row)
                and all(b in tq or b in ('0','1') for b in other))
    if free(s,c) or free(c,s):
        return 'PASS'
    oi=_init_bits(om)
    if any(b not in oi for b in q[len(low):]) and all((b in ti or b in ('0','1')) for b in s+c):
        return 'INITIAL_DOMAIN_NOT_COVERED'
    return 'INITIAL_DOMAIN_UNKNOWN'


def _refinement_assertions(refinement, om, tm):
    """Verify."""
    if isinstance(refinement, dict):
        return refinement.get('assertions',[]), []
    asserts, skipped = [], []
    for item in refinement or []:
        q=item.get('original_q_name')
        names=item.get('state_names',{})
        tag=item.get('helper','').removeprefix('bear_state_')
        if not names and tag:
            names={'os':'bear_'+tag+'_sum','oc':'bear_'+tag+'_carry','ol':'bear_'+tag+'_low'}
        if not q or q not in om.get('netnames',{}) or any(names.get(k) not in tm.get('netnames',{}) for k in ('os','oc')):
            skipped.append(dict(register=item.get('register'),reason='Unbound original Q or candidate state name; output equivalence is still checked'))
            continue
        h=int(item['width'])-int(item['k'])
        summed='bear_ref_sum_'+str(len(asserts))
        expr=f'{{{_id("t."+names["os"])}+{_id("t."+names["oc"])}, {_id("t."+names["ol"])}}}' if item['k'] else f'({_id("t."+names["os"])}+{_id("t."+names["oc"])})'
        asserts.append(f'{_id("o."+q)} == {expr}')
    return asserts,skipped


def _inject_refinement_json(path, refinement, clock, warmup, om=None, tm=None,
                            initial_coupling=False):
    """Verify."""
    graph=json.loads(Path(path).read_text(encoding='utf-8'))
    mod=graph['modules']['formal']
    nets,cells=mod['netnames'],mod['cells']
    used=[b for n in nets.values() for b in n['bits'] if isinstance(b,int)]
    nxt=max(used or [0])+1
    def bits(name):
        return nets.get(name,{}).get('bits')
    def number(n):
        return format(int(n),'032b')
    def cell(name,typ,parameters,connections,directions):
        cells[name]={'hide_name':0,'type':typ,'parameters':parameters,'attributes':{},
                     'port_directions':directions,'connections':connections}
    skipped=[];mapped=set();mapped_bits=set();index=0;claimed_initial_bits=set()
    def claim_initial_domain(qname,target_bits):
        actual={b for b in target_bits if isinstance(b,int)}
        if actual&claimed_initial_bits:
            skipped.append({'register':qname,'reason':'Candidate representations of independent original states share flops; joint initial projection is unproven',
                            'initial_domain':'INITIAL_DOMAIN_UNKNOWN'})
        claimed_initial_bits.update(actual)
    def needs_initial(name):
        if initial_coupling:return True
        if om is None or name not in om.get('netnames',{}):return True
        qb=om['netnames'][name]['bits']
        types=[c['type'] for c in om.get('cells',{}).values() if c.get('connections',{}).get('Q')==qb]
        return not types or any(t not in ('$adff','$adffe') for t in types)
    def equality(q,t,tag,initialize=False):
        nonlocal nxt,index
        if tag.startswith('bear_unchanged_'):
            driven={b for ce in cells.values() for p,bs in ce.get('connections',{}).items()
                    if ce.get('port_directions',{}).get(p)=='output' for b in bs}
            driven.update(b for p in mod.get('ports',{}).values() if p['direction']=='input' for b in p['bits'])
            keep=[i for i,(a,b) in enumerate(zip(q,t)) if a in driven or b in driven or isinstance(a,str) or isinstance(b,str)]
            projected=[i for i in range(len(q)) if i not in keep]
            if projected:
                receipt=Path(path).parent/'UNCHANGED_DEAD_BIT_PROJECTIONS.json'
                records=json.loads(receipt.read_text(encoding='utf-8')) if receipt.exists() else []
                records.append({'tag':tag,'both_undriven_positions':projected,'original_width':len(q),'retained_width':len(keep),'rule':'Project only unused bits removed by prep and undriven on both sides; retain output assertions and driven bits'})
                receipt.write_text(json.dumps(records,ensure_ascii=False,indent=2),encoding='utf8')
                q=[q[i] for i in keep];t=[t[i] for i in keep]
            if not q:return
        eq=[nxt];nxt+=1;index+=1
        cell(tag+'_eq','$eq',{'A_SIGNED':number(0),'B_SIGNED':number(0),
             'A_WIDTH':number(len(q)),'B_WIDTH':number(len(t)),'Y_WIDTH':number(1)},
             {'A':q,'B':t,'Y':eq},{'A':'input','B':'input','Y':'output'})
        cell(tag+'_assert','$assert',{}, {'A':eq,'EN':['1']},{'A':'input','EN':'input'})
        if initialize:
            initial=bits('bear_initial')
            if initial:
                cell(tag+'_initial_assume','$assume',{}, {'A':eq,'EN':initial},{'A':'input','EN':'input'})
            else:
                skipped.append({'register':tag,'reason':'Missing $initstate enable; initial relation was not added'})
    for idx,item in enumerate(refinement):
        qname=item.get('original_q_name');state=item.get('state_names',{})
        q=bits('o.'+qname) if qname else None
        if item.get('kind')=='IDENTITY':
            target=bits('t.'+item.get('candidate_q_name',qname or ''))
            if q is not None and target is not None:
                initialize=needs_initial(qname)
                if initialize:
                    targetname=item.get('candidate_q_name',qname)
                    domain=_identity_initial_domain(om['netnames'][qname]['bits'],tm['netnames'][targetname]['bits'],om,tm)
                    if domain!='PASS':skipped.append({'register':qname,'reason':domain,'initial_domain':domain})
                    claim_initial_domain(qname,tm['netnames'][targetname]['bits'])
                equality(q,target,'bear_identity_'+str(idx),initialize);mapped.add(qname)
                if om and qname in om.get('netnames',{}):mapped_bits.add(tuple(om['netnames'][qname]['bits']))
            else:
                skipped.append({'register':qname,'reason':'Missing IDENTITY signal'})
            continue
        s=bits('t.'+state.get('os',''));c=bits('t.'+state.get('oc',''))
        l=bits('t.'+state.get('ol','')) if item.get('k') else []
        if q is None or s is None or c is None or l is None:
            skipped.append({'register':item.get('register'),'reason':'Exact state signals missing from JSON; no inferred binding'})
            continue
        initialize=needs_initial(qname)
        if initialize:
            domain=_csa_initial_domain(item,om,tm)
            if domain!='PASS':skipped.append({'register':qname,'reason':domain,'initial_domain':domain})
            names=item['state_names']
            claim_initial_domain(qname,tm['netnames'][names['os']]['bits']+tm['netnames'][names['oc']]['bits']+
                                 (tm['netnames'][names['ol']]['bits'] if item.get('k') else []))
        h=len(s);w=len(q)
        summ=list(range(nxt,nxt+h));nxt+=h
        pre='bear_refinement_'+str(idx)
        cell(pre+'_add','$add',{'A_SIGNED':number(0),'B_SIGNED':number(0),
             'A_WIDTH':number(h),'B_WIDTH':number(h),'Y_WIDTH':number(h)},
             {'A':s,'B':c,'Y':summ},{'A':'input','B':'input','Y':'output'})
        equality(q,l+summ,pre,initialize);mapped.add(qname)
        if om and qname in om.get('netnames',{}):mapped_bits.add(tuple(om['netnames'][qname]['bits']))
    if om is not None:
        regtypes=_REGTYPES
        target_registers={tuple(c.get('connections',{}).get('Q',[])) for c in (tm or {}).get('cells',{}).values() if c['type'] in regtypes}
        for reg,c in om.get('cells',{}).items():
            if c['type'] not in regtypes: continue
            qb=c.get('connections',{}).get('Q',[])
            if tuple(qb) in mapped_bits:continue
            candidates=sorted((n for n,v in om.get('netnames',{}).items() if v['bits']==qb),
                              key=lambda n:(bool(om['netnames'][n].get('hide_name')),len(n),n))
            name=next((n for n in candidates if bits('t.'+n) is not None
                       and n in (tm or {}).get('netnames',{})
                       and tuple(tm['netnames'][n]['bits']) in target_registers),None)
            if name is None:
                skipped.append({'register':reg,'reason':'No candidate state with the original register Q name'})
            elif name not in mapped:
                initialize=needs_initial(name)
                if initialize:
                    domain=_identity_initial_domain(qb,tm['netnames'][name]['bits'],om,tm)
                    if domain!='PASS':skipped.append({'register':name,'reason':domain,'initial_domain':domain})
                    claim_initial_domain(name,tm['netnames'][name]['bits'])
                equality(bits('o.'+name),bits('t.'+name),'bear_unchanged_'+str(index),initialize);mapped.add(name)
    Path(path).write_text(json.dumps(graph),encoding='utf-8')
    return skipped


def _aligned_wrapper(path, module, ports, latency, readouts):
    """Delay reference readouts by d clocks; candidate readouts pass through."""
    inputs={p for p,v in ports.items() if v['direction']=='input'}
    clock,resets,_=_controls(inputs)
    if not clock or len(resets)!=1:
        raise ValueError('Alignment requires a recognized clock and one reset')
    reset,active=next(iter(resets.items()))
    core=module+'_core'
    text=path.read_text(encoding='utf-8')
    text=re.sub(r'\bmodule\s+'+module+r'\b','module '+core,text,count=1)
    lines=[f'module {module}('+','.join(_id(p) for p in ports)+');']
    for p,v in ports.items():
        lines.append(f"{v['direction']} {_width(len(v['bits']))}{_id(p)};")
        if p not in inputs:lines.append(f"wire {_width(len(v['bits']))}{_id('w_'+p)};")
    lines.append(core+' u('+','.join(f'.{_id(p)}({_id(p if p in inputs else "w_"+p)})' for p in ports)+');')
    for p,v in ports.items():
        if p in inputs:continue
        prev='w_'+p
        if p in readouts and latency:
            names=[f'bear_delay_{p}_{i}' for i in range(latency)]
            lines += [f'reg {_width(len(v["bits"]))}{_id(n)};' for n in names]
            lines.append(f'always @(posedge {_id(clock)} or {"posedge" if active else "negedge"} {_id(reset)}) begin')
            lines.append(f'if ({_id(reset)} == 1\'b{active}) begin')
            lines += [f'{_id(n)} <= 0;' for n in names]
            lines.append('end else begin')
            for n in names:
                lines.append(f'{_id(n)} <= {_id(prev)};');prev=n
            lines.append('end end')
        lines.append(f'assign {_id(p)} = {_id(prev)};')
    path.write_text(text+'\n'+'\n'.join(lines)+'\nendmodule\n',encoding='utf-8')


def prove(original, candidate, top, out, *, source_files=None, candidate_files=None,
          refinement=None, sequential=None, cycles=100000, timeout=300,
          memory_mb=3072, seed=20261007, warmup=4, simulation_receipt=None,
          formal_engine='sby', latency=0, readout_ports=(), **kwargs):
    """Verify."""
    started = time.monotonic()
    if not isinstance(latency,int) or isinstance(latency,bool) or latency<0:
        raise ValueError('latency must be a nonnegative integer number of clocks')
    if readout_ports and not latency:
        raise ValueError('readout_ports requires positive latency')
    if formal_engine not in ('sby','yosys_sat'):
        raise ValueError('formal_engine must be sby or yosys_sat')
    if isinstance(refinement,dict):
        if 'records' in refinement:refinement=refinement['records']
        elif 'entries' in refinement:refinement=refinement['entries']
        elif 'original_q_name' in refinement:refinement=[refinement]
        elif not refinement:refinement=[]
        else:raise ValueError('refinement requires named state mappings; raw assertion strings are unsupported')
    out = Path(out).resolve()
    if out.exists() and any(out.iterdir()):
        # Preserve incomplete/interrupted raw attempts as well as terminal ones.
        out=out/('attempt_'+str(time.time_ns()))
    out.mkdir(parents=True, exist_ok=True)
    source_files = source_files or kwargs.pop('files', None)
    if kwargs:
        raise TypeError('Unknown verify arguments: '+','.join(kwargs))
    of = _sources(original, source_files)
    tf = _sources(candidate, candidate_files if candidate_files is not None else source_files)
    result = {'status':'UNKNOWN', 'formal':{'status':'UNKNOWN'}, 'simulation':{'status':'UNKNOWN'},
              'top':top, 'source_sha256':{p:hashlib.sha256(Path(p).read_bytes()).hexdigest() for p in of+tf},
              'refinement':refinement, 'seed':seed, 'out':str(out),'proof_scope_version':'FULL_PREFIX_V2',
              'proof_code_sha256':IMPLEMENTATION_SHA256,'formal_engine':formal_engine}
    orec, om = _flatten(of, top, 'apx_original', out, timeout, memory_mb)
    trec, tm = _flatten(tf, top, 'apx_candidate', out, timeout, memory_mb)
    result['frontend'] = [orec,trec]
    if latency and om is not None and tm is not None:
        outputs={p for p,v in om['ports'].items() if v['direction']=='output'}
        readout_ports=list(readout_ports or outputs)
        if not set(readout_ports)<=outputs:raise ValueError('Aligned readout is not an output')
        if {p:(v['direction'],len(v['bits'])) for p,v in om['ports'].items()} != {p:(v['direction'],len(v['bits'])) for p,v in tm['ports'].items()}:
            raise ValueError('Alignment requires matching interfaces')
        for name,mod,delay in [('apx_original',om,latency),('apx_candidate',tm,0)]:
            path=out/(name+'.v')
            _aligned_wrapper(path,name,mod['ports'],delay,readout_ports)
            aligned=out/(name+'_aligned.v')
            path.rename(aligned)
            rec,mod=_flatten([aligned],name,name,out,timeout,memory_mb)
            result['frontend'].append(rec)
            if name=='apx_original':om=mod
            else:tm=mod
        refinement=[{**r,'original_q_name':'u.'+r['original_q_name'],
                     'state_names':{p:'u.'+n for p,n in r.get('state_names',{}).items()},
                     **({'candidate_q_name':'u.'+r['candidate_q_name']} if 'candidate_q_name' in r else {})}
                    for r in (refinement or [])]
        result.update(latency=latency,readout_ports=readout_ports,
                      alignment=f'Candidate readout equals the original readout through a {latency}-stage reference delay line cleared on every reset')
    if om is None or tm is None:
        result['reason'] = 'Proof frontend failed; see the first failure log'
    elif {p:(v['direction'],len(v['bits'])) for p,v in om['ports'].items()} != {p:(v['direction'],len(v['bits'])) for p,v in tm['ports'].items()}:
        result['status']='FAIL_INTERFACE'
        result['reason']='Candidate ports or widths differ from the original design'
    else:
        ports = om['ports']
        ins = {p for p,v in ports.items() if v['direction']=='input'}
        clock,resets,initials = _controls(ins)
        sequential = bool(clock) if sequential is None else sequential
        result['sequential']=sequential
        result['scope_status']='FULL_PREFIX'
        result['boundary'] = {'initialization':resets if sequential else {},
                              'warmup_cycles':0,
                              'initial_state_relation':'Couple original Q and candidate decode only at $initstate; assert thereafter' if sequential and not resets else 'Declared initial reset; assertions start at the first state',
                              'async_reset':'async2sync abstraction; subcycle asynchronous events NOT_ASSESSED' if sequential else None,
                              'simulation':'Finite random and boundary vectors do not replace full-domain proof'}
        formal = out/'formal.v'
        formal.write_text(_harness(ports,sequential,warmup),encoding='utf-8')
        result['refinement_skipped']=[]
        formal_read = 'read -formal apx_original.v apx_candidate.v formal.v\nprep -top formal -flatten\n'
        if sequential and (refinement is None or isinstance(refinement,list)):
            pre=out/'refinement_pre.ys'
            pre.write_text(formal_read+'write_json flattened_formal.json\n',encoding='utf-8')
            pre_rec=run_guarded([tool('yosys'),'-s',pre],cwd=out,log=out/'refinement_pre.log',timeout=timeout,memory_mb=memory_mb)
            result['refinement_frontend']=pre_rec
            if pre_rec['returncode']==0:
                relation_om=om
                if latency:
                    # Delay flops are proved by the output alignment, rather
                    # than requiring identical segmented pipeline state names.
                    relation_om={**om,'cells':{n:c for n,c in om['cells'].items()
                        if not any(v.get('bits')==c.get('connections',{}).get('Q')
                                   for p,v in om.get('netnames',{}).items() if p.startswith('bear_delay_'))}}
                result['refinement_skipped'] += _inject_refinement_json(out/'flattened_formal.json',refinement or [],clock,warmup,relation_om,tm,initial_coupling=not bool(resets))
                if result['refinement_skipped']:
                    result['scope_status']='INITIAL_DOMAIN_NOT_COVERED' if any(s.get('initial_domain')=='INITIAL_DOMAIN_NOT_COVERED' for s in result['refinement_skipped']) else 'INITIAL_PREFIX_UNKNOWN'
                formal_read='read_json flattened_formal.json\nprep -top formal -flatten\n'
            else:
                result['scope_status']='INITIAL_PREFIX_UNKNOWN'
        if sequential:
            script=formal_read+'async2sync\ndffunmap\nmemory_map\nopt\n'
            depth=max(6,warmup+2,latency+3)
            init_script=formal_read+'async2sync\ndffunmap\nmemory_map\nopt\nchformal -assert -remove\nsat -seq 1 -set-assumes -show-inputs\n'
            (out/'initial_consistency.ys').write_text(init_script, encoding='utf-8')
            initrec=run_guarded([tool('yosys'),'-s','initial_consistency.ys'],cwd=out,log=out/'initial_consistency.log',timeout=timeout,memory_mb=memory_mb)
            initok=initrec['returncode']==0 and 'model found' in initrec.get('stdout','') and 'no model found' not in initrec.get('stdout','')
            result['initial_consistency']={'status':'PASS' if initok else 'FAIL' if 'no model found' in initrec.get('stdout','') else 'UNKNOWN','execution':initrec}
            if not initok:
                result['scope_status']='INITIAL_PREFIX_UNKNOWN'
            (out/'proof.sby').write_text('[options]\nmode prove\ndepth '+str(depth)+'\ntimeout '+str(timeout)+'\n'
                         '[engines]\nsmtbmc z3\n[script]\n'+script+
                         '[files]\napx_original.v\napx_candidate.v\nformal.v\n'+
                         ('flattened_formal.json\n' if (out/'flattened_formal.json').exists() else '')+
                         '', encoding='utf-8')
            if formal_engine=='sby':
                rec=run_guarded([tool('sby'),'-f','proof.sby'],cwd=out,log=out/'proof.log',timeout=timeout+20,memory_mb=memory_mb)
                raw=(out/'proof/status').read_text(encoding='utf-8').strip() if (out/'proof/status').exists() else 'UNKNOWN'
                status=raw.split()[0] if raw else 'UNKNOWN'
                result['formal']={'status':status if status in ('PASS','FAIL') else 'UNKNOWN','raw_status':raw,
                                  'method':'SBY_K_INDUCTION_DEPTH'+str(depth),'execution':rec}
            else:
                (out/'induction.ys').write_text(script+
                    f'sat -seq 1 -tempinduct -maxsteps {depth} -prove-asserts -set-assumes -verify\n', encoding='utf-8')
                rec=run_guarded([tool('yosys'),'-s','induction.ys'],cwd=out,
                                log=out/'induction.log',timeout=timeout,memory_mb=memory_mb)
                txt=rec.get('stdout','')
                status=('PASS' if rec['returncode']==0 and 'Induction step proven: SUCCESS!' in txt else
                        'FAIL' if 'SAT proof finished - model found: FAIL!' in txt or
                        'SAT temporal induction proof finished - model found for base case: FAIL!' in txt or
                        'FAIL: proof for base case failed!' in txt or
                        'ERROR: Called with -verify and proof did fail!' in txt else 'UNKNOWN')
                result['formal']={'status':status,'raw_status':rec.get('status'),
                                  'method':'YOSYS_SAT_K_INDUCTION_MAXSTEPS'+str(depth),'execution':rec}
        else:
            (out/'cec.ys').write_text(formal_read+'memory_map\nchformal -lower\nopt\nsat -verify -prove-asserts -show-inputs\n', encoding='utf-8')
            rec=run_guarded([tool('yosys'),'-s','cec.ys'],cwd=out,log=out/'cec.log',timeout=timeout,memory_mb=memory_mb)
            # Legacy Yosys already emits $assert cells and has no chformal -lower.
            # Retry only that exact frontend incompatibility; preserve the first log/script.
            if rec['returncode'] and 'chformal -lower' in rec.get('stdout','') and 'Unknown option' in rec['stdout']:
                result['legacy_assert_frontend']=rec
                (out/'cec.log').rename(out/'cec_unsupported_lower.log')
                rec['log']=str(out/'cec_unsupported_lower.log')
                text=(out/'cec.ys').read_text(encoding='utf-8')
                (out/'cec_unsupported_lower.ys').write_text(text,encoding='utf-8')
                (out/'cec.ys').write_text(text.replace('chformal -lower\n',''),encoding='utf-8')
                rec=run_guarded([tool('yosys'),'-s','cec.ys'],cwd=out,log=out/'cec.log',timeout=timeout,memory_mb=memory_mb)
            txt=rec.get('stdout','')
            status='PASS' if rec['returncode']==0 and 'SUCCESS' in txt else 'FAIL' if 'proof did fail' in txt or 'FAIL!' in txt else 'UNKNOWN'
            result['formal']={'status':status,'method':'FULL_DOMAIN_COMBINATIONAL_CEC','execution':rec}
        count=max(1000,int(cycles))
        simulation=None
        if simulation_receipt is not None:
            old=json.loads(Path(simulation_receipt).read_text(encoding='utf-8')) if not isinstance(simulation_receipt,dict) else simulation_receipt
            os=old.get('simulation',{})
            if (old.get('top')==top and old.get('source_sha256')==result['source_sha256']
                    and old.get('latency',0)==latency and old.get('readout_ports',[])==result.get('readout_ports',[])
                    and os.get('status')=='PASS' and os.get('cycles_or_vectors',0)>=count):
                simulation={**os,'reuse':True,'receipt':str(simulation_receipt),
                            'reuse_scope':'Source/candidate digests match; retain the existing finite simulation scope; formal checks the initial prefix',
                            'original_boundary':old.get('boundary')}
            else:
                result['simulation_reuse_rejected']='Simulation reuse rejected: source/candidate digest, top, or passed sample count mismatch'
        if simulation is None:
            (out/'tb.v').write_text(_testbench(ports,sequential,count,seed),encoding='utf-8')
            rec=run_guarded([tool('verilator'),'--binary','--timing','--top-module','tb','-Wno-fatal',
                             '--build-jobs','1','--Mdir','obj_dir','apx_original.v','apx_candidate.v','tb.v'],
                            cwd=out,log=out/'verilator_build.log',timeout=max(timeout,600),memory_mb=memory_mb)
            simulation={'status':'UNKNOWN','build':rec,'cycles_or_vectors':0,'requested':count,'seed':seed}
            exe=out/'obj_dir/Vtb'
            if rec['returncode']==0 and exe.exists():
                sim=run_guarded([exe],cwd=out,log=out/'simulation.log',timeout=max(timeout,600),memory_mb=memory_mb)
                m=re.search(r'BEAR_SIM_PASS checked=(\d+)',sim.get('stdout',''))
                simulation.update(execution=sim,cycles_or_vectors=int(m.group(1)) if m else 0,
                                  status='PASS' if sim['returncode']==0 and m and int(m.group(1))>=count else 'FAIL' if 'BEAR_MISMATCH' in sim.get('stdout','') else 'UNKNOWN')
        result['simulation']=simulation
        result['status']='PASS' if result['formal']['status']=='PASS' and simulation['status']=='PASS' else 'FAIL' if 'FAIL' in (result['formal']['status'],simulation['status']) else 'UNKNOWN'
        if result.get('scope_status')!='FULL_PREFIX' and result['status']=='PASS':
            result['status']='UNKNOWN'
    result['elapsed_s']=time.monotonic()-started
    (out/'receipt.json').write_text(json.dumps(result,ensure_ascii=False,indent=2),encoding='utf-8')
    return result

