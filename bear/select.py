"""Select."""
from __future__ import annotations
import json, math, re, time, os
from pathlib import Path
from .runtime import ENV, run_guarded, tool, sha

LIB = Path(os.environ['BEAR_LIBERTY']).resolve() if os.environ.get('BEAR_LIBERTY') else None
CONSTR = Path(os.environ['BEAR_CONSTRAINTS']).resolve() if os.environ.get('BEAR_CONSTRAINTS') else None
STAENV = dict(ENV)


def configure(liberty=None, constraints=None):
    """Set the Liberty library and ABC constraints supplied by the caller."""
    global LIB, CONSTR
    if liberty is not None: LIB = Path(liberty).resolve()
    if constraints is not None: CONSTR = Path(constraints).resolve()


def readout_options(readout='every-cycle', readout_ports=(), readout_budget_ps=None, readout_contract=None):
    """Select."""
    if readout not in ('every-cycle', 'on-readout'):
        raise ValueError('readout must be every-cycle or on-readout')
    ports=list(dict.fromkeys(readout_ports or ()))
    if any(not re.fullmatch(r'[A-Za-z_][A-Za-z0-9_$]*', p) for p in ports):
        raise ValueError('Readout ports must be explicit top-level identifiers, without wildcards or Tcl expressions')
    if readout=='on-readout':
        if not ports or readout_budget_ps is None or not math.isfinite(float(readout_budget_ps)) or float(readout_budget_ps)<=0:
            raise ValueError('on-readout requires ports and a positive independent readout budget in ps')
        if not readout_contract or not str(readout_contract).strip():
            raise ValueError('on-readout requires an external protocol allowing the readout budget after the last update and no other observations')
    elif ports or readout_budget_ps is not None or readout_contract:
        raise ValueError('every-cycle does not accept relaxed readout parameters')
    return dict(mode=readout, ports=ports, budget_ps=float(readout_budget_ps) if readout_budget_ps is not None else None,
                contract=readout_contract, validation='USER_DECLARED_EXTERNAL_PROTOCOL' if readout=='on-readout' else 'EVERY_CYCLE',
                rtl_latency_change=0)

def apply_readout_semantics(point, *, readout='every-cycle', readout_ports=(), readout_budget_ps=None,
                            readout_contract=None, all_output_ports=None):
    """Select."""
    opts=readout_options(readout,readout_ports,readout_budget_ps,readout_contract)
    row={**point,'readout_semantics':opts};paths=row.get('paths_ps',{})
    row['all_paths_delay_ps']=max((v for v in paths.values() if v is not None),default=row.get('budget_delay_ps'))
    if readout=='every-cycle':
        row['budget_delay_ps']=row['all_paths_delay_ps'];row['readout_delay_ps']=None
        row['timing_scope']='Every-cycle observation: one budget for RR/IR/RO/IO with identical interfaces and loads'
        return row
    if all_output_ports is not None:
        if not set(opts['ports'])<=set(all_output_ports):
            raise ValueError('Readout port is not a top-level output')
    if 'RO_READOUT' in paths and 'IO_READOUT' in paths:
        core=[paths.get(k) for k in ('RR','IR','RO_EVERY','IO_EVERY')]
        sampled=[paths.get(k) for k in ('RO_READOUT','IO_READOUT')]
    elif all_output_ports is not None and set(opts['ports'])==set(all_output_ports):
        core=[paths.get(k) for k in ('RR','IR')];sampled=[paths.get(k) for k in ('RO','IO')]
    else:
        row.update(status='UNKNOWN_READOUT_TIMING',budget_delay_ps=None,readout_delay_ps=None,
                   readout_error='STA lacks separate readout/every-cycle output groups; rerun STA')
        return row
    row['budget_delay_ps']=max((v for v in core if v is not None),default=None)
    row['readout_delay_ps']=max((v for v in sampled if v is not None),default=None)
    if row['budget_delay_ps'] is None:row['budget_delay_ps']=0.0
    if row['readout_delay_ps'] is None:row['status']='UNKNOWN_READOUT_TIMING'
    row['timing_scope']='RR/IR and other outputs use the cycle budget; readout RO/IO use the declared readout budget; retain all paths, interfaces and loads'
    return row

def point_feasible(point,budget):
    if point.get('status')!='PASS' or point.get('budget_delay_ps') is None or point['budget_delay_ps']>budget:
        return False
    opts=point.get('readout_semantics',{})
    return opts.get('mode','every-cycle')!='on-readout' or (
        point.get('readout_delay_ps') is not None and opts.get('budget_ps') is not None and
        point['readout_delay_ps']<=opts['budget_ps'])

def _max_path_delay_ps(report, period_ns=10):
    """Select."""
    slacks=[float(v) for v in re.findall(r'^\s*(-?[0-9.]+)\s+slack',report,re.M)]
    return round((period_ns-min(slacks))*1000,1) if slacks else None


def sta(net, top, out, has_clock=True, tag='sta', *, readout='every-cycle', readout_ports=(),
        readout_budget_ps=None, readout_contract=None):
    readout_options(readout,readout_ports,readout_budget_ps,readout_contract)
    out=Path(out).resolve(); out.mkdir(parents=True,exist_ok=True)
    txt=Path(net).read_text(encoding='utf-8')
    netview=out/(tag+'_compatible.v')
    netview.write_text(re.sub(r'\bwire\s+signed\b','wire',txt), encoding='utf-8')
    setup=[f'read_liberty {{{LIB}}}',f'read_verilog {{{netview}}}',f'link_design {top}',
           'set_wire_load_model -name 1K_hvratio_1_4','set_wire_load_mode top']
    if has_clock:
        setup += ['create_clock -name clk -period 10 [get_ports clk]',
                  'set_input_delay 0 -clock clk [delete_from_list [all_inputs] [get_ports clk]]',
                  'set_driving_cell -lib_cell INV_X1 -pin ZN [delete_from_list [all_inputs] [get_ports clk]]',
                  'set_output_delay 0 -clock clk [all_outputs]']
    else:
        setup += ['create_clock -name virtual -period 10','set_input_delay 0 -clock virtual [all_inputs]',
                  'set_output_delay 0 -clock virtual [all_outputs]',
                  'set_driving_cell -lib_cell INV_X1 -pin ZN [all_inputs]']
    setup += ['set_load 6.80092 [all_outputs]']
    groups={'IO':'-from [all_inputs] -to [all_outputs]'}
    if has_clock:
        groups.update(RR='-from [all_registers -clock_pins] -to [all_registers -data_pins]',
                      IR='-from [delete_from_list [all_inputs] [get_ports clk]] -to [all_registers -data_pins]',
                      RO='-from [all_registers -clock_pins] -to [all_outputs]')
    if readout=='on-readout':
        setup += ['set readout_ports {}']
        for name in readout_ports:
            pattern='^'+re.escape(name)+r'(\[[0-9]+\])?$'
            setup += ['set matched_ports {}',
                      f'foreach p [all_outputs] {{ if {{[regexp {{{pattern}}} [get_full_name $p]]}} {{ lappend matched_ports $p }} }}',
                      f'if {{[llength $matched_ports] == 0}} {{ error "Readout port {name} is missing or is not an output" }}',
                      'set readout_ports [concat $readout_ports $matched_ports]']
        setup += ['set every_outputs [delete_from_list [all_outputs] $readout_ports]']
        groups.update(IO_READOUT='-from [all_inputs] -to $readout_ports',
                      IO_EVERY='-from [all_inputs] -to $every_outputs')
        if has_clock:
            groups.update(RO_READOUT='-from [all_registers -clock_pins] -to $readout_ports',
                          RO_EVERY='-from [all_registers -clock_pins] -to $every_outputs')
    for name,opts in groups.items():
        report=f'report_checks -path_delay max {opts} -digits 4 -format full_clock_expanded'
        if name.endswith('_EVERY'):report='if {[llength $every_outputs] > 0} { '+report+' }'
        setup += ['puts =='+name+'==',report]
    setup += ['puts ==POWER==','report_power','puts ==END==',f'write_sdf -digits 4 -no_timestamp -no_version {{{out/(tag+".sdf")}}}','exit']
    script=out/(tag+'.tcl');script.write_text('\n'.join(setup)+'\n', encoding='utf-8')
    result=run_guarded([tool('sta'),'-no_splash',script],cwd=out,log=out/(tag+'.log'),env=STAENV,timeout=300)
    values={}
    for name in groups:
        part=result['stdout'].split('=='+name+'==')[1].split('==')[0] if '=='+name+'==' in result['stdout'] else ''
        values[name]=_max_path_delay_ps(part)
    if readout=='on-readout' and not has_clock:values['RO_READOUT']=None
    allv=[v for v in values.values() if v is not None]
    core=[values[k] for k in ('RR','IR') if values.get(k) is not None]
    row=dict(status=result['status'] if allv else 'UNKNOWN_STA',paths_ps=values,
                period_ps=max(core) if core else values.get('IO'),
                budget_delay_ps=max(allv) if allv else None,
                readout_ps=values.get('RO'),log=result['log'],
                static_activity_power_log=result['log'],energy_proxy='NOT_ASSESSED',
                timing_scope='period=max(RR,IR); report RO separately; feasibility includes RO/IO with identical interfaces and loads')
    return apply_readout_semantics(row,readout=readout,readout_ports=readout_ports,
                                  readout_budget_ps=readout_budget_ps,readout_contract=readout_contract)

def synthesize(files,top,out,D=100,heavy=False,*,readout='every-cycle',readout_ports=(),
               readout_budget_ps=None,readout_contract=None):
    readout_options(readout,readout_ports,readout_budget_ps,readout_contract)
    started=time.monotonic();files=[Path(p).resolve() for p in files];out=Path(out).resolve();out.mkdir(parents=True,exist_ok=True)
    net=out/'mapped.v';script=out/'synth.ys'
    from .synthesis_frontend import prepare
    
    if LIB is None or CONSTR is None:
        raise ValueError('Supply --liberty and --constraints, or BEAR_LIBERTY and BEAR_CONSTRAINTS')
    frontend=prepare(files,top,LIB,heavy=heavy,out=out/'frontend')
    if frontend['status']!='PASS':
        row=dict(status=frontend['status'],D=D,area=None,period_ps=None,budget_delay_ps=None,top=top,
                 source_sha256={str(p):sha(p) for p in files},frontend=frontend,runtime_s=time.monotonic()-started)
        (out/'PPA.json').write_text(json.dumps(row,ensure_ascii=False,indent=2), encoding='utf-8');return row
    lines=[f'read_rtlil {frontend["prepared"]}',
           f'abc -exe {tool("yosys-abc")} -liberty {LIB} -constr {CONSTR} -D {D}',
           'opt_clean','check -assert',f'tee -o {out/"stat.txt"} stat -liberty {LIB}',f'write_verilog -noattr {net}']
    script.write_text('\n'.join(lines)+'\n', encoding='utf-8')
    result=run_guarded([tool('yosys'),'-q','-s',script],cwd=out,log=out/'synth.log',heavy=heavy,timeout=1800)
    row=dict(status=result['status'],D=D,area=None,period_ps=None,budget_delay_ps=None,
             source_sha256={str(p):sha(p) for p in files},lib_sha256=sha(LIB),
             flow='ordinary',top=top,job_dir=str(out),runtime_s=time.monotonic()-started)
    row.update(frontend_reused=frontend['frontend_reused'],frontend={k:v for k,v in frontend.items() if k!='execution'})
    if result['returncode'] or not net.exists(): return row
    stat=(out/'stat.txt').read_text(encoding='utf-8');m=re.search(r'Chip area[^:]*:\s*([0-9.]+)',stat)
    row['area']=float(m[1]) if m else None
    text=net.read_text(encoding='utf-8');row['n_dff']=len(re.findall(r'^\s*DFF\w*_X\d+\s',text,re.M))
    row['netlist_sha256']=sha(net);row['mapped']=str(net)
    row.update(sta(net,top,out,has_clock=bool(re.search(r'\binput\s+(?:wire\s+)?clk\s*;',text)),
                   readout=readout,readout_ports=readout_ports,readout_budget_ps=readout_budget_ps,readout_contract=readout_contract))
    row['status']='PASS' if row['area'] is not None and row['budget_delay_ps'] is not None and row['status']=='PASS' else 'UNKNOWN_PPA'
    row['runtime_s']=time.monotonic()-started
    (out/'PPA.json').write_text(json.dumps(row,ensure_ascii=False,indent=2), encoding='utf-8')
    return row

def select(points,budgets=(),original='original',proofs=None,objective='area@budget'):
    """Select."""
    if objective not in ('area@budget','fastest'):
        raise ValueError('objective must be area@budget or fastest')
    if objective=='fastest':
        scopes={json.dumps(p.get('readout_semantics',{'mode':'every-cycle'}),sort_keys=True) for p in points}
        if len(scopes)>1:raise ValueError('Cannot mix points with different readout modes, protocols or budgets')
        eligible=[p for p in points if point_feasible(p,float('inf')) and
                  p.get('area') is not None and math.isfinite(float(p['area'])) and
                  math.isfinite(float(p['budget_delay_ps'])) and
                  (p['variant']==original or (proofs or {}).get(p['variant'],{}).get('status')=='PASS' and
                   (proofs or {}).get(p['variant'],{}).get('scope_status')=='FULL_PREFIX')]
        best=min(eligible,key=lambda p:(p['budget_delay_ps'],p['area']),default=None)
        base=min((p for p in eligible if p['variant']==original),
                 key=lambda p:(p['budget_delay_ps'],p['area']),default=None)
        return [dict(objective=objective,budget_ps=None,selected=best,baseline=base,
                     fallback_reason='NO_FEASIBLE_PROVEN_POINT' if best is None else
                     'ORIGINAL_IS_FASTEST' if best['variant']==original else None)]
    decisions=[]
    for budget in budgets:
        feasible=[p for p in points if point_feasible(p,budget)]
        scopes={json.dumps(p.get('readout_semantics') if p.get('readout_semantics',{}).get('mode')=='on-readout'
                           else {'mode':'every-cycle'},sort_keys=True) for p in points}
        if len(scopes)>1:raise ValueError('Cannot mix points with different readout modes, protocols or budgets')
        base=[p for p in feasible if p['variant']==original]
        base_ties=[p for p in base if p['area']==min(q['area'] for q in base)] if base else []
        base_energy_complete=bool(base_ties) and all(p.get('dynamic_pJ_per_cycle') is not None for p in base_ties)
        bestbase=min(base_ties,key=lambda p:(p['dynamic_pJ_per_cycle'],p['budget_delay_ps'])) if base_energy_complete else min(base_ties,key=lambda p:p['budget_delay_ps']) if base_ties else None
        eligible=[p for p in feasible if p['variant']==original or proofs is None or (
            proofs.get(p['variant'],{}).get('status')=='PASS' and
            proofs.get(p['variant'],{}).get('scope_status')=='FULL_PREFIX')]
        ties=[p for p in eligible if p['area']==min(q['area'] for q in eligible)] if eligible else []
        energy_complete=bool(ties) and all(p.get('dynamic_pJ_per_cycle') is not None for p in ties)
        best=min(ties,key=lambda p:(p['dynamic_pJ_per_cycle'],p['budget_delay_ps'])) if energy_complete else min(ties,key=lambda p:p['budget_delay_ps']) if ties else None
        reason=None
        if not best: reason='NO_FEASIBLE_PROVEN_POINT'
        elif best['variant']==original: reason='NO_AREA_GAIN_AT_BUDGET'
        decisions.append(dict(budget_ps=budget,selected=best,baseline=bestbase,fallback_reason=reason,
                              readout_semantics=points[0].get('readout_semantics',{'mode':'every-cycle'}) if points else {'mode':'every-cycle'},
                              energy_secondary='ASSESSED_ON_EQUAL_AREA' if energy_complete else 'NOT_ASSESSED_INCOMPLETE_TIE_ENERGY',
                              area_gain_percent=100*(bestbase['area']-best['area'])/bestbase['area'] if best and bestbase else None))
    return decisions


