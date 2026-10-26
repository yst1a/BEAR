"""Shared array readout, actual-mux CEC and reset-aware pipeline alignment.

The PE array and periphery are integration boundaries, not re-proved here.
"""
from __future__ import annotations

import hashlib
import json
import re
from pathlib import Path
from .runtime import run_guarded, tool
from .verify import _quote


def _write(path, text):
    path = Path(path)
    path.parent.mkdir(parents=True, exist_ok=True)
    temporary = path.with_name(path.name + '.tmp')
    with temporary.open('w', encoding='utf-8', newline='\n') as stream:
        stream.write(text)
    temporary.replace(path)


def _save(path, value):
    _write(path, json.dumps(value, ensure_ascii=False, indent=2) + '\n')


def selection_valid(sel, n, mode):
    """Executable interface check, also emitted as RTL in the generated shell."""
    if mode == 'binary':
        return 0 <= sel < (1 << max(1, n.bit_length()))
    if mode not in ('onehot', 'onehot0'):
        raise ValueError('Unknown selection mode')
    return 0 <= sel < (1 << n) and not (sel & (sel - 1)) and (mode != 'onehot' or sel != 0)


def _options(n, width, k, mode, segments, mux_top):
    if n < 1 or not 0 <= k < width or not 1 <= segments <= width-k:
        raise ValueError('Require N>=1, 0<=k<W and 1<=segments<=W-k')
    if mode not in ('binary', 'onehot', 'onehot0'):
        raise ValueError('Unknown selection mode')
    if not re.fullmatch(r'[A-Za-z_][A-Za-z_0-9]*', mux_top):
        raise ValueError('Invalid mux module name')
    return max(1, n.bit_length()) if mode == 'binary' else n


def _valid(mode):
    if mode == 'binary':
        return "1'b1"
    return "((sel & (sel - 1'b1)) == 0)" + (" && (sel != 0)" if mode == 'onehot' else '')


def _mux(top, instance, width, n, sw, data, default, result):
    return (f'{top} #(.WIDTH({width}),.N({n}),.SEL_WIDTH({sw})) {instance}'
            f'(.sel(sel),.data({data}),.default_value({width}\'d{default}),.y({result}));')


def selector_groups(n, stages, groups=None):
    """Low selection bits are consumed first; zero-bit stages just register."""
    bits = max(1, (n-1).bit_length())
    if not isinstance(stages, int) or stages < 0:
        raise ValueError('selector_stages must be nonnegative')
    if groups is None:
        return [bits//stages + (j < bits % stages) for j in range(stages)] if stages else []
    groups = list(groups)
    if not stages or len(groups) != stages or any(type(g) is not int or g < 0 for g in groups) or sum(groups) != bits:
        raise ValueError('Selector groups must be M nonnegative bit counts summing to ceil(log2(N)) (at least 1)')
    return groups


def _staged_selector(n, width, k, mode, stages, groups, default):
    h, lw = width-k, max(1,k)
    bits = max(1,(n-1).bit_length())
    tw = lw+2*h
    l,s,c = default
    dv = (c << (h+lw)) | (s << lw) | l
    lines = [f'wire [{bits-1}:0] select_index;']
    if mode == 'binary':
        lines += [f'assign select_index=sel[{bits-1}:0];',f'wire has_lane=(sel < {n});']
    else:
        expr = f"{bits}'d0"
        for i in reversed(range(n)):
            expr = f"(sel[{i}] ? {bits}'d{i} : {expr})"
        lines += [f'assign select_index={expr};', "wire has_lane=(sel != 0);"]
    data=[]
    for i in range(1 << bits):
        name=f'select_input_{i}'
        value=f'{{carries[{i*h} +: {h}],sums[{i*h} +: {h}],lows[{i*lw} +: {lw}]}}' if i<n else f"{tw}'d{dv}"
        lines += [f"wire [{tw-1}:0] {name}=has_lane ? {value} : {tw}'d{dv};"]
        data.append(name)
    index,tag,remaining='select_index','tag',bits
    for j,g in enumerate(groups):
        new=[];regs=[];shifts=[]
        for i in range(len(data) >> g):
            name=f'select_data_{j}_{i}'
            expr=data[i*(1<<g)]
            for v in reversed(range(1,1<<g)):
                expr=f"({index}[{g-1}:0]=={g}'d{v} ? {data[i*(1<<g)+v]} : {expr})"
            lines += [f'reg [{tw-1}:0] {name};']
            new.append(name);regs.append(name);shifts.append(f'{name}<={expr};')
        remaining-=g
        if remaining:
            name=f'select_bits_{j}'
            lines += [f'reg [{remaining-1}:0] {name};']
            regs.append(name);shifts.append(f'{name}<={index}[{remaining+g-1}:{g}];');index=name
        name=f'select_tag_{j}'
        lines += [f'reg [31:0] {name};']
        regs.append(name);shifts.append(f'{name}<={tag};');tag=name
        lines += ['always @(posedge clk or negedge rst_n) if(!rst_n) begin',
                  *[f'{r}<=0;' for r in regs],'end else begin',*shifts,'end']
        data=new
    lines += [f'assign {{selected_carry,selected_sum,selected_low}}={data[0]};']
    return lines,tag






def readout_rtl(n, width, k, mux_top, *, mode='binary', segments=1,
                default=(0, 0, 0), selector_stages=0, selector_group_bits=None):
    """Emit a bus-level shell: lane i occupies the least significant slice i.

    Inputs are the exposed encoded PE states; no PE output decoder is instantiated.
    M registered selector levels plus L arithmetic segments give d=M+L-1 clocks.
    M=0 preserves the legacy combinational selector. Side signals travel with data.
    """
    sw = _options(n, width, k, mode, segments, mux_top)
    groups = selector_groups(n, selector_stages, selector_group_bits)
    h, lw = width-k, max(k, 1)
    l, s, c = default
    if not (0 <= l < (1 << k) and 0 <= s < (1 << h) and 0 <= c < (1 << h)):
        raise ValueError('Encoded default is outside the decoder domain')
    lines = [f'''module bear_array_readout(input clk,rst_n,
input [{sw-1}:0] sel,input [{n*lw-1}:0] lows,
input [{n*h-1}:0] sums,carries,input [31:0] tag,
output [{width-1}:0] y,output [31:0] tag_out,output selection_valid);
wire [{lw-1}:0] selected_low;
wire [{h-1}:0] selected_sum,selected_carry;
assign selection_valid={_valid(mode)};''',
             _mux(mux_top, 'select_low', lw, n, sw, 'lows', l, 'selected_low'),
             _mux(mux_top, 'select_sum', h, n, sw, 'sums', s, 'selected_sum'),
             _mux(mux_top, 'select_carry', h, n, sw, 'carries', c, 'selected_carry')]
    selected_tag = 'tag'
    if selector_stages:
        lines = lines[:-3]
        staged, selected_tag = _staged_selector(n,width,k,mode,selector_stages,groups,default)
        lines += staged
    # Each cut captures the unprocessed operands, carry, completed sum and LSBs.
    a, b, carry, done, low, tag = 'selected_sum', 'selected_carry', "1'b0", None, 'selected_low', selected_tag
    offset = 0
    regs, shifts = [], []
    for j in range(segments):
        size = h//segments + (j < h % segments)
        lines += [f"wire [{size}:0] add_{j}={{1'b0,{a}[{size-1}:0]}}+{{1'b0,{b}[{size-1}:0]}}+{carry};"]
        complete = f'add_{j}[{size-1}:0]' if done is None else f'{{add_{j}[{size-1}:0],{done}}}'
        offset += size
        if j == segments-1:
            lines += [f'assign y={{{complete},{low}}};' if k else f'assign y={complete};',
                      f'assign tag_out={tag};']
            break
        remain = h-offset
        for name, bits, expr in [(f'a{j}', remain, f'{a}[{h-offset+size-1}:{size}]'),
                                 (f'b{j}', remain, f'{b}[{h-offset+size-1}:{size}]'),
                                 (f'c{j}', 1, f'add_{j}[{size}]'),
                                 (f'd{j}', offset, complete), (f'l{j}', lw, low),
                                 (f't{j}', 32, tag)]:
            lines += [f'reg [{bits-1}:0] {name};']
            regs.append(name)
            shifts.append(f'{name}<={expr};')
        a, b, carry, done, low, tag = f'a{j}', f'b{j}', f'c{j}', f'd{j}', f'l{j}', f't{j}'
    if regs:
        lines += ['always @(posedge clk or negedge rst_n) if(!rst_n) begin',
                  *[f'{r}<=0;' for r in regs], 'end else begin', *shifts, 'end']
    return '\n'.join(lines + ['endmodule', ''])


def _cec(n, width, k, top, mode, default, original_default):
    sw = _options(n, width, k, mode, 1, top)
    h, lw = width-k, max(k, 1)
    l, s, c = default
    lines = [f'''module array_cec(input [{sw-1}:0] sel,
input [{n*lw-1}:0] lows,input [{n*h-1}:0] sums,carries);
wire [{lw-1}:0] ml; wire [{h-1}:0] ms,mc;
wire [{h-1}:0] high=ms+mc;
wire [{width-1}:0] shared_value={'{high,ml}' if k else 'high'};
wire [{n*width-1}:0] decoded;
wire [{width-1}:0] original_value;
wire valid={_valid(mode)};''',
             _mux(top, 'mlow', lw, n, sw, 'lows', l, 'ml'),
             _mux(top, 'msum', h, n, sw, 'sums', s, 'ms'),
             _mux(top, 'mcarry', h, n, sw, 'carries', c, 'mc'),
             _mux(top, 'mdecoded', width, n, sw, 'decoded', original_default, 'original_value')]
    checks = ['shared_value == original_value']
    for comp, bits, output, dv in [('lows', lw, 'ml', l), ('sums', h, 'ms', s), ('carries', h, 'mc', c)]:
        expr = f"{bits}'d{dv}"
        for i in reversed(range(n)):
            condition = f'sel == {sw}\'d{i}' if mode == 'binary' else f'sel[{i}]'
            expr = f'({condition} ? {comp}[{i*bits} +: {bits}] : {expr})'
        checks.append(f'{output} == {expr}')
    for i in range(n):
        lines += [f'wire [{h-1}:0] dh{i}=sums[{i*h} +: {h}]+carries[{i*h} +: {h}];',
                  f'assign decoded[{i*width} +: {width}]=' + (f'{{dh{i},lows[{i*lw} +: {lw}]}};' if k else f'dh{i};')]
    # The complete-tuple checks prevent arithmetic coincidences hiding split selects.
    lines += ['always @* begin', 'assume(valid);',
              *[f'assert({check});' for check in checks], 'end', 'endmodule', '']
    return '\n'.join(lines)


def _alignment(n, width, k, sw, delay, conditional=False):
    h, lw = width-k, max(k, 1)
    lines = [f'''module array_alignment(input clk,rst_n,input [{sw-1}:0] sel,
input [{n*lw-1}:0] lows,input [{n*h-1}:0] sums,carries,input [31:0] tag);
wire [{width-1}:0] y,reference;
wire [31:0] t,reference_tag;
wire valid,unused;
bear_array_readout dut(.*,.tag_out(t),.selection_valid(valid));
bear_array_reference ref0(.clk(clk),.rst_n(rst_n),.sel(sel),.lows(lows),
.sums(sums),.carries(carries),.tag(tag),.y(reference),
.tag_out(reference_tag),.selection_valid(unused));''']
    if conditional:
        lines += ['always @* assume(valid);']
    previous, previous_tag = 'reference', 'reference_tag'
    for j in range(delay):
        lines += [f'reg [{width-1}:0] q{j}; reg [31:0] tq{j};',
                  f'always @(posedge clk or negedge rst_n) if(!rst_n) begin q{j}<=0;tq{j}<=0;end',
                  f'else begin q{j}<={previous};tq{j}<={previous_tag};end']
        previous, previous_tag = f'q{j}', f'tq{j}'
    # Only initial reset is constrained; later resets and input histories are free.
    lines += ['always @* begin if($initstate) assume(!rst_n);',
              f'assert(y=={previous}); assert(t=={previous_tag}); end', 'endmodule', '']
    return '\n'.join(lines)


def _sat(out, name, sources, top, command, timeout):
    script = 'read_verilog -formal -sv ' + ' '.join(_quote(p) for p in sources)
    script += f'\nhierarchy -check -top {top}\nprep -top {top} -flatten\nasync2sync\ndffunmap\nmemory_map\nopt\n'
    script += command + '\n'
    _write(out/(name+'.ys'), script)
    rec = run_guarded([tool('yosys'), '-s', out/(name+'.ys')], cwd=out,
                      log=out/(name+'.log'), timeout=timeout)
    text = rec['stdout']
    passed = rec['returncode'] == 0 and ('SUCCESS!' in text)
    failed = 'model found: FAIL!' in text or 'proof did fail' in text or 'proof for base case failed' in text
    status = 'PASS' if passed else 'FAIL' if failed else 'UNKNOWN'
    return dict(status=status, execution=rec)


def reuse_pe(proof_path, pe_files, width, k):
    record = json.loads(Path(proof_path).read_text(encoding='utf-8-sig'))
    if (record.get('status') != 'PASS' or record.get('formal', {}).get('status') != 'PASS'
            or record.get('simulation', {}).get('status') != 'PASS'
            or record.get('scope_status') != 'FULL_PREFIX' or record.get('latency', 0) != 0
            or record.get('refinement_skipped')):
        raise ValueError('Require a completed full-prefix, zero-delay bear verify PE result')
    sources = record.get('source_sha256', {})
    for path in pe_files:
        digest = hashlib.sha256(Path(path).read_bytes()).hexdigest()
        if digest not in sources.values():
            raise ValueError('PE source differs from the existing verify result')
    states = record.get('refinement')
    if not isinstance(states, list) or not states or any(
            r.get('width') != width or r.get('k') != k for r in states):
        raise ValueError('PE refinement must identify states with the requested W and k')
    source_text = '\n'.join(Path(p).read_text(encoding='utf-8-sig') for p in pe_files)
    for state in states:
        names = state.get('state_names', {})
        if any(not names.get(key) or names[key] not in source_text
               for key in (('os','oc','ol') if k else ('os','oc'))):
            raise ValueError('Supply candidate RTL exposing the proved sum/carry/low state names')
    return dict(status='REUSED', proof=str(Path(proof_path).resolve()), instances='all',
                state_names=[r.get('state_names', {}) for r in states])


def build_array(pe_files, pe_proof, mux_files, mux_top, n, width, k, out, *,
                mode='binary', segments=1, default=(0, 0, 0), original_default=0,
                timeout=120, selector_files=(), selector_top=None, control_width=None,
                selector_stages=0, selector_group_bits=None):
    """Generate and prove the readout; PE operands/periphery remain user obligations."""
    out = Path(out).resolve()
    sw = _options(n, width, k, mode, segments, mux_top)
    groups = selector_groups(n, selector_stages, selector_group_bits)
    delay = selector_stages + segments - 1
    if not pe_files or not mux_files:
        raise ValueError('Supply the proven PE sources and actual mux sources')
    pe = reuse_pe(pe_proof, pe_files, width, k)
    if selector_files and (mode == 'binary' or not selector_top or not control_width or control_width < 1):
        raise ValueError('Selector check requires a onehot mode, selector top and positive control width')
    if selector_top and not re.fullmatch(r'[A-Za-z_][A-Za-z_0-9]*', selector_top):
        raise ValueError('Invalid selector module name')
    if not 0 <= original_default < (1 << width):
        raise ValueError('Original default is outside W bits')
    rtl = readout_rtl(n, width, k, mux_top, mode=mode, segments=segments, default=default,
                      selector_stages=selector_stages, selector_group_bits=groups if groups else None)
    # Retain exactly the mux text used by both production RTL and the proof.
    mux_paths = []
    for i, p in enumerate(mux_files):
        dest = out/f'mux_{i}.sv'
        _write(dest, Path(p).read_text(encoding='utf-8-sig'))
        mux_paths.append(dest)
    _write(out/'readout.sv', rtl)
    _write(out/'commutation.sv', _cec(n, width, k, mux_top, mode, default, original_default))
    cec = _sat(out, 'commutation', mux_paths+[out/'commutation.sv'], 'array_cec',
               'sat -prove-asserts -set-assumes -show-inputs -show-outputs -dump_json commutation_counterexample.json', timeout)
    _write(out/'reference.sv', readout_rtl(n, width, k, mux_top, mode=mode, default=default).replace(
        'module bear_array_readout(', 'module bear_array_reference('))
    _write(out/'alignment.sv', _alignment(n, width, k, sw, delay, mode != 'binary'))
    alignment = _sat(out, 'alignment', mux_paths+[out/'readout.sv',out/'reference.sv',out/'alignment.sv'],
                     'array_alignment', f'sat -seq 1 -tempinduct -maxsteps {delay+4} -prove-asserts -set-assumes', timeout)
    statuses = [cec['status'], alignment['status']]
    selection_check = None
    if selector_files:
        paths = []
        for i,p in enumerate(selector_files):
            dest = out/f'selector_{i}.sv'
            _write(dest, Path(p).read_text(encoding='utf-8-sig'))
            paths.append(dest)
        _write(out/'selection.sv', f'''module selection_check(input [{control_width-1}:0] control);
wire [{n-1}:0] sel;
{selector_top} dut(.control(control),.sel(sel));
always @* assert({_valid(mode)});
endmodule
''')
        selection_check = _sat(out, 'selection', paths+[out/'selection.sv'], 'selection_check',
                               'sat -prove-asserts -show-inputs -dump_json selection_counterexample.json', timeout)
        statuses.append(selection_check['status'])
    result = dict(status='PASS' if all(s == 'PASS' for s in statuses) else 'FAIL' if 'FAIL' in statuses else 'UNKNOWN',
                  scope='READOUT_COMPOSITION', pe=pe, n=n, width=width, k=k, latency=delay,
                  selector_stages=selector_stages, selector_group_bits=groups, arithmetic_segments=segments,
                  latency_definition='d=M+L-1 extra readout clocks; M=0 is the legacy combinational selector',
                  alignment_contract='Readout equals the original readout through a d-stage reference delay line cleared on every reset', 
                  commutation=cec, alignment=alignment, rtl=str(out/'readout.sv'), mux_sources=list(map(str,mux_paths)),
                  selection=dict(mode=mode, status='UNCONDITIONAL' if mode=='binary' else
                                 'PROVEN_PRODUCER' if selection_check and selection_check['status']=='PASS' else 'CONDITIONAL',
                                 producer_check=selection_check,
                                 check_output='selection_valid',
                                 requirement='all selection codes' if mode=='binary' else mode+' on every sampled input'),
                  integration_obligations=['Same decoder for every PE and initial state relation',
                      'Same operands, loads, enables and periphery transitions',
                      'Selection observes PE state only through decoded values; no other per-PE decoded reader',
                      'Connect lows/sums/carries to the proved encoded states; preserve paired tags',
                      'For onehot modes, prove selection_valid from the array controller or constrain the external protocol'],
                  reset_model='async2sync cycle semantics; every reset clears all readout registers; no enable gating')
    _save(out/'ARRAY.json', result)
    return result
