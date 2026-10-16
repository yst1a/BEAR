""" pipeline."""
from __future__ import annotations
from copy import deepcopy
import hashlib
import json
import re
from pathlib import Path
import time
from .extract import NetGraph, _integer, _quote


class Unsupported(ValueError):
    pass


def _low_function(cert, name="lowfn"):
    if int(cert.get('k',cert.get('k_min',0)))>10:
        from ._lowfn import low_function_lines
        return low_function_lines(cert,name)
    if cert.get('_gate_netlist'):
        try:
            from .gate_low_function import gate_low_function
            return gate_low_function(cert,name)
        except ModuleNotFoundError as exc:
            if exc.name != 'numpy':
                raise
            return _truth_table_low_function_preserved(cert,name)
    try:
        import numpy as np
    except ModuleNotFoundError as exc:
        if exc.name == 'numpy':
            return _truth_table_low_function_preserved(cert,name)
        raise
    k=cert.get('k');B=1<<k;a=np.arange(B)[:,None];b=np.arange(B)[None,:]
    ph=np.asarray(cert['phi']);ka=np.asarray(cert['kappa'])
    options=[('(a|b)',a|b),('(a^b)',a^b),('(a&b)',a&b),('(a+b)',(a+b)%(1<<k))]
    carries=[("1'b0",np.zeros((B,B),dtype=int)),(f'(a[{k-1}]&b[{k-1}])',(a>>(k-1))&(b>>(k-1))),("( ({1'b0,a}+{1'b0,b}) >> "+str(k)+" )",(a+b)>>k)]
    pe=next((expr for expr,v in options if np.array_equal(ph,v)),None)
    ce=next((expr for expr,v in carries if np.array_equal(ka,v)),None)
    if pe is not None and ce is not None:
        if pe=='(a+b)' and np.array_equal(ka,(a+b)>>k):
            return [f'function [{k}:0] {name}(input [{k-1}:0] a,b);',"begin",f"{name}={{1'b0,a}}+{{1'b0,b}};","end","endfunction"]
        return [f'function [{k}:0] {name}(input [{k-1}:0] a,b);','begin',f'{name}={{{ce},{pe}}};','end','endfunction']
    return _truth_table_low_function_preserved(cert,name)


def _truth_table_low_function_preserved(cert, name="lowfn"):
    from ._lowfn import low_function_lines
    return low_function_lines(cert,name)


class Helper:
    def __init__(self, name, width, k):
        self.name, self.width, self.k = name, width, k
        self.ports, self.lines, self.connections = [], [], {}
        self.n = 0
        self.fusion_cache = {}

    def port(self, bits, prefix="p"):
        bits = list(bits)
        for key, value in self.connections.items():
            if value == bits and key not in ("q", "os", "oc", "ol"):
                return key
        name = f"{prefix}{self.n}"
        self.n += 1
        self.connections[name] = bits
        self.ports.append(f"input [{len(bits)-1}:0] {name}")
        return name

    def wire(self, expr, width, prefix="v"):
        name = f"{prefix}{self.n}"
        self.n += 1
        self.lines.append(f"wire [{width-1}:0] {name}={expr};")
        return name

    def raw(self, bits):
        if not 0 < len(bits) <= self.width:
            raise Unsupported("Load/operand widths do not match the state")
        bits = list(bits) + ['0'] * (self.width-len(bits))
        v = self.port(bits)
        return f"{v}[{self.k-1}:0]", f"{v}[{self.width-1}:{self.k}]", f"{self.width-self.k}'b0"

    def shift(self, encoded, shift):
        low, s, c = encoded
        w, k, h = self.width, self.k, self.width - self.k
        if shift < 0:
            raise Unsupported("Right-shift carry-save state is unsupported")
        if shift >= w:
            return f"{k}'b0", f"{h}'b0", f"{h}'b0"
        lo = self.wire(f"({low}) << {shift}", k)
        injection = f"(({low}) >> {k-shift})" if shift < k else f"(({low}) << {shift-k})"
        ss = self.wire(f"(({s}) << {shift}) | ({injection})", h)
        cc = self.wire(f"({c}) << {shift}", h)
        return lo, ss, cc

    def state(self, path, encoded):
        if path is None:
            raise Unsupported("State path cannot be re-encoded")
        if path["kind"] == "state":
            reg = path["register"]
            if reg not in encoded:
                raise Unsupported("Upstream state lacks a representation with matching width and k")
            return self.shift(encoded[reg], path["shift"])
        if path["kind"] == "shift":
            return self.shift(self.state(path["a"], encoded), path["shift"])
        if path["kind"] == "mux":
            a, b = self.state(path["a"], encoded), self.state(path["b"], encoded)
            select = self.port(path["select"], "sel")
            return tuple(self.wire(f"{select} ? ({bb}) : ({aa})", width) for aa, bb, width in zip(a, b, [self.k, self.width-self.k, self.width-self.k]))
        raise Unsupported("Unknown state path")

    def compress(self, terms, carry):
        h = self.width - self.k
        terms = [t for t in terms if t != f"{h}'b0"]
        while len(terms) > 3:
            a, b, c = terms[:3]
            s = self.wire(f"({a}) ^ ({b}) ^ ({c})", h)
            m = self.wire(f"(({a})&({b})) | (({a})&({c})) | (({b})&({c}))", h)
            cy = self.wire(f"({m}) << 1", h)
            terms = [s, cy] + terms[3:]
        terms += [f"{h}'b0"] * (3 - len(terms))
        a, b, c = terms
        s = self.wire(f"({a}) ^ ({b}) ^ ({c})", h)
        m = self.wire(f"(({a})&({b})) | (({a})&({c})) | (({b})&({c}))", h)
        cy = self.wire(f"(({m}) << 1) | ({carry})", h)
        return s, cy


def _new_bits(module, width):
    all_bits = [b for v in module.get("netnames", {}).values() for b in v["bits"] if isinstance(b, int)]
    all_bits += [b for c in module.get("cells", {}).values() for v in c["connections"].values() for b in v if isinstance(b, int)]
    start = max(all_bits + [1]) + 1
    return list(range(start, start + width))


def _alloc(module, name, width):
    bits = _new_bits(module, width)
    module.setdefault("netnames", {})[name] = {"hide_name": 0, "bits": bits, "attributes": {"keep": "00000000000000000000000000000001"}}
    return bits


def _cell(helper):
    directions = {p: "input" for p in helper.connections}
    for p in ("q", "os", "oc", "ol"):
        if p in directions:
            directions[p] = "output"
    return {"hide_name": 0, "type": helper.name, "parameters": {}, "attributes": {},
            "port_directions": directions, "connections": helper.connections}


def _unsigned_bound(graph,bits,depth=0,memo=None):
    """ pipeline."""
    bits=list(bits)
    memo={} if memo is None else memo
    key=tuple(bits)
    fallback=sum((v!='0') << i for i,v in enumerate(bits))
    if key in memo:
        return memo[key]
    if depth>64 or not bits:
        return fallback
    driver=graph.drivers.get(key)
    if driver is None:
        for produced,candidate in graph.drivers.items():
            if not produced or not any(isinstance(v,int) for v in produced):
                continue
            for offset in range(len(bits)):
                n=min(len(produced),len(bits)-offset)
                if bits==['0']*offset+list(produced[:n])+['0']*(len(bits)-offset-n):
                    bound=_unsigned_bound(graph,list(produced),depth+1,memo)
                    result=min(bound,(1<<n)-1) << offset
                    memo[key]=result
                    return result
        return fallback
    cell=graph.cells[driver[0]]
    typ,con,par=cell['type'],cell['connections'],cell.get('parameters',{})
    result=fallback
    if typ in ('$add','$mul') and not any(_integer(par.get(p+'_SIGNED','0')) for p in ('A','B')):
        a=_unsigned_bound(graph,con['A'],depth+1,memo)
        b=_unsigned_bound(graph,con['B'],depth+1,memo)
        mathematical=a+b if typ=='$add' else a*b
        result=mathematical if mathematical < 1<<len(bits) else fallback
    elif typ=='$mux':
        result=max(_unsigned_bound(graph,con[p],depth+1,memo) for p in ('A','B'))
    elif typ=='$and':
        result=min(_unsigned_bound(graph,con[p],depth+1,memo) for p in ('A','B'))
    elif typ in ('$shl','$sshl'):
        a=_unsigned_bound(graph,con['A'],depth+1,memo)
        if _integer(par.get('A_SIGNED','0')) and len(con['A'])<len(bits) and con['A'][-1]!='0':
            a=(1<<len(bits))-1
        shift=_unsigned_bound(graph,con['B'],depth+1,memo)
        if shift < len(bits) and a << shift < 1<<len(bits):
            result=a << shift
    memo[key]=min(result,fallback)
    return memo[key]


def _fused_raw(graph, bits, helper, depth=0):
    """ pipeline."""
    w, k, h = helper.width, helper.k, helper.width-helper.k
    bits=list(bits)[:w]
    external=getattr(helper,'external_encoded',{})
    if external:
        path=graph.state_path(bits)
        if path is not None and graph.state_sources(path) <= set(external):
            regs=graph.state_sources(path)
            fullwidth=all(len(graph.registers[r]['connections']['Q'])==w for r in regs)
            native_direct=(path['kind']=='state' and path.get('shift',0)==0)
            if fullwidth or native_direct:
                return helper.state(path,external),[{'kind':'REGISTER_ENCODED_SOURCE','width':w,'no_wrap_proven':False}]
        for reg,rows in external.items():
            qb=list(graph.registers[reg]['connections']['Q'])
            if len(qb)<=w and bits==qb+['0']*(len(bits)-len(qb)):
                # Lifted state invariant already constrains upper decoded bits to zero.
                return rows,[{'kind':'LIFTED_REGISTER_ZERO_EXTENSION','width':w,'no_wrap_proven':False}]
            if len(qb)<len(bits) and bits==qb+[qb[-1]]*(len(bits)-len(qb)):
                # Native sign extension requires the decoded sign, not a row sign.
                return helper.raw(bits),[]

    cachekey=(tuple(bits),w)
    if cachekey in helper.fusion_cache:
        return helper.fusion_cache[cachekey]
    driver = graph.drivers.get(tuple(bits))
    view_width=len(bits)
    if driver is None and depth<=8:
        for produced,candidate in graph.drivers.items():
            if graph.cells[candidate[0]]['type'] not in ('$add','$mul','$mux','$shl','$sshl','$neg'):
                continue
            found=False
            for offset in range(len(bits)-k):
                if any(v!='0' for v in bits[:offset]):
                    continue
                for n in range(min(len(produced),len(bits)-offset),k,-1):
                    if offset==0 and n==len(bits):
                        continue
                    if bits[offset:offset+n]!=list(produced[:n]):
                        continue
                    suffix=bits[offset+n:]
                    zeroext=all(v=='0' for v in suffix)
                    signedext=bool(suffix) and all(v==produced[n-1] for v in suffix)
                    if not zeroext and not signedext:
                        continue
                    encoded,fusion=_fused_raw(graph,list(produced[:n]),helper,depth+1)
                    if not fusion:
                        continue
                    low,s,c=encoded
                    if signedext and not zeroext:
                        sign=helper.port([produced[n-1]],'view_sign')
                        upper=((1<<h)-1)^((1<<(n-k))-1)
                        pad=helper.wire(f"{sign}?{h}'d{upper}:{h}'b0",h,'view_pad')
                        s=helper.wire(f'({s}) | ({pad})',h,'view_s')
                    encoded=helper.shift((low,s,c),offset)
                    bound=_unsigned_bound(graph,list(produced[:n]))
                    nowrap=fusion[-1].get('no_wrap_proven',False) and zeroext and (bound<<offset)<1<<w
                    result=(encoded,fusion+[{'cell':candidate[0],'kind':'FOLDED_WIRING_LEFT_SHIFT_AND_EXTENSION',
                                           'shift':offset,'source_width':n,'target_width':w,'signed_extension':signedext and not zeroext,'no_wrap_proven':nowrap}])
                    helper.fusion_cache[cachekey]=result
                    return result
    if driver is None:
        for produced,candidate in graph.drivers.items():
            if graph.cells[candidate[0]]['type'] not in ('$add','$mul','$mux','$shl','$sshl','$neg'):
                continue
            for n in range(min(len(produced),len(bits)),k,-1):
                if bits[:n] == list(produced[:n]) and all(v=='0' for v in bits[n:]):
                    driver=candidate
                    view_width=n
                    break
            if driver is not None:
                break
    if not driver or depth > 8:
        return helper.raw(bits), []
    cell = graph.cells[driver[0]]
    if cell['type'] not in ('$add', '$mul','$mux','$shl','$sshl','$neg'):
        return helper.raw(bits), []
    if k < view_width < w:
        sw=view_width
        helper.width=sw
        try:
            encoded,fusion=_fused_raw(graph,bits[:sw],helper,depth+1)
        finally:
            helper.width=w
        if not fusion:
            return helper.raw(bits),[]
        low,s,c=encoded
        sh=sw-k
        if fusion[-1].get('no_wrap_proven',False):
            ss=helper.wire(f"{{{h-sh}'b0,{s}}}",h,'width_ext_s')
            cc=helper.wire(f"{{{h-sh}'b0,{c}}}",h,'width_ext_c')
            result=((low,ss,cc),fusion+[{'cell':driver[0],'kind':'NO_WRAP_INTERVAL_ZERO_EXTENSION','source_width':sw,'target_width':w,'no_wrap_proven':True}])
        else:
            decoded=helper.wire(f'({s})+({c})',sh,'width_norm')
            expanded=helper.wire(f"{{{h-sh}'b0,{decoded}}}",h,'width_ext')
            result=((low,expanded,f"{h}'b0"),fusion+[{'cell':driver[0],'kind':'WIDTH_NORMALIZATION_CPA','source_width':sw,'target_width':w,'no_wrap_proven':True}])
        helper.fusion_cache[cachekey]=result
        return result
    if view_width != w:
        return helper.raw(bits),[]
    con, par = cell['connections'], cell.get('parameters', {})
    def operand_encoding(port):
        original=list(con[port])
        if _integer(par.get(port+'_SIGNED','0')) and len(original)<w:
            external=getattr(helper,'external_encoded',{})
            if any(original==list(graph.registers[r]['connections']['Q']) for r in external):
                return helper.raw(original+[original[-1]]*(w-len(original))),[]
        encoded,fusion=_fused_raw(graph,original,helper,depth+1)
        if _integer(par.get(port+'_SIGNED','0')) and len(original)<w:
            sw=len(original)
            if sw<=k:
                return helper.raw(original+[original[-1]]*(w-sw)),fusion
            low,s,c=encoded
            sign=helper.port([original[-1]],'fsign')
            upper=((1<<h)-1)^((1<<(sw-k))-1)
            pad=helper.wire(f"{sign}?{h}'d{upper}:{h}'b0",h,'sign_pad')
            s=helper.wire(f'({s}) | ({pad})',h,'sign_s')
            return (low,s,c),fusion+[{'cell':driver[0],'kind':'SIGNED_INPUT_EXTENSION','source_width':sw,'target_width':w,'no_wrap_proven':True}] if fusion else []
        return encoded,fusion
    if cell['type']=='$mux':
        aa,af=_fused_raw(graph,con['A'],helper,depth+1)
        bb,bf=_fused_raw(graph,con['B'],helper,depth+1)
        if not af and not bf:
            return helper.raw(bits),[]
        sel=helper.port(con['S'],'fsel')
        no_wrap=(not af or af[-1].get('no_wrap_proven',False)) and (not bf or bf[-1].get('no_wrap_proven',False))
        result=(tuple(helper.wire(f'{sel}?({b}):({a})',width) for a,b,width in zip(aa,bb,[k,h,h])),af+bf+[{'cell':driver[0],'kind':'SELECT_ENCODED_ROWS','no_wrap_proven':no_wrap}])
        helper.fusion_cache[cachekey]=result
        return result
    if cell['type'] in ('$shl','$sshl'):
        encoded,fusion=operand_encoding('A')
        if not fusion:
            return helper.raw(bits),[]
        low,s,c=encoded
        amount=helper.port(con['B'],'fshift')
        lowwide=helper.wire(low,w,'low_ext')
        shiftedlow=helper.wire(f'{lowwide} << {amount}',w,'low_shift')
        lo=f'{shiftedlow}[{k-1}:0]'
        ss=helper.wire(f'(({s}) << {amount}) | {shiftedlow}[{w-1}:{k}]',h,'fsh_s')
        cc=helper.wire(f'({c}) << {amount}',h,'fsh_c')
        maxshift=_unsigned_bound(graph,con['B'])
        abound=_unsigned_bound(graph,con['A'])
        if _integer(par.get('A_SIGNED','0')) and len(con['A'])<w and con['A'][-1]!='0':
            abound=(1<<w)-1
        nowrap=fusion[-1].get('no_wrap_proven',False) and maxshift<w and (abound << maxshift) < 1<<w
        result=((lo,ss,cc),fusion+[{'cell':driver[0],'kind':'DYNAMIC_LEFT_SHIFT','width':w,'no_wrap_proven':nowrap}])
        helper.fusion_cache[cachekey]=result
        return result
    if cell['type']=='$neg':
        encoded,fusion=operand_encoding('A')
        if not fusion:
            return helper.raw(bits),[]
        low,s,c=encoded
        lo=helper.wire(f'-({low})',k,'neg_lo')
        correction=helper.wire(f"(({low})=={k}'b0)?{h}'d2:{h}'d1",h,'neg_cor')
        ss,cc=helper.compress([f'~({s})',f'~({c})',correction],"1'b0")
        result=((lo,ss,cc),fusion+[{'cell':driver[0],'kind':'MODULAR_NEGATION','width':w,'no_wrap_proven':False}])
        helper.fusion_cache[cachekey]=result
        return result
    def extended(port):
        v = list(con[port])[:w]
        sign = _integer(par.get(port+'_SIGNED', '0'))
        v += [v[-1] if sign else '0'] * (w-len(v))
        return helper.port(v)
    a, b = extended('A'), extended('B')
    unsigned=not any(_integer(par.get(p+'_SIGNED','0')) for p in ('A','B'))
    ba,bb=_unsigned_bound(graph,con['A']),_unsigned_bound(graph,con['B'])
    maximum=ba+bb if cell['type']=='$add' else ba*bb
    fusion = [{'cell': driver[0], 'kind': cell['type'], 'width': w,
               'no_wrap_proven':unsigned and maximum < 1<<w,'unsigned_interval_max':maximum,
               'semantics': 'Exact result modulo 2^W; signed inputs use two-complement extension'}]
    if cell['type'] == '$add':
        ea,fa=operand_encoding('A')
        eb,fb=operand_encoding('B')
        al,aS,aC=ea
        bl,bS,bC=eb
        low = helper.wire(f"{{1'b0,{al}}} + {{1'b0,{bl}}}", k+1)
        s,c = helper.compress([aS,aC,bS,bC], f'{low}[{k}]')
        fusion[0]['no_wrap_proven'] = fusion[0]['no_wrap_proven'] and (not fa or fa[-1].get('no_wrap_proven',False)) and (not fb or fb[-1].get('no_wrap_proven',False))
        result=((f'{low}[{k-1}:0]',s,c),fa+fb+fusion)
        helper.fusion_cache[cachekey]=result
        return result
    rows = []
    bw = min(w, len(con['B']))
    if bw > 32 or w > 128:
        return helper.raw(bits), []
    signed_b = bool(_integer(par.get('B_SIGNED', '0')))
    for i in range(bw):
        negative = signed_b and i == bw-1
        expr = f'~(({a}) << {i})' if negative else f'(({a}) << {i})'
        rows.append(helper.wire(f"{b}[{i}] ? ({expr}) : {w}'b0", w, 'pp'))
        if negative:
            rows.append(helper.wire(f"{b}[{i}] ? {w}'d1 : {w}'b0", w, 'cor'))
    while len(rows) > 2:
        aa,bb,cc = rows[:3]
        ss = helper.wire(f'({aa}) ^ ({bb}) ^ ({cc})', w, 'pps')
        maj = helper.wire(f'(({aa})&({bb})) | (({aa})&({cc})) | (({bb})&({cc}))', w, 'ppmaj')
        cy = helper.wire(f'({maj}) << 1', w, 'ppc')
        rows = [ss,cy]+rows[3:]
    rows += [f"{w}'b0"] * (2-len(rows))
    aa,bb = rows
    aa = helper.wire(aa,w)
    bb = helper.wire(bb,w)
    low = helper.wire(f"{{1'b0,{aa}[{k-1}:0]}} + {{1'b0,{bb}[{k-1}:0]}}", k+1)
    s,c = helper.compress([f'{aa}[{w-1}:{k}]',f'{bb}[{w-1}:{k}]'],f'{low}[{k}]')
    result=((f'{low}[{k-1}:0]',s,c),fusion)
    helper.fusion_cache[cachekey]=result
    return result


def _prefix_readout(lines,a,b,w,pre='readpp'):
    """ pipeline."""
    lines += [f'wire [{w-1}:0] {pre}_p0={a}^{b};',f'wire [{w-1}:0] {pre}_g0={a}&{b};']
    p,g=f'{pre}_p0',f'{pre}_g0'
    distance,stage=1,0
    while distance<w:
        stage+=1
        pn,gn=f'{pre}_p{stage}',f'{pre}_g{stage}'
        lines += [f'wire [{w-1}:0] {pn}={p}&({p}<<{distance});',
                  f'wire [{w-1}:0] {gn}={g}|({p}&({g}<<{distance}));']
        p,g=pn,gn
        distance*=2
    result=f'{pre}_sum'
    lines.append(f'wire [{w-1}:0] {result}={pre}_p0^({g}<<1);')
    return result



def _select_readout(lines,a,b,w,pre='readsel'):
    block=4;chunks=[]
    for i,lo in enumerate(range(0,w,block)):
        n=min(block,w-lo);hi=lo+n-1;z=f'{pre}_z{i}';o=f'{pre}_o{i}';pp=f'{pre}_p{i}'
        lines.extend([f"wire [{n}:0] {z}={{1'b0,{a}[{hi}:{lo}]}}+{{1'b0,{b}[{hi}:{lo}]}};",
                      f"wire [{n}:0] {o}={{1'b0,{a}[{hi}:{lo}]}}+{{1'b0,{b}[{hi}:{lo}]}}+1'b1;",
                      f'wire {pp}=&({a}[{hi}:{lo}] ^ {b}[{hi}:{lo}]);'])
        chunks.append((lo,n,z,o,pp))
    n=len(chunks)
    lines.extend([f'wire [{n-1}:0] {pre}_G={{'+','.join(x[2]+f'[{x[1]}]' for x in reversed(chunks))+'};',
                  f'wire [{n-1}:0] {pre}_P={{'+','.join(x[4] for x in reversed(chunks))+'};'])
    g,pp=f'{pre}_G',f'{pre}_P';d=1;j=0
    while d<n:
        ng,np=f'{pre}_groupg{j}',f'{pre}_groupp{j}'
        lines.extend([f'wire [{n-1}:0] {ng}={g}|({pp}&({g}<<{d}));',f'wire [{n-1}:0] {np}={pp}&({pp}<<{d});'])
        g,pp=ng,np;d*=2;j+=1
    lines.append(f'wire [{w-1}:0] {pre}_sum;')
    for i,(lo,nb,z,o,_) in enumerate(chunks):
        ci="1'b0" if i==0 else f'{g}[{i-1}]'
        lines.append(f'assign {pre}_sum[{lo+nb-1}:{lo}] = {ci} ? {o}[{nb-1}:0] : {z}[{nb-1}:0];')
    return f'{pre}_sum'

def _sequential(graph, module, stages, fused=False, readout_prefix=False, product_csa=False):
    byreg = {s["register"]: dict(s) for s in stages if s["rewritable"]}
    pcs_refused = []
    if product_csa:
        # Lift native Q into consumer-width state; _fused_raw preserves native wrapping.
        # The refinement relation asserts CW decode == zeroext(native Q).
        def exact_source_registers(bits):
            pending=list(bits);seen=set();found=set()
            while pending:
                bit=pending.pop()
                entry=graph.bit_drivers.get(bit)
                if entry is None or entry[0] in seen:
                    continue
                name=entry[0];seen.add(name)
                if name in graph.registers:
                    found.add(name)
                    continue
                if name in graph.adders:
                    continue
                cell=graph.cells[name]
                typ=cell['type'];con=cell['connections']
                if typ not in ('$add','$mul','$mux','$shl','$sshl','$neg'):
                    continue
                ports=('A','B') if typ in ('$add','$mul','$mux') else ('A',)
                for port in ports:
                    pending.extend(con.get(port,[]))
            return found
        proposals = {}
        for consumer in list(byreg.values()):
            ip,_=graph.adder_ports(consumer['adder'])
            inputs=graph.cells[consumer['adder']]['connections']
            discovered=set(consumer['predecessors'])
            for port in ip:
                discovered.update(exact_source_registers(inputs[port]))
            # Guard incomplete upstream takeover even when native P Q is zero-extended.
            consumer['predecessors']=sorted(discovered)
            for prev in consumer['predecessors']:
                if prev in byreg or prev not in graph.registers:
                    continue
                rc = graph.registers[prev]
                pw = len(rc['connections']['Q'])
                if pw > consumer['width']:
                    pcs_refused.append({'register':prev,'reason':'PCS_UPSTREAM_WIDER_THAN_CONSUMER'})
                    continue
                if not 0 < consumer['k'] < pw:
                    pcs_refused.append({'register':prev,'reason':'PCS_INVALID_SPLIT'})
                    continue
                if not graph.upstream_arithmetic(rc['connections']['D']):
                    pcs_refused.append({'register':prev,'reason':'PCS_NO_VISIBLE_EXACT_UPSTREAM_ARITHMETIC'})
                    continue
                if prev in proposals and (proposals[prev]['k'] != consumer['k'] or proposals[prev]['width'] != consumer['width']):
                    raise Unsupported('PCS_SHARED_UPSTREAM_INCOMPATIBLE_K')
                sp=graph.state_path(rc['connections']['D'])
                proposals[prev]={'register':prev,'width':consumer['width'],'native_width':pw,'k':consumer['k'],
                    'rewritable':True,'direct_raw':True,'predecessors':sorted(exact_source_registers(rc['connections']['D']))}
        byreg.update(proposals)
    accepted, refused, sources, mappings = [], pcs_refused, [], []
    exported = {}
    for reg, st in byreg.items():
        h = st["width"] - st["k"]
        prefix = "bear_" + hashlib.sha256(reg.encode()).hexdigest()[:10]
        exported[reg] = {"ol": _alloc(module, prefix + "_low", st["k"]),
                         "os": _alloc(module, prefix + "_sum", h),
                         "oc": _alloc(module, prefix + "_carry", h)}
    for reg, st in byreg.items():
        try:
            w, k = st["width"], st["k"]
            h = w - k
            helper = Helper("bear_state_" + hashlib.sha256(reg.encode()).hexdigest()[:10]+('_pp' if readout_prefix else ''), w, k)
            register = graph.registers[reg]
            typ, con, params = register["type"], register["connections"], register["parameters"]
            if typ not in ("$dff", "$adff", "$dffe", "$adffe", "$sdff", "$sdffe", "$sdffce"):
                raise Unsupported("Unsupported register type")
            clk = helper.port(con["CLK"], "clk")
            edge = "posedge" if _integer(params.get("CLK_POLARITY", 1)) else "negedge"
            qw=st.get("native_width",w)
            helper.ports += [f"output [{qw-1}:0] q", f"output [{h-1}:0] os,oc", f"output [{k-1}:0] ol"]
            helper.connections.update({"q": con["Q"], **exported[reg]})
            helper.lines += [f"reg [{h-1}:0] S,C;", f"reg [{k-1}:0] l;", "assign os=S;assign oc=C;assign ol=l;"]
            if readout_prefix=='select':
                readout=_select_readout(helper.lines,'S','C',h)
                helper.lines.append(f'wire [{h-1}:0] decoded_hi={readout};assign q={{decoded_hi,l}};')
            elif readout_prefix:
                readout=_prefix_readout(helper.lines,'S','C',h)
                helper.lines.append(f'wire [{h-1}:0] decoded_hi={readout};assign q={{decoded_hi,l}};')
            else:
                helper.lines.append(f'wire [{h-1}:0] decoded_hi=S+C;assign q={{decoded_hi,l}};')
            if not st.get("direct_raw"):
                helper.lines += _low_function(graph.adders[st["adder"]])
            encoded = {reg: ("l", "S", "C")}
            for prev in st["predecessors"]:
                if prev != reg and prev in byreg and byreg[prev]["width"] == w and byreg[prev]["k"] == k:
                    encoded[prev] = tuple(helper.port(exported[prev][p], p) for p in ("ol", "os", "oc"))
            if product_csa:
                for prev in byreg:
                    if prev != reg and byreg[prev]['width'] == w and byreg[prev]['k'] == k:
                        encoded[prev] = tuple(helper.port(exported[prev][p],p) for p in ('ol','os','oc'))
            helper.external_encoded = encoded if product_csa else {}
            if st.get('direct_raw'):
                (nl,ns,nc),fusion = _fused_raw(graph,con['D'],helper)
                if not fusion:
                    raise Unsupported('PCS_DIRECT_D_FUSION_NOT_GENERATED')
            else:
                adder = st["adder"]
                ip, _ = graph.adder_ports(adder)
                operands = graph.cells[adder]["connections"]
                values = []
                fusion = []
                for port, path in zip(ip, st["operand_paths"]):
                    if path is not None and graph.state_sources(path) <= set(encoded):
                        values.append(helper.state(path, encoded))
                    elif fused:
                        value, details = _fused_raw(graph, operands[port], helper)
                        values.append(value)
                        fusion += details
                    else:
                        values.append(helper.raw(operands[port]))
                al, aS, aC = values[0]
                bl, bS, bC = values[1]
                lowfn = helper.wire(f"lowfn({al},{bl})", k + 1)
                ns, nc = helper.compress([aS, aC, bS, bC], f"{lowfn}[{k}]")
                update = (f"{lowfn}[{k-1}:0]", ns, nc)
                def data(path):
                    if path["kind"] == "adder":
                        if path["cell"] != adder:
                            raise Unsupported("Multiple approximate update sources for one register")
                        return update
                    if path["kind"] == "mux":
                        a, b = data(path["a"]), data(path["b"])
                        sel = helper.port(path["select"], "sel")
                        return tuple(helper.wire(f"{sel} ? ({bb}) : ({aa})", width) for aa, bb, width in zip(a, b, [k, h, h]))
                    statepath = graph.state_path(path["bits"], reg)
                    if statepath is not None:
                        return helper.state(statepath, encoded)
                    return helper.raw(path["bits"])
                nl, ns, nc = data(st["data_path"])
            reset = None
            async_reset = typ in ("$adff", "$adffe")
            if async_reset or typ in ("$sdff", "$sdffe", "$sdffce"):
                rp = "ARST" if async_reset else "SRST"
                r = helper.port(con[rp], "rst")
                polarity = _integer(params[rp + "_POLARITY"])
                value = _integer(params[rp + "_VALUE"])
                reset = (r if polarity else "!" + r, f"{k}'d{value & ((1 << k)-1)}", f"{h}'d{value >> k}", r, polarity)
            enable = None
            if typ in ("$dffe", "$adffe", "$sdffe", "$sdffce"):
                en = helper.port(con["EN"], "en")
                enable = en if _integer(params.get("EN_POLARITY", 1)) else "!" + en
            assign = f"begin l<={nl};S<={ns};C<={nc};end"
            if enable:
                assign = f"if({enable}) " + assign
            if reset:
                rstassign = f"begin l<={reset[1]};S<={reset[2]};C<=0;end"
                if typ == "$sdffce" and enable:
                    assign = f"if({enable}) begin if({reset[0]}) {rstassign} else begin l<={nl};S<={ns};C<={nc};end end"
                else:
                    assign = f"if({reset[0]}) {rstassign} else " + assign
            event = f"{edge} {clk}"
            if async_reset:
                event += f" or {'posedge' if reset[4] else 'negedge'} {reset[3]}"
            helper.lines.append(f"always @({event}) {assign}")
            init = {}
            for net in graph.module.get("netnames", {}).values():
                if "init" in net.get("attributes", {}):
                    raw = net["attributes"]["init"]
                    for i, b in enumerate(net["bits"]):
                        init[b] = raw[-1-i] if i < len(raw) else "x"
            if any(b in init for b in con["Q"]):
                iv = ''.join(init.get(b, "x") for b in reversed(con["Q"]))
                helper.lines.append(f"initial begin l={k}'b{iv[-k:]};S={h}'b{iv[:-k]};C=0;end")
                for net in module.get("netnames", {}).values():
                    if set(net["bits"]) & set(con["Q"]):
                        net.get("attributes", {}).pop("init", None)
            rtl = f"module {helper.name}({','.join(helper.ports)});\n" + '\n'.join(helper.lines) + "\nendmodule\n"
            sources.append(rtl)
            del module["cells"][reg]
            module["cells"]["bear:" + reg] = _cell(helper)
            accepted.append(reg)
            qnames = [name for name,net in graph.module.get('netnames',{}).items() if net['bits']==con['Q']]
            qnames.sort(key=lambda name:(graph.module['netnames'][name].get('hide_name',0),len(name),name))
            prefix = 'bear_'+hashlib.sha256(reg.encode()).hexdigest()[:10]
            mappings.append({"register": reg, "helper": helper.name, "width": w, "k": k,
                             "decode": "q = {S+C,l}", "original_q_bits": con["Q"],
                             "original_q_name": qnames[0] if qnames else None,
                             "state_names": {'os':prefix+'_sum','oc':prefix+'_carry','ol':prefix+'_low'},
                             "initial_correspondence": "Couple original q={S+C,l} only at $initstate, including arbitrary unreset states; assert the relation thereafter",
                             "original_initial_bits": ''.join(init.get(b,'x') for b in reversed(con['Q'])),
                             "state_bits": exported[reg], "reset": typ,
                             "fusion": fusion, "encoding_role":"UPSTREAM_EXACT_REGISTER" if st.get("direct_raw") else "APPROXIMATE_STATE",
                             "readout_implementation": "BLOCK_CARRY_SELECT" if readout_prefix=="select" else "EXPLICIT_PARALLEL_PREFIX" if readout_prefix else "ORDINARY_PLUS",
                             "readout": "Retain all original Q fanouts and decode every cycle without done gating"})
        except (Unsupported, KeyError, ValueError) as exc:
            refused.append({"register": reg, "reason": str(exc)})
    referenced = {p for reg in accepted for p in byreg[reg]["predecessors"] if p in byreg and p != reg}
    if referenced - set(accepted):
        raise Unsupported("Rejected upstream states leave an incomplete pipeline representation: " + ','.join(sorted(referenced-set(accepted))))
    return sources, mappings, accepted, refused


def _balanced(helper, terms, width):
    terms = list(terms)
    while len(terms) > 1:
        terms = [helper.wire(f"({terms[i]})+({terms[i+1]})", width) if i+1 < len(terms) else terms[i]
                 for i in range(0, len(terms), 2)]
    return terms[0]


def _quotient_prefix_low(helper, topology, cert, carries):
    """ pipeline."""
    k = helper.k
    B = 1 << k
    phi, kap = cert['phi'], cert['kappa']
    reachable = {int(v) for row in phi for v in row}
    while True:
        closure = reachable | {int(v) for r in reachable for v in phi[r]}
        if closure == reachable:
            break
        reachable = closure
    rows, reps, code = {}, [], {}
    for state in sorted(reachable):
        row = (tuple(phi[state]), tuple(kap[state]))
        if row not in rows:
            rows[row] = len(reps)
            reps.append(state)
        code[state] = rows[row]
    m = len(reps)
    if m > 16:
        raise Unsupported('T2 quotient state count exceeds 16: ' + str(m))
    b = max(1, (m-1).bit_length())
    def function(name, iw, ow, values):
        lines = [f'function [{ow-1}:0] {name}(input [{iw-1}:0] v);', 'case(v)']
        lines += [f"{iw}'d{i}:{name}={ow}'d{int(value)};" for i,value in values]
        helper.lines += lines+ [f'default:{name}=0;', 'endcase','endfunction']
    function('qenc',k,b,code.items())
    function('qdec',b,k,enumerate(reps))
    function('qtrans',k,m*b,((operand,sum(code[int(phi[r][operand])] << (j*b) for j,r in enumerate(reps))) for operand in range(B)))
    function('qcarry',b+k,1,(((j<<k)|operand,kap[r][operand]) for j,r in enumerate(reps) for operand in range(B)))
    def ev(t):
        if isinstance(t,str):
            return t
        rights = []
        left = t
        while not isinstance(left,str):
            rights.append(left[1])
            left = left[0]
        inputs = [left]+[ev(r) for r in reversed(rights)]
        first = helper.wire(f'lowfn({inputs[0]},{inputs[1]})',k+1,'qfirst')
        carries.append(f'{first}[{k}]')
        if len(inputs) == 2:
            return f'{first}[{k-1}:0]'
        c0 = helper.wire(f'qenc({first}[{k-1}:0])',b,'qinit')
        packed = [helper.wire(f'{{{m}{{{c0}}}}}',m*b,'qmap')]
        packed += [helper.wire(f'qtrans({v})',m*b,'qmap') for v in inputs[2:-1]]
        distance = 1
        while distance < len(packed):
            previous = packed
            packed = list(previous)
            for i in range(distance,len(previous)):
                later,earlier = previous[i],previous[i-distance]
                slices = [f'{later}[{earlier}[{j*b} +: {b}]*{b} +: {b}]' for j in range(m)]
                packed[i] = helper.wire('{'+','.join(reversed(slices))+'}',m*b,'qprefix')
            distance <<= 1
        states = [helper.wire(f'{p}[{b-1}:0]',b,'qstate') for p in packed]
        for j,v in enumerate(inputs[2:]):
            carries.append(helper.wire(f'qcarry({{{states[j]},{v}}})',1,'qcy'))
        final = helper.wire(f'lowfn(qdec({states[-1]}),{inputs[-1]})',k+1,'qfinal')
        return f'{final}[{k-1}:0]'
    return ev(topology), {'state_count':m,'state_bits':b,'algorithm':'ORDERED_LEFT_SPINE_QUOTIENT_KOGGE_STONE'}


def _combinational(graph, module, structure, variant):
    nodes = set(structure["adders"])
    roots = nodes - {a for a, b in structure["edges"]}
    if len(roots) != 1:
        raise Unsupported("Combinational component is not a single-root tree/chain")
    root = next(iter(roots))
    cert = graph.adders[root]
    ip, op = graph.adder_ports(root)
    w = len(graph.cells[root]["connections"][ip[0]])
    k = cert.get("k", cert.get("k_min"))
    if not 0 < k < w:
        raise Unsupported("Combinational state has no accurate high region")
    for n in nodes:
        ni, no = graph.adder_ports(n)
        if any(len(graph.cells[n]["connections"][p]) != w for p in ni + [no]):
            raise Unsupported("Combinational re-encoding requires matching fixed-width modular semantics at every node")
    helper = Helper("bear_comb_" + hashlib.sha256(root.encode()).hexdigest()[:10] + '_' + variant, w, k)
    helper.lines += _low_function(cert)
    leaf_high, leaves, carries, seen = [], [], [], set()
    def tree(name):
        if name in seen:
            raise Unsupported("Shared-subtree DAG requires separate multi-output handling")
        seen.add(name)
        args = []
        ni, _ = graph.adder_ports(name)
        for port in ni:
            bits = graph.cells[name]["connections"][port]
            path = graph.data_path(bits)
            if path["kind"] == "adder" and path["cell"] in nodes:
                args.append(tree(path["cell"]))
            else:
                v = helper.port(bits)
                low = f"{v}[{k-1}:0]"
                leaves.append(low)
                leaf_high.append(f"{v}[{w-1}:{k}]")
                args.append(low)
        return tuple(args)
    topology = tree(root)
    if variant == "T1":
        level = list(leaves)
        while len(level) > 1:
            level = [(level[i], level[i+1]) if i+1 < len(level) else level[i] for i in range(0, len(level), 2)]
        topology = level[0]
    def low(t):
        if isinstance(t, str):
            return t
        a, b = low(t[0]), low(t[1])
        v = helper.wire(f"lowfn({a},{b})", k+1)
        carries.append(f"{v}[{k}]")
        return f"{v}[{k-1}:0]"
    quotient = None
    if variant == 'T2':
        lo, quotient = _quotient_prefix_low(helper,topology,cert,carries)
    else:
        lo = low(topology)
    potential=cert.get('t1',{}).get('psi',{})
    integer_lift=(variant=='T1' and potential.get('status')=='PASS' and potential.get('denominator')==1
                  and len(potential.get('psi_times_D',[]))==1<<k)
    if integer_lift:
        vals=potential['psi_times_D']
        h=w-k
        helper.lines += [f'function [{h-1}:0] psi(input [{k-1}:0] v);','case(v)']
        helper.lines += [f"{k}'d{i}:psi={h}'d{int(value)% (1<<h)};" for i,value in enumerate(vals)]
        helper.lines += ['default:psi=0;','endcase','endfunction']
        aggregate=_balanced(helper,leaf_high+[f'psi({v})' for v in leaves],h)
        hi=helper.wire(f'({aggregate})-psi({lo})',h,'potential_hi')
    else:
        hi = _balanced(helper, leaf_high + carries, w-k)
    helper.ports.append(f"output [{w-1}:0] q")
    helper.connections["q"] = graph.cells[root]["connections"][op]
    helper.lines.append(f"assign q={{{hi},{lo}}};")
    del module["cells"][root]
    module["cells"]["bear:" + root] = _cell(helper)
    rtl = f"module {helper.name}({','.join(helper.ports)});\n" + '\n'.join(helper.lines) + "\nendmodule\n"
    return rtl, {"root": root, "helper": helper.name, "width": w, "k": k,
                 "decode": "q = {sum(leaf_hi+psi(leaf_lo))-psi(root_phi),root_phi}" if integer_lift else "q = {sum(leaf_hi)+sum(node_kappa),root_phi}",
                 "low_topology": "balanced_order_preserving" if variant == "T1" else "original_ordered_tree",
                 "implementation": "T1_INTEGER_POTENTIAL_LIFT" if integer_lift else "T1_REASSOCIATION" if variant == "T1" else "T2_ORDERED_QUOTIENT_PREFIX",
                 "quotient": quotient}


def rewrite_design(detection, certificates, out_dir, variant="T_cs", runner=None, yosys=None):
    """ pipeline."""
    from .runtime import run_guarded, tool
    started = time.monotonic()
    runner, yosys = runner or run_guarded, yosys or tool("yosys")
    out = Path(out_dir).resolve()
    out.mkdir(parents=True, exist_ok=True)
    if detection.get("status") != "PASS":
        return {"status": "SKIPPED", "variant": variant, "reason": "Extraction did not pass"}
    if variant not in ("T_cs", "T_csf", "T_cs_pp", "T_csf_pp", "T_pcs", "T_pcs_pp", "T_pcs_sel", "T_tree", "T_tree_pp", "T_tree_sel", "T_cs_sel", "T1", "T2"):
        return {"status": "SKIPPED", "variant": variant, "reason": "Candidate is not implemented"}
    net = json.loads(Path(detection["graph_json"]).read_text(encoding='utf-8'))
    full = json.loads(Path(detection["elaborated_json"]).read_text(encoding='utf-8'))
    top = detection["top"]
    graph = NetGraph(deepcopy(net["modules"][top]), certificates, net["modules"])
    module = net["modules"][top]
    for name, original_module in full['modules'].items():
        if name != top:
            net['modules'][name] = deepcopy(original_module)
    sources, mappings, refused, accepted = [], [], [], []
    try:
        if variant in ("T_cs", "T_csf", "T_cs_pp", "T_csf_pp", "T_pcs", "T_pcs_pp", "T_pcs_sel", "T_tree", "T_tree_pp", "T_tree_sel", "T_cs_sel"):
            sources, mappings, accepted, refused = _sequential(graph, module, detection.get("stages", []), variant.startswith(("T_csf","T_pcs","T_tree")), "select" if variant.endswith("_sel") else variant.endswith("_pp"), product_csa=variant.startswith(("T_pcs","T_tree")))
            if variant.startswith("T_pcs") and not any(m.get("encoding_role")=="UPSTREAM_EXACT_REGISTER" for m in mappings):
                return {"status":"SKIPPED","variant":variant,"reason":"No upstream accurate arithmetic register can be re-encoded","rejected":refused}
            if variant.startswith("T_tree") and not any(d.get("kind")=="$add" for m in mappings for d in m.get("fusion",[])):
                return {"status":"SKIPPED","variant":variant,"reason":"No accurate addition tree can be merged","rejected":refused}
            if variant.startswith("T_csf") and not any(m.get('fusion') for m in mappings):
                return {"status": "SKIPPED", "variant": variant, "reason": "No upstream $add/$mul can be merged; retain T_cs",'rejected':refused}
        else:
            for st in detection.get("structures", []):
                if st["kind"] not in ("CHAIN", "TREE"):
                    continue
                if variant not in st.get("candidates", []):
                    refused.append({"structure": st["id"], "reason": "Certificate does not permit " + variant})
                    continue
                try:
                    rtl, mapping = _combinational(graph, module, st, variant)
                    sources.append(rtl)
                    mappings.append(mapping)
                    accepted.append(st["id"])
                except Unsupported as exc:
                    refused.append({"structure": st["id"], "reason": str(exc)})
    except Unsupported as exc:
        return {"status": "SKIPPED", "variant": variant, "reason": str(exc), "rejected": refused}
    if not accepted:
        return {"status": "SKIPPED", "variant": variant, "reason": "No applicable legal structure", "rejected": refused}
    modified, helperfile, rtlfile = out / "modified.json", out / "helpers.v", out / "candidate.v"
    modified.write_text(json.dumps(net), encoding="utf-8")
    helperfile.write_text('\n'.join(sources), encoding="utf-8")
    script = out / "rewrite.ys"
    script.write_text('\n'.join(["read_json " + _quote(modified), "read_verilog -sv " + _quote(helperfile),
                                 "hierarchy -check -top " + top, "proc", "flatten", "opt_clean",
                                 "check -assert", "write_verilog -noattr " + _quote(rtlfile)]), encoding="utf-8")
    rec = runner([str(yosys), "-Q", "-s", str(script)], cwd=out, log=out / "rewrite.log", timeout=300)
    result = {"status": "GENERATED" if rec["returncode"] == 0 and rtlfile.exists() else rec.get("status", "UNKNOWN_GENERATION"),
              "variant": variant, "rtl": str(rtlfile), "accepted": accepted, "rejected": refused,
              "refinement": mappings, "tool": rec, "elapsed_s": time.monotonic()-started,
              "proof_status": "NOT_ASSESSED", "fusion_status": "GENERATED" if variant.startswith('T_csf') else "NOT_REQUESTED"}
    if rtlfile.exists():
        result["rtl_sha256"] = hashlib.sha256(rtlfile.read_bytes()).hexdigest()
    (out / "REWRITE.json").write_text(json.dumps(result, ensure_ascii=False, indent=2), encoding="utf-8")
    return result


def _pipe_segments(width, levels):
    if levels not in (2, 3):
        raise ValueError("pipe_l must be 2 or 3")
    if width < levels:
        raise Unsupported("Final high width is smaller than the pipeline stage count")
    cuts = [0]
    for i in range(1, levels):
        cuts.append((width * i) // levels)
    cuts.append(width)
    return [(cuts[i], cuts[i + 1]) for i in range(levels)]


def _replace_pipe_helper(module_text, pipe_l):
    """ pipeline."""
    if "reg [" not in module_text or " S,C;" not in module_text or "assign q=" not in module_text:
        return module_text, False
    m_h = re.search(r"reg \[(\d+):0\] S,C;", module_text)
    m_k = re.search(r"reg \[(\d+):0\] l;", module_text)
    if not (m_h and m_k):
        return module_text, False
    h = int(m_h.group(1)) + 1
    k = int(m_k.group(1)) + 1
    if h < pipe_l or k <= 0:
        raise Unsupported(f"Unsupported state width for pipeline L={pipe_l}: H={h}, k={k}")
    segs = _pipe_segments(h, pipe_l)
    event_m = re.search(r"always @\(([^)\n]+)\)", module_text)
    if not event_m:
        raise Unsupported("State helper has no reusable clock event")
    event = event_m.group(1)
    reset_m = re.search(r"if\(([^)]+)\) begin l<=", module_text)
    reset_cond = reset_m.group(1) if reset_m else None
    declarations = []
    for i, (lo, hi) in enumerate(segs):
        width = hi - lo
        declarations.append(f"reg [{width-1}:0] pipe_sum_{i};")
        if i < pipe_l - 1:
            declarations.append(f"reg [{h-hi-1}:0] pipe_s_{i};")
            declarations.append(f"reg [{h-hi-1}:0] pipe_c_{i};")
            declarations.append(f"reg pipe_carry_{i};")
    declarations.append(f"reg [{k-1}:0] pipe_low;")
    low_aligned = "pipe_low" if pipe_l == 2 else f"pipe_low_d{pipe_l-2}"
    for dly in range(1, pipe_l - 1):
        declarations.append(f"reg [{k-1}:0] pipe_low_d{dly};")
    aligned_sum = {}
    for i in range(pipe_l - 1):
        delay = pipe_l - 1 - i
        aligned_sum[i] = f"pipe_sum_{i}" if delay == 1 else f"pipe_sum_{i}_d{delay-1}"
        for dly in range(1, delay):
            segw = segs[i][1] - segs[i][0]
            declarations.append(f"reg [{segw-1}:0] pipe_sum_{i}_d{dly};")
    wires = []
    for i, (lo, hi) in enumerate(segs):
        width = hi - lo
        a = f"S[{hi-1}:{lo}]" if i == 0 else f"pipe_s_{i-1}[{hi-1-segs[i-1][1]}:{lo-segs[i-1][1]}]"
        b = f"C[{hi-1}:{lo}]" if i == 0 else f"pipe_c_{i-1}[{hi-1-segs[i-1][1]}:{lo-segs[i-1][1]}]"
        carry = "1'b0" if i == 0 else f"pipe_carry_{i-1}"
        wires.append(f"wire [{width}:0] pipe_add_{i}={{1'b0,{a}}}+{{1'b0,{b}}}+{carry};")
    body = []
    if reset_cond:
        body.append(f"if({reset_cond}) begin")
        for i, (lo, hi) in enumerate(segs):
            body.append(f"  pipe_sum_{i}<={hi-lo}'b0;")
            if i < pipe_l - 1:
                delay = pipe_l - 1 - i
                for dly in range(1, delay):
                    body.append(f"  pipe_sum_{i}_d{dly}<={hi-lo}'b0;")
            if i < pipe_l - 1:
                body += [f"  pipe_s_{i}<={h-hi}'b0;", f"  pipe_c_{i}<={h-hi}'b0;", f"  pipe_carry_{i}<=1'b0;"]
        body += [f"  pipe_low<={k}'b0;"]
        for dly in range(1, pipe_l - 1):
            body.append(f"  pipe_low_d{dly}<={k}'b0;")
        body.append("end else begin")
    else:
        body.append("begin")
    for i, (lo, hi) in enumerate(segs):
        width = hi - lo
        body.append(f"  pipe_sum_{i}<=pipe_add_{i}[{width-1}:0];")
        if i < pipe_l - 1:
            delay = pipe_l - 1 - i
            for dly in range(1, delay):
                prev = f"pipe_sum_{i}" if dly == 1 else f"pipe_sum_{i}_d{dly-1}"
                body.append(f"  pipe_sum_{i}_d{dly}<={prev};")
        if i < pipe_l - 1:
            if i == 0:
                src_s = f"S[{h-1}:{hi}]"
                src_c = f"C[{h-1}:{hi}]"
            else:
                prev_width = h - segs[i-1][1]
                cur_width = hi - lo
                remain_width = h - hi
                src_s = f"pipe_s_{i-1}[{prev_width-1}:{cur_width}]"
                src_c = f"pipe_c_{i-1}[{prev_width-1}:{cur_width}]"
            body += [f"  pipe_s_{i}<={src_s};", f"  pipe_c_{i}<={src_c};",
                     f"  pipe_carry_{i}<=pipe_add_{i}[{width}];"]
    body.append("  pipe_low<=l;")
    for dly in range(1, pipe_l - 1):
        prev = "pipe_low" if dly == 1 else f"pipe_low_d{dly-1}"
        body.append(f"  pipe_low_d{dly}<={prev};")
    body.append("end")
    last = pipe_l - 2
    lo_last, hi_last = segs[-1]
    width_last = hi_last - lo_last
    a_last = f"pipe_s_{last}[{width_last-1}:0]"
    b_last = f"pipe_c_{last}[{width_last-1}:0]"
    carry_last = f"pipe_carry_{last}"
    wires.append(f"wire [{width_last}:0] pipe_final={{1'b0,{a_last}}}+{{1'b0,{b_last}}}+{carry_last};")
    concat = ",".join([f"pipe_final[{width_last-1}:0]"] + [aligned_sum[i] for i in reversed(range(pipe_l-1))] + [low_aligned])
    qline = f"assign q={{{concat}}};"
    new = re.sub(r"\n?[^\n]*assign q=\{decoded_hi,l\};", "", module_text)
    marker = "endmodule"
    insert = "\n" + "\n".join(declarations + wires + [f"always @({event}) "+" ".join(body), qline]) + "\n"
    if marker not in new:
        raise Unsupported("State helper has no endmodule")
    new = new.replace(marker, insert + marker, 1)
    return new, True


def _pipe_helpers(helpers_text, pipe_l):
    starts = list(re.finditer(r"(?m)^module\s+bear_state_[^\n]+", helpers_text))
    if not starts:
        raise Unsupported("No state helper found; candidate does not use T_cs state")
    out, pos, count = [], 0, 0
    for i, match in enumerate(starts):
        end = starts[i + 1].start() if i + 1 < len(starts) else len(helpers_text)
        chunk = helpers_text[match.start():end]
        chunk, changed = _replace_pipe_helper(chunk, pipe_l)
        count += int(changed)
        out.append(helpers_text[pos:match.start()]); out.append(chunk); pos = end
    out.append(helpers_text[pos:])
    if count == 0:
        raise Unsupported("No replaceable S+C readout found")
    return "".join(out), count


def rewrite_pipe_design(detection, certificates, out_dir, pipe_l=2, runner=None, yosys=None):
    """ pipeline."""
    if pipe_l not in (2, 3):
        raise ValueError("pipe_l must be 2 or 3")
    from .runtime import run_guarded, tool
    out = Path(out_dir).resolve(); out.mkdir(parents=True, exist_ok=True)
    base_dir = out / "base_tcs"
    base = rewrite_design(detection, certificates, base_dir, variant="T_cs", runner=runner, yosys=yosys)
    if base.get("status") != "GENERATED":
        return {"status":"SKIPPED", "variant":f"T_cs_pipe{pipe_l}", "reason":"Base T_cs candidate was not generated", "base":base}
    helpers = Path(base["refinement"][0].get("helper_file", base_dir/"helpers.v")) if base.get("refinement") else base_dir/"helpers.v"
    helpers = base_dir / "helpers.v"
    transformed, n = _pipe_helpers(helpers.read_text(encoding="utf-8"), pipe_l)
    helperfile = out / "helpers.v"; helperfile.write_text(transformed, encoding="utf-8")
    modified = base_dir / "modified.json"
    rtlfile = out / "candidate.v"
    script = out / "rewrite.ys"
    script.write_text("\n".join(["read_json "+_quote(modified), "read_verilog -sv "+_quote(helperfile),
                                  "hierarchy -check -top "+detection["top"], "proc", "flatten", "opt_clean",
                                  "check -assert", "write_verilog -noattr "+_quote(rtlfile)])+"\n", encoding="utf-8")
    rec = (runner or run_guarded)([str(yosys or tool("yosys")), "-Q", "-s", str(script)], cwd=out, log=out/"rewrite.log", timeout=600)
    result = {"status":"GENERATED" if rec.get("returncode")==0 and rtlfile.exists() else rec.get("status","UNKNOWN_GENERATION"),
              "variant":f"T_cs_pipe{pipe_l}", "pipe_l":pipe_l, "pipe_helpers":n,
              # Segment count L corresponds to d=L-1 extra clocks in verify.
              "latency":pipe_l-1, "refinement":base.get('refinement'),
              "rtl":str(rtlfile), "base":base, "tool":rec,
              "proof_status":"NOT_ASSESSED", "readout_contract":"q(t)=T_cs_q(t-(L-1)); all output paths set_output_delay 0"}
    if rtlfile.exists(): result["rtl_sha256"] = hashlib.sha256(rtlfile.read_bytes()).hexdigest()
    (out/"REWRITE.json").write_text(json.dumps(result, ensure_ascii=False, indent=2), encoding="utf-8")
    return result




