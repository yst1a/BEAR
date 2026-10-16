"""Exact Boolean-DAG low-function emitter; no arbitrary k resource gate.
Construct from the available full table and independently evaluate all table rows.
No SAT, synthesis or simulation tool is run by this helper.
"""
from pathlib import Path
import hashlib,json

def emit_boolean_low_function(cert,name='lowfn',receipt_path=None):
    k=int(cert.get('k',cert.get('k_min')))
    if k<=0:raise ValueError('BDD_REQUIRES_NONEMPTY_SEMANTIC_PARTITION')
    B=1<<k;N=B*B;phi=cert['phi'];kap=cert['kappa']
    if len(phi)!=B or len(kap)!=B or any(len(r)!=B for rows in (phi,kap) for r in rows):raise ValueError('LOW_TABLE_DIMENSION_MISMATCH')
    # Single-bit carry is the existing T_cs interface, not a resource budget.
    packed_expected=[bytearray((N+7)//8) for _ in range(k+1)]
    packed_ordered=[bytearray((N+7)//8) for _ in range(k+1)]
    order=[]
    for i in range(k):order.extend([('b',i,i),('a',i,k+i)])
    sourcehash=hashlib.sha256()
    for a in range(B):
        for b in range(B):
            lo=int(phi[a][b]);carry=int(kap[a][b])
            if not 0<=lo<B:raise ValueError('PHI_WIDTH_OVERFLOW')
            if carry not in (0,1):raise ValueError('MULTIBIT_KAPPA_REQUIRES_INTERFACE_EXTENSION')
            value=lo|(carry<<k);ix=(a<<k)|b
            permuted=0
            for position,(_,_,sourcebit) in enumerate(order):
                permuted|=((ix>>sourcebit)&1)<<(2*k-1-position)
            sourcehash.update(value.to_bytes((k+8)//8,'little'))
            for bit in range(k+1):
                if (value>>bit)&1:
                    packed_expected[bit][ix>>3]|=1<<(ix&7)
                    packed_ordered[bit][permuted>>3]|=1<<(permuted&7)
    expected=[int.from_bytes(p,'little') for p in packed_expected]
    ordered=[int.from_bytes(p,'little') for p in packed_ordered]
    nodes={};unique={};memo={}
    def node(variable,low,high):
        if low==high:return low
        key=(variable,low,high)
        if key not in unique:
            identity=len(nodes)+2;unique[key]=identity;nodes[identity]=key
        return unique[key]
    def cofactor(table,width):
        if table==0:return 0
        if table==(1<<width)-1:return 1
        key=(table,width)
        if key in memo:return memo[key]
        half=width//2;level=width.bit_length()-2
        low=cofactor(table&((1<<half)-1),half);high=cofactor(table>>half,half)
        position=2*k-1-level
        result=node(position,low,high);memo[key]=result
        return result
    roots=[cofactor(t,N) for t in ordered]
    # Independent exhaustive evaluation in ORIGINAL {a,b} address order. A bit
    # vector encodes all N assignments, so equality checks every actual pair.
    allones=(1<<N)-1;variables={};values={0:0,1:allones}
    for position,(_,_,sourcebit) in enumerate(order):
        block=1<<sourcebit;period=2*block
        variables[position]=(((1<<N)-1)//((1<<period)-1))*(((1<<block)-1)<<block)
    for identity,(variable,low,high) in nodes.items():
        select=variables[variable]
        values[identity]=(select&values[high])|((allones^select)&values[low])
    for bit,root in enumerate(roots):
        if values[root]!=expected[bit]:raise ValueError('EXHAUSTIVE_DAG_TABLE_MISMATCH_OUTPUT_BIT_'+str(bit))
    def expr(identity):return "1'b0" if identity==0 else "1'b1" if identity==1 else 'bdd_'+str(identity)
    lines=[f'function [{k}:0] {name}(input [{k-1}:0] a,b);']
    lines +=['reg bdd_'+str(identity)+';' for identity in nodes]
    lines +=['begin']
    for identity,(variable,low,high) in nodes.items():
        port,index,_=order[variable]
        lines.append(f'bdd_{identity}={port}[{index}] ? {expr(high)} : {expr(low)};')
    lines +=[name+'={'+','.join(expr(root) for root in reversed(roots))+'};','end','endfunction']
    text='\n'.join(lines)+'\n'
    metadata={'status':'PASS_EXHAUSTIVE_TABLE_DAG','k':k,'actual_pairs':N,'expected_pairs':N,'output_bits':k+1,'bdd_nodes':len(nodes),'resource_k_cap':None,'variable_order':[port+str(bit) for port,bit,_ in order],'source_table_value_sha256':sourcehash.hexdigest(),'function_sha256':hashlib.sha256(text.encode()).hexdigest(),'validation':'All output truth bitvectors independently evaluated against original phi/kappa for every binary input pair. No time-dependent assumption; no state/reset/initial-domain change. RTL X/Z propagation outside binary hardware input domain NOT_ASSESSED.'}
    if receipt_path:Path(receipt_path).write_text(json.dumps(metadata,indent=2)+'\n',encoding='utf-8')
    return lines,metadata

def low_function_lines(cert,name='lowfn'):
    return emit_boolean_low_function(cert,name)[0]

