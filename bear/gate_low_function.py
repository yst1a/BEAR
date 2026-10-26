from pathlib import Path
import json,hashlib
import numpy as np
from .characterize import GateEvaluator

def _gate_expr(kind,c):
 a=c.get('A');b=c.get('B');s=c.get('S')
 if kind=='$_AND_':return f'({a}&{b})'
 if kind=='$_OR_':return f'({a}|{b})'
 if kind=='$_XOR_':return f'({a}^{b})'
 if kind=='$_XNOR_':return f'~({a}^{b})'
 if kind=='$_NOT_':return f'~({a})'
 if kind=='$_NAND_':return f'~({a}&{b})'
 if kind=='$_NOR_':return f'~({a}|{b})'
 if kind=='$_MUX_':return f'({s}?{b}:{a})'
 if kind=='$_BUF_':return f'({a})'
 if kind=='$_ANDNOT_':return f'({a}&~({b}))'
 if kind=='$_ORNOT_':return f'({a}|~({b}))'
 raise ValueError('UNSUPPORTED_BIT_GATE:'+kind)

def emit_gate_function(cert,gatefile,name='lowfn'):
 net=json.loads(Path(gatefile).read_text(encoding='utf-8'))['modules'][cert['module']]
 ev=GateEvaluator(net,cert.get('input_ports'),cert.get('output_port'))
 k=cert.get('k',cert.get('k_min'));phi=np.asarray(cert['phi'],dtype=np.int64);kap=np.asarray(cert['kappa'],dtype=np.int64)
 assert 0<k<=10 and phi.shape==kap.shape==(1<<k,1<<k)
 kap_min=int(kap.min());kap_max=int(kap.max());assert kap_min>=0
 carry_width=max(1,kap_max.bit_length());width=k+carry_width
 if width>ev.output_width:raise ValueError('CARRY_WIDTH_EXCEEDS_NATIVE_OUTPUT')
 expr={'0':"1'b0",'1':"1'b1"};declarations=[];assignments=[];types=set()
 for port,variable in zip(ev.inputs,('a','b')):
  for i,bit in enumerate(ev.ports[port]['bits']):
   if not isinstance(bit,int):continue
   value=f'{variable}[{i}]' if i<k else "1'b0"
   if bit in expr and expr[bit]!=value:raise ValueError('ALIASED_INDEPENDENT_INPUT_BITS')
   expr[bit]=value
 for cellname,cell in ev.order:
  inputs={p:expr[bs[0]] for p,bs in cell['connections'].items() if cell['port_directions'][p]=='input'}
  if any(len(bs)!=1 for p,bs in cell['connections'].items()):raise ValueError('NON_BIT_CELL')
  value=_gate_expr(cell['type'],inputs);types.add(cell['type'])
  outputs=[bs[0] for p,bs in cell['connections'].items() if cell['port_directions'][p]=='output']
  if len(outputs)!=1 or not isinstance(outputs[0],int):raise ValueError('NON_SINGLE_BIT_OUTPUT')
  bit=outputs[0]
  if bit in expr:raise ValueError('MULTIPLE_OR_INPUT_DRIVER')
  variable='gn'+str(bit);declarations.append('reg '+variable+';');assignments.append(variable+'='+value+';');expr[bit]=variable
 output=ev.ports[ev.output]['bits'][:width]
 lines=[f'function [{width-1}:0] {name}(input [{k-1}:0] a,b);']+declarations+['begin']+assignments+[name+'={'+','.join(expr[b] for b in reversed(output))+'};','end','endfunction']
 return lines,ev,{'k':k,'carry_min':kap_min,'carry_max':kap_max,'actual_carry_bits':carry_width,'function_output_width':width,'native_output_width':ev.output_width,'gate_types':sorted(types),'gate_count':len(ev.order),'gate_netlist_sha256':hashlib.sha256(Path(gatefile).read_bytes()).hexdigest(),'function_sha256':hashlib.sha256(('\n'.join(lines)+'\n').encode()).hexdigest()}

def validate_gate_table(cert,gatefile):
 lines,ev,meta=emit_gate_function(cert,gatefile);k=meta['k'];B=1<<k;phi=np.asarray(cert['phi'],dtype=np.uint64).reshape(-1);kap=np.asarray(cert['kappa'],dtype=np.uint64).reshape(-1);digest=hashlib.sha256();checked=0
 for first in range(0,B*B,65536):
  ix=np.arange(first,min(B*B,first+65536),dtype=np.uint64);actual=ev.evaluate(ix>>k,ix&(B-1));expected=phi[first:first+len(ix)]+(kap[first:first+len(ix)]<<k)
  if not np.array_equal(actual,expected):raise ValueError('FULL_LOW_TABLE_MISMATCH_AT_'+str(first+int(np.flatnonzero(actual!=expected)[0])))
  digest.update(actual.astype('<u8').tobytes());checked+=len(ix)
 meta.update(status='PASS_EXHAUSTIVE_LOW_TABLE_GATE_NETWORK',checked_pairs=checked,expected_pairs=B*B,chunk_pairs=65536,full_native_output_compared=True,table_gate_output_sha256=digest.hexdigest(),no_carry_truncation=True)
 return lines,meta

def gate_low_function(cert,name='lowfn'):
 path=cert.get('_gate_netlist');check=cert.get('_gate_table_validation')
 if not path or not check or check.get('status')!='PASS_EXHAUSTIVE_LOW_TABLE_GATE_NETWORK':raise ValueError('MISSING_VALIDATED_GATE_REPRESENTATION')
 lines,ev,meta=emit_gate_function(cert,path,name)
 if meta['actual_carry_bits']!=1:raise ValueError('T_CS_INTERFACE_MULTI_CARRY_UNSUPPORTED_'+str(meta['actual_carry_bits']))
 if meta['gate_netlist_sha256']!=check['gate_netlist_sha256']:raise ValueError('GATE_NETLIST_SHA_CHANGED')
 return lines

