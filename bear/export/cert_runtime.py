from __future__ import annotations
"""Cert runtime."""
import sys
sys.dont_write_bytecode=True
import json, hashlib, os
from pathlib import Path
import numpy as np
import torch
try:
    import triton
    import triton.language as tl
except ImportError:
    triton = None
    tl = None
def _jit(fn):
    return triton.jit(fn) if triton is not None else fn

MAX_K=12

class UnsupportedCertificate(ValueError): pass

def certificate_table(c):
    if c.get('status')!='PASS' or c.get('low_local') is not True: raise UnsupportedCertificate('CERTIFICATE_NOT_LOCAL_PASS')
    k=c.get('k'); w=c.get('output_width')
    if not isinstance(k,int) or not 0<=k<=MAX_K: raise UnsupportedCertificate(f'TABLE_LIMIT: k={k}, maximum={MAX_K}')
    if not isinstance(w,int) or not k<w<=32: raise UnsupportedCertificate('WIDTH_UNSUPPORTED: require k < W <= 32')
    b=1<<k
    if c.get('phi') is None or c.get('kappa') is None:raise UnsupportedCertificate('MISSING_OR_PARTIAL_LOW_TABLE')
    phi=np.asarray(c.get('phi'));kap=np.asarray(c.get('kappa'))
    if not np.issubdtype(phi.dtype,np.integer) or not np.issubdtype(kap.dtype,np.integer):raise UnsupportedCertificate('LOW_TABLE_REQUIRES_INTEGERS')
    phi=phi.astype(np.int64,copy=False);kap=kap.astype(np.int64,copy=False)
    if phi.shape!=(b,b) or kap.shape!=(b,b):raise UnsupportedCertificate('MISSING_OR_PARTIAL_LOW_TABLE')
    if np.any(phi<0) or np.any(phi>=b):raise UnsupportedCertificate('PHI_OUT_OF_RANGE')
    if np.any(kap<0) or np.any(kap>=1<<(w-k)):raise UnsupportedCertificate('KAPPA_OUT_OF_RANGE')
    widths=c.get('input_widths',[c.get('width'),c.get('width')])
    if len(widths)!=2 or any(not isinstance(v,int) or not k<=v<=w for v in widths):raise UnsupportedCertificate('INPUT_WIDTH_UNSUPPORTED')
    # packed int32 bit patterns, preserving non-Boolean high residuals when present.
    packed=(phi|(kap<<k)).astype(np.uint32).view(np.int32).reshape(-1)
    return packed,k,w,widths

@_jit
def _step(a,b,T,K:tl.constexpr,W:tl.constexpr):
    mask=(1<<K)-1
    v=tl.load(T+((a&mask)<<K)+(b&mask)).to(tl.uint32)
    r=((((a.to(tl.uint32)>>K)+(b.to(tl.uint32)>>K)+(v>>K))<<K)|(v&mask))
    return (r&((1<<W)-1)).to(tl.int32)

@_jit
def _chain(A,B,T,O,M:tl.constexpr,N:tl.constexpr,L:tl.constexpr,K:tl.constexpr,W:tl.constexpr,BN:tl.constexpr):
    rr=tl.program_id(0)*32+tl.arange(0,32);nn=tl.program_id(1)*BN+tl.arange(0,BN)
    acc=tl.load(A+rr,rr<M,0)[:,None]*tl.load(B+nn,nn<N,0)[None,:]
    acc=(acc.to(tl.uint32)&((1<<W)-1)).to(tl.int32)
    for i in range(1,L):
        p=tl.load(A+i*M+rr,rr<M,0)[:,None]*tl.load(B+i*N+nn,nn<N,0)[None,:]
        acc=_step(acc,p,T,K,W)
    # W32 int32 is already the signed two's-complement value.
    if W<32: acc=tl.where(acc>=(1<<(W-1)),acc-(1<<W),acc)
    tl.store(O+rr[:,None]*N+nn[None,:],acc,(rr<M)[:,None]&(nn<N)[None,:])

@_jit
def _shift_prefix(P,S,R,T,O,L:tl.constexpr,K:tl.constexpr,W:tl.constexpr):
    lanes=tl.arange(0,32);acc=tl.full((32,),0,tl.int32)
    for i in range(L):
        word=tl.load(P+i).to(tl.uint32)&((1<<W)-1)
        shift=tl.load(S+i);start=tl.load(R+i)
        augend=(acc.to(tl.uint32)<<shift)&((1<<W)-1)
        acc=tl.where(start==1,word.to(tl.int32),_step(augend,word,T,K,W))
        tl.store(O+i+lanes*0,acc,lanes==0)

@_jit
def _prefix(P,T,O,L:tl.constexpr,K:tl.constexpr,W:tl.constexpr,INITIAL:tl.constexpr,PRODUCT_FIRST:tl.constexpr,WA:tl.constexpr,WB:tl.constexpr):
    lanes=tl.arange(0,32)
    acc=tl.full((32,),INITIAL,tl.int32)
    for i in range(L):
        p=tl.load(P+i)
        if PRODUCT_FIRST:acc=_step(p.to(tl.uint32)&((1<<WA)-1),acc.to(tl.uint32)&((1<<WB)-1),T,K,W)
        else:acc=_step(acc.to(tl.uint32)&((1<<WA)-1),p.to(tl.uint32)&((1<<WB)-1),T,K,W)
        tl.store(O+i+lanes*0,acc,lanes==0)

class CertificateAccumulator(torch.nn.Module):
    def __init__(self,certificate):
        super().__init__()
        path=Path(certificate) if isinstance(certificate,(str,Path)) else None
        c=json.loads(path.read_text(encoding='utf-8-sig')) if path is not None else certificate
        if 'packed_table' in c:
            if c.get('status')!='PASS' or c.get('low_local') is not True:raise UnsupportedCertificate('CERTIFICATE_NOT_LOCAL_PASS')
            if path is None:raise UnsupportedCertificate('PACKED_TABLE_REQUIRES_METADATA_PATH')
            tablepath=path.with_name(c['packed_table'])
            if hashlib.sha256(tablepath.read_bytes()).hexdigest()!=c['packed_table_sha256']:raise UnsupportedCertificate('TABLE_ASSET_HASH_MISMATCH')
            t=np.load(tablepath,allow_pickle=False)['table']
            self.k,self.width,self.input_widths=c['k'],c['output_width'],c['input_widths']
            if not 0<=self.k<=MAX_K or not self.k<self.width<=32 or t.dtype!=np.int32 or t.shape!=(1<<(2*self.k),):raise UnsupportedCertificate('PACKED_TABLE_INVALID')
            if len(self.input_widths)!=2 or any(not isinstance(v,int) or not self.k<=v<=self.width for v in self.input_widths):raise UnsupportedCertificate('INPUT_WIDTH_UNSUPPORTED')
            if self.width<32 and np.any(t.view(np.uint32)>=(1<<self.width)):raise UnsupportedCertificate('PACKED_TABLE_OUT_OF_RANGE')
        else:t,self.k,self.width,self.input_widths=certificate_table(c)
        self.certificate=c
        self.register_buffer('table',torch.from_numpy(t))
    def _check(self,A,B):
        if A.dtype!=torch.int32 or B.dtype!=torch.int32:raise TypeError('OPERANDS_REQUIRE_INT32')
        if A.device!=B.device or A.device!=self.table.device:raise ValueError('DEVICE_MISMATCH: move the module and operands explicitly')
    def step(self,a,b,signed=False):
        self._check(a,b)
        a=a.to(torch.int64)&((1<<self.input_widths[0])-1);b=b.to(torch.int64)&((1<<self.input_widths[1])-1)
        mask=(1<<self.k)-1
        v=self.table[((a&mask)<<self.k)+(b&mask)].to(torch.int64)&0xffffffff
        r=((((a>>self.k)+(b>>self.k)+(v>>self.k))<<self.k)|(v&mask))&((1<<self.width)-1)
        if signed:r=torch.where(r>=(1<<(self.width-1)),r-(1<<self.width),r)
        return r.to(torch.int32) if signed else r
    def forward(self,A,B):
        self._check(A,B)
        if A.ndim!=2 or B.ndim!=2 or A.shape[1]!=B.shape[1] or A.shape[1]<1:raise ValueError('SHAPE: A[M,L], B[N,L], same positive L')
        if self.input_widths!=[self.width,self.width]:raise UnsupportedCertificate('CHAIN_REQUIRES_EQUAL_WIDE_OPERAND_PORTS')
        if A.is_cuda:
            if triton is None: raise ImportError('CUDA export requires Triton')
            at=A.T.contiguous();bt=B.T.contiguous();l,m=at.shape;n=bt.shape[1]
            out=torch.empty((m,n),device=A.device,dtype=torch.int32)
            if m==0 or n==0:return out
            bn=triton.next_power_of_2(min(n,16))
            _chain[(triton.cdiv(m,32),triton.cdiv(n,bn))](at,bt,self.table,out,m,n,l,self.k,self.width,bn,num_warps=4)
            return out
        acc=(A[:,0:1].long()*B[:,0].long()[None,:])&((1<<self.width)-1)
        for i in range(1,A.shape[1]):
            p=(A[:,i:i+1].long()*B[:,i].long()[None,:])&((1<<self.width)-1)
            acc=self.step(acc.int(),p.int())
        return torch.where(acc>=1<<(self.width-1),acc-(1<<self.width),acc).int()
    def prefix(self,products,initial=0,product_first=False):
        if products.dtype!=torch.int32 or products.ndim!=1 or products.device!=self.table.device:raise ValueError('PREFIX_REQUIRES_MATCHED_1D_INT32')
        if triton is None: raise ImportError('CUDA prefix requires Triton')
        if not products.is_cuda:raise ValueError('PREFIX_CUDA_REQUIRED: CPU prefix use scalar_reference')
        products=products.contiguous()
        out=torch.empty_like(products)
        _prefix[(1,)](products,self.table,out,len(products),self.k,self.width,initial,product_first,*self.input_widths,num_warps=1)
        return out
    def shift_prefix(self,words,shifts,starts):
        if triton is None: raise ImportError('CUDA shift prefix requires Triton')
        if self.input_widths!=[self.width,self.width]:raise UnsupportedCertificate('SHIFT_REQUIRES_EQUAL_WIDE_OPERAND_PORTS')
        for v in (words,shifts,starts):
            if v.dtype!=torch.int32 or v.ndim!=1 or v.device!=self.table.device or not v.is_cuda or v.shape!=words.shape:raise ValueError('SHIFT_PREFIX_REQUIRES_MATCHED_CUDA_1D_INT32')
        if torch.any((shifts<0)|(shifts>1)) or torch.any((starts<0)|(starts>1)):raise ValueError('SHIFT_START_REQUIRE_BINARY_VALUES')
        words=words.contiguous();shifts=shifts.contiguous();starts=starts.contiguous()
        out=torch.empty_like(words)
        _shift_prefix[(1,)](words,shifts,starts,self.table,out,len(words),self.k,self.width,num_warps=1)
        return out

class CertificateQuantizedLayer(torch.nn.Module):
    """Cert runtime."""
    def __init__(self,mod,accumulator,activation_scale,bits=8,wrapper='old_STE'):
        super().__init__();self.mod=mod;self.accumulator=accumulator;self.bits=bits;self.wrapper=wrapper
        if not isinstance(bits,int) or not 2<=bits<=16:raise ValueError('QUANTIZATION_BITS_REQUIRE_2_TO_16')
        self.register_buffer('s_a',torch.as_tensor(activation_scale).detach().clone())
        if not isinstance(mod,(torch.nn.Conv2d,torch.nn.Linear)):raise TypeError('LAYER_UNSUPPORTED')
        if isinstance(mod,torch.nn.Conv2d) and (mod.groups!=1 or mod.dilation!=(1,1)):raise ValueError('CONV_REQUIRES_GROUPS1_DILATION1')
        if wrapper not in ('old_STE','direct_target_old_contiguous'):raise ValueError('WRAPPER_UNSUPPORTED')
    def forward(self,x):
        import torch.nn.functional as F
        sa=self.s_a.clamp(min=1e-8);sw=self.mod.weight.detach().abs().max()/((1<<(self.bits-1))-1)+1e-12
        qa=(x/sa).round().clamp(0,(1<<self.bits)-1);qw=(self.mod.weight/sw).round().clamp(-(1<<(self.bits-1)),(1<<(self.bits-1))-1)
        xq=x+(qa*sa-x).detach();wq=self.mod.weight+(qw*sw-self.mod.weight).detach();conv=isinstance(self.mod,torch.nn.Conv2d)
        y=F.conv2d(xq,wq,None,self.mod.stride,self.mod.padding) if conv else F.linear(xq,wq,None)
        if conv:
            cols=F.unfold(qa,self.mod.kernel_size,padding=self.mod.padding,stride=self.mod.stride);b,k,l=cols.shape;aa=cols.transpose(1,2).reshape(b*l,k).int()
        else:aa=qa.reshape(-1,qa.shape[-1]).int()
        yi=self.accumulator(aa,qw.reshape(qw.shape[0],-1).int())
        ya=yi.reshape(b,l,-1).transpose(1,2).reshape(y.shape).float()*sa*sw if conv else yi.reshape(y.shape).float()*sa*sw
        y=y+(ya-y).detach() if self.wrapper=='old_STE' else ya.detach().contiguous()+(y-y.detach())
        if self.mod.bias is not None:y=y+(self.mod.bias.view(1,-1,1,1) if conv else self.mod.bias)
        return y


