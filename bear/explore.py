"""Select from caller-supplied accuracy and hardware measurements."""
import math

def finite(value,name,positive=False):
    value=float(value)
    if not math.isfinite(value) or (positive and value<=0):raise ValueError(f'{name} must be finite'+(' and positive' if positive else ''))
    return value


def select_curve(candidates,accuracy,hardware,budgets,clocks,metric='task_loss_pp'):
    if metric not in ('task_loss_pp','MRED','error_rate'):raise ValueError('unsupported error metric')
    eligible={c['candidate_id']:c for c in candidates if c.get('status')=='PASS' and c.get('low_local')}
    hw={};seen=set()
    for r in hardware:
        if r.get('status') not in ('PASS','COMPLETE'):continue
        cid=r['candidate_id'];variant=r.get('variant','original');clock=finite(r['target_clock_ns'],'target_clock_ns',True)
        key=(cid,variant,clock)
        if key in seen:raise ValueError(f'duplicate hardware measurement {key}')
        seen.add(key)
        if cid not in eligible:continue
        if variant!='original' and (r.get('proof_status')!='PASS' or r.get('proof_scope')!='FULL_PREFIX'):continue
        if finite(r['delay_ns'],'delay_ns',True)>clock:continue
        area=finite(r['area_um2'],'area_um2',True)
        power=finite(r['power_w'],'power_w',True) if r.get('power_w') else finite(r['energy_j_per_cycle'],'energy_j_per_cycle',True)/(clock*1e-9)
        hw[key]={'area_um2':area,'power_w':power,'area_power':area*power}
    groups={}
    for a in accuracy:
        if a.get('status') not in ('PASS','COMPLETE'):continue
        if a.get('accuracy') not in (None,'') and a.get('reference_accuracy') not in (None,''):
            acc=finite(a['accuracy'],'accuracy');ref=finite(a['reference_accuracy'],'reference_accuracy')
            if not 0<=acc<=1 or not 0<=ref<=1 or abs(finite(a['drop_pp'],'drop_pp')-100*(ref-acc))>1e-6:
                raise ValueError('inconsistent accuracy / percentage-point loss')
        key=(a['network'],a.get('dataset',''),a.get('mode','direct'),a['candidate_id'])
        groups.setdefault(key,[]).append(a)
    means=[]
    for (net,ds,mode,cid),rows in groups.items():
        if cid not in eligible:continue
        if len({str(r.get('seed','')) for r in rows})!=len(rows):raise ValueError('duplicate accuracy seed')
        need=3 if mode=='finetuned' and net=='ResNet18' else 1
        if len(rows)<need:continue
        if metric=='task_loss_pp':loss=sum(finite(r['drop_pp'],'drop_pp') for r in rows)/len(rows)
        else:loss=finite(eligible[cid].get(metric),'arithmetic metric')
        means.append((net,ds,mode,cid,loss,len(rows)))
    # The optional-tuning curve may retain an already feasible direct model.
    # Never average a direct deployment together with independent tuned seeds.
    if metric=='task_loss_pp':
        for net,ds,mode,cid,loss,nseed in list(means):
            if mode=='direct':means.append((net,ds,'optional_finetuning',cid,loss,nseed))
            elif mode=='finetuned':means.append((net,ds,'optional_finetuning',cid,loss,nseed))
    if metric!='task_loss_pp':
        means=[('ARITHMETIC','characterize_metrics','arithmetic',cid,finite(c.get(metric),metric),1) for cid,c in eligible.items()]
    result=[]
    for net,ds,mode in sorted({x[:3] for x in means}):
        for budget in budgets:
            budget=finite(budget,'budget',True)
            for clock in clocks:
                clock=finite(clock,'clock',True);pool=[]
                for n,d,m,cid,loss,seeds in means:
                    if (n,d,m)!=(net,ds,mode) or loss>budget+1e-9:continue
                    for (hid,variant,hclock),cost in hw.items():
                        if hid==cid and hclock==clock:pool.append({**cost,'candidate_id':cid,'variant':variant,'drop_pp':loss,'seeds':seeds})
                best=min(pool,key=lambda x:(x['area_power'],x['candidate_id'],x['variant'],x['drop_pp'])) if pool else {}
                result.append({'network':net,'dataset':ds,'mode':mode,'error_metric':metric,'allowed_loss':budget,'target_clock_ns':clock,'status':'COMPLETE' if pool else 'NOT_ASSESSED','feasible_points':len(pool),**best})
    return result

