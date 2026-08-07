#!/usr/bin/env python3
"""Create-only local Codex review of the 48-run attack8 formal20 composite.

No judge/API scorer is used.  The semantic ALIGNMENTS table is the Codex
review; all atomic scores and aggregates are derived deterministically.
"""
from __future__ import annotations

import hashlib, json, re
from collections import Counter, defaultdict
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
MAIN = ROOT / "docs/current_experiment/results_2026-08-01/attack8_two_model_three_stage_formal_20"
RETRY = ROOT / "docs/current_experiment/results_2026-08-02/attack8_two_model_three_stage_formal_20_retry_01/runs/gpt-4.1-mini/stage1/s3_pt_02_regsvr32_remote_sct_stage1_run.json"
COMPOSITE_AUDIT = ROOT / "docs/current_experiment/results_2026-08-02/attack8_two_model_three_stage_formal_20_composite_audit_20260802.json"
CASES = ROOT / "data/current_experiment/cases/atlasv2_s3_s4_attack8_process_chain_v5_formal_stage_cases_20260727.jsonl"
GOLD_ROOT = ROOT / "data/current_experiment/gold/atlasv2_s3_s4_attack8_process_chain_v5_formal_gold_20260727/by_chain"
OUT = ROOT / "docs/current_experiment/results_2026-08-02/attack8_two_model_three_stage_formal_20_composite_scores_codex_sol_v1"
REPORT_JSON = ROOT / "docs/current_experiment/attack8_two_model_three_stage_codex_sol_results_20260802.json"
REPORT_MD = ROOT / "docs/current_experiment/attack8_two_model_three_stage_codex_sol_results_20260802.md"
KINDS = ("subject", "operation", "object")

# key: model/stage/chain, value: candidate output step -> (Gold ordinal, literal TP kinds).
# Omitted claims are unsupported/nearby/duplicate and all three slots are FP.
A = {
"gpt-4.1-mini/stage1/s3_pt_01_word_document_processing": {1:(2,"so")},
"gpt-4.1-mini/stage2/s3_pt_01_word_document_processing": {1:(2,"so")},
"gpt-4.1-mini/stage3/s3_pt_01_word_document_processing": {1:(2,"so")},
"gpt-5.4-mini/stage1/s3_pt_01_word_document_processing": {1:(2,"sop")},
"gpt-5.4-mini/stage2/s3_pt_01_word_document_processing": {2:(2,"sop")},
"gpt-5.4-mini/stage3/s3_pt_01_word_document_processing": {1:(2,"sop")},
"gpt-4.1-mini/stage1/s3_pt_02_regsvr32_remote_sct": {},
"gpt-4.1-mini/stage2/s3_pt_02_regsvr32_remote_sct": {1:(1,"sop"),2:(2,"sop"),3:(3,"sop")},
"gpt-4.1-mini/stage3/s3_pt_02_regsvr32_remote_sct": {1:(2,"sop")},
"gpt-5.4-mini/stage1/s3_pt_02_regsvr32_remote_sct": {},
"gpt-5.4-mini/stage2/s3_pt_02_regsvr32_remote_sct": {1:(2,"sop"),2:(3,"sop")},
"gpt-5.4-mini/stage3/s3_pt_02_regsvr32_remote_sct": {},
"gpt-4.1-mini/stage1/s3_pt_03_regsvr32_long_chain": {3:(2,"s")},
"gpt-4.1-mini/stage2/s3_pt_03_regsvr32_long_chain": {1:(1,"sop"),2:(2,"sp"),3:(3,"op"),5:(6,"sp")},
"gpt-4.1-mini/stage3/s3_pt_03_regsvr32_long_chain": {2:(1,"sop"),4:(2,"sop"),5:(3,"sp"),6:(5,"sop"),7:(6,"sop")},
"gpt-5.4-mini/stage1/s3_pt_03_regsvr32_long_chain": {1:(2,"s"),2:(3,"so")},
"gpt-5.4-mini/stage2/s3_pt_03_regsvr32_long_chain": {},
"gpt-5.4-mini/stage3/s3_pt_03_regsvr32_long_chain": {1:(2,"sop"),2:(3,"so")},
"gpt-4.1-mini/stage1/s3_pt_04_powershell_mid_chain": {1:(1,"sop"),2:(2,"s"),3:(4,"sop"),4:(5,"sop")},
"gpt-4.1-mini/stage2/s3_pt_04_powershell_mid_chain": {1:(2,"so"),2:(4,"sop"),3:(5,"sop")},
"gpt-4.1-mini/stage3/s3_pt_04_powershell_mid_chain": {2:(1,"sop"),3:(2,"so"),6:(5,"sop")},
"gpt-5.4-mini/stage1/s3_pt_04_powershell_mid_chain": {2:(2,"sop")},
"gpt-5.4-mini/stage2/s3_pt_04_powershell_mid_chain": {1:(1,"sop")},
"gpt-5.4-mini/stage3/s3_pt_04_powershell_mid_chain": {},
"gpt-4.1-mini/stage1/s4_pt_01_word_w1": {1:(1,"sop"),2:(2,"sp")},
"gpt-4.1-mini/stage2/s4_pt_01_word_w1": {1:(2,"sp")},
"gpt-4.1-mini/stage3/s4_pt_01_word_w1": {2:(3,"sop")},
"gpt-5.4-mini/stage1/s4_pt_01_word_w1": {1:(3,"sop")},
"gpt-5.4-mini/stage2/s4_pt_01_word_w1": {1:(3,"sop")},
"gpt-5.4-mini/stage3/s4_pt_01_word_w1": {1:(3,"sop")},
"gpt-4.1-mini/stage1/s4_pt_02_word_w3": {4:(2,"sop")},
"gpt-4.1-mini/stage2/s4_pt_02_word_w3": {1:(2,"sop")},
"gpt-4.1-mini/stage3/s4_pt_02_word_w3": {2:(2,"op")},
"gpt-5.4-mini/stage1/s4_pt_02_word_w3": {},
"gpt-5.4-mini/stage2/s4_pt_02_word_w3": {1:(2,"sop")},
"gpt-5.4-mini/stage3/s4_pt_02_word_w3": {},
"gpt-4.1-mini/stage1/s4_pt_03_mshta_c1": {2:(4,"sop")},
"gpt-4.1-mini/stage2/s4_pt_03_mshta_c1": {1:(1,"sop"),2:(3,"sop"),3:(6,"sop"),4:(7,"op")},
"gpt-4.1-mini/stage3/s4_pt_03_mshta_c1": {1:(1,"sop"),2:(3,"sop"),4:(7,"op")},
"gpt-5.4-mini/stage1/s4_pt_03_mshta_c1": {},
"gpt-5.4-mini/stage2/s4_pt_03_mshta_c1": {2:(3,"so")},
"gpt-5.4-mini/stage3/s4_pt_03_mshta_c1": {1:(3,"sop")},
"gpt-4.1-mini/stage1/s4_pt_04_powershell_c1": {1:(1,"sop"),3:(2,"sop"),5:(4,"sop"),6:(5,"sop")},
"gpt-4.1-mini/stage2/s4_pt_04_powershell_c1": {1:(2,"sop"),3:(5,"sop")},
"gpt-4.1-mini/stage3/s4_pt_04_powershell_c1": {2:(2,"sop"),3:(6,"sop")},
"gpt-5.4-mini/stage1/s4_pt_04_powershell_c1": {},
"gpt-5.4-mini/stage2/s4_pt_04_powershell_c1": {2:(1,"sop"),3:(2,"sop")},
"gpt-5.4-mini/stage3/s4_pt_04_powershell_c1": {3:(1,"sop")},
}

def sha(p):
    h=hashlib.sha256();
    with p.open('rb') as f:
        for b in iter(lambda:f.read(1<<20),b''): h.update(b)
    return h.hexdigest()
def canon(x): return json.dumps(x,ensure_ascii=False,sort_keys=True,separators=(',',':')).encode()
def step_num(step_id): return int(step_id.rsplit('S',1)[1])
def chain_of(instance): return instance.rsplit('_stage',1)[0]
def compact_obj(o):
    if not isinstance(o,dict): return str(o)
    return ' | '.join(str(o.get(k)) for k in ('type','name','path','value','data') if o.get(k) not in (None,''))

def metric(rows):
    t=Counter()
    fp=Counter()
    for r in rows:
        for k in ('gold_action_denominator','gold_action_hits','candidate_slot_denominator','candidate_slot_tp','behavior_step_denominator','behavior_step_hits','critical_evidence_denominator','critical_evidence_hits','order_pair_denominator','order_pair_hits'): t[k]+=r['totals'][k]
        fp.update(r['totals']['false_positive_types'])
    t=dict(t); t['false_positive_types']=dict(fp)
    for name,n,d in [('action_recall','gold_action_hits','gold_action_denominator'),('candidate_precision','candidate_slot_tp','candidate_slot_denominator'),('behavior_step_recall','behavior_step_hits','behavior_step_denominator'),('critical_evidence_recall','critical_evidence_hits','critical_evidence_denominator'),('order_recall','order_pair_hits','order_pair_denominator')]:
        t[name]={'hits':t[n],'denominator':t[d],'value':t[n]/t[d] if t[d] else None}
    return t

def main():
    for p in (OUT,REPORT_JSON,REPORT_MD):
        if p.exists(): raise SystemExit(f'create-only refusal: {p}')
    audit=json.loads(COMPOSITE_AUDIT.read_text(encoding='utf-8'))
    assert audit['status']=='pass' and audit['valid_output_json_count']==48
    case_rows=[json.loads(x) for x in CASES.read_text(encoding='utf-8').splitlines() if x.strip()]
    cases={x['instance_id']:x for x in case_rows}
    gold={}
    for p in GOLD_ROOT.glob('*/chain_gold.json'):
        j=json.loads(p.read_text(encoding='utf-8')); gold[j['chain_id']]=(j,p)
    run_paths=sorted((MAIN/'runs').glob('*/*/*_run.json'))
    selected=[]
    for p in run_paths:
        j=json.loads(p.read_text(encoding='utf-8'))
        if j['model'].startswith('gpt-4.1-mini') and j['instance_id']=='s3_pt_02_regsvr32_remote_sct_stage1': p=RETRY; j=json.loads(p.read_text(encoding='utf-8'))
        selected.append((p,j))
    assert len(selected)==48
    rows=[]
    for p,r in selected:
        model='gpt-4.1-mini' if r['model'].startswith('gpt-4.1-mini') else 'gpt-5.4-mini'
        instance=r['instance_id']; stage=r['experiment_stage']; chain=chain_of(instance); c=cases[instance]; g,gp=gold[chain]
        out=json.loads(r['output_text']); steps=out.get('code_steps',[]) or []
        key=f'{model}/{stage}/{chain}'; decision=A[key]
        gsteps={step_num(x['step_id']):x for x in g['gold_steps']}
        gold_items=[]; hit_ids=set(); aligned={}; slots=[]; fp=Counter()
        for idx,s in enumerate(steps,1):
            ci=int(re.sub(r'\D','',str(s.get('step_id',idx))) or idx); spec=decision.get(ci)
            if spec: gn,letters=spec; aligned[ci]=gn
            for kind,letter,val in [('subject','s',(s.get('subject_process') or {}).get('name')),('operation','p',s.get('operation')),('object','o',compact_obj(s.get('object') or {}))]:
                target=None; tp=0
                if spec and letter in spec[1]: target=f"{gsteps[spec[0]]['step_id']}:{kind}"; tp=1; hit_ids.add(target)
                fpt='' if tp else ('wrong_component' if spec else 'unsupported_or_nearby')
                if fpt: fp[fpt]+=1
                slots.append({'slot_id':f'C{ci}:{kind}','candidate_claim_id':f'C{ci}','kind':kind,'candidate_slot_excerpt':val,'include_in_denominator':1,'is_true_positive':tp,'aligned_gold_step_id':gsteps[spec[0]]['step_id'] if spec else None,'matched_gold_item_id':target,'false_positive_type':fpt})
        evidence_hits=set()
        for ci,gn in aligned.items():
            s=next((x for x in steps if int(re.sub(r'\D','',str(x.get('step_id','0'))) or 0)==ci),None)
            sig=gsteps[gn].get('critical_evidence_signature') or {}; ev=json.dumps((s or {}).get('evidence',[]),ensure_ascii=False).lower()
            anchors=[sig.get('source_row_id'),sig.get('timestamp_utc'),sig.get('target_key')]
            if any(a not in (None,'') and str(a).lower() in ev for a in anchors): evidence_hits.add(gn)
        for gn,s in gsteps.items():
            for kind in KINDS:
                iid=f"{s['step_id']}:{kind}"; gold_items.append({'item_id':iid,'step_id':s['step_id'],'kind':kind,'gold_value':s['subject'] if kind=='subject' else s['action'] if kind=='operation' else s['object'],'score':int(iid in hit_ids),'score_source':'derived_from_unique_literal_tp_matched_gold_item_id'})
            gold_items.append({'item_id':f"{s['step_id']}:critical_evidence",'step_id':s['step_id'],'kind':'critical_evidence','gold_value':s.get('critical_evidence_signature'),'score':int(gn in evidence_hits),'score_source':'separate_exact_canonical_evidence_anchor_review'})
        order=[]
        pos={gn:i for i,gn in aligned.items() if 'p' in decision[i][1]}
        for left,right in g['gold_order_pairs']:
            a1=step_num(left); a2=step_num(right); score=int(a1 in pos and a2 in pos and pos[a1]<pos[a2])
            order.append({'pair_id':f'{left}->{right}','left_step_id':left,'right_step_id':right,'score':score})
        step_hits=sum(all(f"{s['step_id']}:{k}" in hit_ids for k in KINDS) for s in g['gold_steps'])
        totals={'gold_action_denominator':len(gsteps)*3,'gold_action_hits':len(hit_ids),'candidate_slot_denominator':len(slots),'candidate_slot_tp':sum(x['is_true_positive'] for x in slots),'behavior_step_denominator':len(gsteps),'behavior_step_hits':step_hits,'critical_evidence_denominator':len(gsteps),'critical_evidence_hits':len(evidence_hits),'order_pair_denominator':len(order),'order_pair_hits':sum(x['score'] for x in order),'false_positive_types':dict(fp)}
        act=(r.get('investigation_activity') or {}).get('summary') or {}; usage=r.get('usage') or {}; cost=r.get('cost_estimate') or {}
        row={'queue_id':f'{model}/{stage}/{instance}','model':model,'stage':stage,'instance_id':instance,'chain_id':chain,'run_path':str(p.relative_to(ROOT)).replace('\\','/'),'run_sha256':sha(p),'case_sha256':hashlib.sha256(canon(c)).hexdigest(),'case_file_sha256':sha(CASES),'gold_path':str(gp.relative_to(ROOT)).replace('\\','/'),'gold_sha256':sha(gp),'gold_items':gold_items,'candidate_slots':slots,'order_pairs':order,'fixed_denominators':{'gold_action':len(gsteps)*3,'candidate_slots':len(slots),'behavior_steps':len(gsteps),'critical_evidence':len(gsteps),'order_pairs':len(order)},'totals':totals,'review_summary':{'aligned_candidate_claims':len(aligned),'unsupported_candidate_claims':len(steps)-len(aligned),'complete_gold_steps':step_hits,'missing_gold_steps':len(gsteps)-len({x for x in aligned.values()}),'causal_edge_missing_count':len(order)-sum(x['score'] for x in order),'nearby_or_unsupported_slot_count':fp['unsupported_or_nearby'],'hallucination_risk_claim_count':len(steps)-len(aligned)},'investigation':{**{k:act.get(k,0) for k in ('lead_call_count','unique_lead_count','investigator_question_count','unique_investigator_question_count','sql_query_count','unique_sql_query_count')},'input_tokens':usage.get('input_tokens',0),'output_tokens':usage.get('output_tokens',0),'cached_input_tokens':usage.get('cached_input_tokens',0),'total_tokens':usage.get('total_tokens',0),'cost_usd':cost.get('total_cost_usd',0),'elapsed_seconds':r.get('elapsed_seconds',0)}}
        row['decision_sha256']=hashlib.sha256(canon(row)).hexdigest(); rows.append(row)
    assert len({x['queue_id'] for x in rows})==48
    by_model={k:metric([r for r in rows if r['model']==k]) for k in sorted({r['model'] for r in rows})}
    by_stage={k:metric([r for r in rows if r['stage']==k]) for k in sorted({r['stage'] for r in rows})}
    by_case={k:metric([r for r in rows if r['chain_id']==k]) for k in sorted({r['chain_id'] for r in rows})}
    by_model_stage={f'{m}/{s}':metric([r for r in rows if r['model']==m and r['stage']==s]) for m in sorted(by_model) for s in sorted(by_stage)}
    overall=metric(rows)
    investigation={}
    for m in sorted(by_model):
        rr=[x for x in rows if x['model']==m]; investigation[m]={k:sum(x['investigation'][k] for x in rr) for k in rr[0]['investigation']}
    audit_fail=[]
    for r in rows:
        ids={x['item_id']:x['score'] for x in r['gold_items'] if x['kind'] in KINDS}; tp=[x['matched_gold_item_id'] for x in r['candidate_slots'] if x['include_in_denominator']==1 and x['is_true_positive']==1]
        if len(tp)!=len(set(tp)): audit_fail.append(r['queue_id']+':duplicate_tp')
        for i,v in ids.items():
            if v!=int(i in tp): audit_fail.append(r['queue_id']+':gold_tp_mismatch:'+i)
        if len(r['candidate_slots'])!=r['fixed_denominators']['candidate_slots']: audit_fail.append(r['queue_id']+':candidate_denominator')
    validation={'status':'pass' if not audit_fail else 'fail','row_count':len(rows),'run_hash_count':len({r['run_sha256'] for r in rows}),'case_hash_count':len({r['case_sha256'] for r in rows}),'gold_hash_count':len({r['gold_sha256'] for r in rows}),'gold_action_items_checked':sum(r['fixed_denominators']['gold_action'] for r in rows),'candidate_slots_checked':sum(r['fixed_denominators']['candidate_slots'] for r in rows),'behavior_steps_checked':sum(r['fixed_denominators']['behavior_steps'] for r in rows),'critical_evidence_items_checked':sum(r['fixed_denominators']['critical_evidence'] for r in rows),'order_pairs_checked':sum(r['fixed_denominators']['order_pairs'] for r in rows),'gold1_without_tp':0,'tp_without_gold1':0,'duplicate_tp':0,'failures':audit_fail,'replacement_sha256':sha(RETRY),'composite_audit_sha256':sha(COMPOSITE_AUDIT),'external_judge_api_used':False}
    assert validation['status']=='pass'
    result={'schema_version':'attack8_formal20_codex_sol_v5_atomic_v1','scoring_policy':{'action_components':['subject','operation','object'],'action_alias':'operation','gold_hit_derivation':'unique literal included TP candidate slot matched_gold_item_id','behavior_step_rule':'all subject+operation+object hits','critical_evidence_separate':True,'order_unit':'adjacent Gold pair','pid_scored':False,'hidden_alert_mapping_scored':False,'candidate_denominator':'3 fixed slots per emitted code_step','external_judge_api_used':False},'source':{'main_root':str(MAIN.relative_to(ROOT)).replace('\\','/'),'retry_run':str(RETRY.relative_to(ROOT)).replace('\\','/'),'failed_main_run_frozen_excluded':True,'composite_audit':str(COMPOSITE_AUDIT.relative_to(ROOT)).replace('\\','/')},'validation':validation,'overall':overall,'by_model':by_model,'by_stage':by_stage,'by_case':by_case,'by_model_stage':by_model_stage,'investigation_by_model':investigation,'failure_analysis':{'unrecovered_gold_steps':sum(r['review_summary']['missing_gold_steps'] for r in rows),'missing_adjacent_causal_edges':sum(r['review_summary']['causal_edge_missing_count'] for r in rows),'nearby_or_unsupported_slots':sum(r['review_summary']['nearby_or_unsupported_slot_count'] for r in rows),'hallucination_risk_claims':sum(r['review_summary']['hallucination_risk_claim_count'] for r in rows),'interpretation':'主な未取得要因は、起点近傍だけで停止すること、正しい後続frontierへのpivot欠落、複数の観測を因果edgeとして統合できないこと、時刻近傍のDLL・一時ファイル・レジストリを主行動へ過剰接続すること。'},'rows':rows}
    OUT.mkdir(parents=False); (OUT/'formal_scores.json').write_text(json.dumps(result,ensure_ascii=False,indent=2)+'\n',encoding='utf-8'); (OUT/'per_run_scores.jsonl').write_text(''.join(json.dumps(x,ensure_ascii=False,sort_keys=True)+'\n' for x in rows),encoding='utf-8'); (OUT/'cross_field_consistency_audit.json').write_text(json.dumps(validation,ensure_ascii=False,indent=2)+'\n',encoding='utf-8'); (OUT/'semantic_alignment_decisions.json').write_text(json.dumps(A,ensure_ascii=False,indent=2)+'\n',encoding='utf-8')
    REPORT_JSON.write_text(json.dumps(result,ensure_ascii=False,indent=2)+'\n',encoding='utf-8')
    def f(x): return f"{x['hits']}/{x['denominator']} = {x['value']:.2%}"
    lines=['# Attack8 2モデル×3 Stage Codex正式採点（2026-08-02）','','OpenAI judge API/API scorerは不使用。47件のmain valid runと指定retry 1件を合成し、元の失敗runは凍結保持した。','','## 主要指標','','| 集計 | Action recall | Candidate precision | Behavior-step recall | Critical evidence | Order recall |','|---|---:|---:|---:|---:|---:|']
    for name,b in [('全48件',overall),*by_model.items(),*by_stage.items()]: lines.append(f"| {name} | {f(b['action_recall'])} | {f(b['candidate_precision'])} | {f(b['behavior_step_recall'])} | {f(b['critical_evidence_recall'])} | {f(b['order_recall'])} |")
    lines += ['','## 監査',f"- status: **{validation['status']}**",f"- 48/48 rows、Action {validation['gold_action_items_checked']} items、candidate {validation['candidate_slots_checked']} slots、behavior {validation['behavior_steps_checked']} steps、critical {validation['critical_evidence_items_checked']} items、order {validation['order_pairs_checked']} pairsを固定分母で照合。",f"- Gold=1/TPなし: {validation['gold1_without_tp']}、TP/Gold=0: {validation['tp_without_gold1']}、duplicate TP: {validation['duplicate_tp']}。",f"- retry SHA-256: `{validation['replacement_sha256']}`",'','## 調査・失敗分析',f"- 未取得Gold step（run横断）: {result['failure_analysis']['unrecovered_gold_steps']}、隣接因果edge欠落: {result['failure_analysis']['missing_adjacent_causal_edges']}。",f"- 近傍/Gold外slot: {result['failure_analysis']['nearby_or_unsupported_slots']}、幻覚リスクclaim: {result['failure_analysis']['hallucination_risk_claims']}。",f"- {result['failure_analysis']['interpretation']}",'','機械可読な全run hash・case hash・Gold hash、全Gold item、candidate slot、order pair、固定分母はscore rootの `formal_scores.json` と `per_run_scores.jsonl` に記録した。']
    REPORT_MD.write_text('\n'.join(lines)+'\n',encoding='utf-8')
    print(json.dumps({'status':'pass','overall':overall,'validation':validation},ensure_ascii=False,indent=2))
if __name__=='__main__': main()
