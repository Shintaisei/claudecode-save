#!/usr/bin/env python3
"""Create-only independent Codex gpt-5.6-sol review of gpt-5.5 attack8.

This is a local semantic review.  It does not invoke OpenAI judge APIs or an
API scorer.  Gold action hits are derived only from unique literal TP slots.
"""
from __future__ import annotations

import hashlib, json, re
from collections import Counter
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
SRC = ROOT / "docs/current_experiment/results_2026-08-02/gpt55_normal8_attack8_three_stage_budget10_pilot_01"
RUN_ROOT = SRC / "attack8/runs/gpt-5.5"
AUDIT_ROOT = SRC / "audits/attack8"
CASES = ROOT / "data/current_experiment/cases/atlasv2_s3_s4_attack8_process_chain_v5_formal_stage_cases_20260727.jsonl"
GOLD_ROOT = ROOT / "data/current_experiment/gold/atlasv2_s3_s4_attack8_process_chain_v5_formal_gold_20260727/by_chain"
BASELINE = ROOT / "docs/current_experiment/attack8_two_model_three_stage_codex_sol_results_20260802.json"
OUT = SRC / "attack8_scores_codex_gpt56sol_v5_atomic_v1_20260803"
REPORT_JSON = ROOT / "docs/current_experiment/gpt55_attack8_budget10_codex_gpt56sol_results_20260803.json"
REPORT_MD = ROOT / "docs/current_experiment/gpt55_attack8_budget10_codex_gpt56sol_results_20260803.md"
EXCLUDED = {"s4_pt_04_powershell_c1_stage1", "s4_pt_03_mshta_c1_stage3"}
KINDS = ("subject", "operation", "object")

# Candidate list index -> (Gold ordinal, literal TP kinds).  s/o/p mean
# subject/object/operation.  Omitted claims are unsupported/nearby/duplicate.
A = {
"stage1/s3_pt_01_word_document_processing": {2:(1,"sp")},
"stage2/s3_pt_01_word_document_processing": {2:(2,"sop")},
"stage3/s3_pt_01_word_document_processing": {2:(2,"sop")},
"stage1/s3_pt_02_regsvr32_remote_sct": {1:(2,"sop")},
"stage2/s3_pt_02_regsvr32_remote_sct": {1:(1,"sop"),2:(2,"sop"),3:(3,"sop")},
"stage3/s3_pt_02_regsvr32_remote_sct": {1:(1,"sop"),2:(2,"sop"),3:(3,"sop")},
"stage1/s3_pt_03_regsvr32_long_chain": {2:(1,"sop"),6:(2,"sop"),7:(3,"sop")},
"stage2/s3_pt_03_regsvr32_long_chain": {2:(1,"sop"),5:(2,"sop"),6:(3,"sop"),8:(5,"sop"),9:(6,"sop"),10:(7,"sop"),11:(8,"sop")},
"stage3/s3_pt_03_regsvr32_long_chain": {2:(1,"sop"),4:(2,"sop"),5:(3,"sop"),6:(5,"sop"),7:(6,"sop"),9:(7,"sop"),10:(8,"sop")},
"stage1/s3_pt_04_powershell_mid_chain": {5:(1,"sop"),7:(2,"sp"),9:(4,"sop"),10:(5,"sop"),12:(6,"sop"),13:(7,"sop")},
"stage2/s3_pt_04_powershell_mid_chain": {4:(1,"sop"),5:(2,"sop"),7:(4,"sop"),8:(5,"sop"),9:(6,"sop"),10:(7,"sop")},
"stage3/s3_pt_04_powershell_mid_chain": {3:(1,"sop"),4:(2,"sop"),5:(3,"sop"),7:(4,"sop"),8:(5,"sop"),9:(6,"sop"),10:(7,"sop")},
"stage1/s4_pt_01_word_w1": {1:(1,"sop"),2:(2,"sp")},
"stage2/s4_pt_01_word_w1": {1:(1,"sop"),5:(3,"sop"),6:(4,"sop")},
"stage3/s4_pt_01_word_w1": {3:(1,"sop"),5:(2,"sop"),6:(3,"sop")},
"stage1/s4_pt_02_word_w3": {2:(2,"sop")},
"stage2/s4_pt_02_word_w3": {4:(2,"sop"),6:(3,"sop")},
"stage3/s4_pt_02_word_w3": {3:(2,"sop")},
"stage1/s4_pt_03_mshta_c1": {1:(1,"sop"),2:(3,"sop")},
"stage2/s4_pt_03_mshta_c1": {3:(2,"sop"),4:(3,"sop"),5:(4,"sop"),6:(5,"sop"),7:(6,"sop"),8:(7,"sop"),10:(8,"sop"),11:(9,"sop")},
"stage2/s4_pt_04_powershell_c1": {2:(1,"sop"),3:(2,"sop"),4:(3,"sop")},
"stage3/s4_pt_04_powershell_c1": {2:(1,"sop"),3:(2,"sop"),6:(3,"sop")},
}

def sha(p: Path) -> str:
    h=hashlib.sha256()
    with p.open('rb') as f:
        for b in iter(lambda:f.read(1<<20),b''): h.update(b)
    return h.hexdigest()
def canon(x): return json.dumps(x,ensure_ascii=False,sort_keys=True,separators=(',',':')).encode()
def chain_of(instance): return instance.rsplit('_stage',1)[0]
def step_num(s): return int(s.rsplit('S',1)[1])
def compact_obj(o):
    if not isinstance(o,dict): return str(o)
    return ' | '.join(str(o.get(k)) for k in ('type','name','path','value','data') if o.get(k) not in (None,''))

def metric(rows):
    t=Counter(); fp=Counter()
    for r in rows:
        for k in ('gold_action_denominator','gold_action_hits','candidate_slot_denominator','candidate_slot_tp','behavior_step_denominator','behavior_step_hits','critical_evidence_denominator','critical_evidence_hits','order_pair_denominator','order_pair_hits'): t[k]+=r['totals'][k]
        fp.update(r['totals'].get('false_positive_types',{}))
    t=dict(t); t['false_positive_types']=dict(fp)
    for name,n,d in [('action_recall','gold_action_hits','gold_action_denominator'),('candidate_precision','candidate_slot_tp','candidate_slot_denominator'),('behavior_step_recall','behavior_step_hits','behavior_step_denominator'),('critical_evidence_recall','critical_evidence_hits','critical_evidence_denominator'),('order_recall','order_pair_hits','order_pair_denominator')]:
        t[name]={'hits':t.get(n,0),'denominator':t.get(d,0),'value':t.get(n,0)/t.get(d,1) if t.get(d,0) else None}
    return t
def activity(rows):
    keys=('api_calls','lead_call_count','unique_lead_count','investigator_question_count','unique_investigator_question_count','sql_query_count','unique_sql_query_count','input_tokens','output_tokens','cached_input_tokens','total_tokens','cost_usd','elapsed_seconds')
    return {k:sum(r['investigation'].get(k,0) for r in rows) for k in keys}

def main():
    for p in (OUT,REPORT_JSON,REPORT_MD):
        if p.exists(): raise SystemExit(f'create-only refusal: {p}')
    cases={x['instance_id']:x for x in map(json.loads,filter(str.strip,CASES.read_text(encoding='utf-8').splitlines()))}
    gold={}
    for p in GOLD_ROOT.glob('*/chain_gold.json'):
        j=json.loads(p.read_text(encoding='utf-8')); gold[j['chain_id']]=(j,p)
    audits={}
    for ap in AUDIT_ROOT.glob('stage*/*_audit.json'):
        a=json.loads(ap.read_text(encoding='utf-8')); audits[a['instance_id']]=(a,ap)
    assert len(audits)==24 and {k for k,(a,_) in audits.items() if a['run_budget_guard']['budget_censored']}==EXCLUDED
    inventory=[]; rows=[]
    for rp in sorted(RUN_ROOT.glob('stage*/*_run.json')):
        r=json.loads(rp.read_text(encoding='utf-8')); instance=r['instance_id']; a,ap=audits[instance]; censored=a['run_budget_guard']['budget_censored']; chain=chain_of(instance); stage=a['stage']
        assert sha(rp)==a['sha256']
        inv={'instance_id':instance,'stage':stage,'chain_id':chain,'run_path':str(rp.relative_to(ROOT)).replace('\\','/'),'run_sha256':sha(rp),'audit_path':str(ap.relative_to(ROOT)).replace('\\','/'),'audit_sha256':sha(ap),'audit_status':a['status'],'budget_censored':censored,'budget_limited':a['run_budget_guard']['budget_limited'],'soft_triggered':a['run_budget_guard']['soft_triggered'],'hard_triggered':a['run_budget_guard']['hard_triggered'],'headline_included':not censored,'run_budget_guard':a['run_budget_guard']}
        inventory.append(inv)
        if censored: continue
        assert a['status']=='PASS'
        out=json.loads(r['output_text']); steps=out.get('code_steps',[]) or []; c=cases[instance]; g,gp=gold[chain]; decision=A[f'{stage}/{chain}']; gsteps={step_num(x['step_id']):x for x in g['gold_steps']}
        slots=[]; hit_ids=set(); aligned={}; fp=Counter()
        for ci,s in enumerate(steps,1):
            spec=decision.get(ci)
            if spec: aligned[ci]=spec[0]
            vals={'subject':(s.get('subject_process') or {}).get('name'),'operation':s.get('operation'),'object':compact_obj(s.get('object') or {})}
            for kind,letter in [('subject','s'),('operation','p'),('object','o')]:
                tp=int(bool(spec and letter in spec[1])); target=f"{gsteps[spec[0]]['step_id']}:{kind}" if tp else None
                if tp: hit_ids.add(target)
                fpt='' if tp else ('wrong_component' if spec else 'unsupported_or_nearby')
                if fpt: fp[fpt]+=1
                slots.append({'slot_id':f'C{ci}:{kind}','candidate_claim_id':f'C{ci}','source_step_id':s.get('step_id'),'source_order':s.get('order'),'kind':kind,'candidate_slot_excerpt':vals[kind],'include_in_denominator':1,'is_true_positive':tp,'aligned_gold_step_id':gsteps[spec[0]]['step_id'] if spec else None,'matched_gold_item_id':target,'false_positive_type':fpt})
        evidence_hits=set()
        for ci,gn in aligned.items():
            s=steps[ci-1]; sig=gsteps[gn].get('critical_evidence_signature') or {}; ev=json.dumps(s.get('evidence',[]),ensure_ascii=False).lower(); anchors=[sig.get('source_row_id'),sig.get('timestamp_utc'),sig.get('target_key')]
            if any(x not in (None,'') and str(x).lower() in ev for x in anchors): evidence_hits.add(gn)
        gold_items=[]
        for gn,s in gsteps.items():
            for kind in KINDS:
                iid=f"{s['step_id']}:{kind}"; val=s['subject'] if kind=='subject' else s['action'] if kind=='operation' else s['object']; gold_items.append({'item_id':iid,'step_id':s['step_id'],'kind':kind,'gold_value':val,'score':int(iid in hit_ids),'score_source':'derived_from_unique_literal_tp_matched_gold_item_id'})
            gold_items.append({'item_id':f"{s['step_id']}:critical_evidence",'step_id':s['step_id'],'kind':'critical_evidence','gold_value':s.get('critical_evidence_signature'),'score':int(gn in evidence_hits),'score_source':'separate_exact_canonical_evidence_anchor_review'})
        op_pos={gn:ci for ci,gn in aligned.items() if 'p' in decision[ci][1]}; order=[]
        for left,right in g['gold_order_pairs']:
            l,rn=step_num(left),step_num(right); order.append({'pair_id':f'{left}->{right}','left_step_id':left,'right_step_id':right,'score':int(l in op_pos and rn in op_pos and op_pos[l]<op_pos[rn])})
        behavior_hits=sum(all(f"{s['step_id']}:{k}" in hit_ids for k in KINDS) for s in g['gold_steps'])
        totals={'gold_action_denominator':3*len(gsteps),'gold_action_hits':len(hit_ids),'candidate_slot_denominator':len(slots),'candidate_slot_tp':sum(x['is_true_positive'] for x in slots),'behavior_step_denominator':len(gsteps),'behavior_step_hits':behavior_hits,'critical_evidence_denominator':len(gsteps),'critical_evidence_hits':len(evidence_hits),'order_pair_denominator':len(order),'order_pair_hits':sum(x['score'] for x in order),'false_positive_types':dict(fp)}
        ac=a.get('activity_summary') or {}; u=a.get('usage') or {}; bg=a['run_budget_guard']
        cost=a.get('cost_estimate') or {}
        row={'queue_id':f'gpt-5.5/{stage}/{instance}','reviewer':'Codex gpt-5.6-sol','model':'gpt-5.5','stage':stage,'instance_id':instance,'chain_id':chain,'run_path':inv['run_path'],'run_sha256':inv['run_sha256'],'audit_path':inv['audit_path'],'audit_sha256':inv['audit_sha256'],'case_sha256':hashlib.sha256(canon(c)).hexdigest(),'case_file_sha256':sha(CASES),'gold_path':str(gp.relative_to(ROOT)).replace('\\','/'),'gold_sha256':sha(gp),'budget_censored':False,'budget_limited':bg['budget_limited'],'gold_items':gold_items,'candidate_slots':slots,'order_pairs':order,'fixed_denominators':{'gold_action':3*len(gsteps),'candidate_slots':len(slots),'behavior_steps':len(gsteps),'critical_evidence':len(gsteps),'order_pairs':len(order)},'totals':totals,'failure_diagnostics':{'gold_steps_without_aligned_claim':len(gsteps)-len(set(aligned.values())),'incomplete_behavior_steps':len(gsteps)-behavior_hits,'missing_adjacent_causal_edges':len(order)-sum(x['score'] for x in order),'unsupported_or_nearby_slots':fp['unsupported_or_nearby'],'wrong_component_slots':fp['wrong_component']},'investigation':{'api_calls':bg['api_calls'],**{k:ac.get(k,0) for k in ('lead_call_count','unique_lead_count','investigator_question_count','unique_investigator_question_count','sql_query_count','unique_sql_query_count')},'input_tokens':u.get('input_tokens',0),'output_tokens':u.get('output_tokens',0),'cached_input_tokens':u.get('cached_input_tokens',0),'total_tokens':u.get('total_tokens',0),'cost_usd':cost.get('total_cost_usd',0),'elapsed_seconds':a.get('elapsed_seconds',0)}}
        row['decision_sha256']=hashlib.sha256(canon(row)).hexdigest(); rows.append(row)
    assert len(rows)==22 and len(inventory)==24
    overall=metric(rows); by_stage={s:metric([r for r in rows if r['stage']==s]) for s in ('stage1','stage2','stage3')}; by_case={c:metric([r for r in rows if r['chain_id']==c]) for c in sorted({r['chain_id'] for r in rows})}; act=activity(rows); act_stage={s:activity([r for r in rows if r['stage']==s]) for s in by_stage}
    baseline=json.loads(BASELINE.read_text(encoding='utf-8')); brows=[r for r in baseline['rows'] if r['instance_id'] not in EXCLUDED]; assert len(brows)==44
    baseline_matched={m:metric([r for r in brows if r['model']==m]) for m in ('gpt-4.1-mini','gpt-5.4-mini')}
    resource_comparison={m:activity([r for r in brows if r['model']==m]) for m in ('gpt-4.1-mini','gpt-5.4-mini')}
    resource_comparison['gpt-5.5']=act
    comparison={'matched_22_strata':{'gpt-4.1-mini':baseline_matched['gpt-4.1-mini'],'gpt-5.4-mini':baseline_matched['gpt-5.4-mini'],'gpt-5.5':overall},'full_24_reference':baseline['by_model'],'by_stage':{},'by_case':{}}
    for s in by_stage:
        comparison['by_stage'][s]={'gpt-4.1-mini':metric([r for r in brows if r['model']=='gpt-4.1-mini' and r['stage']==s]),'gpt-5.4-mini':metric([r for r in brows if r['model']=='gpt-5.4-mini' and r['stage']==s]),'gpt-5.5':by_stage[s]}
    for c in by_case:
        comparison['by_case'][c]={'gpt-4.1-mini':metric([r for r in brows if r['model']=='gpt-4.1-mini' and r['chain_id']==c]),'gpt-5.4-mini':metric([r for r in brows if r['model']=='gpt-5.4-mini' and r['chain_id']==c]),'gpt-5.5':by_case[c]}
    cens=[x for x in inventory if x['budget_censored']]; soft_only=[x for x in inventory if x['soft_triggered'] and not x['budget_censored']]
    budget={'audited_run_count':24,'headline_included_count':22,'headline_excluded_count':2,'excluded_instances':sorted(EXCLUDED),'soft_triggered_non_censored_count':len(soft_only),'soft_triggered_non_censored_instances':[x['instance_id'] for x in soft_only],'excluded_usage':{k:sum(x['run_budget_guard']['usage'].get(k,0) for x in cens) for k in ('input_tokens','output_tokens','cached_input_tokens','total_tokens')},'excluded_cost_usd':sum(x['run_budget_guard']['estimated_cost_usd'] for x in cens),'headline_gold_denominator_reduction':{'gold_action':48,'behavior_steps':16,'critical_evidence':16,'order_pairs':14},'interpretation':'hard budget censoring is an execution-status exclusion, not a zero score; soft-triggered but valid finalized runs remain included and are labeled.'}
    failures=[]
    for r in rows:
        action={x['item_id']:x['score'] for x in r['gold_items'] if x['kind'] in KINDS}; tp=[x['matched_gold_item_id'] for x in r['candidate_slots'] if x['include_in_denominator']==1 and x['is_true_positive']==1]
        if len(tp)!=len(set(tp)): failures.append(r['queue_id']+':duplicate_tp')
        for i,v in action.items():
            if v!=int(i in tp): failures.append(r['queue_id']+':gold_tp_mismatch:'+i)
        if len(r['candidate_slots'])!=r['fixed_denominators']['candidate_slots']: failures.append(r['queue_id']+':candidate_denominator')
    validation={'status':'pass' if not failures else 'fail','headline_rows':len(rows),'audit_inventory_rows':len(inventory),'run_hashes_checked':len(inventory),'gold_action_items_checked':sum(r['fixed_denominators']['gold_action'] for r in rows),'candidate_slots_checked':sum(r['fixed_denominators']['candidate_slots'] for r in rows),'behavior_steps_checked':sum(r['fixed_denominators']['behavior_steps'] for r in rows),'critical_evidence_items_checked':sum(r['fixed_denominators']['critical_evidence'] for r in rows),'order_pairs_checked':sum(r['fixed_denominators']['order_pairs'] for r in rows),'gold1_without_tp':0,'tp_without_gold1':0,'duplicate_tp':0,'failures':failures,'external_judge_api_used':False}
    assert validation['status']=='pass'
    addendum={'title':'Budget-censored run handling addendum proposal','proposed_clauses':['Pre-register soft/hard budget thresholds and inclusion policy before execution.','A run with run_budget_guard.budget_censored=true is excluded from headline accuracy and retained as a frozen censored artifact; it is not scored as zero.','A soft-triggered run that emits valid final JSON and is not budget-censored remains headline-eligible, with budget_limited status reported.','All model comparisons use the intersection of headline-eligible case×stage strata; full-grid values may be shown only as labeled references.','Publish the 24-run audit inventory, inclusion mask, run/audit hashes, excluded denominator delta, and censored resource use.','Any rerun/replacement must use a new versioned root and declare both original and replacement hashes; never overwrite the censored run.','Gold denominators are fixed by eligible strata; candidate precision denominator is three fixed subject/operation/object slots per emitted code step.']}
    result={'schema_version':'gpt55_attack8_budget10_codex_gpt56sol_v5_atomic_v1','reviewer':'Codex gpt-5.6-sol','scoring_policy':{'action_components':['subject','operation','object'],'action_alias':'operation','gold_hit_derivation':'unique literal included TP candidate slot matched_gold_item_id','behavior_step_rule':'all subject+operation+object hits','critical_evidence_separate':True,'order_unit':'adjacent Gold pair','pid_scored':False,'hidden_alert_mapping_scored':False,'candidate_denominator':'3 fixed slots per emitted code_step','budget_censored_excluded_from_headline':True,'external_judge_api_used':False},'source':{'source_root':str(SRC.relative_to(ROOT)).replace('\\','/'),'source_root_contract_sha256':sha(SRC/'experiment_contract.json'),'baseline_report':str(BASELINE.relative_to(ROOT)).replace('\\','/'),'baseline_report_sha256':sha(BASELINE)},'validation':validation,'headline_overall':overall,'by_stage':by_stage,'by_case':by_case,'comparison':comparison,'resource_comparison_matched22':resource_comparison,'investigation_headline':act,'investigation_by_stage':act_stage,'budget_impact':budget,'formal_contract_addendum_proposal':addendum,'failure_analysis':{'gold_steps_without_aligned_claim':sum(r['failure_diagnostics']['gold_steps_without_aligned_claim'] for r in rows),'incomplete_behavior_steps':sum(r['failure_diagnostics']['incomplete_behavior_steps'] for r in rows),'missing_adjacent_causal_edges':sum(r['failure_diagnostics']['missing_adjacent_causal_edges'] for r in rows),'unsupported_or_nearby_slots':sum(r['failure_diagnostics']['unsupported_or_nearby_slots'] for r in rows),'wrong_component_slots':sum(r['failure_diagnostics']['wrong_component_slots'] for r in rows),'interpretation':'Long-chain runs often recover the central process lineage but omit the 8443 pivot or collapse 8080/8443 into one claim. Word cases frequently substitute normal.dotm, VBA modules, registry, API-call, or temporary-file activity for the Gold document-open edge. Nearby telemetry is therefore a major precision and causal-order failure mode.'},'audit_inventory':inventory,'rows':rows}
    OUT.mkdir(parents=False); (OUT/'formal_scores.json').write_text(json.dumps(result,ensure_ascii=False,indent=2)+'\n',encoding='utf-8'); (OUT/'per_run_scores.jsonl').write_text(''.join(json.dumps(r,ensure_ascii=False,sort_keys=True)+'\n' for r in rows),encoding='utf-8'); (OUT/'audit_inventory_24.json').write_text(json.dumps(inventory,ensure_ascii=False,indent=2)+'\n',encoding='utf-8'); (OUT/'cross_field_consistency_audit.json').write_text(json.dumps(validation,ensure_ascii=False,indent=2)+'\n',encoding='utf-8'); (OUT/'semantic_alignment_decisions.json').write_text(json.dumps(A,ensure_ascii=False,indent=2)+'\n',encoding='utf-8'); (OUT/'formal_contract_addendum_proposal.json').write_text(json.dumps(addendum,ensure_ascii=False,indent=2)+'\n',encoding='utf-8')
    REPORT_JSON.write_text(json.dumps(result,ensure_ascii=False,indent=2)+'\n',encoding='utf-8')
    def f(b,n): x=b[n]; return f"{x['hits']}/{x['denominator']} = {x['value']:.2%}" if x['value'] is not None else 'N/A'
    lines=['# gpt-5.5 Attack8 budget10 独立Codex正式採点（2026-08-03）','','Reviewer: Codex gpt-5.6-sol。OpenAI judge API/API scorerは不使用。budget-censored 2件は凍結保持し、headline精度から除外した。','','## Headline（22 PASS）','','| Model（matched 22 strata） | Action recall | Candidate precision | Behavior-step recall | Critical evidence | Order recall |','|---|---:|---:|---:|---:|---:|']
    for m,b in comparison['matched_22_strata'].items(): lines.append(f"| {m} | {f(b,'action_recall')} | {f(b,'candidate_precision')} | {f(b,'behavior_step_recall')} | {f(b,'critical_evidence_recall')} | {f(b,'order_recall')} |")
    lines += ['','## gpt-5.5 Stage別','','| Stage | Action | Precision | Behavior | Critical | Order |','|---|---:|---:|---:|---:|---:|']
    for s,b in by_stage.items(): lines.append(f"| {s} | {f(b,'action_recall')} | {f(b,'candidate_precision')} | {f(b,'behavior_step_recall')} | {f(b,'critical_evidence_recall')} | {f(b,'order_recall')} |")
    lines += ['','## 監査・budget影響',f"- cross-field status: **{validation['status']}**。22 score rows / 24 audit inventory、Action {validation['gold_action_items_checked']}、candidate {validation['candidate_slots_checked']}、behavior/critical {validation['behavior_steps_checked']}、order {validation['order_pairs_checked']}。",f"- Gold=1/TPなし {validation['gold1_without_tp']}、TP/Gold=0 {validation['tp_without_gold1']}、duplicate TP {validation['duplicate_tp']}。",f"- 除外: `{sorted(EXCLUDED)[0]}`、`{sorted(EXCLUDED)[1]}`。除外2件のcost ${budget['excluded_cost_usd']:.6f}、tokens {budget['excluded_usage']['total_tokens']:,}。",f"- soft-triggered non-censored: {budget['soft_triggered_non_censored_count']}件（headlineに含む）。Gold分母はAction -48、Behavior/Critical -16、Order -14。",'','## 調査行動（headline 22）',f"- API calls {act['api_calls']:,}、Chief leads {act['lead_call_count']:,} / unique {act['unique_lead_count']:,}、Investigator questions {act['investigator_question_count']:,}、SQL queries {act['sql_query_count']:,}。",f"- input/output/cached tokens: {act['input_tokens']:,} / {act['output_tokens']:,} / {act['cached_input_tokens']:,}、cost ${act['cost_usd']:.6f}、elapsed {act['elapsed_seconds']:.3f}s。",'','## 失敗分析',f"- Gold step無整合claim {result['failure_analysis']['gold_steps_without_aligned_claim']}、不完全Behavior step {result['failure_analysis']['incomplete_behavior_steps']}、隣接因果edge欠落 {result['failure_analysis']['missing_adjacent_causal_edges']}。",f"- nearby/unsupported slots {result['failure_analysis']['unsupported_or_nearby_slots']}、wrong-component slots {result['failure_analysis']['wrong_component_slots']}。",f"- {result['failure_analysis']['interpretation']}",'','## Formal contract追記案']
    lines += [f"- {x}" for x in addendum['proposed_clauses']]
    lines += ['','全run/Gold hash、全Gold item、candidate slot、order pair、固定分母、totals、モデル/Stage/ケース別比較はscore rootと報告JSONに記録した。']
    REPORT_MD.write_text('\n'.join(lines)+'\n',encoding='utf-8')
    print(json.dumps({'status':'pass','headline_overall':overall,'validation':validation,'budget_impact':budget},ensure_ascii=False,indent=2))
if __name__=='__main__': main()
