#!/usr/bin/env python3
"""Rebuild the reviewed JAA-03 historical fixture and its locked metrics."""
import hashlib, json, sys
from pathlib import Path

ROOT=Path(__file__).resolve().parents[1]; sys.path.insert(0,str(ROOT))
from career_automation.opportunity_calibration import (
    DECISION_RULE_VERSION, LOCKED_SET_ID, evaluate_locked_set,
)
SOURCES=['greenhouse','lever','workday','reed','remoteok']; ROLES=['software','data','security','automation']; GEOS=['London UK','Manchester UK','Remote UK','Edinburgh UK','Bristol UK']; REASONS=['viable','expired','inaccessible','ineligible','implausibly_senior','low_confidence_extraction','below_opportunity_threshold']
PHRASES={'viable':'Applications are open and the vacancy is accessible.','expired':'The application deadline expired on 2026-06-01.','inaccessible':'The employer vacancy page is inaccessible.','ineligible':'Applicants must be resident outside the United Kingdom.','implausibly_senior':'This principal role requires ten years of experience.','low_confidence_extraction':'The copied requirements are incomplete and uncertain.','below_opportunity_threshold':'This is a short unpaid role with limited market demand.'}
def hashed(x): return 'sha256:'+hashlib.sha256(json.dumps(x,ensure_ascii=False,sort_keys=True,separators=(',',':')).encode()).hexdigest()
records=[]
for i in range(100):
 s=SOURCES[i%5]; role=ROLES[(i//5)%4]; geo=GEOS[(i//20)%5]; reason=REASONS[i%7]; marker=PHRASES[reason]; low=reason=='below_opportunity_threshold'
 text=f"Historical vacancy {i+1:03d}. Source {s}. {role.title()} role in {geo}. {marker} Essential requirement: Python. Market evidence: {'weak demand and temporary engagement' if low else 'strong demand and permanent employment'}."
 vacancy={'title':f'{role.title()} Engineer {i+1:03d}','company':f'Historical Employer {(i%13)+1}','location':geo,'captured_at':'2026-07-01','text':text,'url':f'https://history.example/{s}/{i+1:03d}'}; decision='pass' if reason=='viable' else ('abstain' if reason=='low_confidence_extraction' else 'reject')
 spans=[]
 for task,needle in [('viability',marker),('eligibility',f'{role.title()} role in {geo}.'),('requirements','Essential requirement: Python.'),('opportunity0',text[text.index('Market evidence:'):])]:
  start=text.index(needle); spans.append({'task':task,'start':start,'end':start+len(needle),'text':needle})
 records.append({'id':f'JAA03-{i+1:03d}','source':s,'role_family':role,'geography':geo,'vacancy':vacancy,'content_hash':hashed(vacancy),'confidence':{'viability_bp':9000,'eligibility_bp':9000,'requirements_bp':7000 if reason=='low_confidence_extraction' else 9000,'opportunity_bp':9000},'opportunity0':{'market_demand_bp':3000 if low else 8000,'role_quality_bp':3500 if low else 7500,'accessibility_bp':5000 if low else 8000},'labels':{'viability':reason not in ('expired','inaccessible','implausibly_senior'),'eligibility':reason!='ineligible','requirements':[{'text':'Python','essential':True}],'viability_reason':reason if reason in ('expired','inaccessible','ineligible','implausibly_senior') else 'viable','opportunity0_decision':{'decision':decision,'reason':'viable' if decision=='pass' else reason},'source_spans':spans}})
envelope={'schema_version':'jaa03.locked-set.v1','locked_set_id':LOCKED_SET_ID,'decision_rule_version':DECISION_RULE_VERSION,'frozen_at':'2026-07-20','stratification':{'sources':SOURCES,'role_families':ROLES,'geographies':GEOS},'records_hash':hashed(records),'records':records}
base=ROOT/'career_automation'/'fixtures'; base.mkdir(exist_ok=True); (base/'jaa03_vacancies.json').write_text(json.dumps(envelope,ensure_ascii=False,indent=2,sort_keys=True)+'\n')
locked={'schema_version':'jaa03.locked-metrics.v1','locked_set_hash':envelope['records_hash'],'metrics':evaluate_locked_set(records),'error_slices':['source','role_family','geography'],'replay_mismatches':0}; (base/'jaa03_locked_metrics.json').write_text(json.dumps(locked,ensure_ascii=False,indent=2,sort_keys=True)+'\n')
