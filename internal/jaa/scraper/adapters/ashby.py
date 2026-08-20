"""Ashby public job-board API adapter for configured UK employers."""
from __future__ import annotations
from typing import Any, Iterable
from .base import Adapter, USER_AGENT, contracts_now, http_get_json, register
from .uk_common import matches_terms, plain_text, salary_text, uk_or_eligible_remote
from contracts import JobUrl, RawPosting

API = "https://api.ashbyhq.com/posting-api/job-board/{account}"

@register
class AshbyAdapter(Adapter):
    board = "ashby"
    def __init__(self,*a:Any,**kw:Any)->None:
        super().__init__(*a,**kw); self._jobs:dict[str,dict[str,Any]]={}
    def _discover_live(self, terms:list[str])->Iterable[JobUrl]:
        cfg=self._board_config(); accounts=cfg.get("companies") or {}
        for account,company in accounts.items():
            try:
                data=http_get_json(API.format(account=account),params={"includeCompensation":"true"},headers={"User-Agent":USER_AGENT},timeout=float(cfg.get("timeout_seconds",30)))
            except Exception as exc:
                print(f"[ashby] {account} failed: {exc}"); continue
            for job in data.get("jobs",[]):
                location=" ".join([str(job.get("location") or "")]+[str(x.get("location") or "") for x in job.get("secondaryLocations",[])])
                if not job.get("isListed",True) or not uk_or_eligible_remote(location,remote=bool(job.get("isRemote")),body=job.get("descriptionPlain")): continue
                if not matches_terms([job.get("title"),job.get("descriptionPlain"),job.get("department"),job.get("team")],terms): continue
                jid=f"{account}:{job.get('id')}"; row=dict(job); row["company"]=str(company); row["location_text"]=location; row["content_text"]=plain_text(job.get("descriptionHtml") or job.get("descriptionPlain")); row["salary_text"]=salary_text((job.get("compensation") or {}).get("compensationTierSummary")); self._jobs[jid]=row
                yield JobUrl(self.board,jid,str(job.get("jobUrl") or ""),str(job.get("publishedAt") or "") or None)
    def _fetch_live(self,j:JobUrl)->RawPosting:
        row=self._jobs[j.job_id]; return RawPosting(self.board,j.job_id,j.url,contracts_now(),raw_json=row)
