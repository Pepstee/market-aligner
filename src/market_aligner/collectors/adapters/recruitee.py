"""Recruitee public Careers Site API adapter."""
from __future__ import annotations
from typing import Any,Iterable
from .base import Adapter,USER_AGENT,contracts_now,http_get_json,register
from .uk_common import matches_terms,plain_text,uk_or_eligible_remote
from market_aligner.domain.contracts import JobUrl,RawPosting

@register
class RecruiteeAdapter(Adapter):
    board="recruitee"
    def __init__(self,*a:Any,**kw:Any)->None: super().__init__(*a,**kw); self._jobs={}
    def _discover_live(self,terms:list[str])->Iterable[JobUrl]:
        cfg=self._board_config()
        for account,company in (cfg.get("companies") or {}).items():
            try:data=http_get_json(f"https://{account}.recruitee.com/api/offers/",headers={"User-Agent":USER_AGENT},timeout=float(cfg.get("timeout_seconds",30)))
            except Exception as exc: print(f"[recruitee] {account} failed: {exc}"); continue
            for job in data.get("offers",[]):
                loc=" ".join(filter(None,[str(job.get("location") or ""),str(job.get("city") or ""),str(job.get("country") or "")]))
                body=f"{job.get('description','')} {job.get('requirements','')}"
                if not uk_or_eligible_remote(loc,remote=bool(job.get("remote")),body=body): continue
                if not matches_terms([job.get("title"),body,job.get("department"),job.get("tags")],terms): continue
                jid=f"{account}:{job.get('id') or job.get('guid') or job.get('slug')}"; row=dict(job); row["company"]=str(company or job.get("company_name") or account); row["location_text"]=loc; row["content_text"]=plain_text(body); self._jobs[jid]=row
                yield JobUrl(self.board,jid,str(job.get("careers_url") or ""),str(job.get("published_at") or "") or None)
    def _fetch_live(self,j:JobUrl)->RawPosting: return RawPosting(self.board,j.job_id,j.url,contracts_now(),raw_json=self._jobs[j.job_id])
