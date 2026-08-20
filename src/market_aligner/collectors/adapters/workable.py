"""Workable's documented public published-jobs endpoint."""
from __future__ import annotations
from typing import Any,Iterable
from .base import Adapter,USER_AGENT,contracts_now,http_get_json,register
from .uk_common import matches_terms,plain_text,uk_or_eligible_remote
from market_aligner.domain.contracts import JobUrl,RawPosting

@register
class WorkableAdapter(Adapter):
    board="workable"
    def __init__(self,*a:Any,**kw:Any)->None: super().__init__(*a,**kw); self._jobs={}
    def owns(self,j:JobUrl)->bool:
        if not super().owns(j): return False
        account,separator,_shortcode=j.job_id.partition(":")
        return bool(separator and account in (self._board_config().get("companies") or {}))
    def _discover_live(self,terms:list[str])->Iterable[JobUrl]:
        cfg=self._board_config(); seen:set[str]=set()
        for account,company in (cfg.get("companies") or {}).items():
            try:data=http_get_json(f"https://www.workable.com/api/accounts/{account}",params={"details":"true"},headers={"User-Agent":USER_AGENT},timeout=float(cfg.get("timeout_seconds",30)))
            except Exception as exc: print(f"[workable] {account} failed: {exc}"); continue
            for job in data.get("jobs",[]):
                loc=" ".join(filter(None,[str(job.get("city") or ""),str(job.get("state") or ""),str(job.get("country") or "")]))
                if not uk_or_eligible_remote(loc,remote=bool(job.get("telecommuting")),body=job.get("description")): continue
                if not matches_terms([job.get("title"),job.get("description"),job.get("function"),job.get("department")],terms): continue
                jid=f"{account}:{job.get('shortcode')}"
                if jid in seen: continue
                seen.add(jid); row=dict(job); row["company"]=str(company or data.get("name") or account); row["location_text"]=loc; row["content_text"]=plain_text(job.get("description")); self._jobs[jid]=row
                yield JobUrl(self.board,jid,str(job.get("url") or job.get("shortlink") or ""),str(job.get("published_on") or "") or None)
    def _fetch_live(self,j:JobUrl)->RawPosting:
        if not self.owns(j): raise ValueError(f"configured Workable adapter does not own {j.key}")
        if j.job_id in self._jobs:
            row=self._jobs[j.job_id]
        else:
            account,_,shortcode=j.job_id.partition(":")
            cfg=self._board_config()
            data=http_get_json(f"https://www.workable.com/api/accounts/{account}",params={"details":"true"},headers={"User-Agent":USER_AGENT},timeout=float(cfg.get("timeout_seconds",30)),attempts=1)
            match=next((job for job in data.get("jobs",[]) if str(job.get("shortcode") or "")==shortcode),None)
            if match is None: raise LookupError(f"Workable vacancy is no longer published: {j.key}")
            row=dict(match); row["company"]=str((cfg.get("companies") or {}).get(account) or data.get("name") or account); row["location_text"]=" ".join(filter(None,[str(match.get("city") or ""),str(match.get("state") or ""),str(match.get("country") or "")])); row["content_text"]=plain_text(match.get("description"))
        return RawPosting(self.board,j.job_id,str(row.get("url") or row.get("shortlink") or j.url),contracts_now(),raw_json=row)
