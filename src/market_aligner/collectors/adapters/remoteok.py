"""Remote OK official JSON feed with UK eligibility filtering."""
from __future__ import annotations
from typing import Any,Iterable
from .base import Adapter,USER_AGENT,contracts_now,http_get_json,register
from .uk_common import matches_terms,plain_text,uk_or_eligible_remote
from market_aligner.domain.contracts import JobUrl,RawPosting

API="https://remoteok.com/api"
@register
class RemoteOKAdapter(Adapter):
    board="remoteok"
    def __init__(self,*a:Any,**kw:Any)->None: super().__init__(*a,**kw); self._jobs={}
    def _discover_live(self,terms:list[str])->Iterable[JobUrl]:
        cfg=self._board_config(); rows=http_get_json(API,headers={"User-Agent":USER_AGENT,"Accept":"application/json"},timeout=float(cfg.get("timeout_seconds",30)))
        for job in rows if isinstance(rows,list) else []:
            jid=str(job.get("id") or "").strip(); body=job.get("description"); loc=job.get("location") or ""
            if not jid or not job.get("position") or not job.get("url"): continue
            if not uk_or_eligible_remote(loc,remote=True,body=body): continue
            if not matches_terms([job.get("position"),body,job.get("tags")],terms): continue
            row=dict(job); row["title"]=str(job.get("position") or ""); row["company"]=str(job.get("company") or ""); row["location_text"]=str(loc or "Remote"); row["content_text"]=plain_text(body); row["source_attribution"]="Remote OK"; self._jobs[jid]=row
            yield JobUrl(self.board,jid,str(job.get("url")),str(job.get("date") or job.get("epoch") or "") or None)
    def _fetch_live(self,j:JobUrl)->RawPosting:return RawPosting(self.board,j.job_id,j.url,contracts_now(),raw_json=self._jobs[j.job_id])
