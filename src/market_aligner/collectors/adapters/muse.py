"""The Muse public Jobs API adapter."""
from __future__ import annotations
from typing import Any,Iterable
from .base import Adapter,USER_AGENT,contracts_now,http_get_json,register
from .uk_common import matches_terms,plain_text,uk_or_eligible_remote
from market_aligner.domain.contracts import JobUrl,RawPosting

API="https://www.themuse.com/api/public/jobs"
@register
class MuseAdapter(Adapter):
    board="muse"
    def __init__(self,*a:Any,**kw:Any)->None: super().__init__(*a,**kw); self._jobs={}
    def _discover_live(self,terms:list[str])->Iterable[JobUrl]:
        cfg=self._board_config(); page=1
        while True:
            data=http_get_json(API,params={"page":page,"category":str(cfg.get("category","Computer and IT")),"location":"London, United Kingdom"},headers={"User-Agent":USER_AGENT},timeout=float(cfg.get("timeout_seconds",30)))
            jobs=list(data.get("results") or [])
            for job in jobs:
                loc="; ".join(str(x.get("name") or "") for x in job.get("locations",[])); body=job.get("contents")
                if not uk_or_eligible_remote(loc,remote="remote" in loc.casefold(),body=body): continue
                if not matches_terms([job.get("name"),body,job.get("categories")],terms): continue
                jid=str(job.get("id")); row=dict(job); row["company"]=str((job.get("company") or {}).get("name") or ""); row["location_text"]=loc; row["content_text"]=plain_text(body); self._jobs[jid]=row
                yield JobUrl(self.board,jid,str((job.get("refs") or {}).get("landing_page") or ""),str(job.get("publication_date") or "") or None)
            if not jobs or page>=int(data.get("page_count") or 0): break
            page+=1
    def _fetch_live(self,j:JobUrl)->RawPosting: return RawPosting(self.board,j.job_id,j.url,contracts_now(),raw_json=self._jobs[j.job_id])
