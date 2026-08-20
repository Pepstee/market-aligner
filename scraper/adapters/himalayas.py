"""Himalayas public paginated remote-jobs search API."""
from __future__ import annotations
from typing import Any,Iterable
from .base import Adapter,USER_AGENT,contracts_now,http_get_json,register
from .uk_common import plain_text,uk_or_eligible_remote
from contracts import JobUrl,RawPosting

API="https://himalayas.app/jobs/api/search"
@register
class HimalayasAdapter(Adapter):
    board="himalayas"
    def __init__(self,*a:Any,**kw:Any)->None: super().__init__(*a,**kw); self._jobs={}
    def _discover_live(self,terms:list[str])->Iterable[JobUrl]:
        cfg=self._board_config(); queries=list(cfg.get("queries") or terms); seen=set()
        for query in queries:
            page=1
            while True:
                data=http_get_json(API,params={"q":query,"country":"GB","sort":"recent","page":page},headers={"User-Agent":USER_AGENT},timeout=float(cfg.get("timeout_seconds",30)))
                jobs=list(data.get("jobs") or [])
                for job in jobs:
                    gid=str(job.get("guid") or "")
                    if not gid or gid in seen: continue
                    restrictions=job.get("locationRestrictions") or []
                    if not uk_or_eligible_remote(" ".join(map(str,restrictions)),remote=True,body=job.get("description")): continue
                    seen.add(gid); row=dict(job); row["company"]=str(job.get("companyName") or ""); row["location_text"]="; ".join(map(str,restrictions)) or "Remote"; row["content_text"]=plain_text(job.get("description")); self._jobs[gid]=row
                    yield JobUrl(self.board,gid,str(job.get("applicationLink") or job.get("url") or ""),str(job.get("pubDate") or "") or None)
                if not jobs or page*int(data.get("limit") or 20)>=int(data.get("totalCount") or 0): break
                page+=1
    def _fetch_live(self,j:JobUrl)->RawPosting: return RawPosting(self.board,j.job_id,j.url,contracts_now(),raw_json=self._jobs[j.job_id])
