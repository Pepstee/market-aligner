"""Jooble REST API adapter, enabled when JOOBLE_API_KEY is configured."""
from __future__ import annotations
import os
from typing import Any,Iterable
from .base import Adapter,SourceUnavailable,USER_AGENT,contracts_now,register
from .uk_common import plain_text
from market_aligner.domain.contracts import JobUrl,RawPosting

@register
class JoobleAdapter(Adapter):
    board="jooble"
    def __init__(self,*a:Any,**kw:Any)->None:super().__init__(*a,**kw);self._jobs={}
    def _key(self)->str:
        cfg=self._board_config(); key=os.getenv(str(cfg.get("api_key_env","JOOBLE_API_KEY")),"").strip()
        if not key: raise SourceUnavailable("Jooble skipped: set JOOBLE_API_KEY")
        return key
    def _discover_live(self,terms:list[str])->Iterable[JobUrl]:
        import requests
        cfg=self._board_config(); key=self._key(); seen=set()
        for query in list(cfg.get("queries") or terms):
            page=1
            while True:
                resp=requests.post(f"https://jooble.org/api/{key}",json={"keywords":query,"location":"United Kingdom","page":str(page),"ResultOnPage":"100"},headers={"Content-Type":"application/json"},timeout=float(cfg.get("timeout_seconds",30)));resp.raise_for_status();data=resp.json();jobs=list(data.get("jobs") or [])
                for job in jobs:
                    jid=str(job.get("id") or "");
                    if not jid or jid in seen:continue
                    seen.add(jid);self._jobs[jid]=dict(job);yield JobUrl(self.board,jid,str(job.get("link") or ""),str(job.get("updated") or "") or None)
                if not jobs or page*100>=int(data.get("totalCount") or 0):break
                page+=1
    def _fetch_live(self,j:JobUrl)->RawPosting:
        import requests
        row=dict(self._jobs[j.job_id]); text=plain_text(row.get("snippet"))
        try:
            resp=requests.get(j.url,headers={"User-Agent":USER_AGENT},timeout=30);resp.raise_for_status();full=plain_text(resp.text)
            if len(full)>len(text):text=full
        except Exception:pass
        row["content_text"]=text;row["location_text"]=str(row.get("location") or "");return RawPosting(self.board,j.job_id,j.url,contracts_now(),raw_text=text,raw_json=row)
