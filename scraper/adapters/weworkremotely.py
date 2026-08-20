"""We Work Remotely's official public RSS feed."""
from __future__ import annotations
import hashlib,xml.etree.ElementTree as ET
from typing import Any,Iterable
from .base import Adapter,USER_AGENT,contracts_now,register
from .uk_common import matches_terms,plain_text,uk_or_eligible_remote
from contracts import JobUrl,RawPosting

RSS="https://weworkremotely.com/remote-jobs.rss"
@register
class WeWorkRemotelyAdapter(Adapter):
    board="weworkremotely"
    def __init__(self,*a:Any,**kw:Any)->None: super().__init__(*a,**kw); self._jobs={}
    def _discover_live(self,terms:list[str])->Iterable[JobUrl]:
        import requests
        cfg=self._board_config(); resp=requests.get(RSS,headers={"User-Agent":USER_AGENT},timeout=float(cfg.get("timeout_seconds",30))); resp.raise_for_status(); root=ET.fromstring(resp.content)
        for item in root.findall(".//item"):
            def val(name:str)->str:return str(item.findtext(name) or "").strip()
            title=val("title"); body=val("description"); region=val("region"); url=val("link") or val("guid")
            if not uk_or_eligible_remote(region,remote=True,body=body): continue
            if not matches_terms([title,body,val("skills"),val("category")],terms): continue
            jid=hashlib.sha1((val("guid") or url).encode()).hexdigest(); company=title.split(":",1)[0] if ":" in title else ""; row={"title":title.split(":",1)[-1].strip(),"company":company,"location_text":region or "Remote","content_text":plain_text(body),"description":body,"category":val("category"),"skills":val("skills"),"expires_at":val("expires_at"),"source_attribution":"We Work Remotely"}; self._jobs[jid]=row
            yield JobUrl(self.board,jid,url,val("pubDate") or None)
    def _fetch_live(self,j:JobUrl)->RawPosting:return RawPosting(self.board,j.job_id,j.url,contracts_now(),raw_json=self._jobs[j.job_id])
