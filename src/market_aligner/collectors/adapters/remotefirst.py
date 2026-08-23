"""Remote First Jobs official public skill/category RSS feeds."""
from __future__ import annotations
import hashlib,xml.etree.ElementTree as ET
from typing import Any,Iterable
from .base import Adapter,USER_AGENT,contracts_now,register
from .uk_common import matches_terms,plain_text,uk_or_eligible_remote
from market_aligner.domain.contracts import JobUrl,RawPosting

@register
class RemoteFirstAdapter(Adapter):
    board="remotefirst"
    def __init__(self,*a:Any,**kw:Any)->None:super().__init__(*a,**kw);self._jobs={}
    def _discover_live(self,terms:list[str])->Iterable[JobUrl]:
        import requests
        cfg=self._board_config();seen=set()
        for slug in list(cfg.get("feeds") or ["ai","python","data-science","devops","cybersecurity","software-development","entry-level"]):
            try:
                resp=requests.get(f"https://remotefirstjobs.com/rss/jobs/{slug}.rss",headers={"User-Agent":USER_AGENT},timeout=float(cfg.get("timeout_seconds",30)));resp.raise_for_status();root=ET.fromstring(resp.content)
            except Exception as exc:print(f"[remotefirst] {slug} failed: {exc}");continue
            for item in root.findall(".//item"):
                title=str(item.findtext("title") or "");body=str(item.findtext("description") or "");url=str(item.findtext("link") or "");guid=str(item.findtext("guid") or url)
                if guid in seen or not uk_or_eligible_remote("",remote=True,body=body):continue
                if not matches_terms([title,body],terms):continue
                seen.add(guid);jid=hashlib.sha1(guid.encode()).hexdigest();company=title.rsplit(" at ",1)[-1] if " at " in title else "";position=title.rsplit(" at ",1)[0];row={"title":position,"company":company,"location_text":"Remote — UK/Europe/worldwide eligible","content_text":plain_text(body),"description":body,"source_attribution":"Remote First Jobs"};self._jobs[jid]=row
                yield JobUrl(self.board,jid,url,str(item.findtext("pubDate") or "") or None)
    def _fetch_live(self,j:JobUrl)->RawPosting:return RawPosting(self.board,j.job_id,j.url,contracts_now(),raw_json=self._jobs[j.job_id])
