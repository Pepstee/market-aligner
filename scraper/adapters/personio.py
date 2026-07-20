"""Personio public XML career-feed adapter."""
from __future__ import annotations
import xml.etree.ElementTree as ET
from typing import Any,Iterable
from .base import Adapter,USER_AGENT,contracts_now,register
from .uk_common import matches_terms,plain_text,uk_or_eligible_remote
from contracts import JobUrl,RawPosting

def _text(node:ET.Element,name:str)->str: return str(node.findtext(name) or "").strip()

@register
class PersonioAdapter(Adapter):
    board="personio"
    def __init__(self,*a:Any,**kw:Any)->None: super().__init__(*a,**kw); self._jobs={}
    def _discover_live(self,terms:list[str])->Iterable[JobUrl]:
        import requests
        cfg=self._board_config()
        for host,company in (cfg.get("companies") or {}).items():
            try:
                resp=requests.get(f"https://{host}/xml",params={"language":"en"},headers={"User-Agent":USER_AGENT},timeout=float(cfg.get("timeout_seconds",30))); resp.raise_for_status(); root=ET.fromstring(resp.content)
            except Exception as exc: print(f"[personio] {host} failed: {exc}"); continue
            for pos in root.findall(".//position"):
                sections=[]
                for sec in pos.findall("./jobDescriptions/jobDescription"):
                    sections.append(f"{_text(sec,'name')}\n{_text(sec,'value')}")
                body="\n".join(sections); loc=" ".join(filter(None,[_text(pos,"office"),_text(pos,"subcompany")]))
                if not uk_or_eligible_remote(loc,remote="remote" in loc.casefold(),body=body): continue
                if not matches_terms([_text(pos,"name"),body,_text(pos,"keywords"),_text(pos,"department")],terms): continue
                native=_text(pos,"id"); jid=f"{host}:{native}"; url=f"https://{host}/job/{native}?language=en"; row={c.tag:c.text for c in pos if c.tag!="jobDescriptions"}; row.update(company=str(company),location_text=loc,content_text=plain_text(body),description_sections=sections); self._jobs[jid]=row
                yield JobUrl(self.board,jid,url,_text(pos,"createdAt") or None)
    def _fetch_live(self,j:JobUrl)->RawPosting: return RawPosting(self.board,j.job_id,j.url,contracts_now(),raw_json=self._jobs[j.job_id])
