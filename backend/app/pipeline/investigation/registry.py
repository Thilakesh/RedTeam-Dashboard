"""Adapter registry — maps tool name to InvestigationAdapter instance.

Real adapters land in M-Vuln-9 steps 6-9; until then the placeholder runs.
Replace each entry as the adapter is added.
"""
from __future__ import annotations

from app.pipeline.investigation.adapters.dirsearch import DirsearchAdapter
from app.pipeline.investigation.adapters.ffuf import FfufAdapter
from app.pipeline.investigation.adapters.nmap_deep import NmapDeepAdapter
from app.pipeline.investigation.adapters.testssl import TestSslAdapter
from app.pipeline.investigation.stage import InvestigationAdapter

ADAPTERS: dict[str, InvestigationAdapter] = {
    "nmap_deep": NmapDeepAdapter(),
    "ffuf": FfufAdapter(),
    "dirsearch": DirsearchAdapter(),
    "testssl": TestSslAdapter(),
}


def get_adapter(tool: str) -> InvestigationAdapter | None:
    return ADAPTERS.get(tool)
