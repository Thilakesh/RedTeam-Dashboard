from app.pipeline.vuln.adapters.ai_triage import AiTriageStage
from app.pipeline.vuln.adapters.correlator import CorrelatorStage
from app.pipeline.vuln.adapters.cpe_matcher import CpeMatcherStage
from app.pipeline.vuln.adapters.default_creds_matcher import DefaultCredsMatcherStage
from app.pipeline.vuln.adapters.katana import KatanaStage
from app.pipeline.vuln.adapters.nmap_nse_vuln import NmapNseVulnStage
from app.pipeline.vuln.adapters.nuclei_safe import NucleiSafeStage
from app.pipeline.vuln.adapters.panel_detector import PanelDetectorStage
from app.pipeline.vuln.adapters.testssl import TestsslStage


def _prune_deps(stages: list) -> list:
    """Filter each stage's depends_on to only stages actually in the profile.

    Stages declare their full possible deps for clarity, but profile-time
    composition may omit some (e.g. quick profile skips correlator). The
    coordinator errors on unknown deps, so prune here.
    """
    names = {s.name for s in stages}
    for s in stages:
        s.depends_on = [d for d in s.depends_on if d in names]
    return stages


def _quick():
    return _prune_deps([
        CpeMatcherStage(),
        PanelDetectorStage(),
        DefaultCredsMatcherStage(),
        NucleiSafeStage(),
    ])


def _standard():
    return _prune_deps([
        CpeMatcherStage(),
        PanelDetectorStage(),
        DefaultCredsMatcherStage(),
        NucleiSafeStage(),
        TestsslStage(),
        NmapNseVulnStage(),
        CorrelatorStage(),
        AiTriageStage(),
    ])


def _deep():
    return _prune_deps([
        CpeMatcherStage(),
        PanelDetectorStage(),
        DefaultCredsMatcherStage(),
        NucleiSafeStage(),
        TestsslStage(),
        NmapNseVulnStage(),
        KatanaStage(),
        CorrelatorStage(),
        AiTriageStage(),
    ])


_BUILDERS = {
    "vuln_quick": _quick,
    "vuln_standard": _standard,
    "vuln_deep": _deep,
}


def vuln_stages_for(profile: str) -> list:
    if profile not in _BUILDERS:
        raise ValueError(f"unknown vuln profile: {profile}")
    # New instances each call so depends_on mutations don't leak.
    return _BUILDERS[profile]()
