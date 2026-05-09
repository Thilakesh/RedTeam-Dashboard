from app.pipeline.vuln.adapters.cpe_matcher import CpeMatcherStage
from app.pipeline.vuln.adapters.nuclei_safe import NucleiSafeStage
from app.pipeline.vuln.adapters.panel_detector import PanelDetectorStage

VULN_PROFILES: dict[str, list] = {
    "vuln_quick": [CpeMatcherStage(), PanelDetectorStage(), NucleiSafeStage()],
    "vuln_standard": [CpeMatcherStage(), PanelDetectorStage(), NucleiSafeStage()],
    "vuln_deep": [CpeMatcherStage(), PanelDetectorStage(), NucleiSafeStage()],
}


def vuln_stages_for(profile: str) -> list:
    if profile not in VULN_PROFILES:
        raise ValueError(f"unknown vuln profile: {profile}")
    return list(VULN_PROFILES[profile])
