"""Predefined scan profiles per investigation tool.

Each profile is a named arg list the adapter inserts into the subprocess
command. Adapters always supply the binary + output redirection + target
themselves — profiles only carry the scan-shape arguments.

Custom command flow: when ``params.profile == "custom"`` the adapter reads
``params.custom_args`` (a string) and shlex-splits it as the arg list. This is
safe against shell injection because we never use ``shell=True`` — the args
are passed as a list to ``asyncio.create_subprocess_exec``.

Frontend uses ``PROFILES[tool]`` to populate the profile dropdown and the
``preview`` field to render the editable command preview.
"""
from __future__ import annotations

from typing import TypedDict


class ProfileSpec(TypedDict):
    id: str
    label: str
    args: list[str]
    description: str


class ToolProfileBundle(TypedDict):
    binary: str
    default: str
    profiles: list[ProfileSpec]


PROFILES: dict[str, ToolProfileBundle] = {
    "nmap_deep": {
        "binary": "nmap",
        "default": "aggressive",
        "profiles": [
            {
                "id": "quick",
                "label": "Quick Scan",
                "args": ["-F", "-T4", "-Pn"],
                "description": "Fast scan of the 100 most common ports.",
            },
            {
                "id": "deep",
                "label": "Deep Scan",
                "args": ["-sV", "-sC", "-Pn"],
                "description": "Service + version detection with default scripts.",
            },
            {
                "id": "aggressive",
                "label": "Aggressive Scan",
                "args": ["-A", "-T4", "-Pn"],
                "description": "OS + version + scripts + traceroute (`-A`).",
            },
            {
                "id": "full_port",
                "label": "Full Port Scan",
                "args": ["-p-", "-T4", "-Pn"],
                "description": "All 65535 TCP ports.",
            },
            {
                "id": "vuln",
                "label": "Vulnerability Scan",
                "args": ["--script", "vuln", "-sV", "-T4", "-Pn"],
                "description": "NSE `vuln` category against discovered services.",
            },
            {
                "id": "custom",
                "label": "Custom",
                "args": [],
                "description": "Provide your own nmap args.",
            },
        ],
    },
    "ffuf": {
        "binary": "ffuf",
        "default": "quick",
        "profiles": [
            {
                "id": "quick",
                "label": "Quick Fuzz",
                "args": [
                    "-mc", "200,204,301,302,307,308,400,401,403,405,500,502,503",
                    "-t", "40",
                    "-timeout", "10",
                ],
                "description": "Single-pass directory fuzz with broad match codes.",
            },
            {
                "id": "recursive",
                "label": "Recursive Fuzz",
                "args": [
                    "-mc", "200,204,301,302,307,308,400,401,403,405,500,502,503",
                    "-recursion",
                    "-recursion-depth", "2",
                    "-t", "40",
                    "-timeout", "10",
                ],
                "description": "Recurse into discovered directories (depth 2).",
            },
            {
                "id": "api",
                "label": "API Discovery",
                "args": [
                    "-mc", "200,201,204,400,401,403,405,500",
                    "-t", "40",
                    "-timeout", "10",
                ],
                "description": "Match codes biased toward API-style responses.",
            },
            {
                "id": "custom",
                "label": "Custom",
                "args": [],
                "description": "Provide your own ffuf args.",
            },
        ],
    },
    "dirsearch": {
        "binary": "dirsearch",
        "default": "quick",
        "profiles": [
            {
                "id": "quick",
                "label": "Quick Scan",
                "args": ["-t", "20", "-e", "php,html,js"],
                "description": "Single-pass scan with common web extensions.",
            },
            {
                "id": "recursive",
                "label": "Recursive Scan",
                "args": ["-r", "-R", "3", "-t", "20"],
                "description": "Recurse 3 levels into discovered directories.",
            },
            {
                "id": "sensitive",
                "label": "Sensitive Files",
                "args": [
                    "-e", "bak,old,sql,zip,env,git,swp,backup,conf,key,pem,log",
                    "-t", "20",
                ],
                "description": "Extensions tuned for backup / config / key disclosure.",
            },
            {
                "id": "custom",
                "label": "Custom",
                "args": [],
                "description": "Provide your own dirsearch args.",
            },
        ],
    },
    "testssl": {
        "binary": "testssl.sh",
        "default": "full",
        "profiles": [
            {
                "id": "quick",
                "label": "Quick SSL Check",
                "args": ["--protocols", "--server-defaults"],
                "description": "Protocol matrix + server defaults only.",
            },
            {
                "id": "full",
                "label": "Full SSL Audit",
                "args": [
                    "--protocols",
                    "--server-defaults",
                    "--vulnerable",
                    "-E",
                ],
                "description": "Protocols + ciphers per protocol + CVE checks.",
            },
            {
                "id": "cipher",
                "label": "Cipher Enumeration",
                "args": ["-E"],
                "description": "Enumerate offered ciphers per protocol version.",
            },
            {
                "id": "custom",
                "label": "Custom",
                "args": [],
                "description": "Provide your own testssl.sh args.",
            },
        ],
    },
}


def get_profile(tool: str, profile_id: str | None) -> ProfileSpec | None:
    bundle = PROFILES.get(tool)
    if bundle is None:
        return None
    target_id = profile_id or bundle["default"]
    for p in bundle["profiles"]:
        if p["id"] == target_id:
            return p
    return None


def get_default_profile_id(tool: str) -> str | None:
    bundle = PROFILES.get(tool)
    return bundle["default"] if bundle else None


def list_profiles(tool: str) -> list[ProfileSpec]:
    bundle = PROFILES.get(tool)
    return bundle["profiles"] if bundle else []


def resolve_args(tool: str, params: dict) -> list[str]:
    """Return the arg list the adapter should use.

    Order of precedence:
      1. ``params.custom_args`` (string) when profile == "custom"
      2. profile.args when profile is a known id
      3. default profile's args
      4. empty list (adapter falls back to whatever it hardcodes)
    """
    import shlex

    profile_id = params.get("profile")
    if profile_id == "custom":
        custom = params.get("custom_args") or ""
        if isinstance(custom, str) and custom.strip():
            try:
                return shlex.split(custom)
            except ValueError:
                return []
        return []
    spec = get_profile(tool, profile_id)
    return list(spec["args"]) if spec else []
