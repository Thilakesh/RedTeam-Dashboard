"""Command rendering + input validation for standalone Operations.

Operations own their command building so the console is decoupled from the
investigation adapters. ``render_command`` reproduces the EXACT argv shape each
adapter builds (verified against
``pipeline/investigation/adapters/{nmap_deep,ffuf,dirsearch,testssl}.py``) using
placeholder tokens, so the previewed/stored command equals what the worker runs
(the worker calls the same adapters with the same profile args).

Security:
- ``validate_target`` is an allowlist (domain / IPv4) that rejects argument
  injection — a host like ``-oN`` would otherwise be parsed by the tool as a
  flag (argv, no shell).
- ``validate_custom_args`` denies output/file-redirection flags per tool.
Commands are always argv lists passed to ``create_subprocess_exec`` (never a
shell) — there is no shell-injection surface.
"""
from __future__ import annotations

import ipaddress
import re
import shlex

from app.services.scan_profiles import PROFILES, resolve_args

TOOLS: set[str] = {"nmap_deep", "ffuf", "dirsearch", "testssl"}

WORDLIST_TOKEN = "$INVESTIGATION_WORDLIST"
OUTPUT_TOKEN = "<tmp>"

# Mirror of each adapter's fallback when resolve_args returns [] (e.g. custom
# profile with empty args). Keeps preview == execution.
_DEFAULT_ARGS: dict[str, list[str]] = {
    "nmap_deep": ["-A", "-T4", "-Pn"],
    "ffuf": [
        "-mc", "200,204,301,302,307,308,400,401,403,405,500,502,503",
        "-t", "40",
        "-timeout", "10",
    ],
    "dirsearch": ["-t", "20"],
    "testssl": ["--protocols", "--server-defaults", "--vulnerable", "-E"],
}

# Output / file-redirection flags an analyst may not pass via custom args.
_DENYLIST: dict[str, set[str]] = {
    "nmap_deep": {
        "-on", "-og", "-ox", "-oa", "-os", "--stylesheet",
        "-il", "--script-args-file", "--resume", "--datadir",
    },
    "ffuf": {"-o", "-od", "-debug-log", "-or"},
    "dirsearch": {"-o", "--output", "--config", "-l", "--urls-file"},
    "testssl": {
        "--jsonfile", "--jsonfile-pretty", "--logfile", "--csvfile",
        "--htmlfile", "--file", "-il", "-oa",
    },
}

_DOMAIN_RE = re.compile(
    r"^(?=.{1,253}$)([a-z0-9]([a-z0-9-]{0,61}[a-z0-9])?\.)+[a-z]{2,63}$"
)


def _norm_protocol(protocol: str | None) -> str:
    p = (protocol or "https").lower()
    return p if p in ("http", "https") else "https"


def validate_target(target_type: str, target: str) -> str:
    """Return a normalized lowercased host, or raise ValueError.

    Allowlist only — anything starting with '-', containing whitespace, or
    holding shell/flag metacharacters fails the regex / ip parse and is rejected.
    """
    if not isinstance(target, str):
        raise ValueError("target must be a string")
    host = target.strip().lower()
    if not host:
        raise ValueError("target is required")
    if host.startswith("-"):
        raise ValueError("target may not start with '-'")
    if any(c.isspace() for c in host):
        raise ValueError("target may not contain whitespace")

    if target_type == "domain":
        if not _DOMAIN_RE.match(host):
            raise ValueError("invalid domain")
        return host
    if target_type == "ipv4":
        try:
            ip = ipaddress.IPv4Address(host)
        except ipaddress.AddressValueError:
            raise ValueError("invalid IPv4 address")
        return str(ip)
    raise ValueError("target_type must be 'domain' or 'ipv4'")


def validate_custom_args(tool: str, profile: str | None, custom_args: str | None) -> None:
    """Raise ValueError on a denylisted flag. No-op unless profile == 'custom'."""
    if profile != "custom":
        return
    raw = custom_args or ""
    if not raw.strip():
        return
    try:
        tokens = shlex.split(raw)
    except ValueError:
        raise ValueError("custom args could not be parsed")
    denied = _DENYLIST.get(tool, set())
    for tok in tokens:
        flag = tok.split("=", 1)[0].lower()
        if flag in denied:
            raise ValueError(f"flag '{flag}' is not permitted in custom args for {tool}")


def _resolve_args(tool: str, profile: str | None, custom_args: str | None) -> list[str]:
    args = resolve_args(tool, {"profile": profile, "custom_args": custom_args})
    return args or list(_DEFAULT_ARGS[tool])


def render_command(
    tool: str,
    host: str,
    *,
    profile: str | None,
    protocol: str | None,
    custom_args: str | None,
) -> str:
    """Human-readable command string == the argv the adapter executes."""
    if tool not in TOOLS:
        raise ValueError(f"unknown tool: {tool}")
    binary = PROFILES[tool]["binary"]
    args = _resolve_args(tool, profile, custom_args)
    proto = _norm_protocol(protocol)

    if tool == "nmap_deep":
        parts = [binary, *args, "-oX", OUTPUT_TOKEN, host]
    elif tool == "ffuf":
        url = f"{proto}://{host}/FUZZ"
        parts = [
            binary, "-u", url, "-w", WORDLIST_TOKEN, *args,
            "-of", "json", "-o", OUTPUT_TOKEN, "-noninteractive",
        ]
    elif tool == "dirsearch":
        url = f"{proto}://{host}"
        parts = [
            binary, "-u", url, "-w", WORDLIST_TOKEN,
            "--format=json", "-o", OUTPUT_TOKEN, "--quiet-mode", "--no-color", *args,
        ]
    else:  # testssl
        parts = [
            binary, "--quiet", "--color", "0", "--jsonfile", OUTPUT_TOKEN,
            *args, f"{host}:443",
        ]
    return " ".join(parts)
