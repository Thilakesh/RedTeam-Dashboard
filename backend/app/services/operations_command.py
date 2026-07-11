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
  flag (argv, no shell). It also resolves the host through
  ``app.services.net_guard.assert_target_allowed`` to block loopback,
  link-local/cloud-metadata, and this platform's own service containers.
- ``validate_custom_args`` delegates to ``app.services.tool_args`` — an
  allow-list (not deny-list) of tuning flags per tool, which also rejects
  bare positional tokens (blocking a second injected target/URL). The same
  allow-list is enforced again inside ``scan_profiles.resolve_args`` at
  actual execution time, so this check is belt-and-suspenders, not the only
  gate.
Commands are always argv lists passed to ``create_subprocess_exec`` (never a
shell) — there is no shell-injection surface.
"""
from __future__ import annotations

import ipaddress

from app.services.net_guard import DOMAIN_RE as _DOMAIN_RE
from app.services.net_guard import assert_target_allowed
from app.services.scan_profiles import PROFILES, resolve_args
from app.services.tool_args import validate_custom_args as _validate_custom_args_allowlist

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
        assert_target_allowed(host)
        return host
    if target_type == "ipv4":
        try:
            ip = ipaddress.IPv4Address(host)
        except ipaddress.AddressValueError:
            raise ValueError("invalid IPv4 address")
        assert_target_allowed(str(ip))
        return str(ip)
    raise ValueError("target_type must be 'domain' or 'ipv4'")


def validate_custom_args(tool: str, profile: str | None, custom_args: str | None) -> None:
    """Raise ValueError on a non-allow-listed flag. No-op unless profile == 'custom'."""
    if profile != "custom":
        return
    _validate_custom_args_allowlist(tool, custom_args)


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
