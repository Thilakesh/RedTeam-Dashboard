"""Allow-list validation for free-form custom tool arguments.

Predefined scan profiles never reach this module — their args come straight
from the trusted server-side ``scan_profiles.PROFILES`` table, selected by a
profile *id* the client cannot inject content into. This module only vets
the free-form ``custom_args`` string an analyst may supply when
``profile == "custom"``, on every path that can reach a subprocess: the
Operations console and investigation tasks alike (see
``scan_profiles.resolve_args``, the single choke point both paths call at
execution time).

Model: allow-list, not deny-list. A flag not explicitly listed here is
rejected. Bare positional tokens are always rejected — this is what blocks
injecting a second target/URL (e.g. a stray ``10.0.0.0/8`` or
``http://169.254.169.254/``). Flags that would let an analyst redirect
output, swap in an attacker-controlled wordlist, run arbitrary external
binaries (testssl's ``--openssl``), or proxy traffic are intentionally never
in the allow-list — none of the predefined profiles need them.
"""
from __future__ import annotations

import shlex

# Tuning flags a predefined profile does not already cover but an analyst
# may reasonably want on top of one. Deliberately excludes anything that
# executes external code, reads/writes files, or proxies traffic.
_ALLOWED_FLAGS: dict[str, set[str]] = {
    "nmap_deep": {
        "-T0", "-T1", "-T2", "-T3", "-T4", "-T5",
        "-F", "-Pn", "-sV", "-sC", "-A", "-p-",
        "-v", "-vv", "--reason", "--open",
        "--version-light", "--version-all",
        "-p", "--top-ports", "--min-rate", "--max-rate",
        "--min-parallelism", "--max-parallelism",
        "--host-timeout", "--scan-delay", "--max-retries",
        "--version-intensity",
    },
    "ffuf": {
        "-recursion", "-ac", "-sf",
        "-mc", "-fc", "-ms", "-fs", "-mr", "-fr",
        "-t", "-timeout", "-recursion-depth",
        "-maxtime", "-maxtime-job", "-p", "-rate",
    },
    "dirsearch": {
        "-r", "-f",
        "-t", "-e", "-R", "-i", "-x",
        "--max-time", "--delay", "--timeout",
    },
    "testssl": {
        "--protocols", "--server-defaults", "--vulnerable", "-E",
        "--heartbleed", "--ccs-injection", "--robot", "--breach",
        "--sweet32", "--freak", "--logjam", "--drown",
        "--fs", "--wide", "-6", "--ssl-native",
    },
}

# Flags whose next token is an opaque value (port, count, code list, ...),
# not itself checked as a flag or rejected as a bare positional. Values may
# not start with '-' — none of these tools need negative-number values, so
# that shape is more likely an attempt to smuggle a flag in as a "value".
_TAKES_VALUE: dict[str, set[str]] = {
    "nmap_deep": {
        "-p", "--top-ports", "--min-rate", "--max-rate",
        "--min-parallelism", "--max-parallelism", "--host-timeout",
        "--scan-delay", "--max-retries", "--version-intensity",
    },
    "ffuf": {
        "-mc", "-fc", "-ms", "-fs", "-mr", "-fr",
        "-t", "-timeout", "-recursion-depth", "-maxtime", "-maxtime-job",
        "-p", "-rate",
    },
    "dirsearch": {"-t", "-e", "-R", "-i", "-x", "--max-time", "--delay", "--timeout"},
    "testssl": set(),
}


def validate_custom_args(tool: str, custom_args: str | None) -> None:
    """Raise ValueError if ``custom_args`` contains anything outside the
    tool's allow-list, or any bare positional token. No-op on empty input.
    """
    raw = (custom_args or "").strip()
    if not raw:
        return
    try:
        tokens = shlex.split(raw)
    except ValueError:
        raise ValueError("custom args could not be parsed")

    allowed = _ALLOWED_FLAGS.get(tool, set())
    takes_value = _TAKES_VALUE.get(tool, set())

    i = 0
    while i < len(tokens):
        tok = tokens[i]
        if not tok.startswith("-"):
            raise ValueError(
                f"unexpected argument '{tok}' — bare (non-flag) values are not "
                "permitted in custom args"
            )
        flag = tok.split("=", 1)[0]
        if flag not in allowed:
            raise ValueError(f"flag '{flag}' is not permitted in custom args for {tool}")
        if flag in takes_value and "=" not in tok:
            if i + 1 >= len(tokens) or tokens[i + 1].startswith("-"):
                raise ValueError(f"flag '{flag}' requires a value")
            i += 1  # consume the value token, exempt from the flag checks above
        i += 1
