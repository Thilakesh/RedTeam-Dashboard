"""Subprocess resource isolation for active-scanning stages (M2).

Provides get_preexec_fn() which returns a callable suitable for use as preexec_fn
in asyncio.create_subprocess_exec. This runs in the child process before exec,
applying resource limits to protect the host from runaway recon tools.

Note: preexec_fn is Unix-only. Guard with sys.platform != 'win32' if needed.
"""
from __future__ import annotations

import resource
from typing import Callable


def _apply_limits() -> None:
    """Applied in child process via preexec_fn before exec."""
    # RLIMIT_AS (virtual address space) intentionally omitted: Go binaries (naabu,
    # gowitness) reserve several GB of virtual address space for GC arenas at startup,
    # causing SIGABRT even when actual physical memory usage is tiny.
    #
    # 4096 open file descriptors — naabu opens one socket per concurrent probe.
    # Default kernel soft limit is 1024; we keep that ceiling here.
    try:
        resource.setrlimit(resource.RLIMIT_NOFILE, (4096, 4096))
    except (ValueError, resource.error):
        pass

    # 1hr of cumulative CPU time — well above any legitimate scan (adapters
    # already enforce their own wall-clock timeouts, typically <=600s), but
    # bounds a genuinely stuck/malicious process rather than leaving it
    # unbounded. Threaded tools (ffuf -t 40, nmap -T4) can accumulate more
    # CPU-seconds than wall-clock seconds, hence the wide margin.
    try:
        resource.setrlimit(resource.RLIMIT_CPU, (3600, 3600))
    except (ValueError, resource.error):
        pass

    # 500MB max file size — bounds a runaway output/log file (screenshots and
    # tool JSON output are always small; raw_output is capped at 100KB at the
    # application layer already) without touching real usage.
    try:
        resource.setrlimit(resource.RLIMIT_FSIZE, (500 * 1024 * 1024, 500 * 1024 * 1024))
    except (ValueError, resource.error):
        pass

    # Generous process/thread ceiling — bounds fork-bomb-style abuse. Kept
    # high (not tight) for the same reason RLIMIT_AS is skipped entirely: Go
    # binaries (naabu, gowitness) spawn multiple OS threads for their
    # runtime/GC and a too-low limit here produces the same class of opaque
    # startup failure.
    try:
        resource.setrlimit(resource.RLIMIT_NPROC, (2048, 2048))
    except (ValueError, resource.error):
        pass

    # No core dumps — a crashed recon tool's core file could contain
    # in-memory secrets (e.g. the PDCP API key). Zero-cost, no legitimate
    # use case relies on this being enabled.
    try:
        resource.setrlimit(resource.RLIMIT_CORE, (0, 0))
    except (ValueError, resource.error):
        pass


def get_preexec_fn() -> Callable[[], None]:
    """Return a preexec_fn for subprocess resource limiting.

    Usage:
        proc = await asyncio.create_subprocess_exec(
            binary, *args,
            preexec_fn=get_preexec_fn(),
        )
    """
    return _apply_limits
