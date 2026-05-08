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


def get_preexec_fn() -> Callable[[], None]:
    """Return a preexec_fn for subprocess resource limiting.

    Usage:
        proc = await asyncio.create_subprocess_exec(
            binary, *args,
            preexec_fn=get_preexec_fn(),
        )
    """
    return _apply_limits
