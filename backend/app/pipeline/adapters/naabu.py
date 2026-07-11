"""naabu — fast port scanner for active port discovery.

Active stage: requires authorization_verified=True on the target (enforced by the
coordinator). Takes live subdomains from httpx as input to avoid scanning dead hosts.

Emits `service` type assets with canonical_key = "{host}:{port}/{proto}".
"""
import asyncio
import json
import shutil
import sys

from app.pipeline.stage import AssetRecord, StageContext
from app.services.net_guard import filter_allowed_hosts
from app.workers.sandbox import get_preexec_fn


class NaabuStage:
    name = "naabu"
    source_tool = "naabu"
    inputs = ["subdomain"]
    outputs = ["service"]
    depends_on = ["httpx"]
    weight = 60
    optional = True

    _MAX_HOSTS = 200

    async def execute(self, ctx: StageContext) -> list[AssetRecord]:
        hosts = ctx.inputs.get("subdomain", [])
        if not hosts:
            return []

        binary = shutil.which("naabu")
        if binary is None:
            raise RuntimeError("naabu binary not on PATH")

        hosts = filter_allowed_hosts(sorted(hosts)[: self._MAX_HOSTS])
        if not hosts:
            return []

        proc = await asyncio.create_subprocess_exec(
            binary,
            "-host", ",".join(hosts),
            "-top-ports", "1000",
            "-s", "c",            # connect scan — works through Cloudflare (SYN is blocked)
            "-silent",
            "-json",
            "-disable-update-check",
            stdin=asyncio.subprocess.DEVNULL,
            stdout=asyncio.subprocess.PIPE,
            stderr=asyncio.subprocess.PIPE,
            preexec_fn=get_preexec_fn() if sys.platform != "win32" else None,
        )
        try:
            stdout, _ = await asyncio.wait_for(proc.communicate(), timeout=600)
        except asyncio.TimeoutError:
            proc.kill()
            try:
                await asyncio.wait_for(proc.wait(), timeout=5)
            except asyncio.TimeoutError:
                pass
            raise RuntimeError("naabu timed out after 600s") from None

        records: list[AssetRecord] = []
        for raw in stdout.decode(errors="replace").splitlines():
            line = raw.strip()
            if not line:
                continue
            try:
                obj = json.loads(line)
            except json.JSONDecodeError:
                continue
            host = obj.get("host") or obj.get("ip") or ""
            port = obj.get("port")
            proto = (obj.get("protocol") or "tcp").lower()
            if not host or not port:
                continue
            canonical = f"{host}:{port}/{proto}"
            records.append(
                AssetRecord(
                    type="service",
                    canonical_key=canonical,
                    payload={"host": host, "port": int(port), "proto": proto, "state": "open"},
                    confidence=95,
                )
            )
        return records
