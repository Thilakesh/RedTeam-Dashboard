"""nmap — service/version detection on ports discovered by naabu.

Reads `service` assets from naabu, groups them by host, runs nmap -sV per host
to identify service names and versions.

Emits `service` type assets enriching naabu output with service/product/version info.
"""
from __future__ import annotations

import asyncio
import shutil
import sys
import tempfile
import xml.etree.ElementTree as ET
from pathlib import Path

from app.pipeline.stage import AssetRecord, StageContext
from app.services.net_guard import filter_allowed_hosts
from app.workers.sandbox import get_preexec_fn


class NmapStage:
    name = "nmap"
    source_tool = "nmap"
    inputs = ["service"]
    outputs = ["service"]
    depends_on = ["naabu"]
    weight = 80
    optional = True

    _MAX_HOSTS = 50

    async def execute(self, ctx: StageContext) -> list[AssetRecord]:
        service_keys = ctx.inputs.get("service", [])
        if not service_keys:
            return []

        binary = shutil.which("nmap")
        if binary is None:
            raise RuntimeError("nmap binary not on PATH")

        # Group ports by host. key format: "{host}:{port}/{proto}"
        host_ports: dict[str, list[int]] = {}
        for key in service_keys:
            try:
                host_part, rest = key.rsplit(":", 1)
                port_str = rest.split("/")[0]
                port = int(port_str)
                host_ports.setdefault(host_part, []).append(port)
            except (ValueError, IndexError):
                continue

        hosts = filter_allowed_hosts(sorted(host_ports.keys())[: self._MAX_HOSTS])
        records: list[AssetRecord] = []

        for host in hosts:
            ports = host_ports[host]
            port_arg = ",".join(str(p) for p in sorted(ports))
            with tempfile.NamedTemporaryFile(suffix=".xml", delete=False) as f:
                out_path = Path(f.name)
            try:
                proc = await asyncio.create_subprocess_exec(
                    binary,
                    "-sV",
                    "--open",
                    "-p", port_arg,
                    "-oX", str(out_path),
                    host,
                    stdin=asyncio.subprocess.DEVNULL,
                    stdout=asyncio.subprocess.DEVNULL,
                    stderr=asyncio.subprocess.PIPE,
                    preexec_fn=get_preexec_fn() if sys.platform != "win32" else None,
                )
                try:
                    await asyncio.wait_for(proc.communicate(), timeout=120)
                except asyncio.TimeoutError:
                    proc.kill()
                    try:
                        await asyncio.wait_for(proc.wait(), timeout=5)
                    except asyncio.TimeoutError:
                        pass
                    continue
                except asyncio.CancelledError:
                    proc.kill()
                    try:
                        await asyncio.wait_for(proc.wait(), timeout=5)
                    except (asyncio.TimeoutError, asyncio.CancelledError):
                        pass
                    raise

                if not out_path.exists() or out_path.stat().st_size == 0:
                    continue
                try:
                    tree = ET.parse(str(out_path))
                except ET.ParseError:
                    continue

                for port_el in tree.findall(".//port"):
                    state_el = port_el.find("state")
                    if state_el is None or state_el.get("state") != "open":
                        continue
                    portid = int(port_el.get("portid", 0))
                    proto = port_el.get("protocol", "tcp").lower()
                    svc_el = port_el.find("service")
                    service_name = svc_el.get("name") if svc_el is not None else None
                    product = svc_el.get("product") if svc_el is not None else None
                    version = svc_el.get("version") if svc_el is not None else None
                    canonical = f"{host}:{portid}/{proto}"
                    records.append(
                        AssetRecord(
                            type="service",
                            canonical_key=canonical,
                            payload={
                                "host": host,
                                "port": portid,
                                "proto": proto,
                                "state": "open",
                                "service_name": service_name,
                                "product": product,
                                "version": version,
                            },
                            confidence=95,
                        )
                    )
            finally:
                out_path.unlink(missing_ok=True)

        return records
