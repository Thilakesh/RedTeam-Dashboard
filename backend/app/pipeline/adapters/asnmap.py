"""asnmap (ProjectDiscovery) — IP → ASN/Org lookup.

Recent asnmap versions require a PDCP API key. We provide it via the
`PDCP_API_KEY` env var on the worker container. The first run on a fresh
container creates the provider config; subsequent runs reuse it.

Stage reads IPs from the deduped ipv4 set produced by dnsx and emits one
ipv4 record per IP carrying {asn, org, asn_country}. The aggregator merges
this with dnsx's {resolves: [...]} payload at query time.
"""
import asyncio
import json
import os
import shutil
import tempfile
from pathlib import Path

from app.pipeline.stage import AssetRecord, StageContext


_PDCP_CONFIG_DIR = Path("/root/.config/asnmap")
_PDCP_CONFIG_FILE = _PDCP_CONFIG_DIR / "provider-config.yaml"


def _ensure_pdcp_config() -> None:
    """Drop the API key into asnmap's config file so the binary doesn't try to
    prompt for it interactively (which fails in a worker without a tty).
    """
    api_key = os.environ.get("PDCP_API_KEY")
    if not api_key or _PDCP_CONFIG_FILE.exists():
        return
    _PDCP_CONFIG_DIR.mkdir(parents=True, exist_ok=True)
    _PDCP_CONFIG_FILE.write_text(f'pdcp:\n  api-key: "{api_key}"\n')


class AsnmapStage:
    name = "asnmap"
    source_tool = "asnmap"
    inputs = ["ipv4"]
    outputs = ["ipv4"]
    depends_on = ["dnsx"]
    weight = 10
    # ASN enrichment is best-effort — a timeout on a large IP set should not abort the scan.
    optional = True

    async def execute(self, ctx: StageContext) -> list[AssetRecord]:
        ips = ctx.inputs.get("ipv4", [])
        if not ips:
            return []

        binary = shutil.which("asnmap")
        if binary is None:
            raise RuntimeError("asnmap binary not on PATH")

        _ensure_pdcp_config()

        # asnmap takes IPs via -f FILE / -i IP. File-based scales past a few targets.
        tmp = Path(tempfile.mkstemp(prefix="asnmap-", suffix=".txt")[1])
        try:
            tmp.write_text("\n".join(ips) + "\n")
            proc = await asyncio.create_subprocess_exec(
                binary,
                "-silent",
                "-json",
                "-disable-update-check",
                "-f", str(tmp),
                stdin=asyncio.subprocess.DEVNULL,
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.PIPE,
                env={**os.environ},
            )
            try:
                stdout, stderr = await asyncio.wait_for(proc.communicate(), timeout=300)
            except asyncio.TimeoutError:
                proc.kill()
                raise RuntimeError("asnmap timed out after 300s") from None
        finally:
            tmp.unlink(missing_ok=True)

        if proc.returncode != 0:
            raise RuntimeError(
                f"asnmap exited {proc.returncode}: {stderr.decode(errors='replace')[:500]}"
            )

        seen: dict[str, dict] = {}
        for raw in stdout.decode(errors="replace").splitlines():
            line = raw.strip()
            if not line:
                continue
            try:
                obj = json.loads(line)
            except json.JSONDecodeError:
                continue
            ip = obj.get("input") or obj.get("ip") or ""
            if not ip:
                continue
            asn = obj.get("as_number") or obj.get("asn") or ""
            org = obj.get("as_name") or obj.get("org") or ""
            country = obj.get("as_country") or obj.get("country") or ""
            if ip not in seen and (asn or org):
                seen[ip] = {
                    "asn": f"AS{asn}" if asn and not str(asn).startswith("AS") else (asn or ""),
                    "org": org,
                    "asn_country": country,
                }

        return [
            AssetRecord(
                type="ipv4",
                canonical_key=ip,
                payload=data,
                confidence=95,
            )
            for ip, data in seen.items()
        ]
