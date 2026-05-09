"""Subfinder — primary passive subdomain enumeration.

Uses streaming to collect results as they arrive. On timeout the process is
killed and whatever was collected is returned — a partial result is better
than a failed scan, and other L0 tools (assetfinder, amass, bbot) fill gaps.
"""
import asyncio
import shutil

from app.pipeline.stage import AssetRecord, StageContext


class SubfinderStage:
    name = "subfinder"
    source_tool = "subfinder"
    inputs: list[str] = []
    outputs = ["subdomain"]
    depends_on: list[str] = []
    weight = 30
    optional = False

    async def execute(self, ctx: StageContext) -> list[AssetRecord]:
        binary = shutil.which("subfinder")
        if binary is None:
            raise RuntimeError("subfinder binary not on PATH")

        proc = await asyncio.create_subprocess_exec(
            binary,
            "-d", ctx.domain,
            "-silent",
            "-all",
            "-timeout", "30",   # per-source HTTP timeout in seconds
            stdout=asyncio.subprocess.PIPE,
            stderr=asyncio.subprocess.PIPE,
        )

        seen: set[str] = set()
        domain_lower = ctx.domain.lower()

        async def _collect() -> None:
            assert proc.stdout is not None
            async for raw in proc.stdout:
                host = raw.decode(errors="replace").strip().lower()
                if host and " " not in host and (
                    host.endswith(f".{domain_lower}") or host == domain_lower
                ):
                    seen.add(host)
            await proc.wait()

        try:
            await asyncio.wait_for(_collect(), timeout=300)
        except asyncio.TimeoutError:
            # Kill and return partial results rather than failing the scan.
            try:
                proc.kill()
            except ProcessLookupError:
                pass
            try:
                await asyncio.wait_for(proc.wait(), timeout=5)
            except asyncio.TimeoutError:
                pass

        # Non-zero exit is normal when some passive sources fail; ignore it.
        return [
            AssetRecord(
                type="subdomain",
                canonical_key=host,
                payload={"source": "subfinder"},
                confidence=85,
            )
            for host in seen
        ]
