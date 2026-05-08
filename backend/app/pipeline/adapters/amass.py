"""OWASP Amass — passive subdomain enumeration as a backup source.

Sits alongside subfinder + assetfinder. Three independent sources increase
coverage and surface dedup-confidence ("seen by 3/3" vs "seen by 1/3" later).

We run amass in passive-only mode (`enum -passive`) to keep it fast and to
honor the M2 active-scanning gate — passive sources don't touch the target.

Streaming approach: we read amass stdout line-by-line as results come in.
When the asyncio timeout fires we kill amass and return whatever was collected
— a partial result is fine for an enrichment stage and avoids marking it as
"failed" just because razorpay.com has too many DNS sources.
"""
import asyncio
import shutil

from app.pipeline.stage import AssetRecord, StageContext


class AmassStage:
    name = "amass"
    source_tool = "amass"
    inputs: list[str] = []
    outputs = ["subdomain"]
    depends_on: list[str] = []
    # Amass passive covers different sources than subfinder/assetfinder but is slower.
    weight = 45
    # Backup/enrichment stage — a timeout or API failure should not abort the scan.
    optional = True

    async def execute(self, ctx: StageContext) -> list[AssetRecord]:
        binary = shutil.which("amass")
        if binary is None:
            raise RuntimeError("amass binary not on PATH")

        proc = await asyncio.create_subprocess_exec(
            binary,
            "enum",
            "-passive",
            "-silent",
            "-nocolor",
            "-d", ctx.domain,
            "-timeout", "2",  # minutes — amass-internal cap per source group
            stdin=asyncio.subprocess.DEVNULL,
            stdout=asyncio.subprocess.PIPE,
            stderr=asyncio.subprocess.PIPE,
        )

        seen: set[str] = set()
        domain_lower = ctx.domain.lower()

        async def _collect() -> None:
            """Read subdomains from amass stdout as they stream in."""
            assert proc.stdout is not None
            async for raw in proc.stdout:
                host = raw.decode(errors="replace").strip().lower()
                if host and " " not in host and host.endswith(domain_lower):
                    seen.add(host)
            await proc.wait()

        try:
            await asyncio.wait_for(_collect(), timeout=150)
        except asyncio.TimeoutError:
            # amass v5 doesn't always respect its own -timeout flag on large targets.
            # Kill the process and return whatever partial results we streamed so far.
            try:
                proc.kill()
            except ProcessLookupError:
                pass
            try:
                await asyncio.wait_for(proc.wait(), timeout=5)
            except asyncio.TimeoutError:
                pass

        # Non-zero exit is normal when amass sources partially fail; ignore it.
        return [
            AssetRecord(
                type="subdomain",
                canonical_key=host,
                payload={},
                confidence=80,
            )
            for host in seen
        ]
