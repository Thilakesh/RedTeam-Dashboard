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
            "-d",
            ctx.domain,
            "-silent",
            "-all",
            stdout=asyncio.subprocess.PIPE,
            stderr=asyncio.subprocess.PIPE,
        )
        try:
            stdout, stderr = await asyncio.wait_for(proc.communicate(), timeout=120)
        except asyncio.TimeoutError:
            proc.kill()
            raise RuntimeError("subfinder timed out after 120s") from None

        if proc.returncode != 0:
            raise RuntimeError(
                f"subfinder exited {proc.returncode}: {stderr.decode(errors='replace')[:500]}"
            )

        seen: set[str] = set()
        records: list[AssetRecord] = []
        for raw in stdout.decode(errors="replace").splitlines():
            sub = raw.strip().lower()
            if not sub or sub in seen:
                continue
            seen.add(sub)
            records.append(
                AssetRecord(
                    type="subdomain",
                    canonical_key=sub,
                    payload={"source": "subfinder"},
                    confidence=85,
                )
            )
        return records
