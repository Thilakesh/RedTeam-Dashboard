import asyncio
import shutil

from app.pipeline.stage import AssetRecord, StageContext, StageExecutionError


class AssetfinderStage:
    name = "assetfinder"
    source_tool = "assetfinder"
    inputs: list[str] = []
    outputs = ["subdomain"]
    depends_on: list[str] = []
    weight = 30
    optional = False

    async def execute(self, ctx: StageContext) -> list[AssetRecord]:
        binary = shutil.which("assetfinder")
        if binary is None:
            raise RuntimeError("assetfinder binary not on PATH")

        proc = await asyncio.create_subprocess_exec(
            binary,
            "--subs-only",
            ctx.domain,
            stdout=asyncio.subprocess.PIPE,
            stderr=asyncio.subprocess.PIPE,
        )
        try:
            stdout, stderr = await asyncio.wait_for(proc.communicate(), timeout=120)
        except asyncio.TimeoutError:
            proc.kill()
            raise RuntimeError("assetfinder timed out after 120s") from None

        if proc.returncode != 0:
            stderr_text = stderr.decode(errors="replace")
            raise StageExecutionError(
                f"assetfinder exited {proc.returncode}: {stderr_text[:500]}",
                exit_code=proc.returncode,
                stderr=stderr_text,
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
                    payload={"source": "assetfinder"},
                    confidence=80,
                )
            )
        return records
