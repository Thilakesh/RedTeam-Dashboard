import asyncio
import json
import shutil

from app.pipeline.stage import AssetRecord, StageContext


class Wafw00fStage:
    """wafw00f — fingerprints the WAF in front of an HTTP service.

    Passive enough (one HEAD/GET burst per host) that it ships in M1.5 without the
    M2 active-scanning authz gate. Outputs are denormalized onto each subdomain so
    the Subdomains table can render WAF + WAF Conf columns directly.
    """

    name = "wafw00f"
    source_tool = "wafw00f"
    inputs = ["subdomain"]
    outputs = ["subdomain"]
    depends_on = ["httpx"]
    weight = 40
    # WAF fingerprinting is enrichment — a timeout on large targets should not abort the scan.
    optional = True

    # Cap the host count to keep wall-clock bounded: at ~3s/host without -a this
    # keeps the stage under ~5 minutes for typical targets.
    _MAX_HOSTS = 80

    async def execute(self, ctx: StageContext) -> list[AssetRecord]:
        hosts = ctx.inputs.get("subdomain", [])
        if not hosts:
            return []

        # Probe at most _MAX_HOSTS to keep the stage bounded on large targets.
        hosts = sorted(hosts)[: self._MAX_HOSTS]

        binary = shutil.which("wafw00f")
        if binary is None:
            raise RuntimeError("wafw00f binary not on PATH")

        # -f json -o - writes JSON to stdout; drop -a so we stop at the first WAF
        # match per host (much faster than testing all ~140 signatures).
        proc = await asyncio.create_subprocess_exec(
            binary,
            "-f", "json",
            "-o", "-",
            *hosts,
            stdin=asyncio.subprocess.DEVNULL,
            stdout=asyncio.subprocess.PIPE,
            stderr=asyncio.subprocess.PIPE,
        )
        try:
            stdout, stderr = await asyncio.wait_for(proc.communicate(), timeout=600)
        except asyncio.TimeoutError:
            proc.kill()
            raise RuntimeError("wafw00f timed out after 600s") from None

        # wafw00f exits non-zero on partial failures (e.g., hosts that don't resolve).
        # That's fine — we still want whatever JSON it managed to emit.
        text = stdout.decode(errors="replace").strip()
        if not text:
            return []

        try:
            data = json.loads(text)
        except json.JSONDecodeError:
            return []

        # Output is a list of {url, detected, trigger, firewall, manufacturer}.
        records: list[AssetRecord] = []
        for entry in data:
            url = entry.get("url") or ""
            firewall = entry.get("firewall") or ""
            manufacturer = entry.get("manufacturer") or ""
            detected = bool(entry.get("detected"))
            # Confidence — wafw00f doesn't ship a numeric score; derive from signal
            # count. trigger is a string of matched fingerprints; more = higher conf.
            trigger = entry.get("trigger") or ""
            sig_count = len([t for t in trigger.split(",") if t.strip()])
            if not detected:
                conf = "NONE"
            elif sig_count >= 3:
                conf = "HIGH"
            elif sig_count == 2:
                conf = "MED"
            else:
                conf = "LOW"

            host = _host_from_url(url)
            if not host:
                continue
            label = ""
            if detected and firewall:
                label = f"{firewall}" + (f" ({manufacturer})" if manufacturer else "")

            records.append(
                AssetRecord(
                    type="subdomain",
                    canonical_key=host,
                    payload={
                        "waf": label,
                        "waf_conf": conf,
                        "waf_detected": detected,
                        "waf_firewall": firewall,
                        "waf_manufacturer": manufacturer,
                    },
                    confidence=85,
                )
            )
        return records


def _host_from_url(url: str) -> str:
    if "://" in url:
        url = url.split("://", 1)[1]
    return url.split("/", 1)[0].split(":", 1)[0].lower()
