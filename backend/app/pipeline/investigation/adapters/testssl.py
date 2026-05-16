"""testssl.sh investigation adapter — per-asset TLS posture probe.

Single-host variant of the vuln-side testssl stage. Targets one subdomain at a
time (analyst-clicked), runs testssl.sh against {fqdn}:443, parses the JSON
output, and emits:

- One TlsObservationRecord per host (cert metadata, protocol matrix, weak ciphers, grade)
- FindingRecord rows for each non-INFO testssl finding, classified into:
    weak_cipher | insecure_protocol | expired_cert | self_signed_cert | tls_vuln (CVE-bearing)
- Raw output: trimmed testssl JSON for the collapsible "Raw output" block

No authz gate (TLS handshake only, no attack traffic).
"""
from __future__ import annotations

import asyncio
import json
import logging
import shutil
import tempfile
from datetime import datetime
from pathlib import Path

from app.pipeline.investigation.stage import (
    FindingRecord,
    InvestigationResult,
    TaskContext,
    TlsObservationRecord,
)

log = logging.getLogger(__name__)

_BINARY = "testssl.sh"
_TIMEOUT_SEC = 600
_DEFAULT_PORT = 443

_SEVERITY_MAP = {
    "CRITICAL": "critical",
    "HIGH": "high",
    "MEDIUM": "med",
    "LOW": "low",
    "WARN": "low",
    "INFO": "info",
    "OK": "info",
    "DEBUG": "info",
}

# IDs we never emit as findings — pure scan metadata.
_NOISE_IDS = {
    "scanTime", "scanProblem", "service", "engine", "openssl", "scriptVersion",
    "openssl_version", "pre_128cipher", "session_ticket", "TLS_session_ticket",
    "sessionresumption_ticket", "sessionresumption_ID",
}

# Heuristics to classify a finding into our kind taxonomy.
_PROTOCOL_IDS = {"SSLv2", "SSLv3", "TLS1", "TLS1_1"}
_CERT_EXPIRED_IDS = {"cert_notAfter", "cert_expirationStatus"}
_CERT_SELFSIGNED_IDS = {"cert_chain_of_trust", "cert_trust"}
_PROTOCOL_KEY_IDS = {"TLS1", "TLS1_1", "TLS1_2", "TLS1_3", "SSLv2", "SSLv3"}
_CIPHERLIST_IDS = {
    "cipherlist_NULL", "cipherlist_aNULL", "cipherlist_EXPORT",
    "cipherlist_LOW", "cipherlist_3DES_IDEA", "cipherlist_OBSOLETED",
    "cipher_negotiated", "cipherorder",
}


def _binary_available() -> bool:
    return shutil.which(_BINARY) is not None


def _classify(fid: str, finding_text: str, cve_ids: list[str]) -> str:
    if cve_ids:
        return "tls_vuln"
    if fid in _CERT_EXPIRED_IDS or "expired" in finding_text.lower():
        return "expired_cert"
    if fid in _CERT_SELFSIGNED_IDS or "self-signed" in finding_text.lower():
        return "self_signed_cert"
    if fid in _PROTOCOL_IDS or any(p in fid for p in _PROTOCOL_IDS):
        return "insecure_protocol"
    if any(c.lower() in fid.lower() for c in ("cipher", "rc4", "3des", "null", "export")):
        return "weak_cipher"
    return "tls_misconfig"


def _parse_iso_date(value: str | None) -> str | None:
    """testssl emits 'YYYY-MM-DD HH:MM' for cert dates — normalize to ISO."""
    if not value:
        return None
    try:
        dt = datetime.strptime(value.strip(), "%Y-%m-%d %H:%M")
        return dt.isoformat()
    except ValueError:
        try:
            return datetime.fromisoformat(value.strip()).isoformat()
        except ValueError:
            return value.strip()


def _extract_tls_observation(
    host: str, port: int, raw_findings: list[dict]
) -> TlsObservationRecord:
    cert_subject = None
    cert_issuer = None
    cert_not_before = None
    cert_not_after = None
    cert_san: list[str] = []
    protocols: dict[str, bool] = {}
    weak_ciphers: list[str] = []
    grade: str | None = None

    for f in raw_findings:
        fid = f.get("id", "")
        finding = (f.get("finding") or "").strip()
        if not fid:
            continue
        if fid == "cert_commonName" or fid == "cert_subject":
            cert_subject = cert_subject or finding[:500]
        elif fid == "cert_caIssuers" or fid == "cert_issuer":
            cert_issuer = cert_issuer or finding[:500]
        elif fid == "cert_notBefore":
            cert_not_before = _parse_iso_date(finding)
        elif fid == "cert_notAfter":
            cert_not_after = _parse_iso_date(finding)
        elif fid == "cert_subjectAltName":
            cert_san.extend(s.strip() for s in finding.split() if s.strip())
        elif fid in _PROTOCOL_KEY_IDS:
            protocols[fid] = "offered" in finding.lower() or "deprecated" in finding.lower()
        elif fid.startswith("cipherlist_") and ("offered" in finding.lower() or "vulnerable" in finding.lower()):
            sev = str(f.get("severity", "")).upper()
            if sev in ("HIGH", "CRITICAL", "MEDIUM"):
                weak_ciphers.append(fid.replace("cipherlist_", ""))
        elif fid == "overall_grade":
            grade = finding[:5]

    return TlsObservationRecord(
        host=host,
        port=port,
        cert_subject=cert_subject,
        cert_issuer=cert_issuer,
        cert_not_before=cert_not_before,
        cert_not_after=cert_not_after,
        cert_san=cert_san[:20],
        protocols=protocols,
        weak_ciphers=sorted(set(weak_ciphers)),
        grade=grade,
    )


async def _run_testssl(host_port: str, out_path: Path) -> None:
    cmd = [
        _BINARY,
        "--quiet",
        "--color", "0",
        "--jsonfile-pretty", str(out_path),
        "--protocols",
        "--server-defaults",
        "--vulnerable",
        host_port,
    ]
    proc = await asyncio.create_subprocess_exec(
        *cmd,
        stdout=asyncio.subprocess.DEVNULL,
        stderr=asyncio.subprocess.DEVNULL,
    )
    try:
        await asyncio.wait_for(proc.wait(), timeout=_TIMEOUT_SEC)
    except asyncio.TimeoutError:
        proc.kill()
        try:
            await proc.wait()
        except Exception:
            pass
        raise


class TestSslAdapter:
    tool = "testssl"

    async def execute(self, ctx: TaskContext) -> InvestigationResult:
        if not _binary_available():
            return InvestigationResult(
                findings=[
                    FindingRecord(
                        kind="tool_unavailable",
                        severity="info",
                        title="testssl.sh not installed on worker",
                        description=(
                            "The investigation-worker container is missing the "
                            "testssl.sh binary. Rebuild the image."
                        ),
                    )
                ],
                raw_output="",
            )

        port = int(ctx.params.get("port") or _DEFAULT_PORT)
        host_port = f"{ctx.asset_canonical_key}:{port}"

        with tempfile.NamedTemporaryFile(suffix=".json", delete=False) as tf:
            out_path = Path(tf.name)

        try:
            try:
                await _run_testssl(host_port, out_path)
            except asyncio.TimeoutError:
                return InvestigationResult(
                    findings=[
                        FindingRecord(
                            kind="tool_timeout",
                            severity="info",
                            title=f"testssl timed out after {_TIMEOUT_SEC}s",
                            evidence={"host": host_port},
                        )
                    ],
                    raw_output=f"[timeout] testssl on {host_port}\n",
                )

            if not out_path.exists():
                return InvestigationResult(
                    findings=[
                        FindingRecord(
                            kind="tool_error",
                            severity="info",
                            title="testssl produced no output",
                            evidence={"host": host_port},
                        )
                    ],
                    raw_output="",
                )

            raw_text = out_path.read_text(errors="replace")
            try:
                data = json.loads(raw_text)
            except json.JSONDecodeError:
                return InvestigationResult(
                    findings=[
                        FindingRecord(
                            kind="tool_error",
                            severity="info",
                            title="testssl JSON parse failed",
                            evidence={"host": host_port},
                        )
                    ],
                    raw_output=raw_text,
                )

            raw_findings = data if isinstance(data, list) else []

            tls_obs = _extract_tls_observation(
                host=ctx.asset_canonical_key,
                port=port,
                raw_findings=raw_findings,
            )

            findings: list[FindingRecord] = []
            for f in raw_findings:
                fid = f.get("id", "")
                if not fid or fid in _NOISE_IDS:
                    continue
                sev_raw = str(f.get("severity", "INFO")).upper()
                severity = _SEVERITY_MAP.get(sev_raw, "info")
                if severity == "info":
                    continue
                finding_text = (f.get("finding") or fid).strip()
                cve = f.get("cve") or ""
                cve_ids = [c for c in cve.split() if c.startswith("CVE-")]
                kind = _classify(fid, finding_text, cve_ids)
                findings.append(
                    FindingRecord(
                        kind=kind,
                        severity=severity,
                        title=f"TLS · {fid}",
                        description=finding_text[:1000],
                        evidence={
                            "id": fid,
                            "host": host_port,
                            "ip": f.get("ip"),
                            "port": f.get("port") or port,
                            "raw_severity": sev_raw,
                            "finding": finding_text,
                            "cve_ids": cve_ids,
                        },
                    )
                )

            return InvestigationResult(
                findings=findings,
                tls_observations=[tls_obs],
                raw_output=raw_text,
            )
        finally:
            try:
                out_path.unlink(missing_ok=True)
            except Exception:
                pass
