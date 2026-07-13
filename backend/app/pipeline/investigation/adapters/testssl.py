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
import re
import shutil
import sys
import tempfile
from datetime import datetime
from pathlib import Path

from app.pipeline.investigation.stage import (
    FindingRecord,
    InvestigationResult,
    TaskContext,
    TlsObservationRecord,
)
from app.services.cipher_strength import (
    cipher_recommendation,
    classify_cipher,
    is_secure_protocol,
    protocol_recommendation,
)
from app.workers.sandbox import get_preexec_fn

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


_PROTOCOL_LABEL = {
    "SSLv2": "SSL 2.0",
    "SSLv3": "SSL 3.0",
    "TLS1": "TLS 1.0",
    "TLS1_1": "TLS 1.1",
    "TLS1_2": "TLS 1.2",
    "TLS1_3": "TLS 1.3",
}


def _emit_protocol_findings(host_port: str, raw: list[dict]) -> list[FindingRecord]:
    """One FindingRecord per protocol version testssl probed.

    testssl emits each protocol id more than once when both --protocols and
    --server-defaults run; dedupe by protocol_id keeping the first occurrence.
    """
    out: list[FindingRecord] = []
    seen_protocols: set[str] = set()
    for f in raw:
        fid = f.get("id", "")
        if fid not in _PROTOCOL_KEY_IDS:
            continue
        if fid in seen_protocols:
            continue
        seen_protocols.add(fid)
        finding_text = (f.get("finding") or "").strip()
        low = finding_text.lower()
        offered = "offered" in low
        deprecated_offered = offered and "deprecated" in low
        # "not offered" reads as not enabled; mark as disabled.
        enabled = offered and "not offered" not in low
        secure = is_secure_protocol(fid) and enabled
        label = _PROTOCOL_LABEL.get(fid, fid)
        status = (
            "enabled-insecure"
            if enabled and not is_secure_protocol(fid)
            else "enabled"
            if enabled
            else "disabled"
        )
        sev = (
            "high"
            if enabled and not is_secure_protocol(fid)
            else "info"
        )
        out.append(
            FindingRecord(
                kind="protocol_info",
                severity=sev,
                title=f"{label} · {status}",
                description=finding_text[:1000],
                evidence={
                    "host": host_port,
                    "protocol": label,
                    "protocol_id": fid,
                    "enabled": enabled,
                    "secure": secure,
                    "deprecated": deprecated_offered,
                    "raw_finding": finding_text,
                },
            )
        )
    return out


_IANA_CIPHER_RE = re.compile(r"\bTLS_[A-Z0-9_]+\b")


def _extract_cipher_name(finding_text: str) -> str | None:
    """Pull the canonical cipher name out of a testssl 'finding' string.

    testssl emits lines like:
      'TLSv1.2   xc02c   ECDHE-ECDSA-AES256-GCM-SHA384  ECDH 256  AESGCM 256  TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384'
      'TLS_RSA_WITH_AES_128_GCM_SHA256, no PFS'
      'ECDHE-RSA-AES256-GCM-SHA384 (0xc030) ECDH 256 ...'

    Prefer the IANA name (TLS_*_WITH_* or TLS_AES_*) when present — that's
    what ciphersuite.info uses for lookups. Fall back to the OpenSSL-style
    hyphenated name (ECDHE-RSA-…) if no IANA name appears.
    """
    text = finding_text.strip()
    if not text:
        return None
    m = _IANA_CIPHER_RE.search(text)
    if m:
        return m.group(0)
    for tok in text.split():
        tok = tok.rstrip(",")
        if "-" in tok and any(ch.isalpha() for ch in tok):
            return tok
    return None


def _emit_cipher_findings(host_port: str, raw: list[dict]) -> list[FindingRecord]:
    """One FindingRecord per offered cipher with strength classification."""
    out: list[FindingRecord] = []
    seen: set[tuple[str, str]] = set()
    for f in raw:
        fid = f.get("id", "")
        low_fid = fid.lower()
        if not (low_fid.startswith("cipher_") or low_fid.startswith("cipher-")):
            continue
        # cipherorder / cipher_negotiated belong to general findings, not the
        # per-cipher list.
        if low_fid.startswith("cipherorder"):
            continue
        finding_text = (f.get("finding") or "").strip()
        if not finding_text:
            continue
        name = _extract_cipher_name(finding_text) or fid
        # Figure out which protocol version this came from.
        # testssl id formats observed:
        #   cipher-tls1_2_xc02c   (preferred — with underscore between digits)
        #   cipher-tls1_3_x1303
        #   cipher-tls12_xc02f    (older format, no underscore between digits)
        # First try the finding text (most reliable — testssl prints "TLSv1.2"
        # as the leading token of the description), then fall back to id parsing.
        proto = "Unknown"
        finding_lower = finding_text.lower()
        if "tlsv1.3" in finding_lower or "tls1.3" in finding_lower:
            proto = "TLS 1.3"
        elif "tlsv1.2" in finding_lower or "tls1.2" in finding_lower:
            proto = "TLS 1.2"
        elif "tlsv1.1" in finding_lower or "tls1.1" in finding_lower:
            proto = "TLS 1.1"
        elif "tlsv1.0" in finding_lower or "tls1.0" in finding_lower or "tlsv1 " in finding_lower:
            proto = "TLS 1.0"
        elif "sslv3" in finding_lower or "ssl3" in finding_lower:
            proto = "SSL 3.0"
        elif "sslv2" in finding_lower or "ssl2" in finding_lower:
            proto = "SSL 2.0"
        else:
            # Fall back to id parsing — order matters: check more-specific
            # patterns first so tls1_2 doesn't match a tls1 prefix.
            if "tls1_3" in low_fid or "tls13" in low_fid:
                proto = "TLS 1.3"
            elif "tls1_2" in low_fid or "tls12" in low_fid:
                proto = "TLS 1.2"
            elif "tls1_1" in low_fid or "tls11" in low_fid:
                proto = "TLS 1.1"
            elif "tls1_0" in low_fid or "tls10" in low_fid:
                proto = "TLS 1.0"
            elif "ssl3" in low_fid or "sslv3" in low_fid:
                proto = "SSL 3.0"
        key = (name, proto)
        if key in seen:
            continue
        seen.add(key)
        strength = classify_cipher(name)
        sev_map = {
            "recommended": "info",
            "secure": "info",
            "weak": "low",
            "insecure": "high",
            "unknown": "info",
        }
        out.append(
            FindingRecord(
                kind="cipher_info",
                severity=sev_map.get(strength, "info"),
                title=f"{name} · {strength}",
                description=finding_text[:1000],
                evidence={
                    "host": host_port,
                    "cipher": name,
                    "protocol": proto,
                    "strength": strength,
                    "id": fid,
                    "raw_finding": finding_text,
                },
            )
        )
    return out


def _emit_recommendation_findings(
    host_port: str, findings: list[FindingRecord]
) -> list[FindingRecord]:
    """Summarize protocol + cipher posture into recommendation findings."""
    out: list[FindingRecord] = []
    proto_findings = [f for f in findings if f.kind == "protocol_info"]
    cipher_findings = [f for f in findings if f.kind == "cipher_info"]

    if proto_findings:
        all_secure = all(
            (not f.evidence.get("enabled")) or f.evidence.get("secure")
            for f in proto_findings
        )
        out.append(
            FindingRecord(
                kind="protocol_recommendation",
                severity="info" if all_secure else "med",
                title="Protocol recommendation",
                description=protocol_recommendation(all_secure),
                evidence={"host": host_port, "all_secure": all_secure},
            )
        )

    if cipher_findings:
        counts: dict[str, int] = {}
        for c in cipher_findings:
            s = str(c.evidence.get("strength") or "unknown")
            counts[s] = counts.get(s, 0) + 1
        out.append(
            FindingRecord(
                kind="cipher_recommendation",
                severity=(
                    "high"
                    if counts.get("insecure", 0) > 0
                    else "med"
                    if counts.get("weak", 0) > 0
                    else "info"
                ),
                title="Cipher recommendation",
                description=cipher_recommendation(counts),
                evidence={"host": host_port, "strength_counts": counts},
            )
        )

    return out


def _flatten_testssl_data(data) -> list[dict]:
    """Normalize testssl output to a flat list of finding dicts.

    testssl supports two JSON output modes:
      --jsonfile         → flat array of {id, severity, finding, cve, ...}
      --jsonfile-pretty  → nested {clientProblem*, Invocation, scanResult: [{
                              targetHost, ip, port, pretest, [other-keyed lists]
                            }]}

    Adapter prefers --jsonfile; this helper keeps backward compatibility with
    any --jsonfile-pretty outputs already on disk.
    """
    if isinstance(data, list):
        return [f for f in data if isinstance(f, dict)]
    if not isinstance(data, dict):
        return []
    out: list[dict] = []
    for v in data.values():
        if isinstance(v, list):
            out.extend(f for f in v if isinstance(f, dict) and "id" in f)
    scan_results = data.get("scanResult") or []
    if isinstance(scan_results, list):
        for sr in scan_results:
            if not isinstance(sr, dict):
                continue
            for v in sr.values():
                if isinstance(v, list):
                    out.extend(f for f in v if isinstance(f, dict) and "id" in f)
    return out


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


async def _run_testssl(
    host_port: str, out_path: Path, profile_args: list[str]
) -> tuple[int | None, str]:
    """Returns (exit_code, stderr_text). Raises asyncio.TimeoutError on timeout —
    exit_code is then whatever the killed process reports (often None/-9)."""
    cmd = [
        _BINARY,
        "--quiet",
        "--color", "0",
        # --jsonfile emits a flat JSON array of finding dicts; --jsonfile-pretty
        # emits a nested object (clientProblem*, Invocation, scanResult) that
        # this adapter does NOT walk. Stick to flat array — it's the contract
        # the parser below assumes.
        "--jsonfile", str(out_path),
        *profile_args,
        host_port,
    ]
    proc = await asyncio.create_subprocess_exec(
        *cmd,
        stdout=asyncio.subprocess.DEVNULL,
        stderr=asyncio.subprocess.PIPE,
        preexec_fn=get_preexec_fn() if sys.platform != "win32" else None,
    )
    try:
        _, stderr_b = await asyncio.wait_for(proc.communicate(), timeout=_TIMEOUT_SEC)
        return proc.returncode, (stderr_b or b"").decode("utf-8", errors="replace")
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

        from app.services.net_guard import assert_target_allowed
        from app.services.scan_profiles import resolve_args

        try:
            assert_target_allowed(ctx.asset_canonical_key)
        except ValueError as e:
            return InvestigationResult(
                findings=[
                    FindingRecord(
                        kind="tool_error",
                        severity="info",
                        title="target blocked",
                        description=str(e),
                    )
                ],
                raw_output=str(e),
            )

        port = int(ctx.params.get("port") or _DEFAULT_PORT)
        host_port = f"{ctx.asset_canonical_key}:{port}"
        profile_args = resolve_args("testssl", ctx.params or {})
        if not profile_args:
            profile_args = [
                "--protocols",
                "--server-defaults",
                "--vulnerable",
                "-E",
            ]

        with tempfile.NamedTemporaryFile(suffix=".json", delete=False) as tf:
            out_path = Path(tf.name)

        try:
            try:
                exit_code, tool_stderr = await _run_testssl(host_port, out_path, profile_args)
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
                    exit_code=exit_code,
                    stderr=tool_stderr,
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
                    exit_code=exit_code,
                    stderr=tool_stderr,
                )

            raw_findings = _flatten_testssl_data(data)

            tls_obs = _extract_tls_observation(
                host=ctx.asset_canonical_key,
                port=port,
                raw_findings=raw_findings,
            )

            findings: list[FindingRecord] = []
            findings.extend(
                _emit_protocol_findings(host_port, raw_findings)
            )
            findings.extend(
                _emit_cipher_findings(host_port, raw_findings)
            )
            for f in raw_findings:
                fid = f.get("id", "")
                if not fid or fid in _NOISE_IDS:
                    continue
                # Skip protocol / cipher entries — emitted separately above with
                # full classification + strength metadata.
                if fid in _PROTOCOL_KEY_IDS:
                    continue
                if fid.lower().startswith(("cipher_", "cipher-", "cipherorder")):
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

            findings.extend(_emit_recommendation_findings(host_port, findings))

            return InvestigationResult(
                findings=findings,
                tls_observations=[tls_obs],
                raw_output=raw_text,
                exit_code=exit_code,
                stderr=tool_stderr,
            )
        finally:
            try:
                out_path.unlink(missing_ok=True)
            except Exception:
                pass
