"""TLS cipher strength classifier.

Mirrors the classification at https://ciphersuite.info/cs/?singlepage=true
collapsed into four buckets:

    recommended  — TLS 1.3 AEAD ciphers (Mozilla "Modern")
    secure       — TLS 1.2 with ECDHE + AEAD (Mozilla "Intermediate")
    weak         — CBC mode, RSA key exchange without PFS, SHA1 MAC
    insecure     — RC4, 3DES, DES, NULL, EXPORT, MD5, anonymous

We do not bundle ciphersuite.info CSV at build time (network round trip on
worker boot is fragile). Instead this is a self-contained heuristic over the
cipher name string. Curated overrides handle the well-known IANA + OpenSSL
names that the heuristic mis-classifies.
"""
from __future__ import annotations

# Curated overrides — IANA / OpenSSL names whose heuristic verdict differs from
# ciphersuite.info's published rating. Keys lowercased.
_OVERRIDES: dict[str, str] = {
    # TLS 1.3
    "tls_aes_256_gcm_sha384": "recommended",
    "tls_chacha20_poly1305_sha256": "recommended",
    "tls_aes_128_gcm_sha256": "recommended",
    "tls_aes_128_ccm_sha256": "recommended",
    "tls_aes_128_ccm_8_sha256": "secure",
    # TLS 1.2 ECDHE + AEAD (secure)
    "ecdhe-ecdsa-aes256-gcm-sha384": "secure",
    "ecdhe-rsa-aes256-gcm-sha384": "secure",
    "ecdhe-ecdsa-aes128-gcm-sha256": "secure",
    "ecdhe-rsa-aes128-gcm-sha256": "secure",
    "ecdhe-ecdsa-chacha20-poly1305": "secure",
    "ecdhe-rsa-chacha20-poly1305": "secure",
    "dhe-rsa-aes256-gcm-sha384": "secure",
    "dhe-rsa-aes128-gcm-sha256": "secure",
    "dhe-rsa-chacha20-poly1305": "secure",
    # ECDHE + CBC (weak — no AEAD)
    "ecdhe-rsa-aes256-sha384": "weak",
    "ecdhe-rsa-aes128-sha256": "weak",
    "ecdhe-rsa-aes256-sha": "weak",
    "ecdhe-rsa-aes128-sha": "weak",
    "ecdhe-ecdsa-aes256-sha384": "weak",
    "ecdhe-ecdsa-aes128-sha256": "weak",
    # Static RSA key exchange — no forward secrecy (weak)
    "aes256-gcm-sha384": "weak",
    "aes128-gcm-sha256": "weak",
    "aes256-sha256": "weak",
    "aes128-sha256": "weak",
    "aes256-sha": "weak",
    "aes128-sha": "weak",
    # Insecure
    "rc4-md5": "insecure",
    "rc4-sha": "insecure",
    "des-cbc3-sha": "insecure",
    "edh-rsa-des-cbc3-sha": "insecure",
    "null-md5": "insecure",
    "null-sha": "insecure",
    "exp-rc4-md5": "insecure",
}


def classify_cipher(name: str | None) -> str:
    """Return one of: recommended | secure | weak | insecure | unknown."""
    if not name:
        return "unknown"
    raw = name.strip()
    if not raw:
        return "unknown"
    key = raw.lower()
    if key in _OVERRIDES:
        return _OVERRIDES[key]

    upper = raw.upper()

    # Insecure markers — broken primitives or anonymity
    insecure_markers = (
        "RC4",
        "_3DES",
        "3DES_",
        "-DES-",
        "_DES_",
        "DES-CBC",
        "DES_CBC",
        "NULL",
        "EXPORT",
        "EXP_",
        "_MD5",
        "MD5_",
        "-MD5",
        "ANON",
        "_ADH_",
        "AECDH",
    )
    if any(m in upper for m in insecure_markers):
        return "insecure"

    # TLS 1.3 ciphers (recommended)
    if upper.startswith("TLS_AES_") or upper.startswith("TLS_CHACHA20_"):
        return "recommended"
    if upper.startswith("TLS_SM4_"):
        return "recommended"

    is_aead = (
        "GCM" in upper
        or "CHACHA20" in upper
        or "CCM" in upper
        or "POLY1305" in upper
    )
    has_pfs = "ECDHE" in upper or "DHE_" in upper or "DHE-" in upper

    if is_aead and has_pfs:
        return "secure"

    # CBC mode → weak (no AEAD); static-RSA → weak (no PFS)
    return "weak"


def is_secure_protocol(name: str | None) -> bool:
    """Return True if the protocol version is considered secure today."""
    if not name:
        return False
    n = name.upper().replace(" ", "").replace(".", "")
    # TLS1_2, TLS12, TLSV12, TLS_1_2 → all map to "12"
    if "TLS13" in n or "TLS_13" in n or n == "TLS13" or "TLSV13" in n:
        return True
    if "TLS12" in n or "TLSV12" in n or "TLS_12" in n:
        return True
    return False


def protocol_recommendation(secure_only: bool) -> str:
    if secure_only:
        return (
            "Configuration is acceptable. Maintain TLS 1.2/1.3 only and disable "
            "any older protocols if they become enabled later."
        )
    return (
        "Disable SSLv2, SSLv3, TLS 1.0, and TLS 1.1 on the server. Restrict to "
        "TLS 1.2 and TLS 1.3."
    )


def cipher_recommendation(counts: dict[str, int]) -> str:
    insecure = counts.get("insecure", 0)
    weak = counts.get("weak", 0)
    if insecure > 0:
        return (
            f"Remove {insecure} insecure cipher(s) immediately (RC4 / 3DES / "
            "NULL / EXPORT / MD5 / anonymous). These are exploitable today."
        )
    if weak > 0:
        return (
            f"Replace {weak} weak cipher(s) (CBC mode or static-RSA key exchange) "
            "with ECDHE + AEAD suites (e.g. ECDHE-RSA-AES256-GCM-SHA384, "
            "ECDHE-RSA-CHACHA20-POLY1305)."
        )
    return (
        "Cipher suite list looks healthy. Prefer TLS 1.3 ciphers "
        "(TLS_AES_256_GCM_SHA384, TLS_CHACHA20_POLY1305_SHA256) where possible."
    )
