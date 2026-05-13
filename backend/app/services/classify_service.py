"""Heuristic ServiceClassification computation.

Called from `services/assets.py::_upsert_services` so classification happens at
recon write-time. Vuln stages then read it from `Service.classification` for
conditional routing (e.g. `required_signals=["service.classification:database"]`).

Same heuristic as migration 0010's backfill — keep them in sync.
"""

from __future__ import annotations

from app.models.service import ServiceClassification

_PORT_RULES: dict[int, ServiceClassification] = {
    # Web
    80: ServiceClassification.web, 443: ServiceClassification.web,
    8080: ServiceClassification.web, 8443: ServiceClassification.web,
    8000: ServiceClassification.web, 8888: ServiceClassification.web,
    # Database
    3306: ServiceClassification.database, 5432: ServiceClassification.database,
    1433: ServiceClassification.database, 1521: ServiceClassification.database,
    27017: ServiceClassification.database, 6379: ServiceClassification.database,
    9042: ServiceClassification.database, 5984: ServiceClassification.database,
    7474: ServiceClassification.database,
    # Cache
    11211: ServiceClassification.cache,
    # Messaging
    5672: ServiceClassification.messaging, 15672: ServiceClassification.messaging,
    9092: ServiceClassification.messaging, 1883: ServiceClassification.messaging,
    61616: ServiceClassification.messaging,
    # Control plane
    22: ServiceClassification.control_plane, 23: ServiceClassification.control_plane,
    3389: ServiceClassification.control_plane, 5985: ServiceClassification.control_plane,
    5986: ServiceClassification.control_plane, 2375: ServiceClassification.control_plane,
    2376: ServiceClassification.control_plane, 6443: ServiceClassification.control_plane,
    10250: ServiceClassification.control_plane,
    # File share
    21: ServiceClassification.file_share, 445: ServiceClassification.file_share,
    139: ServiceClassification.file_share, 2049: ServiceClassification.file_share,
    # Mail
    25: ServiceClassification.mail, 110: ServiceClassification.mail,
    143: ServiceClassification.mail, 465: ServiceClassification.mail,
    587: ServiceClassification.mail, 993: ServiceClassification.mail,
    995: ServiceClassification.mail,
    # Directory
    389: ServiceClassification.directory, 636: ServiceClassification.directory,
    88: ServiceClassification.directory, 464: ServiceClassification.directory,
    # RPC
    135: ServiceClassification.rpc, 111: ServiceClassification.rpc,
    # Monitoring
    9090: ServiceClassification.monitoring, 3000: ServiceClassification.monitoring,
    5601: ServiceClassification.monitoring,
}

_NAME_RULES: dict[str, ServiceClassification] = {
    "mysql": ServiceClassification.database,
    "postgresql": ServiceClassification.database,
    "mssql": ServiceClassification.database,
    "oracle": ServiceClassification.database,
    "mongodb": ServiceClassification.database,
    "redis": ServiceClassification.database,
    "cassandra": ServiceClassification.database,
    "couchdb": ServiceClassification.database,
    "neo4j": ServiceClassification.database,
    "memcached": ServiceClassification.cache,
    "amqp": ServiceClassification.messaging,
    "kafka": ServiceClassification.messaging,
    "mqtt": ServiceClassification.messaging,
    "activemq": ServiceClassification.messaging,
    "ssh": ServiceClassification.control_plane,
    "telnet": ServiceClassification.control_plane,
    "rdp": ServiceClassification.control_plane,
    "docker": ServiceClassification.control_plane,
    "kubelet": ServiceClassification.control_plane,
    "ftp": ServiceClassification.file_share,
    "smb": ServiceClassification.file_share,
    "nfs": ServiceClassification.file_share,
    "netbios-ssn": ServiceClassification.file_share,
    "microsoft-ds": ServiceClassification.file_share,
    "smtp": ServiceClassification.mail,
    "pop3": ServiceClassification.mail,
    "imap": ServiceClassification.mail,
    "submission": ServiceClassification.mail,
    "imaps": ServiceClassification.mail,
    "pop3s": ServiceClassification.mail,
    "ldap": ServiceClassification.directory,
    "ldaps": ServiceClassification.directory,
    "kerberos": ServiceClassification.directory,
    "msrpc": ServiceClassification.rpc,
    "rpcbind": ServiceClassification.rpc,
    "sunrpc": ServiceClassification.rpc,
    "prometheus": ServiceClassification.monitoring,
    "grafana": ServiceClassification.monitoring,
    "kibana": ServiceClassification.monitoring,
}


def classify_service(*, port: int, service_name: str | None) -> ServiceClassification:
    """Return the best-fit classification for a service. Defaults to unknown.

    Order of precedence: service_name match > port match > unknown. service_name
    wins because nmap -sV gives high-confidence IDs that beat port heuristics.
    """
    if service_name:
        normalized = service_name.lower().strip()
        if normalized in _NAME_RULES:
            return _NAME_RULES[normalized]
        if normalized.startswith("http"):
            return ServiceClassification.web
    if port in _PORT_RULES:
        return _PORT_RULES[port]
    return ServiceClassification.unknown
