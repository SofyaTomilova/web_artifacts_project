
from __future__ import annotations

import json
import logging
import socket
import ssl
from datetime import datetime
from pathlib import Path

logger = logging.getLogger(__name__)


def _convert_asn1_date(date_str: str) -> str:
    """
    Переводит ASN.1-дату 'YYYYMMDDHHMMSSZ' в ISO-формат.
    """
    try:
        dt = datetime.strptime(date_str, "%Y%m%d%H%M%SZ")
        return dt.isoformat()
    except Exception:  # noqa: BLE001
        return date_str


def get_ssl_info(hostname: str, port: int = 443, timeout: int = 5) -> dict:
    """
    Получает базовую информацию о TLS-сертификате удалённого хоста.
    """
    context = ssl.create_default_context()

    with socket.create_connection((hostname, port), timeout=timeout) as sock:
        with context.wrap_socket(sock, server_hostname=hostname) as ssock:
            cert = ssock.getpeercert()

    info = {
        "subject": dict(x[0] for x in cert.get("subject", [])),
        "issuer": dict(x[0] for x in cert.get("issuer", [])),
        "version": cert.get("version"),
        "serialNumber": cert.get("serialNumber"),
        "notBefore": _convert_asn1_date(cert.get("notBefore", "")),
        "notAfter": _convert_asn1_date(cert.get("notAfter", "")),
        "subjectAltName": cert.get("subjectAltName", []),
    }
    return info


def save_ssl_info(info: dict, base_path: Path) -> Path:
    """
    Сохраняет информацию о сертификате TLS в JSON-файл.
    """
    ssl_path = base_path.with_suffix(".ssl.json")
    try:
        ssl_path.write_text(json.dumps(info, ensure_ascii=False, indent=2), encoding="utf-8")
        logger.info("Информация о TLS-сертификате сохранена: %s", ssl_path)
    except Exception as exc:  # noqa: BLE001
        logger.error("Не удалось сохранить информацию о TLS-сертификате: %s", exc)
    return ssl_path
