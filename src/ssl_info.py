from __future__ import annotations

import json
import logging
import socket
import ssl
from datetime import datetime
from pathlib import Path
from typing import List, Optional
from urllib.parse import urlparse

logger = logging.getLogger(__name__)


def _convert_asn1_date(date_str: str) -> str:
    """
    Переводит ASN.1-дату 'YYYYMMDDHHMMSSZ' в ISO-формат.
    """
    try:
        dt = datetime.strptime(date_str, "%Y%m%d%H%M%SZ")
        return dt.isoformat()
    except Exception:
        return date_str


def _check_hostname_match(hostname: str, cert_cn: Optional[str], san_list: List[str]) -> bool:
    """
    Проверяет, соответствует ли hostname сертификату.
    Поддерживает wildcard сертификаты (*.example.com).
    """
    if not hostname:
        return False
    
    hostname = hostname.lower()
    
    # Проверка по CN (Common Name)
    if cert_cn and cert_cn.lower() == hostname:
        return True
    
    # Проверка по SAN (Subject Alternative Names)
    for san in san_list:
        san = san.lower()
        # Поддержка wildcard сертификатов
        if san.startswith("*."):
            domain_part = san[2:]
            if hostname.endswith(domain_part):
                return True
        elif san == hostname:
            return True
    
    return False


def get_ssl_info(url: str, port: int = 443, timeout: int = 5) -> dict:
    """
    Получает информацию о TLS-сертификате удалённого хоста 
    с проверкой соответствия hostname.
    
    Args:
        url: URL в формате https://example.com или просто example.com
        port: Порт для подключения (по умолчанию 443)
        timeout: Таймаут подключения в секундах
    
    Returns:
        dict: Информация о сертификате или {"error": "..."} при ошибке
    """
    # ========== ИСПРАВЛЕНИЕ: Нормализация URL ==========
    # Если URL не начинается со схемы, добавляем https://
    if not url.startswith(('http://', 'https://')):
        url = f'https://{url}'
    
    try:
        parsed = urlparse(url)
        hostname = parsed.hostname
    except Exception as e:
        logger.error("Ошибка парсинга URL '%s': %s", url, e)
        return {"error": f"Invalid URL: {str(e)}"}
    
    if not hostname:
        logger.error("Hostname не найден в URL: %s", url)
        return {"error": "Hostname not found in URL"}
    
    # Создание SSL-контекста
    context = ssl.create_default_context()
    
    try:
        with socket.create_connection((hostname, port), timeout=timeout) as sock:
            with context.wrap_socket(sock, server_hostname=hostname) as ssock:
                cert = ssock.getpeercert()
    except socket.timeout:
        logger.warning("Timeout при подключении к %s", hostname)
        return {"error": f"Connection timeout to {hostname}"}
    except ssl.SSLError as e:
        logger.warning("SSL ошибка для %s: %s", hostname, e)
        return {"error": f"SSL error: {str(e)}"}
    except socket.gaierror:
        logger.warning("DNS resolution failed для %s", hostname)
        return {"error": f"DNS resolution failed for {hostname}"}
    except Exception as e:
        logger.warning("Ошибка подключения к %s: %s", hostname, e)
        return {"error": str(e)}

    # Извлечение Common Name из subject
    cert_cn = None
    for rdn in cert.get("subject", ()):
        for attr in rdn:
            if attr[0] == "commonName":
                cert_cn = attr[1]
                break
    
    # Извлечение Subject Alternative Names
    san_list = []
    for san_type, san_value in cert.get("subjectAltName", []):
        if san_type == "DNS":
            san_list.append(san_value)

    info = {
        "subject": dict(x[0] for x in cert.get("subject", [])),
        "issuer": dict(x[0] for x in cert.get("issuer", [])),
        "version": cert.get("version"),
        "serialNumber": cert.get("serialNumber"),
        "notBefore": _convert_asn1_date(cert.get("notBefore", "")),
        "notAfter": _convert_asn1_date(cert.get("notAfter", "")),
        "subjectAltName": san_list,
        "certificate_cn": cert_cn,
        "hostname": hostname,
        # Проверка hostname mismatch
        "hostname_mismatch": not _check_hostname_match(hostname, cert_cn, san_list),
    }
    
    logger.info("SSL-сертификат получен для %s", hostname)
    return info


def save_ssl_info(info: dict, base_path: Path) -> Path:
    """
    Сохраняет информацию о сертификате TLS в JSON-файл.
    
    Args:
        info: Словарь с информацией о сертификате
        base_path: Путь к базовому файлу (без расширения)
    
    Returns:
        Path: Путь к сохраненному файлу
    """
    ssl_path = base_path.with_suffix(".ssl.json")
    try:
        ssl_path.write_text(
            json.dumps(info, ensure_ascii=False, indent=2), 
            encoding="utf-8"
        )
        logger.info("Информация о TLS-сертификате сохранена: %s", ssl_path)
    except Exception as exc:
        logger.error("Не удалось сохранить информацию о TLS-сертификате: %s", exc)
    return ssl_path
