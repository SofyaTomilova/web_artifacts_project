from __future__ import annotations

import logging
import os
from typing import Optional

import requests

logger = logging.getLogger(__name__)

# Базовые URL для API
VT_BASE_URL = "https://www.virustotal.com/vtapi/v2"
OPENTIP_BASE_URL = "https://opentip.kaspersky.com/api/v1"


# ===== Вспомогательные функции для получения ключей =====


def get_vt_api_key(explicit: Optional[str] = None) -> Optional[str]:
    """
    Возвращает API-ключ VirusTotal.

    Приоритет:
      1) явный параметр explicit,
      2) переменная окружения VT_API_KEY.

    Ключ в код жестко НЕ прошиваем — его лучше хранить
    в переменной окружения или в .env файле, чтобы случайно
    не закоммитить в GitHub.
    """
    if explicit:
        return explicit
    return os.getenv("VT_API_KEY")


def get_opentip_api_key(explicit: Optional[str] = None) -> Optional[str]:
    """
    Возвращает API-ключ Kaspersky OpenTIP.

    Приоритет:
      1) явный параметр explicit,
      2) переменная окружения OPENTIP_API_KEY.
    """
    if explicit:
        return explicit
    return os.getenv("OPENTIP_API_KEY")


# ===== Запросы к VirusTotal (public API v2) =====


def query_virustotal_url(
    url: str,
    api_key: str,
    timeout: int = 15,
) -> dict:
    """
    Запрашивает отчёт по URL в VirusTotal (public API v2).

    В ответе нас обычно интересуют поля:
      - response_code (1 — есть отчёт, 0 — нет данных),
      - positives (сколько движков пометили URL как malicious),
      - total (сколько движков проверяло),
      - scan_date и т.п.

    Полный JSON мы просто возвращаем наверх и при желании
    сохраняем в *.vt.json.
    """
    endpoint = f"{VT_BASE_URL}/url/report"
    params = {
        "apikey": api_key,
        "resource": url,
    }

    try:
        resp = requests.get(endpoint, params=params, timeout=timeout)
        resp.raise_for_status()
        data = resp.json()
        logger.info("VirusTotal: успешно получен отчёт по URL %s", url)
        return {
            "ok": True,
            "source": "virustotal",
            "url": url,
            "raw": data,
        }
    except requests.RequestException as exc:
        logger.error("VirusTotal: ошибка при запросе URL %s: %s", url, exc)
        return {
            "ok": False,
            "source": "virustotal",
            "url": url,
            "error": str(exc),
        }


def query_virustotal_domain(
    domain: str,
    api_key: str,
    timeout: int = 15,
) -> dict:
    """
    Запрашивает отчёт по домену в VirusTotal (public API v2).

    Эндпоинт: /domain/report

    Можно использовать для получения связанной инфраструктуры:
    IP-адреса, другие URL, пассивный DNS и т.п.
    """
    endpoint = f"{VT_BASE_URL}/domain/report"
    params = {
        "apikey": api_key,
        "domain": domain,
    }

    try:
        resp = requests.get(endpoint, params=params, timeout=timeout)
        resp.raise_for_status()
        data = resp.json()
        logger.info("VirusTotal: успешно получен отчёт по домену %s", domain)
        return {
            "ok": True,
            "source": "virustotal",
            "domain": domain,
            "raw": data,
        }
    except requests.RequestException as exc:
        logger.error("VirusTotal: ошибка при запросе домена %s: %s", domain, exc)
        return {
            "ok": False,
            "source": "virustotal",
            "domain": domain,
            "error": str(exc),
        }


# ===== Запросы к Kaspersky OpenTIP =====


def query_opentip_domain(
    domain: str,
    api_key: str,
    timeout: int = 15,
) -> dict:
    """
    Запрашивает репутацию домена в Kaspersky OpenTIP.

    Эндпоинт (по документации OpenTIP):
      GET https://opentip.kaspersky.com/api/v1/search/domain?request=<domain>
      Заголовок: x-api-key: <API token>

    Ответ содержит информацию о категории, угрозах и т.п.
    Мы возвращаем "raw", чтобы дальше разбирать его уже
    в отдельном модуле (scoring).
    """
    endpoint = f"{OPENTIP_BASE_URL}/search/domain"
    headers = {
        "x-api-key": api_key,
    }
    params = {
        "request": domain,
    }

    try:
        resp = requests.get(endpoint, headers=headers, params=params, timeout=timeout)
        resp.raise_for_status()
        data = resp.json()
        logger.info("OpenTIP: успешно получен отчёт по домену %s", domain)
        return {
            "ok": True,
            "source": "opentip",
            "domain": domain,
            "raw": data,
        }
    except requests.RequestException as exc:
        logger.error("OpenTIP: ошибка при запросе домена %s: %s", domain, exc)
        return {
            "ok": False,
            "source": "opentip",
            "domain": domain,
            "error": str(exc),
        }
