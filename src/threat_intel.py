from __future__ import annotations

import base64
import logging
import os
from typing import Optional

import requests
from dotenv import load_dotenv

# Загружаем переменные из .env
load_dotenv()

logger = logging.getLogger(__name__)

# Базовые URL для API
VT_BASE_URL_V3 = "https://www.virustotal.com/api/v3"
OPENTIP_BASE_URL = "https://opentip.kaspersky.com/api/v1"


# ===== Вспомогательные функции для получения ключей =====


def get_vt_api_key(explicit: Optional[str] = None) -> Optional[str]:
    """
    Возвращает API-ключ VirusTotal.

    Приоритет:
      1) явный параметр explicit,
      2) переменная окружения VT_API_KEY.
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


# ===== Запросы к VirusTotal (public API v3) =====


def query_virustotal_url(
    url: str,
    api_key: str,
    timeout: int = 15,
) -> dict:
    """
    Запрашивает отчёт по URL в VirusTotal (public API v3).

    В ответе нас обычно интересуют поля:
      - last_analysis_stats (статистика детекций),
      - last_analysis_results (детали от каждого движка),
      - last_analysis_date и т.п.

    Полный JSON мы возвращаем в поле 'raw'.
    """
    # VirusTotal API v3 требует URL в base64 для GET-запроса
    url_id = base64.urlsafe_b64encode(url.encode()).decode().strip("=")
    
    endpoint = f"{VT_BASE_URL_V3}/urls/{url_id}"
    headers = {
        "x-apikey": api_key
    }

    try:
        resp = requests.get(endpoint, headers=headers, timeout=timeout)
        
        # Если URL не найден в базе, отправим на сканирование
        if resp.status_code == 404:
            logger.info("VirusTotal: URL %s не найден в базе, отправляем на сканирование...", url)
            
            submit_endpoint = f"{VT_BASE_URL_V3}/urls"
            submit_data = {"url": url}
            submit_resp = requests.post(
                submit_endpoint,
                headers=headers,
                data=submit_data,
                timeout=timeout
            )
            
            if submit_resp.status_code == 200:
                submit_result = submit_resp.json()
                return {
                    "ok": True,
                    "source": "virustotal",
                    "url": url,
                    "status": "submitted",
                    "message": "URL отправлен на сканирование. Повторите запрос через 1-2 минуты.",
                    "raw": submit_result,
                }
            else:
                logger.warning("Не удалось отправить URL на сканирование: %s", submit_resp.text)
                return {
                    "ok": False,
                    "source": "virustotal",
                    "url": url,
                    "error": f"URL не найден и не удалось отправить на сканирование: {submit_resp.status_code}",
                }
        
        resp.raise_for_status()
        data = resp.json()
        
        # Извлекаем статистику анализа
        attributes = data.get("data", {}).get("attributes", {})
        stats = attributes.get("last_analysis_stats", {})
        
        logger.info("VirusTotal: успешно получен отчёт по URL %s (malicious: %d, suspicious: %d)", 
                   url, stats.get("malicious", 0), stats.get("suspicious", 0))
        
        return {
            "ok": True,
            "source": "virustotal",
            "url": url,
            "stats": stats,
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
    Запрашивает отчёт по домену в VirusTotal (public API v3).

    Эндпоинт: /domains/{domain}

    Можно использовать для получения связанной инфраструктуры:
    IP-адреса, другие URL, пассивный DNS и т.п.
    """
    endpoint = f"{VT_BASE_URL_V3}/domains/{domain}"
    headers = {
        "x-apikey": api_key
    }

    try:
        resp = requests.get(endpoint, headers=headers, timeout=timeout)
        resp.raise_for_status()
        data = resp.json()
        
        attributes = data.get("data", {}).get("attributes", {})
        stats = attributes.get("last_analysis_stats", {})
        
        logger.info("VirusTotal: успешно получен отчёт по домену %s (malicious: %d)", 
                   domain, stats.get("malicious", 0))
        
        return {
            "ok": True,
            "source": "virustotal",
            "domain": domain,
            "stats": stats,
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

