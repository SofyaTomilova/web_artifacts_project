from __future__ import annotations

import base64
import logging
import os
from typing import Optional

import requests
from dotenv import load_dotenv

load_dotenv()

logger = logging.getLogger(__name__)

VT_BASE_URL_V3 = "https://www.virustotal.com/api/v3"
OPENTIP_BASE_URL = "https://opentip.kaspersky.com/api/v1"

def get_vt_api_key(explicit: Optional[str] = None) -> Optional[str]:
    if explicit:
        return explicit
    return os.getenv("VT_API_KEY")


def get_opentip_api_key(explicit: Optional[str] = None) -> Optional[str]:
    if explicit:
        return explicit
    return os.getenv("OPENTIP_API_KEY")

def query_virustotal_url(
    url: str,
    api_key: str,
    timeout: int = 15,
) -> dict:
    url_id = base64.urlsafe_b64encode(url.encode()).decode().strip("=")
    
    endpoint = f"{VT_BASE_URL_V3}/urls/{url_id}"
    headers = {
        "x-apikey": api_key
    }

    try:
        resp = requests.get(endpoint, headers=headers, timeout=timeout)
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

def query_opentip_domain(
    domain: str,
    api_key: str,
    timeout: int = 15,
) -> dict:

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