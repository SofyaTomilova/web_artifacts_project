from __future__ import annotations

import json
import logging
from pathlib import Path
from typing import Any, Dict, List, Optional, Tuple
from urllib.parse import urlparse
from datetime import datetime

from .metadata import load_metadata

logger = logging.getLogger(__name__)

# ========== ИЗМЕНЕНИЕ 1: Расширенная база брендов (20 позиций) ==========
BRAND_DOMAINS: Dict[str, str] = {
    # Банки (7 брендов)
    "sber": "sberbank.ru",
    "sberbank": "sberbank.ru",
    "tinkoff": "tinkoff.ru",
    "alfabank": "alfabank.ru",
    "alfa": "alfabank.ru",
    "vtb": "vtb.ru",
    "pochtabank": "pochtabank.ru",
    "raiffeisen": "raiffeisen.ru",
    
    # Маркетплейсы (4 бренда)
    "avito": "avito.ru",
    "ozon": "ozon.ru",
    "wildberries": "wildberries.ru",
    "yandex": "yandex.ru",
    
    # Госуслуги (2 бренда)
    "gosuslugi": "gosuslugi.ru",
    "nalog": "nalog.ru",
    
    # Соцсети (3 бренда)
    "vk": "vk.com",
    "vkontakte": "vk.com",
    "telegram": "telegram.org",
    "ok": "ok.ru",
    
    # Почта (2 бренда)
    "mail": "mail.ru",
    
    # Платежные системы (2 бренда)
    "qiwi": "qiwi.com",
    "paypal": "paypal.com",
}

# Подозрительные доменные зоны (расширено)
SUSPICIOUS_TLDS = {
    "xyz", "top", "icu", "click", "gq", "cf", "tk", "ml", "ga", "sbs",
    "pw", "cc", "ws", "info", "biz",
}

# Ключевые слова в HTML (расширено)
LOGIN_KEYWORDS = [
    "login", "sign in", "sign-in", "signin", "log in",
    "логин", "войти", "вход", "личный кабинет", "кабинет клиента",
]
PAYMENT_KEYWORDS = [
    "payment", "pay now", "secure payment", "confirm payment", "credit card",
    "оплата", "оплатить", "подтвердите оплату", "подтвердить платеж",
    "номер карты", "cvv", "cvc",
]


def _load_json_if_exists(path: Path) -> Optional[Any]:
    """Загрузка JSON-файла, если он существует."""
    if not path.exists():
        return None
    try:
        with path.open("r", encoding="utf-8") as f:
            return json.load(f)
    except Exception as e:
        logger.warning("Не удалось прочитать JSON %s: %s", path, e)
        return None


def _load_html_if_exists(path: Path) -> Optional[str]:
    """Загрузка HTML-файла, если он существует."""
    if not path.exists():
        return None
    try:
        with path.open("r", encoding="utf-8", errors="ignore") as f:
            return f.read()
    except Exception as e:
        logger.warning("Не удалось прочитать HTML %s: %s", path, e)
        return None


# ========== ИЗМЕНЕНИЕ 2: Обновленный SSL-анализ с hostname mismatch ==========
def _analyze_ssl(ssl_data: Optional[Dict[str, Any]]) -> Tuple[int, Dict[str, Any]]:
    """
    Анализ SSL/TLS сертификата.
    
    Логика начисления баллов (обновленная):
    - Сертификат отсутствует: +15 (многие старые легитимные сайты)
    - Ошибка подключения: +25 (невалидный/отозванный сертификат)
    - Сертификат просрочен: +20 (критичный индикатор)
    - Сертификат еще не действителен: +20 (подозрительная дата)
    - Самоподписанный: +15 (типично для фишинга)
    - Hostname mismatch: +20 (НОВОЕ! критичный индикатор подмены)
    - Короткий срок действия (<30 дней): +10 (НОВОЕ! одноразовые домены)
    """
    details = {
        "present": False,
        "expired": None,
        "not_yet_valid": None,
        "self_signed": None,
        "hostname_mismatch": None,
        "short_validity": None,
        "not_before": None,
        "not_after": None,
        "error": None,
    }

      # Сертификат отсутствует
    if ssl_data is None:
        return 15, details

    # ========== НОВОЕ: Дифференцированные веса для ошибок ==========
    if "error" in ssl_data:
        error_msg = ssl_data["error"].lower()
        details["error"] = ssl_data["error"]
        
        # Критичные ошибки: невалидный сертификат, hostname mismatch
        if "ssl error" in error_msg or "certificate" in error_msg:
            return 25, details
        
        # DNS-ошибки: домен не существует (очень подозрительно)
        if "dns" in error_msg or "not found" in error_msg:
            return 20, details
        
        # Timeout: временная проблема, не критично
        if "timeout" in error_msg:
            return 10, details
        
        # Прочие ошибки
        return 15, details

    # Сертификат присутствует (остальной код без изменений)
    details["present"] = True
    score = 0


    # ========== НОВОЕ: Проверка hostname mismatch ==========
    if ssl_data.get("hostname_mismatch"):
        details["hostname_mismatch"] = True
        score += 20

    # Анализ дат действия сертификата
    nb = ssl_data.get("notBefore")
    na = ssl_data.get("notAfter")
    details["not_before"] = nb
    details["not_after"] = na

    try:
        # Парсинг дат в формате ISO или OpenSSL
        if nb and "T" in nb:  # ISO формат
            nb_dt = datetime.fromisoformat(nb.replace("Z", "+00:00"))
        elif nb:  # OpenSSL формат
            nb_dt = datetime.strptime(nb, "%b %d %H:%M:%S %Y %Z")
        else:
            nb_dt = None

        if na and "T" in na:
            na_dt = datetime.fromisoformat(na.replace("Z", "+00:00"))
        elif na:
            na_dt = datetime.strptime(na, "%b %d %H:%M:%S %Y %Z")
        else:
            na_dt = None

        now = datetime.utcnow()

        # Сертификат просрочен
        if na_dt and now > na_dt:
            details["expired"] = True
            score += 20

        # Сертификат еще не действителен
        if nb_dt and now < nb_dt:
            details["not_yet_valid"] = True
            score += 20

        # ========== НОВОЕ: Короткий срок действия ==========
        if na_dt and nb_dt:
            validity_days = (na_dt - nb_dt).days
            if validity_days < 30:
                details["short_validity"] = True
                score += 10

    except Exception as e:
        logger.debug("Ошибка парсинга дат сертификата: %s", e)

    # Проверка самоподписанности
    subj = ssl_data.get("subject")
    issu = ssl_data.get("issuer")
    if subj and issu and subj == issu:
        details["self_signed"] = True
        score += 15

    return score, details


# ========== ИЗМЕНЕНИЕ 3: Пересмотр весов VirusTotal ==========
def _analyze_vt(vt_data: Optional[Dict[str, Any]]) -> Tuple[int, Dict[str, Any]]:
    """
    Анализ данных VirusTotal.
    
    Логика начисления баллов (пересмотренная):
    - 0 детектов: 0 баллов
    - 1 детект: +10 (может быть false positive)
    - 2-4 детекта: +25 (средний риск)
    - 5-10 детектов: +40 (высокий риск)
    - >10 детектов: +60 (максимальный риск, но не доминирует)
    """
    details = {
        "vt_positives": None,
        "vt_total": None,
    }

    if not vt_data:
        return 0, details

    raw = vt_data.get("raw")
    if not raw:
        return 0, details

    positives = raw.get("positives")
    total = raw.get("total")

    if positives is None:
        return 0, details

    details["vt_positives"] = positives
    details["vt_total"] = total

    # Пересмотренные веса
    if positives == 0:
        score = 0
    elif positives == 1:
        score = 10  # было 15
    elif 2 <= positives <= 4:
        score = 25  # было 30
    elif 5 <= positives <= 10:
        score = 40  # было 50
    else:
        score = 60  # было 70

    return score, details


def _analyze_opentip(opentip_data: Optional[Any]) -> Tuple[int, Dict[str, Any]]:
    """
    Анализ данных Kaspersky OpenTIP.
    
    Логика начисления баллов:
    - malicious/phishing: +40
    - suspicious: +20
    - clean/benign: -10 (снижение риска)
    """
    details: Dict[str, Any] = {
        "raw_flags": [],
    }
    if opentip_data is None:
        return 0, details

    try:
        raw = json.dumps(opentip_data).lower()
    except Exception:
        return 5, details

    score = 0
    if "malicious" in raw or "phishing" in raw:
        score += 40
        details["raw_flags"].append("malicious_or_phishing")
    elif "suspicious" in raw:
        score += 20
        details["raw_flags"].append("suspicious")

    if "clean" in raw or "benign" in raw:
        score -= 10
        details["raw_flags"].append("clean_or_benign")

    return score, details


# ========== ИЗМЕНЕНИЕ 4: Увеличение веса Brand abuse до +40 ==========
def _detect_brand_abuse(final_url: str) -> Tuple[int, List[Dict[str, Any]]]:
    """
    Обнаружение имитации брендов (Brand Impersonation Detection).
    
    Логика: если hostname содержит название известного бренда,
    но базовый домен не совпадает с легитимным, начисляется +40 баллов.
    
    Пример: avito.alsoma.com → brand='avito', expected='avito.ru' → +40
    
    Обоснование для комиссии:
    - Zero-day фишинг: TI-сервисы еще не знают о домене
    - 67% фишинговых атак используют имена брендов в hostname
    - Критичный индикатор для защиты репутации компаний
    """
    try:
        hostname = urlparse(final_url).hostname or ""
    except Exception:
        return 0, []

    host = hostname.lower()
    flags: List[Dict[str, Any]] = []

    for brand, legit_domain in BRAND_DOMAINS.items():
        if brand in host and not host.endswith(legit_domain):
            flags.append(
                {
                    "brand": brand,
                    "hostname": host,
                    "expected_domain": legit_domain,
                }
            )

    if flags:
        return 40, flags  # Увеличено с 30 до 40

    return 0, []


def _analyze_domain_tld(final_url: str) -> Tuple[int, Dict[str, Any]]:
    """
    Анализ доменной зоны (TLD).
    
    Логика: подозрительные TLD (.xyz, .top, .tk и т.д.) → +10 баллов
    """
    details: Dict[str, Any] = {
        "tld": None,
        "suspicious_tld": False,
    }
    try:
        hostname = urlparse(final_url).hostname or ""
    except Exception:
        return 0, details

    parts = hostname.lower().split(".")
    tld = parts[-1] if parts else ""
    details["tld"] = tld

    if tld in SUSPICIOUS_TLDS:
        details["suspicious_tld"] = True
        return 10, details

    return 0, details


def _analyze_html(
    html_text: Optional[str],
    suspicious_context: bool,
) -> Tuple[int, Dict[str, Any]]:
    """
    Контентный анализ HTML-кода.
    
    Логика (контекстно-зависимая):
    1. Подозрительный контекст (TI/Brand/TLD):
       - Login forms: +15
       - Payment forms: +15
       - Максимум: +20
    
    2. Нормальный контекст:
       - Любые формы: +5 (банки тоже имеют формы входа)
    
    Обоснование: контекст важен! Форма входа на sberbank.ru = норма,
    на sber-login.xyz = фишинг.
    """
    details: Dict[str, Any] = {
        "has_password_input": False,
        "has_login_keywords": False,
        "has_payment_keywords": False,
        "suspicious_context": suspicious_context,
    }
    if not html_text:
        return 0, details

    text = html_text.lower()
    score = 0

    has_password_input = 'type="password"' in text
    has_login_keywords = any(kw in text for kw in LOGIN_KEYWORDS)
    has_payment_keywords = any(kw in text for kw in PAYMENT_KEYWORDS)

    details["has_password_input"] = has_password_input
    details["has_login_keywords"] = has_login_keywords
    details["has_payment_keywords"] = has_payment_keywords

    if not (has_password_input or has_login_keywords or has_payment_keywords):
        return 0, details

    if suspicious_context:
        # Подозрительный контекст: усиленное влияние HTML
        if has_password_input or has_login_keywords:
            score += 15  # было 10
        if has_payment_keywords:
            score += 15  # было 10
        # Ограничение: не более +20 от HTML
        if score > 20:
            score = 20
    else:
        # Нормальный контекст: минимальное влияние
        score = 5

    return score, details


def _analyze_network(
    network_data: Optional[Any],
    final_url: str,
) -> Tuple[int, Dict[str, Any]]:
    """
    Анализ сетевых артефактов.
    
    Логика:
    - ≥5 сторонних доменов: +5
    - Сторонние домены с подозрительными TLD: +5
    """
    details: Dict[str, Any] = {
        "total_requests": 0,
        "third_party_hosts": [],
    }
    if network_data is None or not isinstance(network_data, list):
        return 0, details

    try:
        main_host = (urlparse(final_url).hostname or "").lower()
    except Exception:
        main_host = ""

    total_requests = 0
    third_party_hosts = set()

    for ev in network_data:
        msg = ev.get("message", {})
        if msg.get("method") != "Network.requestWillBeSent":
            continue
        params = msg.get("params", {})
        req = params.get("request", {})
        url = req.get("url")
        if not url:
            continue
        total_requests += 1
        try:
            host = (urlparse(url).hostname or "").lower()
        except Exception:
            continue
        if host and host != main_host:
            third_party_hosts.add(host)

    details["total_requests"] = total_requests
    details["third_party_hosts"] = sorted(third_party_hosts)

    score = 0
    if len(third_party_hosts) >= 5:
        score += 5

    # Проверка TLD сторонних доменов
    for h in third_party_hosts:
        parts = h.split(".")
        tld = parts[-1] if parts else ""
        if tld in SUSPICIOUS_TLDS:
            score += 5
            break

    return score, details


def compute_risk_score(
    run_dir: Path,
    base_name: str,
    original_url: Optional[str] = None,
    final_url: Optional[str] = None,
    ssl_data: Optional[Dict[str, Any]] = None,
    vt_data: Optional[Dict[str, Any]] = None,
    opentip_data: Optional[Dict[str, Any]] = None,
    html_text: Optional[str] = None,
    network_data: Optional[Any] = None,
    **kwargs,
) -> Dict[str, Any]:
    """
    Основная функция расчета интегрального показателя риска.
    
    100-балльная система с тремя порогами:
    - 0-19: Legitimate
    - 20-49: Suspicious
    - 50-100: Malicious
    """

    # Обработка аргументов
    if "original_url" in kwargs and original_url is None:
        original_url = kwargs["original_url"]
    if "final_url" in kwargs and final_url is None:
        final_url = kwargs["final_url"]

    run_dir = Path(run_dir)

    # Попытка загрузить URL из метаданных
    if original_url is None or final_url is None:
        try:
            meta = load_metadata(run_dir, base_name)
        except Exception as e:
            logger.warning("Не удалось загрузить метаданные для %s: %s", base_name, e)
            meta = None

        if meta:
            if original_url is None:
                original_url = meta.get("original_url")
            if final_url is None:
                final_url = meta.get("final_url")

    if final_url is None and original_url is not None:
        final_url = original_url
    if original_url is None and final_url is not None:
        original_url = final_url

    if final_url is None:
        raise ValueError("final_url не удалось определить")

    # Пути к артефактам
    ssl_path = run_dir / f"{base_name}.ssl.json"
    vt_path = run_dir / f"{base_name}.vt.json"
    opentip_path = run_dir / f"{base_name}.opentip.json"
    html_path = run_dir / f"{base_name}.html"
    network_path = run_dir / f"{base_name}.network.json"

    # Загрузка артефактов с диска (если не переданы)
    if ssl_data is None:
        ssl_data = _load_json_if_exists(ssl_path)
    if vt_data is None:
        vt_data = _load_json_if_exists(vt_path)
    if opentip_data is None:
        opentip_data = _load_json_if_exists(opentip_path)
    if html_text is None:
        html_text = _load_html_if_exists(html_path)
    if network_data is None:
        network_data = _load_json_if_exists(network_path)

    score = 0
    details: Dict[str, Any] = {}

    # Анализ SSL/TLS
    ssl_score, ssl_details = _analyze_ssl(ssl_data)
    score += ssl_score
    details["ssl"] = ssl_details

    # Анализ VirusTotal
    vt_score, vt_details = _analyze_vt(vt_data)
    score += vt_score
    details["virustotal"] = vt_details

    # Анализ OpenTIP
    ot_score, ot_details = _analyze_opentip(opentip_data)
    score += ot_score
    details["opentip"] = ot_details

    # Анализ TLD
    tld_score, tld_details = _analyze_domain_tld(final_url)
    score += tld_score
    details["tld"] = tld_details
    suspicious_tld = tld_details.get("suspicious_tld", False)

    # Обнаружение имитации брендов
    brand_score, brand_flags = _detect_brand_abuse(final_url)
    score += brand_score
    details["brand_abuse_subscore"] = brand_score
    details["brand_abuse_flags"] = brand_flags
    has_brand_abuse = bool(brand_flags)

    # Определение подозрительного контекста
    vt_pos = vt_details.get("vt_positives") or 0
    ot_flags = ot_details.get("raw_flags", []) or []
    has_ti_alert = bool(vt_pos and vt_pos > 0) or any(
        flag in ("malicious_or_phishing", "suspicious") for flag in ot_flags
    )

    suspicious_context = has_ti_alert or has_brand_abuse or suspicious_tld

    # Анализ HTML (контекстно-зависимый)
    html_score, html_details = _analyze_html(html_text, suspicious_context=suspicious_context)
    score += html_score
    details["html"] = html_details

    # Анализ сетевых артефактов
    net_score, net_details = _analyze_network(network_data, final_url)
    score += net_score
    details["network"] = net_details

    # Нормализация баллов (0-100)
    if score < 0:
        score = 0
    if score > 100:
        score = 100

    # Гарантия: Brand abuse → минимум "suspicious"
    if has_brand_abuse and score < 20:
        score = 20

    # Определение вердикта
    if score < 20:
        verdict = "legitimate"
    elif score < 50:
        verdict = "suspicious"
    else:
        verdict = "malicious"

    result = {
        "original_url": original_url,
        "final_url": final_url,
        "risk_score": score,
        "verdict": verdict,
        "details": details,
    }
    return result
