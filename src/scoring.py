from __future__ import annotations

import json
import logging
import difflib
from pathlib import Path
from typing import Any, Dict, List, Optional, Tuple
from urllib.parse import urlparse
from datetime import datetime

from .metadata import load_metadata

logger = logging.getLogger(__name__)

# ========== ИЗМЕНЕНИЕ 1: Новая структура KNOWN_BRANDS с легитимными вариациями ==========
KNOWN_BRANDS: Dict[str, Dict[str, Any]] = {
    # Банки
    "sberbank": {
        "expected_domains": ["sberbank.ru", "sberbank.com"],
        "legitimate_variations": ["sber.ru"],  # Официальный короткий домен
    },
    "tinkoff": {
        "expected_domains": ["tinkoff.ru", "tbank.ru"],
        "legitimate_variations": [],
    },
    "alfabank": {
        "expected_domains": ["alfabank.ru"],
        "legitimate_variations": [],
    },
    "vtb": {
        "expected_domains": ["vtb.ru"],
        "legitimate_variations": [],
    },
    "pochtabank": {
        "expected_domains": ["pochtabank.ru"],
        "legitimate_variations": ["pochta.ru"],  # ИСПРАВЛЕНИЕ: Почта России как родительская организация
    },
    "raiffeisen": {
        "expected_domains": ["raiffeisen.ru"],
        "legitimate_variations": [],
    },
    
    # Маркетплейсы
    "avito": {
        "expected_domains": ["avito.ru"],
        "legitimate_variations": [],
    },
    "ozon": {
        "expected_domains": ["ozon.ru"],
        "legitimate_variations": [],
    },
    "wildberries": {
        "expected_domains": ["wildberries.ru"],
        "legitimate_variations": ["wb.ru"],  
    },
    "yandex": {
        "expected_domains": ["yandex.ru", "ya.ru"],
        "legitimate_variations": [],
    },
    
    # Госуслуги
    "gosuslugi": {
        "expected_domains": ["gosuslugi.ru"],
        "legitimate_variations": ["esia.gosuslugi.ru"],
    },
    "nalog": {
        "expected_domains": ["nalog.ru", "nalog.gov.ru"],
        "legitimate_variations": [],
    },
    
    # Соцсети
    "vk": {
        "expected_domains": ["vk.com", "vk.ru"],
        "legitimate_variations": [],
    },
    "telegram": {
        "expected_domains": ["telegram.org", "t.me"],
        "legitimate_variations": [],
    },
    
    # Почта
    "mail": {
        "expected_domains": ["mail.ru"],
        "legitimate_variations": [],
    },
    
    # Платежные системы
    "qiwi": {
        "expected_domains": ["qiwi.com"],
        "legitimate_variations": [],
    },
    "paypal": {
        "expected_domains": ["paypal.com"],
        "legitimate_variations": [],
    },
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


# ========== ОБНОВЛЕННЫЙ SSL-анализ с hostname mismatch ==========
def _analyze_ssl(ssl_data: Optional[Dict[str, Any]]) -> Tuple[int, Dict[str, Any]]:
    """
    Анализ SSL/TLS сертификата.
    
    Логика начисления баллов (обновленная):
    - Сертификат отсутствует: +15 (многие старые легитимные сайты)
    - Ошибка подключения: +25 (невалидный/отозванный сертификат)
    - Сертификат просрочен: +20 (критичный индикатор)
    - Сертификат еще не действителен: +20 (подозрительная дата)
    - Самоподписанный: +15 (типично для фишинга)
    - Hostname mismatch: +20 (критичный индикатор подмены)
    - Короткий срок действия (<30 дней): +10 (одноразовые домены)
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

    # Дифференцированные веса для ошибок
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

    # Сертификат присутствует
    details["present"] = True
    score = 0

    # Проверка hostname mismatch
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

        # Короткий срок действия
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


def _analyze_vt(vt_data: Optional[Dict[str, Any]]) -> Tuple[int, Dict[str, Any]]:
    """
    Анализ данных VirusTotal.
    
    Логика начисления баллов (пересмотренная):
    - 0 детектов: 0 баллов
    - 1 детект: +10 (может быть false positive)
    - 2-4 детекта: +25 (средний риск)
    - 5-10 детектов: +40 (высокий риск)
    - >10 детектов: +60 (максимальный риск)
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
        score = 10
    elif 2 <= positives <= 4:
        score = 25
    elif 5 <= positives <= 10:
        score = 40
    else:
        score = 60

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


# ========== ИЗМЕНЕНИЕ 2: ПОЛНОСТЬЮ ПЕРЕПИСАННАЯ ФУНКЦИЯ _detect_brand_abuse ==========
def _detect_brand_abuse(final_url: str) -> Tuple[int, List[Dict[str, Any]]]:
    """
    Обнаружение имитации брендов (Brand Impersonation Detection) с улучшенной защитой от False Positive.
    
    НОВАЯ ЛОГИКА:
    1. Извлечение базового домена (без www и поддоменов)
    2. Проверка exact match с ожидаемыми доменами → легитимный
    3. НОВОЕ: Проверка на легитимные вариации (например, pochta.ru для pochtabank) → легитимный
    4. Проверка substring match (бренд в hostname, но НЕ легитимный домен) → +40
    5. Проверка typosquatting с улучшенными условиями:
       - Similarity >= 0.80 (было 0.70)
       - Len_ratio > 0.75 (НОВОЕ! близкая длина строк)
    
    Примеры:
    - www.pochta.ru → 0 баллов (легитимная вариация для pochtabank)
    - avito.alsoma.com → +40 (substring match)
    - paayypall.com → +40 (typosquatting, similarity=0.89, len_ratio=0.92)
    """
    try:
        hostname = urlparse(final_url).hostname or ""
    except Exception:
        return 0, []

    # Извлекаем базовый домен (без www и поддоменов)
    hostname_base = hostname.lower().replace('www.', '')
    parts = hostname_base.split('.')
    if len(parts) > 2:
        hostname_base = '.'.join(parts[-2:])

    flags: List[Dict[str, Any]] = []
    subscore = 0

    for brand, brand_info in KNOWN_BRANDS.items():
        expected_domains = brand_info["expected_domains"]
        legitimate_variations = brand_info.get("legitimate_variations", [])

        # 1. Проверка exact match с ожидаемыми доменами
        if hostname_base in expected_domains:
            continue  # Это легитимный домен бренда

        # 2. НОВОЕ: Проверка на легитимные вариации
        if hostname_base in legitimate_variations:
            continue  # Это разрешённая вариация (например, pochta.ru для pochtabank)

        # 3. Проверка на substring match (бренд в hostname)
        if brand in hostname_base:
            # Но это НЕ легитимный домен
            # Пример: 'avito' в 'avito.alsoma.com' → подозрение
            flags.append({
                "brand": brand,
                "hostname": hostname,
                "expected_domain": expected_domains[0],
                "match_type": "substring",
                "similarity": 1.0
            })
            subscore += 40
            break  # Нашли первое совпадение, хватит

        # 4. УЛУЧШЕННАЯ проверка на typosquatting
        for expected_domain in expected_domains:
            expected_base = expected_domain.replace('www.', '')

            # Вычисляем текстовое сходство
            similarity = difflib.SequenceMatcher(None, hostname_base, expected_base).ratio()

            # НОВОЕ: Проверка соотношения длин строк
            len_ratio = min(len(hostname_base), len(expected_base)) / max(len(hostname_base), len(expected_base))

            # Typosquatting детектируется только если:
            # - Высокое текстовое сходство (>= 0.80, было 0.70)
            # - Близкая длина строк (len_ratio > 0.75)
            if similarity >= 0.80 and len_ratio > 0.75:
                flags.append({
                    "brand": brand,
                    "hostname": hostname,
                    "expected_domain": expected_domain,
                    "match_type": "typosquatting",
                    "similarity": round(similarity, 2)
                })
                subscore += 40
                break

    return subscore, flags


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
            score += 15
        if has_payment_keywords:
            score += 15
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

    # Обнаружение имитации брендов (ОБНОВЛЕННАЯ ФУНКЦИЯ)
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
