from __future__ import annotations

import json
import logging
from pathlib import Path
from typing import Any, Dict, List, Optional, Tuple
from urllib.parse import urlparse
from datetime import datetime

from .metadata import load_metadata  # импортим наш модуль с метаданными

logger = logging.getLogger(__name__)

# Бренды и "правильные" домены
BRAND_DOMAINS: Dict[str, str] = {
    "avito": "avito.ru",
    "sber": "sberbank.ru",
    "sberbank": "sberbank.ru",
    "pochtabank": "pochtabank.ru",
    "ozon": "ozon.ru",
}

# "Сомнительные" зоны
SUSPICIOUS_TLDS = {
    "xyz", "top", "icu", "click", "gq", "cf", "tk", "ml", "ga", "sbs",
}

# Ключевые слова в HTML
LOGIN_KEYWORDS = [
    "login", "sign in", "sign-in", "signin",
    "логин", "войти", "личный кабинет", "кабинет клиента",
]
PAYMENT_KEYWORDS = [
    "payment", "pay now", "secure payment", "confirm payment",
    "оплата", "оплатить", "подтвердите оплату", "подтвердить платеж",
]


def _load_json_if_exists(path: Path) -> Optional[Any]:
    if not path.exists():
        return None
    try:
        with path.open("r", encoding="utf-8") as f:
            return json.load(f)
    except Exception as e:
        logger.warning("Не удалось прочитать JSON %s: %s", path, e)
        return None


def _load_html_if_exists(path: Path) -> Optional[str]:
    if not path.exists():
        return None
    try:
        with path.open("r", encoding="utf-8", errors="ignore") as f:
            return f.read()
    except Exception as e:
        logger.warning("Не удалось прочитать HTML %s: %s", path, e)
        return None


def _parse_ssl_time(value: str) -> Optional[datetime]:
    """
    Парсинг времени в формате OpenSSL: 'Nov 19 11:03:49 2025 GMT'
    """
    try:
        return datetime.strptime(value, "%b %d %H:%M:%S %Y %Z")
    except Exception:
        return None

def _analyze_ssl(ssl_data):
    """
    Очень простая логика:
    - если ssl_data содержит "error": даём большой штраф +40
    - если сертификат есть, анализируем даты
    - если ssl_data = None → +20 (сертификата нет вообще)
    """

    details = {
        "present": False,
        "expired": None,
        "not_yet_valid": None,
        "self_signed": None,
        "not_before": None,
        "not_after": None,
        "error": None
    }

    # Нет файла — значит вообще нет сертификата
    if ssl_data is None:
        return 20, details

    # Если внутри ошибка — штрафуем
    if "error" in ssl_data:
        details["error"] = ssl_data["error"]
        return 40, details

    # Сертификат есть
    details["present"] = True
    score = -5   # за сам факт наличия

    # Даты сертификата
    nb = ssl_data.get("notBefore")
    na = ssl_data.get("notAfter")
    details["not_before"] = nb
    details["not_after"] = na

    # Пробуем парсить даты
    try:
        from datetime import datetime
        nb_dt = datetime.strptime(nb, "%b %d %H:%M:%S %Y %Z") if nb else None
        na_dt = datetime.strptime(na, "%b %d %H:%M:%S %Y %Z") if na else None
        now = datetime.utcnow()

        if na_dt and now > na_dt:   # просрочен
            details["expired"] = True
            score += 15

        if nb_dt and now < nb_dt:   # ещё не начинается
            details["not_yet_valid"] = True
            score += 15

    except:
        pass  # если дата кривая — ничего не делаем

    # Проверяем самоподписанность
    subj = ssl_data.get("subject")
    issu = ssl_data.get("issuer")
    if subj and issu and subj == issu:
        details["self_signed"] = True
        score += 10

    return score, details

def _analyze_vt(vt_data):
    logger.warning("VT DEBUG: vt_data keys = %s", list(vt_data.keys()) if vt_data else None)

    details = {
        "vt_positives": None,
        "vt_total": None
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

    if positives == 0:
        score = 0
    elif positives == 1:
        score = 15
    elif 2 <= positives <= 4:
        score = 30
    elif 5 <= positives <= 10:
        score = 50
    else:
        score = 70

    return score, details


def _analyze_opentip(opentip_data: Optional[Any]) -> Tuple[int, Dict[str, Any]]:
    """
    Эвристика по ответу OpenTIP:
    ищем в сыром JSON-строке ключевые слова.
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


def _detect_brand_abuse(final_url: str) -> Tuple[int, List[Dict[str, Any]]]:
    """
    Эвристика злоупотребления брендом в доменном имени.
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
        return 30, flags  # +30 за факт злоупотребления брендом

    return 0, []


def _analyze_domain_tld(final_url: str) -> Tuple[int, Dict[str, Any]]:
    """
    Эвристика по зоне домена (TLD).
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
    Контентная эвристика по HTML:
    логин/пароль, платёжные формы.

    Вариант 2:
    - если контекст подозрительный (TI/TLD/brand), даём до +20;
    - если контекст нормальный, максимум +5.
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
        # Подозрительный контекст: даём полную силу HTML
        if has_password_input or has_login_keywords:
            score += 10
        if has_payment_keywords:
            score += 10
        if score > 20:
            score = 20
    else:
        # Нормальный домен без TI-сигналов: HTML почти не влияет
        score = 5

    return score, details


def _analyze_network(
    network_data: Optional[Any],
    final_url: str,
) -> Tuple[int, Dict[str, Any]]:
    """
    Эвристика по сетевым артефактам: количество сторонних доменов.
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

    # Если среди сторонних доменов есть подозрительные TLD — ещё +5
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
    # новые опциональные данные, которые можем передать из executor
    ssl_data: Optional[Dict[str, Any]] = None,
    vt_data: Optional[Dict[str, Any]] = None,
    opentip_data: Optional[Dict[str, Any]] = None,
    html_text: Optional[str] = None,
    network_data: Optional[Any] = None,
    **kwargs,
) -> Dict[str, Any]:
    """
    Основная функция скоринга.

    Поддерживает вызовы:
    - compute_risk_score(run_dir, base_name)
    - compute_risk_score(run_dir, base_name, final_url=...)
    - compute_risk_score(run_dir, base_name, original_url=..., final_url=...)
    - плюс можем сразу передать ssl_data / vt_data / opentip_data и т.п.
    """

    # Если что-то передали через kwargs – тоже подхватываем
    if "original_url" in kwargs and original_url is None:
        original_url = kwargs["original_url"]
    if "final_url" in kwargs and final_url is None:
        final_url = kwargs["final_url"]

    run_dir = Path(run_dir)

    # Если URL не передали – пробуем вытащить их из метаданных
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

    # Если всё равно нет final_url – подстрахуемся
    if final_url is None and original_url is not None:
        final_url = original_url
    if original_url is None and final_url is not None:
        original_url = final_url

    if final_url is None:
        raise ValueError("final_url не удалось определить ни из аргументов, ни из метаданных")

    # --- пути к файлам артефактов ---
    ssl_path = run_dir / f"{base_name}.ssl.json"
    vt_path = run_dir / f"{base_name}.vt.json"
    opentip_path = run_dir / f"{base_name}.opentip.json"
    html_path = run_dir / f"{base_name}.html"
    network_path = run_dir / f"{base_name}.network.json"

    # --- если данные не передали, пробуем читать с диска ---
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

    # (если ставила отладку VT DEBUG — можно удалить/закомментить)
    # logger.warning("VT DEBUG: vt_data keys = %s", list(vt_data.keys()) if vt_data else None)

    score = 0
    details: Dict[str, Any] = {}

    # --- SSL ---
    ssl_score, ssl_details = _analyze_ssl(ssl_data)
    score += ssl_score
    details["ssl"] = ssl_details

    # --- VirusTotal ---
    vt_score, vt_details = _analyze_vt(vt_data)
    score += vt_score
    details["virustotal"] = vt_details

    # --- OpenTIP ---
    ot_score, ot_details = _analyze_opentip(opentip_data)
    score += ot_score
    details["opentip"] = ot_details

    # --- TLD ---
    tld_score, tld_details = _analyze_domain_tld(final_url)
    score += tld_score
    details["tld"] = tld_details
    suspicious_tld = tld_details.get("suspicious_tld", False)

    # --- Brand abuse ---
    brand_score, brand_flags = _detect_brand_abuse(final_url)
    score += brand_score
    details["brand_abuse_subscore"] = brand_score
    details["brand_abuse_flags"] = brand_flags
    has_brand_abuse = bool(brand_flags)

    # --- Контекст для HTML: TI/TLD/brand ---
    vt_pos = vt_details.get("vt_positives") or 0
    ot_flags = ot_details.get("raw_flags", []) or []
    has_ti_alert = bool(vt_pos and vt_pos > 0) or any(
        flag in ("malicious_or_phishing", "suspicious") for flag in ot_flags
    )

    suspicious_context = has_ti_alert or has_brand_abuse or suspicious_tld

    # --- HTML ---
    html_score, html_details = _analyze_html(html_text, suspicious_context=suspicious_context)
    score += html_score
    details["html"] = html_details

    # --- Network ---
    net_score, net_details = _analyze_network(network_data, final_url)
    score += net_score
    details["network"] = net_details

    # --- Нормализация ---
    if score < 0:
        score = 0
    if score > 100:
        score = 100

    # Гарантия: если злоупотребление брендом есть, минимум "suspicious"
    if has_brand_abuse and score < 20:
        score = 20

    # --- Вердикт ---
    if score < 20:
        verdict = "legit"
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
