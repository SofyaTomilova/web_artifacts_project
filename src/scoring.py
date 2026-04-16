from __future__ import annotations

import json
import logging
import difflib
import re
from pathlib import Path
from typing import Any, Dict, List, Optional, Tuple
from urllib.parse import urlparse
from datetime import datetime, timezone

from .metadata import load_metadata
from .tranco_whitelist import is_in_tranco_top10k
from .domain_age import get_domain_age_days

logger = logging.getLogger(__name__)

_brands_path = Path(__file__).parent / "brands.json"
KNOWN_BRANDS: Dict[str, Dict[str, Any]] = json.loads(_brands_path.read_text(encoding="utf-8")) if _brands_path.exists() else {}

SUSPICIOUS_TLDS = {
    "xyz", "top", "icu", "click", "gq", "cf", "tk", "ml", "ga", "sbs",
    "pw", "cc", "ws", "info", "biz", "me",
}

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


def _analyze_ssl(ssl_data: Optional[Dict[str, Any]]) -> Tuple[int, Dict[str, Any]]:
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

    if ssl_data is None:
        return 15, details

    if "error" in ssl_data:
        error_msg = ssl_data["error"].lower()
        details["error"] = ssl_data["error"]
        
        if "ssl error" in error_msg or "certificate" in error_msg:
            return 25, details
        if "dns" in error_msg or "not found" in error_msg:
            return 20, details
        if "timeout" in error_msg:
            return 10, details
        return 15, details

    details["present"] = True
    score = 0

    if ssl_data.get("hostname_mismatch"):
        details["hostname_mismatch"] = True
        score += 20

    nb = ssl_data.get("notBefore")
    na = ssl_data.get("notAfter")
    details["not_before"] = nb
    details["not_after"] = na

    try:
        if nb and "T" in nb:
            nb_dt = datetime.fromisoformat(nb.replace("Z", "+00:00"))
        elif nb:
            nb_dt = datetime.strptime(nb, "%b %d %H:%M:%S %Y %Z")
        else:
            nb_dt = None

        if na and "T" in na:
            na_dt = datetime.fromisoformat(na.replace("Z", "+00:00"))
        elif na:
            na_dt = datetime.strptime(na, "%b %d %H:%M:%S %Y %Z")
        else:
            na_dt = None

        now = datetime.now(tz=timezone.utc)

        if nb_dt and nb_dt.tzinfo is None:
            nb_dt = nb_dt.replace(tzinfo=timezone.utc)
        if na_dt and na_dt.tzinfo is None:
            na_dt = na_dt.replace(tzinfo=timezone.utc)

        if na_dt and now > na_dt:
            details["expired"] = True
            score += 20

        if nb_dt and now < nb_dt:
            details["not_yet_valid"] = True
            score += 20

        if na_dt and nb_dt:
            validity_days = (na_dt - nb_dt).days
            if validity_days < 30:
                details["short_validity"] = True
                score += 10

    except Exception as e:
        logger.debug("Ошибка парсинга дат сертификата: %s", e)

    subj = ssl_data.get("subject")
    issu = ssl_data.get("issuer")
    if subj and issu and subj == issu:
        details["self_signed"] = True
        score += 15

    return score, details


def _analyze_vt(vt_data: Optional[Dict[str, Any]]) -> Tuple[int, Dict[str, Any]]:
    """Анализ данных VirusTotal."""
    details = {
        "vt_positives": None,
        "vt_total": None,
    }

    if not vt_data:
        return 0, details

    stats = vt_data.get("raw", {}).get("data", {}).get("attributes", {}).get("last_analysis_stats", {})

    if not stats:
        return 0, details

    positives = stats.get("malicious", 0) + stats.get("suspicious", 0)
    total = sum(stats.values()) if stats else None

    details["vt_positives"] = positives
    details["vt_total"] = total

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
    is_malicious = "malicious" in raw or "phishing" in raw

    if is_malicious:
        score += 40
        details["raw_flags"].append("malicious_or_phishing")
    elif "suspicious" in raw:
        score += 20
        details["raw_flags"].append("suspicious")

    if not is_malicious and ("clean" in raw or "benign" in raw):
        details["raw_flags"].append("clean_or_benign")

    return score, details

def _detect_brand_abuse(final_url: str) -> Tuple[int, List[Dict[str, Any]]]:
    try:
        hostname = urlparse(final_url).hostname or ""
    except Exception:
        return 0, []

    hostname_lower = hostname.lower()
    hostname_clean = hostname_lower.replace('www.', '')

    if is_in_tranco_top10k(hostname_clean):
        return 0, []

    flags: List[Dict[str, Any]] = []
    subscore = 0

    for brand, brand_info in KNOWN_BRANDS.items():
        expected_domains = brand_info["expected_domains"]
        legitimate_variations = brand_info.get("legitimate_variations", [])

        brand_already_flagged = False

        if hostname_clean in expected_domains:
            continue

        if hostname_clean in legitimate_variations:
            continue

        if len(brand) < 4:
            segments = hostname_clean.split('.')
            if brand not in segments:
                continue

        if brand in hostname_clean:
            is_legitimate = False
            for expected_domain in expected_domains:
                if hostname_clean.endswith(expected_domain):
                    is_legitimate = True
                    break

            if not is_legitimate:
                flags.append({
                    "brand": brand,
                    "hostname": hostname,
                    "expected_domain": expected_domains[0],
                    "match_type": "substring",
                    "similarity": 1.0
                })
                subscore = min(subscore + 40, 40)  
                brand_already_flagged = True

        if not brand_already_flagged:
            parts = hostname_clean.split('.')
            if len(parts) < 2:
                continue  
            domain_without_tld = parts[-2]
            if len(domain_without_tld) < 4:
                continue  

            for expected_domain in expected_domains:
                expected_parts = expected_domain.split('.')
                expected_without_tld = expected_parts[-2] if len(expected_parts) >= 2 else expected_domain

                similarity = difflib.SequenceMatcher(None, domain_without_tld, expected_without_tld).ratio()
                len_ratio = min(len(domain_without_tld), len(expected_without_tld)) / max(len(domain_without_tld), len(expected_without_tld))

                if similarity >= 0.80 and len_ratio > 0.75:
                    if domain_without_tld != expected_without_tld:
                        flags.append({
                            "brand": brand,
                            "hostname": hostname,
                            "expected_domain": expected_domain,
                            "match_type": "typosquatting",
                            "similarity": round(similarity, 2),
                            "domain_comparison": f"{domain_without_tld} vs {expected_without_tld}"
                        })
                        subscore = min(subscore + 40, 40)  

    return subscore, flags


def _analyze_domain_tld(final_url: str) -> Tuple[int, Dict[str, Any]]:
    """Анализ доменной зоны (TLD)."""
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
        return 15, details

    return 0, details


def _analyze_html(
    html_text: Optional[str],
    suspicious_context: bool,
) -> Tuple[int, Dict[str, Any]]:
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
        if has_password_input or has_login_keywords:
            score += 15
        if has_payment_keywords:
            score += 15
        if score > 20:
            score = 20
    else:
        score = 5

    return score, details


def _get_root_domain(hostname: str) -> str:
    parts = hostname.lower().split('.')
    return '.'.join(parts[-2:]) if len(parts) >= 2 else hostname


def _analyze_network(
    network_data: Optional[Any],
    final_url: str,
) -> Tuple[int, Dict[str, Any]]:
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
    main_root = _get_root_domain(main_host)

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
        if not host:
            continue
        host_root = _get_root_domain(host)
        if host_root != main_root:
            third_party_hosts.add(host)

    details["total_requests"] = total_requests
    details["third_party_hosts"] = sorted(third_party_hosts)

    score = 0
    if len(third_party_hosts) >= 5:
        score += 5

    for h in third_party_hosts:
        parts = h.split(".")
        tld = parts[-1] if parts else ""
        if tld in SUSPICIOUS_TLDS:
            score += 5
            break

    return score, details

def _analyze_redirect(original_url: str, final_url: str) -> Tuple[int, Dict[str, Any]]:

    details: Dict[str, Any] = {
        "has_redirect": False,
        "suspicious_redirect": False,
        "redirect_scheme": None,
    }
    
    if not original_url or not final_url or original_url == final_url:
        return 0, details
    
    details["has_redirect"] = True
    
    suspicious_schemes = ["data:", "about:", "javascript:", "file:"]
    
    for scheme in suspicious_schemes:
        if final_url.startswith(scheme):
            details["suspicious_redirect"] = True
            details["redirect_scheme"] = scheme.replace(":", "")
            logger.warning("Подозрительный редирект: %s → %s", original_url, final_url)
            return 15, details
    
    if final_url in ("data:,", "about:blank"):
        details["suspicious_redirect"] = True
        details["redirect_scheme"] = "empty"
        return 10, details
    
    return 0, details


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

    if "original_url" in kwargs and original_url is None:
        original_url = kwargs["original_url"]
    if "final_url" in kwargs and final_url is None:
        final_url = kwargs["final_url"]

    run_dir = Path(run_dir)

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

    ssl_path = run_dir / f"{base_name}.ssl.json"
    vt_path = run_dir / f"{base_name}.vt.json"
    opentip_path = run_dir / f"{base_name}.opentip.json"
    html_path = run_dir / f"{base_name}.html"
    network_path = run_dir / f"{base_name}.network.json"

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

    try:
        final_hostname = urlparse(final_url).hostname or ""
        is_trusted_domain = is_in_tranco_top10k(final_hostname)
    except Exception:
        is_trusted_domain = False

    ssl_score, ssl_details = _analyze_ssl(ssl_data)

    if is_trusted_domain and ssl_details.get("error"):
        error_lower = (ssl_details.get("error") or "").lower()
        if "certificate" in error_lower or "ssl error" in error_lower:
            ssl_score = min(ssl_score, 5)

    score += ssl_score
    details["ssl"] = ssl_details

    vt_score, vt_details = _analyze_vt(vt_data)
    score += vt_score
    details["virustotal"] = vt_details

    ot_score, ot_details = _analyze_opentip(opentip_data)
    score += ot_score
    details["opentip"] = ot_details

    tld_score, tld_details = _analyze_domain_tld(final_url)
    score += tld_score
    details["tld"] = tld_details
    suspicious_tld = tld_details.get("suspicious_tld", False)

    try:
        hostname = urlparse(final_url).hostname or ""
        domain_age_days = get_domain_age_days(hostname)
    except Exception as e:
        logger.debug("Не удалось определить возраст домена: %s", e)
        domain_age_days = None

    domain_age_details = {"age_days": domain_age_days, "young_domain": False}
    if domain_age_days is not None and domain_age_days < 30:
        score += 15
        domain_age_details["young_domain"] = True
    details["domain_age"] = domain_age_details

    brand_score_final, brand_flags_final = _detect_brand_abuse(final_url)
    
    brand_score_original = 0
    brand_flags_original = []
    if original_url and original_url != final_url:
        brand_score_original, brand_flags_original = _detect_brand_abuse(original_url)
    
    brand_score = max(brand_score_final, brand_score_original)
    brand_flags = brand_flags_final + brand_flags_original
    
    seen = set()
    unique_flags = []
    for flag in brand_flags:
        flag_key = (flag.get("brand"), flag.get("hostname"))
        if flag_key not in seen:
            seen.add(flag_key)
            unique_flags.append(flag)
    
    score += brand_score
    details["brand_abuse_subscore"] = brand_score
    details["brand_abuse_flags"] = unique_flags
    has_brand_abuse = bool(unique_flags)

    redirect_score, redirect_details = _analyze_redirect(original_url, final_url)
    score += redirect_score
    details["redirect"] = redirect_details

    vt_pos = vt_details.get("vt_positives") or 0
    ot_flags = ot_details.get("raw_flags", []) or []
    has_ti_alert = bool(vt_pos and vt_pos > 0) or any(
        flag in ("malicious_or_phishing", "suspicious") for flag in ot_flags
    )

    suspicious_context = has_ti_alert or has_brand_abuse or suspicious_tld

    html_score, html_details = _analyze_html(html_text, suspicious_context=suspicious_context)
    score += html_score
    details["html"] = html_details

    net_score, net_details = _analyze_network(network_data, final_url)
    score += net_score
    details["network"] = net_details

    if score < 0:
        score = 0
    if score > 100:
        score = 100

    if has_brand_abuse and score < 20:
        score = 20

    if score < 20:
        verdict = "Легитимный"
    elif score < 50:
        verdict = "Подозрительный"
    else:
        verdict = "Вредоносный"

    result = {
        "original_url": original_url,
        "final_url": final_url,
        "risk_score": score,
        "verdict": verdict,
        "details": details,
    }
    return result