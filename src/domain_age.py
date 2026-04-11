"""
Определение возраста домена через WHOIS.

Фишинговые домены живут в среднем 24–72 часа (данные APWG).
Домен младше 30 дней — подозрительный признак.
"""

import logging
from datetime import datetime, timezone
from typing import Optional

logger = logging.getLogger(__name__)


def get_domain_age_days(hostname: str) -> Optional[int]:
    """
    Возвращает возраст домена в днях или None, если не удалось определить.

    Примеры:
    - google.com → ~9000+ дней
    - новый фишинговый домен → 1-3 дня
    - приватный домен без WHOIS → None
    """
    try:
        import whois
    except ImportError:
        logger.warning("python-whois не установлен. Установите: pip install python-whois")
        return None

    # Убираем www. и приводим к нижнему регистру
    domain = hostname.lower().replace("www.", "")

    # Если это IP-адрес — WHOIS не применим
    if domain.replace(".", "").isdigit():
        return None

    try:
        w = whois.whois(domain)
    except Exception as e:
        logger.debug("WHOIS-запрос для %s завершился с ошибкой: %s", domain, e)
        return None

    # WHOIS может вернуть несколько дат для registrar — берём самую раннюю
    creation_date = w.creation_date
    if creation_date is None:
        return None

    # creation_date может быть списком или одиночным значением
    if isinstance(creation_date, list):
        # Берём самую раннюю дату
        dates = [d for d in creation_date if d is not None]
        if not dates:
            return None
        earliest = min(dates)
    else:
        earliest = creation_date

    # Приводим к datetime с timezone
    if earliest.tzinfo is None:
        earliest = earliest.replace(tzinfo=timezone.utc)
    else:
        earliest = earliest.astimezone(timezone.utc)

    now = datetime.now(timezone.utc)
    age_days = (now - earliest).days

    return age_days if age_days >= 0 else None
