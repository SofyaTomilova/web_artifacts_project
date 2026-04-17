import logging
from datetime import datetime, timezone
from typing import Optional

logger = logging.getLogger(__name__)


def get_domain_age_days(hostname: str) -> Optional[int]:

    try:
        import whois
    except ImportError:
        logger.warning("python-whois не установлен. Установите: pip install python-whois")
        return None

    domain = hostname.lower().replace("www.", "")

    if domain.replace(".", "").isdigit():
        return None

    try:
        w = whois.whois(domain)
    except Exception as e:
        logger.debug("WHOIS-запрос для %s завершился с ошибкой: %s", domain, e)
        return None

    creation_date = w.creation_date
    if creation_date is None:
        return None

    if isinstance(creation_date, list):
        dates = [d for d in creation_date if d is not None]
        if not dates:
            return None
        earliest = min(dates)
    else:
        earliest = creation_date

    if earliest.tzinfo is None:
        earliest = earliest.replace(tzinfo=timezone.utc)
    else:
        earliest = earliest.astimezone(timezone.utc)

    now = datetime.now(timezone.utc)
    age_days = (now - earliest).days

    return age_days if age_days >= 0 else None
