import logging
from pathlib import Path
from typing import Optional, Set

logger = logging.getLogger(__name__)

TRANCO_CSV_PATH = Path(__file__).parent / "tranco_top10k.csv"
TRANCO_WHITELIST: Set[str] = set()


def load_tranco_whitelist(csv_path: Optional[Path] = None) -> Set[str]:
    global TRANCO_WHITELIST
    path = csv_path or TRANCO_CSV_PATH

    if not path.exists():
        logger.warning(
            "Tranco whitelist не найден: %s. "
            "Скачайте файл: "
            "curl -L https://tranco-list.eu/top-1m.csv.zip -o /tmp/tranco.zip "
            "&& unzip -p /tmp/tranco.zip | head -10000 > %s",
            path,
            path.name,
        )
        return set()

    domains: Set[str] = set()
    try:
        with path.open("r", encoding="utf-8") as f:
            for line in f:
                line = line.strip()
                if not line:
                    continue
                
                parts = line.split(",", 1)
                if len(parts) == 2:
                    domain = parts[1].lower().strip()
                    if domain:
                        domains.add(domain)
    except Exception as e:
        logger.error("Ошибка загрузки Tranco whitelist: %s", e)

    TRANCO_WHITELIST = domains
    logger.info("Загружено %d доменов в Tranco whitelist", len(domains))
    return domains


def is_in_tranco_top10k(hostname: str) -> bool:
    """Проверяет, входит ли hostname в Tranco Top-10k."""
    if not TRANCO_WHITELIST:
        load_tranco_whitelist()
    return hostname.lower().strip() in TRANCO_WHITELIST
