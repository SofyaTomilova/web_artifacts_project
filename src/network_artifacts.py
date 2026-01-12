
from __future__ import annotations

import json
import logging
from pathlib import Path
from typing import Any

from selenium.webdriver.remote.webdriver import WebDriver

logger = logging.getLogger(__name__)


def collect_network_artifacts(driver: WebDriver, base_path: Path) -> Path:

    log_path = base_path.with_suffix(".network.json")
    try:
        raw_logs = driver.get_log("performance")
        events: list[dict[str, Any]] = []
        for entry in raw_logs:
            try:
                message = json.loads(entry.get("message", "{}"))
            except json.JSONDecodeError:
                logger.debug("Не удалось разобрать одно из сообщений performance-лога")
                continue
            events.append(message)
        log_path.write_text(json.dumps(events, ensure_ascii=False, indent=2), encoding="utf-8")
        logger.info("Сетевые артефакты сохранены: %s", log_path)
    except Exception as exc:  
        logger.error("Ошибка при получении performance-логов: %s", exc)
    return log_path
