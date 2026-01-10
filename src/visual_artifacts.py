
from __future__ import annotations

import logging
from pathlib import Path

from selenium.webdriver.remote.webdriver import WebDriver

logger = logging.getLogger(__name__)


def save_screenshot(driver: WebDriver, base_path: Path) -> Path:
    """
    Сохраняет скриншот текущей страницы.
    """
    png_path = base_path.with_suffix(".png")
    try:
        driver.save_screenshot(str(png_path))
        logger.info("Скриншот сохранён: %s", png_path)
    except Exception as exc:  # noqa: BLE001
        logger.error("Не удалось сохранить скриншот %s: %s", png_path, exc)
    return png_path


def save_html(driver: WebDriver, base_path: Path) -> Path:
    """
    Сохраняет HTML-код текущей страницы.
    """
    html_path = base_path.with_suffix(".html")
    try:
        html = driver.page_source
        html_path.write_text(html, encoding="utf-8")
        logger.info("HTML сохранён: %s", html_path)
    except Exception as exc:  # noqa: BLE001
        logger.error("Не удалось сохранить HTML %s: %s", html_path, exc)
    return html_path
