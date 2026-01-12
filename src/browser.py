from __future__ import annotations

import logging
from typing import Optional

from selenium import webdriver
from selenium.webdriver.chrome.options import Options
from selenium.webdriver.remote.webdriver import WebDriver

logger = logging.getLogger(__name__)


def create_driver(headless: bool = True, performance_logging: bool = True) -> WebDriver:
    chrome_options = Options()
    if headless:
        chrome_options.add_argument("--headless=new")

    chrome_options.add_argument("--disable-gpu")
    chrome_options.add_argument("--no-sandbox")
    chrome_options.add_argument("--disable-dev-shm-usage")
    chrome_options.add_argument("--window-size=1366,768")

    if performance_logging:
        chrome_options.set_capability("goog:loggingPrefs", {"performance": "ALL"})

    driver = webdriver.Chrome(options=chrome_options)
    logger.debug("Создан экземпляр Chrome WebDriver")
    return driver


def close_driver(driver: Optional[WebDriver]) -> None:
    if driver is None:
        return
    try:
        driver.quit()
        logger.debug("WebDriver корректно завершён")
    except Exception as exc: 
        logger.warning("Ошибка при завершении WebDriver: %s", exc)
