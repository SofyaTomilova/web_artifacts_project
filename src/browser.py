from __future__ import annotations

import logging
import time
from typing import Optional, Tuple

from selenium import webdriver
from selenium.webdriver.chrome.options import Options
from selenium.webdriver.chrome.service import Service
from selenium.common.exceptions import TimeoutException, WebDriverException
from selenium.webdriver.common.by import By
from selenium.webdriver.support.ui import WebDriverWait
from selenium.webdriver.support import expected_conditions as EC

logger = logging.getLogger(__name__)

def create_driver(
    headless: bool = True,
    performance_logging: bool = True,
    page_load_timeout: int = 45,
) -> webdriver.Chrome:

    options = Options()
    if headless:
        options.add_argument("--headless=new")

    options.add_argument("--no-sandbox")
    options.add_argument("--disable-dev-shm-usage")
    options.add_argument("--disable-gpu")
    options.add_argument("--window-size=1920,1080")
    options.add_argument("--disable-extensions")
    options.add_argument("--disable-infobars")

    if performance_logging:
        options.set_capability("goog:loggingPrefs", {"performance": "ALL"})

    driver = webdriver.Chrome(options=options)
    driver.set_page_load_timeout(page_load_timeout)

    return driver


def close_driver(driver: Optional[webdriver.Chrome]) -> None:

    if driver is None:
        return
    try:
        driver.quit()
    except Exception as exc:
        logger.debug("Ошибка при закрытии драйвера: %s", exc)


def load_url_with_timeout_handling(
    driver: webdriver.Chrome,
    url: str,
) -> Tuple[bool, str]:

    try:
        driver.get(url)
        
        time.sleep(2)
        return True, "Page loaded successfully"

    except TimeoutException:
        
        
        logger.warning("Тайм-аут загрузки страницы: %s", url)
        return False, "Timeout"

    except WebDriverException as exc:
        error_msg = str(exc)
        if "ERR_NAME_NOT_RESOLVED" in error_msg or "net::ERR_NAME_NOT_RESOLVED" in error_msg:
            return False, f"DNS error: domain not found"
        elif "ERR_CONNECTION_REFUSED" in error_msg:
            return False, f"Connection refused"
        elif "ERR_CONNECTION_TIMED_OUT" in error_msg:
            return False, f"Connection timed out"
        elif "net::ERR_SSL" in error_msg:
            return False, f"SSL error"
        else:
            return False, f"WebDriver error: {error_msg[:200]}"

    except Exception as exc:
        return False, f"Unexpected error: {str(exc)[:200]}"