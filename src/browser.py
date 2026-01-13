from __future__ import annotations

import logging
from typing import Optional

from selenium import webdriver
from selenium.webdriver.chrome.options import Options
from selenium.webdriver.remote.webdriver import WebDriver
from selenium.common.exceptions import TimeoutException

logger = logging.getLogger(__name__)


def create_driver(
    headless: bool = True, 
    performance_logging: bool = True,
    page_load_timeout: int = 45,
) -> WebDriver:
    """
    Создание экземпляра Chrome WebDriver с оптимизированными настройками.
    
    Оптимизации для работы с тяжелыми сайтами (rbc.ru, avito.ru):
    1. page_load_strategy='eager' - не ждёт загрузки рекламы и медиаконтента
    2. Увеличенный timeout до 45 секунд (по умолчанию)
    3. Отключение уведомлений и всплывающих окон
    4. Performance logging для сбора сетевых артефактов
    
    Args:
        headless: Запуск в headless режиме (без GUI)
        performance_logging: Включить логирование сетевых событий через DevTools
        page_load_timeout: Таймаут загрузки страницы в секундах (по умолчанию 45)
    
    Returns:
        WebDriver: Экземпляр Chrome WebDriver
    
    Example:
        >>> driver = create_driver(headless=True, page_load_timeout=60)
        >>> driver.get("https://example.com")
    """
    chrome_options = Options()
    
    # ========== Режим headless ==========
    if headless:
        chrome_options.add_argument("--headless=new")
    
    # ========== Базовые настройки производительности ==========
    chrome_options.add_argument("--disable-gpu")
    chrome_options.add_argument("--no-sandbox")
    chrome_options.add_argument("--disable-dev-shm-usage")
    chrome_options.add_argument("--window-size=1366,768")
    
    # ========== НОВОЕ: Стратегия загрузки страницы ==========
    # 'normal' (по умолчанию) - ждёт полной загрузки всех ресурсов, включая рекламу
    # 'eager' - ждёт загрузки DOM и основных ресурсов, НЕ ждёт рекламу/медиа
    # 'none' - не ждёт вообще (самый быстрый, но может быть нестабильным)
    chrome_options.page_load_strategy = 'eager'
    logger.debug("Установлена стратегия загрузки: 'eager' (оптимизация для тяжелых сайтов)")
    
    # ========== НОВОЕ: Отключение уведомлений и всплывающих окон ==========
    chrome_options.add_argument("--disable-popup-blocking")
    chrome_options.add_argument("--disable-notifications")
    
    # ========== ОПЦИОНАЛЬНО: Блокировка изображений для ускорения ==========
    # Раскомментируйте следующий блок, если нужна максимальная скорость
    # ВНИМАНИЕ: Это повлияет на качество скриншотов!
    #
    # prefs = {
    #     "profile.managed_default_content_settings.images": 2,  # Блокировка изображений
    #     "profile.managed_default_content_settings.media_stream": 2,  # Блокировка видео
    # }
    # chrome_options.add_experimental_option("prefs", prefs)
    # logger.debug("Включена блокировка изображений и медиаконтента")
    
    # ========== Performance Logging для сбора сетевых артефактов ==========
    if performance_logging:
        chrome_options.set_capability("goog:loggingPrefs", {"performance": "ALL"})
        logger.debug("Включено логирование performance (сетевые артефакты)")
    
    # ========== Создание драйвера ==========
    try:
        driver = webdriver.Chrome(options=chrome_options)
        logger.debug("Создан экземпляр Chrome WebDriver")
    except Exception as exc:
        logger.error(f"Не удалось создать Chrome WebDriver: {exc}")
        raise
    
    # ========== НОВОЕ: Установка увеличенного timeout ==========
    driver.set_page_load_timeout(page_load_timeout)
    logger.debug(f"Установлен page_load_timeout: {page_load_timeout} секунд")
    
    # ========== НОВОЕ: Установка неявного ожидания для поиска элементов ==========
    driver.implicitly_wait(10)  # Ждём до 10 секунд при поиске элементов DOM
    logger.debug("Установлен implicit_wait: 10 секунд")
    
    return driver


def close_driver(driver: Optional[WebDriver]) -> None:
    """
    Корректное завершение работы WebDriver с обработкой ошибок.
    
    Args:
        driver: Экземпляр WebDriver для закрытия
    
    Example:
        >>> driver = create_driver()
        >>> try:
        ...     driver.get("https://example.com")
        ... finally:
        ...     close_driver(driver)
    """
    if driver is None:
        return
    
    try:
        driver.quit()
        logger.debug("WebDriver корректно завершён")
    except Exception as exc:
        logger.warning(f"Ошибка при завершении WebDriver: {exc}")


def load_url_with_timeout_handling(
    driver: WebDriver, 
    url: str,
    timeout: Optional[int] = None,
) -> tuple[bool, str]:
    """
    НОВАЯ ФУНКЦИЯ: Загрузка URL с обработкой TimeoutException.
    
    При превышении timeout не выбрасывает исключение, а возвращает статус
    и продолжает работу с частично загруженной страницей.
    
    Args:
        driver: Экземпляр WebDriver
        url: URL для загрузки
        timeout: Опциональный custom timeout для этого запроса
    
    Returns:
        tuple[bool, str]: (success, message)
            - success: True если загрузка успешна, False при timeout
            - message: Сообщение об ошибке или "OK"
    
    Example:
        >>> driver = create_driver()
        >>> success, msg = load_url_with_timeout_handling(driver, "https://heavy-site.com")
        >>> if not success:
        ...     logger.warning(f"Частичная загрузка: {msg}")
        >>> # Продолжаем работу с тем, что успело загрузиться
        >>> screenshot = driver.get_screenshot_as_png()
    """
    if timeout is not None:
        original_timeout = driver.timeouts.page_load
        driver.set_page_load_timeout(timeout)
    
    try:
        driver.get(url)
        return True, "OK"
    
    except TimeoutException as exc:
        # Timeout не является критичной ошибкой - страница частично загружена
        logger.warning(
            f"Timeout при загрузке {url}, но продолжаем работу "
            f"с частично загруженной страницей"
        )
        
        # Принудительная остановка загрузки через JavaScript
        try:
            driver.execute_script("window.stop();")
            logger.debug("Выполнена принудительная остановка загрузки через window.stop()")
        except Exception:
            pass
        
        return False, f"Timeout: {str(exc)}"
    
    except Exception as exc:
        # Другие ошибки (DNS, сеть, невалидный URL)
        logger.error(f"Критическая ошибка при загрузке {url}: {exc}")
        return False, f"Error: {str(exc)}"
    
    finally:
        # Восстановление исходного timeout
        if timeout is not None:
            driver.set_page_load_timeout(original_timeout)


# ========== НОВОЕ: Утилита для проверки доступности драйвера ==========
def is_driver_alive(driver: Optional[WebDriver]) -> bool:
    """
    Проверка, активен ли WebDriver.
    
    Args:
        driver: Экземпляр WebDriver для проверки
    
    Returns:
        bool: True если драйвер активен, False иначе
    
    Example:
        >>> driver = create_driver()
        >>> if is_driver_alive(driver):
        ...     driver.get("https://example.com")
    """
    if driver is None:
        return False
    
    try:
        # Проверяем, можем ли получить current_url
        _ = driver.current_url
        return True
    except Exception:
        return False
