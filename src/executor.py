from __future__ import annotations

import logging
import json
from concurrent.futures import ThreadPoolExecutor, as_completed
from pathlib import Path
from typing import Iterable

from .scoring import compute_risk_score
from .threat_intel import (
    get_vt_api_key,
    get_opentip_api_key,
    query_virustotal_url,
    query_opentip_domain,
)

try:
    from tqdm import tqdm
except Exception:  # noqa: BLE001
    tqdm = None  # type: ignore[assignment]

# ========== ИЗМЕНЕНИЕ 1: Импортируем новую функцию ==========
from .browser import create_driver, close_driver, load_url_with_timeout_handling
from .config import Config
from .metadata import write_metadata
from .ssl_info import get_ssl_info, save_ssl_info
from .storage import make_base_path, extract_hostname
from .visual_artifacts import save_screenshot, save_html
from .network_artifacts import collect_network_artifacts

logger = logging.getLogger(__name__)


def process_single_url(url: str, cfg: Config, run_dir: Path) -> None:
    """
    Обрабатывает один URL:
    - загружает страницу в браузере (с обработкой timeout);
    - сохраняет визуальные и сетевые артефакты;
    - опрашивает TLS-сертификат;
    - вызывает VirusTotal и Kaspersky OpenTIP;
    - считает сводный скоринг и сохраняет его в *.score.json.
    
    НОВОЕ: При TimeoutException продолжает работу с частично загруженной страницей.
    """
    driver = None
    original_url = url
    final_url = url
    base_path: Path | None = None
    load_success = False  # НОВОЕ: флаг успешности загрузки
    load_message = "Not attempted"  # НОВОЕ: сообщение о результате загрузки

    try:
        # ========== ИЗМЕНЕНИЕ 2: Создание драйвера с кастомным timeout ==========
        driver = create_driver(
            headless=True,  # Используем headless из cfg, если нужно
            performance_logging=True,
            page_load_timeout=cfg.timeout if hasattr(cfg, 'timeout') else 45,
        )

        # ========== ИЗМЕНЕНИЕ 3: Загрузка URL с обработкой timeout ==========
        logger.info("Загрузка URL: %s", url)
        load_success, load_message = load_url_with_timeout_handling(driver, url)

        if not load_success:
            logger.warning(
                "Проблема при загрузке %s: %s. "
                "Продолжаем работу с частично загруженной страницей.",
                url,
                load_message,
            )
        else:
            logger.info("URL успешно загружен: %s", url)

        # Получаем финальный URL (даже при timeout может быть доступен)
        try:
            final_url = driver.current_url
            logger.info("Фактический URL после редиректов: %s", final_url)
        except Exception as exc:
            logger.warning("Не удалось получить current_url: %s", exc)
            final_url = url  # Используем исходный URL

        # Проверка редиректа
        if cfg.check_redirection and final_url != url:
            logger.info("Обнаружен редирект: %s -> %s", url, final_url)

        # Создание базового пути для артефактов
        base_path = make_base_path(final_url, run_dir)
        run_dir_for_score = base_path.parent
        base_name = base_path.name

        # ========== ИЗМЕНЕНИЕ 4: Сохранение метаданных с флагом load_success ==========
        try:
            write_metadata(
                run_dir_for_score,
                base_name,
                original_url,
                final_url,
                load_success=load_success,  # НОВОЕ: фиксируем успешность загрузки
                load_message=load_message,  # НОВОЕ: сообщение об ошибке/успехе
            )
        except Exception as exc:
            logger.warning("Не удалось сохранить метаданные для %s: %s", final_url, exc)

        # ========== Сохранение визуальных артефактов (работает даже при timeout) ==========
        if cfg.capture_screenshot:
            try:
                save_screenshot(driver, base_path)
            except Exception as exc:
                logger.warning("Не удалось сохранить скриншот для %s: %s", final_url, exc)

        if cfg.save_page_copy:
            try:
                save_html(driver, base_path)
            except Exception as exc:
                logger.warning("Не удалось сохранить HTML для %s: %s", final_url, exc)

        # ========== Сетевые артефакты + SSL ==========
        ssl_info_data = None
        if cfg.capture_artifacts:
            try:
                network_path = collect_network_artifacts(driver, base_path)
            except Exception as exc:
                logger.warning("Не удалось собрать сетевые артефакты для %s: %s", final_url, exc)

            hostname = extract_hostname(final_url)
            if hostname:
                try:
                    ssl_info_data = get_ssl_info(hostname)
                except Exception as exc:
                    logger.error("Ошибка при получении SSL для %s: %s", hostname, exc)
                    ssl_info_data = {"error": str(exc)}

                try:
                    ssl_path = save_ssl_info(ssl_info_data, base_path)
                except Exception as exc:
                    logger.warning("Не удалось сохранить SSL-инфо для %s: %s", final_url, exc)
            else:
                logger.warning("Не удалось извлечь имя хоста из URL: %s", final_url)

        # ========== VirusTotal ==========
        vt_result = None
        vt_key = get_vt_api_key()
        if vt_key:
            try:
                vt_result = query_virustotal_url(final_url, vt_key)
                vt_path = base_path.with_suffix(".vt.json")
                vt_path.write_text(
                    json.dumps(vt_result, ensure_ascii=False, indent=2),
                    encoding="utf-8",
                )
                logger.info("VirusTotal-отчёт сохранён: %s", vt_path)
            except Exception as exc:
                logger.error("Не удалось получить/сохранить VirusTotal-отчёт: %s", exc)
        else:
            logger.debug("VT_API_KEY не задан, VirusTotal не вызывается")

        # ========== Kaspersky OpenTIP ==========
        opentip_key = get_opentip_api_key()
        opentip_result = None
        hostname = extract_hostname(final_url)
        if opentip_key and hostname:
            try:
                opentip_result = query_opentip_domain(hostname, opentip_key)
                ot_path = base_path.with_suffix(".opentip.json")
                ot_path.write_text(
                    json.dumps(opentip_result, ensure_ascii=False, indent=2),
                    encoding="utf-8",
                )
                logger.info("OpenTIP-отчёт сохранён: %s", ot_path)
            except Exception as exc:
                logger.error("Не удалось получить/сохранить OpenTIP-отчёт: %s", exc)
        elif not opentip_key:
            logger.debug("OPENTIP_API_KEY не задан, OpenTIP не вызывается")

        # ========== Риск-скоринг ==========
        try:
            score_data = compute_risk_score(
                run_dir_for_score,
                base_name,
                original_url=url,
                final_url=final_url,
                ssl_data=ssl_info_data,
                vt_data=vt_result,
                opentip_data=opentip_result,
            )

            score_path = base_path.with_suffix(".score.json")
            score_path.write_text(
                json.dumps(score_data, ensure_ascii=False, indent=2),
                encoding="utf-8",
            )
            logger.info("Сводный скоринг сохранён: %s", score_path)

        except Exception as exc:
            logger.error("Ошибка при вычислении скоринга для %s: %s", url, exc)

    except Exception as exc:
        logger.error("Критическая ошибка при обработке URL %s: %s", url, exc)
    finally:
        close_driver(driver)


def run_batch(urls: Iterable[str], cfg: Config, run_dir: Path) -> None:
    """
    Запускает пакетную обработку URL в нескольких потоках.
    
    Args:
        urls: Итератор/список URL для обработки
        cfg: Конфигурация приложения
        run_dir: Директория для сохранения результатов
    """
    url_list = list(urls)
    if not url_list:
        logger.warning("Список URL пуст, нечего обрабатывать")
        return
    
    logger.info("Начало обработки %d URL в %d поток(ах)", len(url_list), cfg.num_threads)

    with ThreadPoolExecutor(max_workers=cfg.num_threads) as executor:
        futures = [executor.submit(process_single_url, url, cfg, run_dir) for url in url_list]
        iterator = as_completed(futures)
        
        if tqdm is not None:
            iterator = tqdm(iterator, total=len(futures), desc="Обработка URL")
        
        for future in iterator:
            try:
                _ = future.result()
            except Exception as exc:
                logger.error("Ошибка в потоке обработки URL: %s", exc)
    
    logger.info("Обработка завершена")