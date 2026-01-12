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

from .browser import create_driver, close_driver
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
    - загружает страницу в браузере;
    - сохраняет визуальные и сетевые артефакты;
    - опрашивает TLS-сертификат;
    - вызывает VirusTotal и Kaspersky OpenTIP;
    - считает сводный скоринг и сохраняет его в *.score.json.
    """
    driver = None
    original_url = url
    final_url = url
    base_path: Path | None = None

    try:
        driver = create_driver()
        driver.set_page_load_timeout(cfg.timeout)

        logger.info("Загрузка URL: %s", url)
        driver.get(url)
        final_url = driver.current_url
        logger.info("Фактический URL после редиректов: %s", final_url)

        if cfg.check_redirection and final_url != url:
            logger.info("Обнаружен редирект: %s -> %s", url, final_url)

        base_path = make_base_path(final_url, run_dir)
        run_dir_for_score = base_path.parent
        base_name = base_path.name

        try:
            write_metadata(run_dir_for_score, base_name, original_url, final_url)
        except Exception as exc:  
            logger.warning("Не удалось сохранить метаданные для %s: %s", final_url, exc)

        if cfg.capture_screenshot:
            save_screenshot(driver, base_path)
        if cfg.save_page_copy:
            save_html(driver, base_path)

        # Сетевые артефакты + SSL
        ssl_info_data = None  # будем хранить словарь с инфой по сертификату
        if cfg.capture_artifacts:
            network_path = collect_network_artifacts(driver, base_path)

            hostname = extract_hostname(final_url)
            if hostname:
                try:
                    ssl_info_data = get_ssl_info(hostname)
                except Exception as exc:
                    logger.error("Ошибка при получении SSL для %s: %s", hostname, exc)
                    ssl_info_data = {"error": str(exc)}

                ssl_path = save_ssl_info(ssl_info_data, base_path)
            else:
                logger.warning("Не удалось извлечь имя хоста из URL: %s", final_url)

        # --- VirusTotal (по финальному URL) ---
        vt_result = None
        vt_key = get_vt_api_key()
        if vt_key:
            vt_result = query_virustotal_url(final_url, vt_key)
            vt_path = base_path.with_suffix(".vt.json")
            try:
                vt_path.write_text(
                    json.dumps(vt_result, ensure_ascii=False, indent=2),
                    encoding="utf-8",
                )
                logger.info("VirusTotal-отчёт сохранён: %s", vt_path)
            except Exception as exc:  # noqa: BLE001
                logger.error("Не удалось сохранить VirusTotal-отчёт: %s", exc)
        else:
            logger.debug("VT_API_KEY не задан, VirusTotal не вызывается")

        # --- OpenTIP (по домену) ---
        opentip_key = get_opentip_api_key()
        opentip_result = None
        hostname = extract_hostname(final_url)
        if opentip_key and hostname:
            opentip_result = query_opentip_domain(hostname, opentip_key)
            ot_path = base_path.with_suffix(".opentip.json")
            try:
                ot_path.write_text(
                    json.dumps(opentip_result, ensure_ascii=False, indent=2),
                    encoding="utf-8",
                )
                logger.info("OpenTIP-отчёт сохранён: %s", ot_path)
            except Exception as exc:  # noqa: BLE001
                logger.error("Не удалось сохранить OpenTIP-отчёт: %s", exc)
        elif not opentip_key:
            logger.debug("OPENTIP_API_KEY не задан, OpenTIP не вызывается")

        # --- СКОРИНГ ---
        try:
            # base_path = <run_dir>/<base_name>
            run_dir_for_score = base_path.parent
            base_name = base_path.name

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

        except Exception as exc:  # noqa: BLE001
            logger.error("Ошибка при вычислении скоринга для %s: %s", url, exc)

    except Exception as exc:  # noqa: BLE001
        logger.error("Ошибка при обработке URL %s: %s", url, exc)
    finally:
        close_driver(driver)


def run_batch(urls: Iterable[str], cfg: Config, run_dir: Path) -> None:
    #Запускает параллельную обработку списка URL.#
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
            # Исключения уже залогированы внутри process_single_url.
            _ = future.result()
    logger.info("Обработка завершена")
