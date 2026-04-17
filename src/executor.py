from __future__ import annotations

import logging
import json
import webbrowser
from concurrent.futures import ThreadPoolExecutor, as_completed
from pathlib import Path
from typing import Iterable, Optional

from .scoring import compute_risk_score
from .report import generate_summary_report
from .threat_intel import (
    get_vt_api_key,
    get_opentip_api_key,
    query_virustotal_url,
    query_opentip_domain,
)

try:
    from tqdm import tqdm
except Exception:  
    tqdm = None 

from .browser import create_driver, close_driver, load_url_with_timeout_handling
from .config import Config
from .metadata import write_metadata
from .ssl_info import get_ssl_info, save_ssl_info
from .storage import make_base_path, extract_hostname
from .visual_artifacts import save_screenshot, save_html
from .network_artifacts import collect_network_artifacts

logger = logging.getLogger(__name__)


def process_single_url(url: str, cfg: Config, run_dir: Path) -> None:

    driver = None
    original_url = url
    final_url = url
    base_path: Optional[Path] = None
    load_success = False  
    load_message = "Not attempted"  

    try:
        driver = create_driver(
            headless=True, 
            performance_logging=True,
            page_load_timeout=cfg.timeout if hasattr(cfg, 'timeout') else 45,
        )

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

        try:
            final_url = driver.current_url
            logger.info("Фактический URL после редиректов: %s", final_url)
        except Exception as exc:
            logger.warning("Не удалось получить current_url: %s", exc)
            final_url = url  

        if cfg.check_redirection and final_url != url:
            logger.info("Обнаружен редирект: %s -> %s", url, final_url)

        base_path = make_base_path(final_url, run_dir)
        run_dir_for_score = base_path.parent
        base_name = base_path.name

        try:
            write_metadata(
                run_dir_for_score,
                base_name,
                original_url,
                final_url,
                load_success=load_success,  
                load_message=load_message,  
            )
        except Exception as exc:
            logger.warning("Не удалось сохранить метаданные для %s: %s", final_url, exc)

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

    all_scores: list = []
    for score_file in sorted(run_dir.rglob("*.score.json")):
        try:
            data = json.loads(score_file.read_text(encoding="utf-8"))
            all_scores.append(data)
        except Exception as exc:
            logger.warning("Не удалось прочитать %s: %s", score_file, exc)

    if not all_scores:
        return

    total     = len(all_scores)
    malicious = [s for s in all_scores if s.get("verdict") == "Вредоносный"]
    suspicious = [s for s in all_scores if s.get("verdict") == "Подозрительный"]

    logger.info("=" * 60)
    logger.info("ИТОГО ПРОВЕРЕНО:      %d URL", total)
    logger.info("Легитимных:        %d", total - len(malicious) - len(suspicious))
    logger.info("Подозрительных:   %d", len(suspicious))
    logger.info("Вредоносных:       %d", len(malicious))

    if malicious:
        logger.info("-" * 60)
        logger.info("ОБНАРУЖЕННЫЕ ВРЕДОНОСНЫЕ / ФИШИНГОВЫЕ САЙТЫ:")
        for s in sorted(malicious, key=lambda x: x.get("score", x.get("risk_score", 0)), reverse=True):
            logger.info(
                "  [score=%3d] %s",
                s.get("score", s.get("risk_score", 0)),
                s.get("url", s.get("original_url", "—")),
            )

    if suspicious:
        logger.info("-" * 60)
        logger.info("ПОДОЗРИТЕЛЬНЫЕ САЙТЫ (требуют дополнительной проверки):")
        for s in sorted(suspicious, key=lambda x: x.get("score", x.get("risk_score", 0)), reverse=True):
            logger.info(
                "  [score=%3d] %s",
                s.get("score", s.get("risk_score", 0)),
                s.get("url", s.get("original_url", "—")),
            )

    logger.info("=" * 60)

    try:
        summary_path = run_dir / "summary_report.html"
        generate_summary_report(all_scores, summary_path)
        logger.info("Сводный HTML-отчёт сохранён: %s", summary_path)

        try:
            webbrowser.open(summary_path.resolve().as_uri())
            logger.info("Сводный отчёт открыт в браузере")
        except Exception as exc:
            logger.warning("Не удалось открыть отчёт в браузере: %s", exc)
    except Exception as exc:
        logger.warning("Не удалось сгенерировать сводный отчёт: %s", exc)