from __future__ import annotations

import argparse
import logging

from .config import config_from_args, interactive_update_config
from .executor import run_batch
from .logging_setup import setup_logging
from .storage import load_urls, create_run_directory

logger = logging.getLogger(__name__)


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        description="Программный комплекс сбора и анализа цифровых артефактов веб-страниц."
    )
    parser.add_argument(
        "--input",
        "-i",
        help="Путь к файлу со списком URL (по одному в строку). По умолчанию data/sample.txt",
        default=None,
    )
    parser.add_argument(
        "--threads",
        "-t",
        type=int,
        help="Количество потоков обработки (по умолчанию 4)",
        default=None,
    )
    parser.add_argument(
        "--timeout",
        type=int,
        help="Тайм-аут загрузки страницы в секундах (по умолчанию 10)",
        default=None,
    )
    parser.add_argument(
        "--no-artifacts",
        action="store_true",
        help="Отключить сбор сетевых артефактов и SSL-параметров",
    )
    parser.add_argument(
        "--no-save-page",
        action="store_true",
        help="Отключить сохранение HTML-копии страницы",
    )
    parser.add_argument(
        "--no-check-redirection",
        action="store_true",
        help="Отключить проверку редиректов",
    )
    parser.add_argument(
        "--output-root",
        help="Корневая директория для сохранения результатов (по умолчанию results)",
        default=None,
    )
    parser.add_argument(
        "--log-file",
        help="Путь к файлу журнала. Если не указан, лог только в консоль.",
        default=None,
    )
    return parser.parse_args()


def main() -> None:
    args = parse_args()

    # Сначала настраиваем логирование
    setup_logging(args.log_file)

    # Базовая конфигурация из аргументов
    cfg = config_from_args(args)

    # Интерактивный диалог с пользователем (capture_artifacts, save_page_copy,
    # check_redirection, timeout, num_threads).
    cfg = interactive_update_config(cfg)

    logger.info("Загрузка списка URL из файла: %s", cfg.input_file)
    urls = load_urls(cfg.input_file)

    run_dir = create_run_directory(cfg.output_root)
    logger.info("Директория запуска: %s", run_dir)

    run_batch(urls, cfg, run_dir)


if __name__ == "__main__":
    main()
