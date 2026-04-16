from __future__ import annotations

from dataclasses import dataclass

DEFAULT_TIMEOUT = 10
DEFAULT_THREADS = 4


@dataclass
class Config:

    input_file: str = "data/sample.txt"
    timeout: int = DEFAULT_TIMEOUT
    num_threads: int = DEFAULT_THREADS

    capture_artifacts: bool = True
    save_page_copy: bool = True
    check_redirection: bool = True
    capture_screenshot: bool = True  

    output_root: str = "results"


def config_from_args(args) -> Config:

    cfg = Config()

    if getattr(args, "input", None):
        cfg.input_file = args.input

    if getattr(args, "timeout", None):
        cfg.timeout = args.timeout

    if getattr(args, "threads", None):
        cfg.num_threads = args.threads

    if getattr(args, "no_artifacts", False):
        cfg.capture_artifacts = False

    if getattr(args, "no_save_page", False):
        cfg.save_page_copy = False

    if getattr(args, "no_check_redirection", False):
        cfg.check_redirection = False

    if getattr(args, "output_root", None):
        cfg.output_root = args.output_root

    return cfg


def _ask_yes_no(prompt: str, current: bool) -> bool:

    default_str = "Y" if current else "n"
    answer = input(f"{prompt} [{default_str}/n]: ").strip().lower()

    if answer in ("y", "yes", "д", "да", "1"):
        return True
    if answer in ("n", "no", "н", "нет", "0"):
        return False
    
    return current


def interactive_update_config(cfg: Config) -> Config:

    print("\n=== Настройка параметров работы комплекса ===")
    print("Нажмите Enter, чтобы оставить значение по умолчанию.\n")

    cfg.capture_artifacts = _ask_yes_no(
        "Выполнять сбор сетевых событий и SSL-параметров?",
        cfg.capture_artifacts,
    )

    cfg.save_page_copy = _ask_yes_no(
        "Сохранять HTML-копию страницы?",
        cfg.save_page_copy,
    )

    cfg.check_redirection = _ask_yes_no(
        "Проверять наличие редиректов при загрузке страницы?",
        cfg.check_redirection,
    )

    timeout_str = input(
        f"Введите тайм-аут загрузки страницы, сек (по умолчанию {DEFAULT_TIMEOUT}): "
    ).strip()
    if timeout_str:
        try:
            value = int(timeout_str)
            if value > 0:
                cfg.timeout = value
            else:
                print(f"Некорректное значение, используется {DEFAULT_TIMEOUT} сек.")
                cfg.timeout = DEFAULT_TIMEOUT
        except ValueError:
            print(f"Некорректное значение, используется {DEFAULT_TIMEOUT} сек.")
            cfg.timeout = DEFAULT_TIMEOUT

    threads_str = input(
        f"Введите количество рабочих потоков (по умолчанию {DEFAULT_THREADS}): "
    ).strip()
    if threads_str:
        try:
            value = int(threads_str)
            if value > 0:
                cfg.num_threads = value
            else:
                print(f"Некорректное значение, используется {DEFAULT_THREADS} поток(а).")
                cfg.num_threads = DEFAULT_THREADS
        except ValueError:
            print(f"Некорректное значение, используется {DEFAULT_THREADS} поток(а).")
            cfg.num_threads = DEFAULT_THREADS

    print("\nПараметры установлены:")
    print(f"  capture_artifacts   = {cfg.capture_artifacts}")
    print(f"  save_page_copy      = {cfg.save_page_copy}")
    print(f"  check_redirection   = {cfg.check_redirection}")
    print(f"  timeout             = {cfg.timeout} сек.")
    print(f"  num_threads         = {cfg.num_threads}\n")

    return cfg
