from __future__ import annotations

from dataclasses import dataclass

# Значения по умолчанию для числовых параметров,
# такие же, как в описании диплома.
DEFAULT_TIMEOUT = 10
DEFAULT_THREADS = 4


@dataclass
class Config:
    """
    Конфигурация программного комплекса.

    Параметры:
        input_file      – путь к файлу со списком URL.
        timeout         – тайм-аут загрузки страницы в секундах.
        num_threads     – количество рабочих потоков.
        capture_artifacts – собирать ли сетевые артефакты и SSL-параметры.
        save_page_copy  – сохранять ли HTML-копию страницы.
        check_redirection – проверять и фиксировать ли редиректы.
        capture_screenshot – сохранять ли скриншот страницы (внутренний параметр).
        output_root     – корневая папка для результатов.
    """
    input_file: str = "data/sample.txt"
    timeout: int = DEFAULT_TIMEOUT
    num_threads: int = DEFAULT_THREADS

    capture_artifacts: bool = True
    save_page_copy: bool = True
    check_redirection: bool = True
    capture_screenshot: bool = True  # скриншоты всегда полезны

    output_root: str = "results"


def config_from_args(args) -> Config:
    """
    Формирует объект Config на основе аргументов командной строки.
    Аргументы задают начальные значения, которые затем можно
    скорректировать в интерактивном диалоге.
    """
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
    """
    Вспомогательная функция: задаёт вопрос вида [Y/n] и
    возвращает булево значение, при пустом вводе оставляет current.
    """
    default_str = "Y" if current else "n"
    answer = input(f"{prompt} [{default_str}/n]: ").strip().lower()

    if answer in ("y", "yes", "д", "да", "1"):
        return True
    if answer in ("n", "no", "н", "нет", "0"):
        return False
    # Пустой или непонятный ввод — оставляем текущее значение
    return current


def interactive_update_config(cfg: Config) -> Config:
    """
    Интерактивный диалог с пользователем для настройки параметров.

    Пользователь вводит:
      - флаг capture_artifacts: собирать сетевые события и SSL-параметры;
      - флаг save_page_copy: сохранять HTML-документ страницы;
      - флаг check_redirection: учитывать редиректы;
      - timeout (секунды) и num_threads (число потоков).

    При некорректном вводе числовых значений применяются значения
    по умолчанию: timeout = 10, num_threads = 4.
    """
    print("\n=== Настройка параметров работы комплекса ===")
    print("Нажмите Enter, чтобы оставить значение по умолчанию.\n")

    # Флаги
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

    # Тайм-аут
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

    # Количество потоков
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
