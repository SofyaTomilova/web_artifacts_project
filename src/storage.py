
from __future__ import annotations

import hashlib
import time
from pathlib import Path
from urllib.parse import urlparse
from typing import Iterable


def load_urls(path: str | Path) -> list[str]:
    """
    Загружает список URL из текстового файла (один URL на строку).
    Пустые строки и строки, начинающиеся с '#', игнорируются.
    """
    file_path = Path(path)
    if not file_path.exists():
        raise FileNotFoundError(f"Файл со списком URL не найден: {file_path}")

    urls: list[str] = []
    with file_path.open("r", encoding="utf-8") as f:
        for line in f:
            line = line.strip()
            if not line or line.startswith("#"):
                continue
            urls.append(line)
    return urls


def create_run_directory(root: str | Path) -> Path:
    """
    Создаёт директорию для текущего запуска с меткой времени.
    Например: results/run_2025-12-04_11-23-00
    """
    root_path = Path(root)
    root_path.mkdir(parents=True, exist_ok=True)

    timestamp = time.strftime("%Y-%m-%d_%H-%M-%S")
    run_dir = root_path / f"run_{timestamp}"
    run_dir.mkdir(parents=True, exist_ok=True)

    return run_dir


def extract_hostname(url: str) -> str:
    """
    Извлекает имя хоста из URL.
    """
    parsed = urlparse(url)
    return parsed.hostname or parsed.netloc or ""


def make_base_path(url: str, run_dir: Path) -> Path:
    """
    Формирует базовое имя файла для артефактов по URL.
    Используем хост и укороченный SHA256 от полного URL, чтобы избежать проблем с длиной имён.
    """
    host = extract_hostname(url) or "unknown"
    short_host = host.replace(":", "_")[:40] or "unknown"

    h = hashlib.sha256(url.encode("utf-8")).hexdigest()[:12]

    base_name = f"{short_host}_{h}"
    return run_dir / base_name
