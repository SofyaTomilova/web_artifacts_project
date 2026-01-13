from __future__ import annotations

from pathlib import Path
import json
import logging
from typing import Any, Dict, Optional
from datetime import datetime

logger = logging.getLogger(__name__)


def _meta_path(run_dir: Path, base_name: str) -> Path:
    """
    Возвращает путь к файлу метаданных.
    
    Args:
        run_dir: Директория для сохранения
        base_name: Базовое имя файла (без расширения)
    
    Returns:
        Path: Полный путь к файлу .meta.json
    """
    return Path(run_dir) / f"{base_name}.meta.json"


# ========== ИЗМЕНЕНИЕ 1: Обновлённая функция save_metadata ==========
def save_metadata(
    run_dir: Path,
    base_name: str,
    original_url: str,
    final_url: str,
    load_success: bool = True,  # НОВОЕ: флаг успешности загрузки
    load_message: str = "OK",   # НОВОЕ: сообщение об ошибке или "OK"
    timestamp: Optional[str] = None,  # НОВОЕ: опциональная временная метка
) -> None:
    """
    Сохраняет метаданные обработки URL в JSON-файл.
    
    Args:
        run_dir: Директория для сохранения
        base_name: Базовое имя файла (без расширения)
        original_url: Исходный URL из входного списка
        final_url: Финальный URL после редиректов
        load_success: Флаг успешности загрузки страницы (True/False)
        load_message: Сообщение о результате загрузки ("OK" или текст ошибки)
        timestamp: ISO-формат временной метки (UTC), если None - генерируется автоматически
    
    Example:
        >>> save_metadata(
        ...     run_dir=Path("results/run_2026-01-13"),
        ...     base_name="example.com_abc123",
        ...     original_url="https://example.com",
        ...     final_url="https://www.example.com",
        ...     load_success=True,
        ...     load_message="OK",
        ... )
    """
    # Генерация timestamp, если не передан
    if timestamp is None:
        timestamp = datetime.utcnow().isoformat() + "Z"
    
    data = {
        "original_url": original_url,
        "final_url": final_url,
        "timestamp": timestamp,  # НОВОЕ: временная метка обработки
        "load_success": load_success,  # НОВОЕ: успешность загрузки
        "load_message": load_message,  # НОВОЕ: детали ошибки/успеха
    }

    path = _meta_path(run_dir, base_name)
    path.parent.mkdir(parents=True, exist_ok=True)

    try:
        with path.open("w", encoding="utf-8") as f:
            json.dump(data, f, ensure_ascii=False, indent=2)
        logger.debug("Метаданные сохранены: %s", path)
    except Exception as exc:
        logger.error("Не удалось сохранить метаданные в %s: %s", path, exc)
        raise


# ========== ИЗМЕНЕНИЕ 2: Обновлённая функция write_metadata ==========
def write_metadata(
    run_dir: Path,
    base_name: str,
    original_url: str,
    final_url: str,
    load_success: bool = True,  # НОВОЕ
    load_message: str = "OK",   # НОВОЕ
    timestamp: Optional[str] = None,  # НОВОЕ
) -> None:
    """
    Alias для save_metadata() с расширенными параметрами.
    
    Используется в executor.py для сохранения метаданных обработки URL.
    
    Args:
        run_dir: Директория для сохранения
        base_name: Базовое имя файла (без расширения)
        original_url: Исходный URL
        final_url: Финальный URL после редиректов
        load_success: Флаг успешности загрузки
        load_message: Сообщение о результате загрузки
        timestamp: Временная метка обработки
    """
    save_metadata(
        run_dir,
        base_name,
        original_url,
        final_url,
        load_success=load_success,
        load_message=load_message,
        timestamp=timestamp,
    )


def load_metadata(run_dir: Path, base_name: str) -> Optional[Dict[str, Any]]:
    """
    Загружает метаданные из JSON-файла.
    
    Args:
        run_dir: Директория с результатами
        base_name: Базовое имя файла (без расширения)
    
    Returns:
        Optional[Dict]: Словарь с метаданными или None, если файл не найден
    
    Example:
        >>> meta = load_metadata(Path("results/run_2026-01-13"), "example.com_abc123")
        >>> if meta:
        ...     print(meta["original_url"])
        ...     print(meta["load_success"])
    """
    path = _meta_path(run_dir, base_name)
    if not path.exists():
        logger.debug("Файл метаданных не найден: %s", path)
        return None

    try:
        with path.open("r", encoding="utf-8") as f:
            data = json.load(f)
        logger.debug("Метаданные загружены: %s", path)
        return data
    except Exception as exc:
        logger.error("Не удалось загрузить метаданные из %s: %s", path, exc)
        return None


# ========== НОВАЯ ФУНКЦИЯ: Получение статистики по метаданным ==========
def get_metadata_stats(run_dir: Path) -> Dict[str, Any]:
    """
    НОВАЯ ФУНКЦИЯ: Собирает статистику по всем метаданным в директории.
    
    Анализирует все .meta.json файлы и возвращает:
    - Общее количество обработанных URL
    - Количество успешных загрузок
    - Количество timeout/ошибок
    - Список URL с проблемами
    
    Args:
        run_dir: Директория с результатами обработки
    
    Returns:
        Dict: Статистика по метаданным
    
    Example:
        >>> stats = get_metadata_stats(Path("results/run_2026-01-13"))
        >>> print(f"Успешно загружено: {stats['successful_loads']}/{stats['total_urls']}")
        >>> print(f"Проблемные URL: {stats['failed_urls']}")
    """
    stats = {
        "total_urls": 0,
        "successful_loads": 0,
        "failed_loads": 0,
        "failed_urls": [],
        "redirects": 0,
    }
    
    run_dir = Path(run_dir)
    if not run_dir.exists():
        logger.warning("Директория не существует: %s", run_dir)
        return stats
    
    meta_files = list(run_dir.glob("*.meta.json"))
    stats["total_urls"] = len(meta_files)
    
    for meta_file in meta_files:
        try:
            with meta_file.open("r", encoding="utf-8") as f:
                meta = json.load(f)
            
            # Подсчёт успешных загрузок
            if meta.get("load_success", True):  # По умолчанию True для старых файлов
                stats["successful_loads"] += 1
            else:
                stats["failed_loads"] += 1
                stats["failed_urls"].append({
                    "url": meta.get("original_url", "unknown"),
                    "error": meta.get("load_message", "Unknown error"),
                })
            
            # Подсчёт редиректов
            if meta.get("original_url") != meta.get("final_url"):
                stats["redirects"] += 1
        
        except Exception as exc:
            logger.warning("Не удалось прочитать метаданные из %s: %s", meta_file, exc)
    
    return stats