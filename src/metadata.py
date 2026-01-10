from pathlib import Path
import json
from typing import Any, Dict, Optional


def _meta_path(run_dir: Path, base_name: str) -> Path:
    """
    Вспомогательная функция: путь к файлу метаданных вида
    <run_dir>/<base_name>.meta.json
    """
    return Path(run_dir) / f"{base_name}.meta.json"


def save_metadata(
    run_dir: Path,
    base_name: str,
    original_url: str,
    final_url: str,
) -> None:
    """
    Сохранить метаданные по URL (исходный и фактический адрес).
    Может вызываться из executor.
    """
    data = {
        "original_url": original_url,
        "final_url": final_url,
    }

    path = _meta_path(run_dir, base_name)
    path.parent.mkdir(parents=True, exist_ok=True)

    with path.open("w", encoding="utf-8") as f:
        json.dump(data, f, ensure_ascii=False, indent=2)


def write_metadata(
    run_dir: Path,
    base_name: str,
    original_url: str,
    final_url: str,
) -> None:
    """
    Обёртка для обратной совместимости.
    executor импортирует write_metadata, поэтому делаем алиас.
    """
    save_metadata(run_dir, base_name, original_url, final_url)


def load_metadata(run_dir: Path, base_name: str) -> Optional[Dict[str, Any]]:
    """
    Загрузить метаданные по сайту.
    Если файла нет, вернуть None.
    """
    path = _meta_path(run_dir, base_name)
    if not path.exists():
        return None

    with path.open("r", encoding="utf-8") as f:
        return json.load(f)
