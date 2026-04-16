from __future__ import annotations

from pathlib import Path
import json
import logging
from typing import Any, Dict, Optional
from datetime import datetime

logger = logging.getLogger(__name__)


def _meta_path(run_dir: Path, base_name: str) -> Path:
    return Path(run_dir) / f"{base_name}.meta.json"


def save_metadata(
    run_dir: Path,
    base_name: str,
    original_url: str,
    final_url: str,
    load_success: bool = True,
    load_message: str = "OK",
    timestamp: Optional[str] = None,
) -> None:

    if timestamp is None:
        timestamp = datetime.utcnow().isoformat() + "Z"
    
    data = {
        "original_url": original_url,
        "final_url": final_url,
        "timestamp": timestamp,  
        "load_success": load_success,  
        "load_message": load_message,  
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

def write_metadata(
    run_dir: Path,
    base_name: str,
    original_url: str,
    final_url: str,
    load_success: bool = True,  
    load_message: str = "OK",   
    timestamp: Optional[str] = None,  
) -> None:

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

def get_metadata_stats(run_dir: Path) -> Dict[str, Any]:

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
            
            
            if meta.get("load_success", True):  
                stats["successful_loads"] += 1
            else:
                stats["failed_loads"] += 1
                stats["failed_urls"].append({
                    "url": meta.get("original_url", "unknown"),
                    "error": meta.get("load_message", "Unknown error"),
                })
            
            if meta.get("original_url") != meta.get("final_url"):
                stats["redirects"] += 1
        
        except Exception as exc:
            logger.warning("Не удалось прочитать метаданные из %s: %s", meta_file, exc)
    
    return stats