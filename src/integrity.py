from __future__ import annotations

import hashlib
from pathlib import Path

def sha256_of_text(text: str) -> str:
    h = hashlib.sha256()
    h.update(text.encode("utf-8"))
    return h.hexdigest()


def sha256_of_file(path: str | Path, chunk_size: int = 65536) -> str:
    file_path = Path(path)
    h = hashlib.sha256()
    with file_path.open("rb") as f:
        while True:
            chunk = f.read(chunk_size)
            if not chunk:
                break
            h.update(chunk)
    return h.hexdigest()