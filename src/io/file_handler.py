import os
from pathlib import Path
import shutil
import tempfile


# ISO-2022-JP は7bitでUTF-8としても復号できてしまうため、先に判定する。
# ASCIIだけのファイルはどちらで復号しても同じ結果になる。
READ_ENCODINGS = ("iso-2022-jp", "utf-8-sig", "utf-8", "cp932", "latin-1")


def read_bytes(path: Path) -> bytes:
    if not path.exists():
        raise FileNotFoundError(f"Input file not found: {path}")
    return path.read_bytes()


def read_text(path: Path) -> str:
    data = read_bytes(path)
    for encoding in READ_ENCODINGS:
        try:
            return data.decode(encoding)
        except UnicodeDecodeError:
            continue
    return data.decode("utf-8", errors="replace")


def write_text(path: Path, content: str) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    fd, temp_name = tempfile.mkstemp(prefix=f".{path.name}.", suffix=".tmp", dir=path.parent)
    temp_path = Path(temp_name)
    try:
        handle = os.fdopen(fd, "w", encoding="utf-8")
        fd = -1  # 以降は handle が所有する
        with handle:
            handle.write(content)
            handle.flush()
            os.fsync(handle.fileno())
        if path.exists():
            shutil.copymode(path, temp_path)
        os.replace(temp_path, path)
    except Exception:
        if fd >= 0:
            try:
                os.close(fd)
            except OSError:
                pass
        try:
            temp_path.unlink(missing_ok=True)
        except OSError:
            pass
        raise
