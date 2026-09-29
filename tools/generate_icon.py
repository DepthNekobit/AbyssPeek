"""アプリアイコン画像 (PNG 各サイズ + Windows 用 .ico) を assets/icon/ に生成する。

使い方:
    python tools/generate_icon.py

.ico の書き出しには Pillow が必要(PNG のみなら不要)。
"""

import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from PySide6.QtWidgets import QApplication

from src.gui.app_icon import ICON_DIR, ICON_SIZES, paint_app_icon


def main() -> None:
    app = QApplication.instance() or QApplication(sys.argv)
    ICON_DIR.mkdir(parents=True, exist_ok=True)

    png_paths: list[Path] = []
    for size in ICON_SIZES:
        path = ICON_DIR / f"abysspeek_{size}.png"
        paint_app_icon(size).save(str(path), "PNG")
        png_paths.append(path)
        print(f"wrote {path}")

    try:
        from PIL import Image
    except ImportError:
        print("Pillow が無いため .ico はスキップしました (pip install pillow)")
        return

    largest = Image.open(png_paths[-1])
    ico_path = ICON_DIR / "abysspeek.ico"
    largest.save(ico_path, sizes=[(s, s) for s in ICON_SIZES])
    print(f"wrote {ico_path}")


if __name__ == "__main__":
    main()
