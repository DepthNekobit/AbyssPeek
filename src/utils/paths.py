"""実行環境(通常実行 / PyInstaller 等でのフリーズ実行)に応じたパス解決。"""

from pathlib import Path
import sys


def project_root() -> Path:
    """assets/ などの同梱リソースの基準ディレクトリを返す。

    PyInstaller でフリーズされた場合は展開先 (_MEIPASS)、
    通常実行ではリポジトリのルートを返す。
    """
    if getattr(sys, "frozen", False):
        meipass = getattr(sys, "_MEIPASS", None)
        if meipass:
            return Path(meipass)
        return Path(sys.executable).resolve().parent
    return Path(__file__).resolve().parents[2]
