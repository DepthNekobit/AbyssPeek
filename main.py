"""AbyssPeek — メールヘッダー デコード & 解析ツール(GUI 版)エントリポイント。"""

import sys

from PySide6.QtWidgets import QApplication

from src.gui.app_icon import load_app_icon
from src.gui.main_window import MainWindow


def main() -> None:
    if sys.platform == "win32":
        # タスクバーで Python ではなく AbyssPeek のアイコンを表示させる
        import ctypes

        ctypes.windll.shell32.SetCurrentProcessExplicitAppUserModelID("AbyssPeek.AbyssPeek")

    app = QApplication(sys.argv)
    app.setApplicationName("AbyssPeek")
    app.setOrganizationName("AbyssPeek")
    app.setWindowIcon(load_app_icon())

    window = MainWindow()
    window.show()
    sys.exit(app.exec())


if __name__ == "__main__":
    main()
