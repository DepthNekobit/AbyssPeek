"""サイドメニュー付きヘルプダイアログ。"""

from PySide6.QtCore import Qt
from PySide6.QtWidgets import (
    QDialog,
    QHBoxLayout,
    QListWidget,
    QTextBrowser,
    QVBoxLayout,
)

from src.gui.help_content import build_help_pages, help_css


class HelpDialog(QDialog):
    def __init__(self, palette: dict, parent=None):
        super().__init__(parent)
        self.setWindowTitle("AbyssPeek — 使い方")
        self.resize(880, 620)
        self.setMinimumSize(700, 480)

        self._nav = QListWidget()
        self._nav.setObjectName("helpNav")
        self._nav.setFixedWidth(220)
        self._nav.setHorizontalScrollBarPolicy(Qt.ScrollBarPolicy.ScrollBarAlwaysOff)

        self._viewer = QTextBrowser()
        self._viewer.setOpenExternalLinks(False)

        layout = QHBoxLayout(self)
        layout.setContentsMargins(14, 14, 14, 14)
        layout.setSpacing(12)

        nav_column = QVBoxLayout()
        nav_column.addWidget(self._nav)
        layout.addLayout(nav_column)
        layout.addWidget(self._viewer, stretch=1)

        self._pages: list[tuple[str, str]] = []
        self._nav.currentRowChanged.connect(self._show_page)
        self.apply_palette(palette)
        self._nav.setCurrentRow(0)

    def apply_palette(self, palette: dict) -> None:
        current_row = max(self._nav.currentRow(), 0)
        self._pages = build_help_pages(palette)
        self._viewer.document().setDefaultStyleSheet(help_css(palette))

        self._nav.blockSignals(True)
        self._nav.clear()
        for title, _ in self._pages:
            self._nav.addItem(title)
        self._nav.setCurrentRow(min(current_row, len(self._pages) - 1))
        self._nav.blockSignals(False)
        self._show_page(self._nav.currentRow())

    def _show_page(self, row: int) -> None:
        if 0 <= row < len(self._pages):
            self._viewer.setHtml(self._pages[row][1])
