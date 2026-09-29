"""ライト / ダークテーマのカラーパレットと QSS スタイルシート。"""


DARK_PALETTE = {
    "name": "dark",
    "bg": "#0b111e",
    "surface": "#121a2c",
    "surface2": "#0e1524",
    "surface3": "#1a2438",
    "border": "#26334f",
    "border_strong": "#33436b",
    "text": "#dce3f2",
    "muted": "#8494b8",
    "accent": "#38bdf8",
    "accent_hover": "#5ecbfa",
    "accent_pressed": "#1e9fdc",
    "accent_text": "#04121d",
    "danger": "#f87171",
    "danger_bg": "#3d1a20",
    "warn": "#fbbf24",
    "warn_bg": "#3a2d12",
    "low": "#c4b5fd",
    "low_bg": "#2a2344",
    "ok": "#4ade80",
    "ok_bg": "#12301f",
    "info": "#93c5fd",
    "info_bg": "#16233d",
    "selection_bg": "#2b567a",
    "selection_text": "#eaf6ff",
    "link": "#7dd3fc",
}

LIGHT_PALETTE = {
    "name": "light",
    "bg": "#eef2f8",
    "surface": "#ffffff",
    "surface2": "#f7f9fd",
    "surface3": "#eaeff7",
    "border": "#d5dcea",
    "border_strong": "#b9c4da",
    "text": "#1c2740",
    "muted": "#5d6c8c",
    "accent": "#0284c7",
    "accent_hover": "#0ea5e9",
    "accent_pressed": "#026da5",
    "accent_text": "#ffffff",
    "danger": "#dc2626",
    "danger_bg": "#fdeaea",
    "warn": "#b45309",
    "warn_bg": "#fdf3e0",
    "low": "#6d28d9",
    "low_bg": "#f1ecfd",
    "ok": "#15803d",
    "ok_bg": "#e8f7ee",
    "info": "#1d4ed8",
    "info_bg": "#e9effd",
    "selection_bg": "#bcdcf5",
    "selection_text": "#102030",
    "link": "#0369a1",
}


def severity_colors(palette: dict) -> dict[str, tuple[str, str]]:
    """severity -> (前景色, 背景色)"""
    return {
        "high": (palette["danger"], palette["danger_bg"]),
        "medium": (palette["warn"], palette["warn_bg"]),
        "low": (palette["low"], palette["low_bg"]),
        "info": (palette["info"], palette["info_bg"]),
        "ok": (palette["ok"], palette["ok_bg"]),
    }


def build_stylesheet(p: dict) -> str:
    return f"""
* {{
    font-family: "Yu Gothic UI", "Meiryo UI", "Hiragino Sans", "Noto Sans CJK JP", "Segoe UI", sans-serif;
    font-size: 13px;
}}

QMainWindow, QDialog {{
    background-color: {p["bg"]};
}}

QWidget {{
    color: {p["text"]};
}}

/* ── ヘッダーバー ─────────────────────────── */
#headerBar {{
    background-color: {p["surface"]};
    border-bottom: 1px solid {p["border"]};
}}

#appTitle {{
    font-size: 21px;
    font-weight: 700;
    color: {p["accent"]};
    letter-spacing: 1px;
}}

#appSubtitle {{
    font-size: 12px;
    color: {p["muted"]};
}}

#themeToggleButton {{
    background-color: {p["surface3"]};
    border: 1px solid {p["border"]};
    border-radius: 16px;
    padding: 5px 14px;
    font-size: 13px;
    color: {p["text"]};
}}

#themeToggleButton:hover {{
    border-color: {p["accent"]};
    color: {p["accent"]};
}}

/* ── メニュー ────────────────────────────── */
QMenuBar {{
    background-color: {p["surface"]};
    color: {p["text"]};
    border-bottom: 1px solid {p["border"]};
    padding: 2px 6px;
}}

QMenuBar::item {{
    padding: 5px 11px;
    border-radius: 6px;
    background: transparent;
}}

QMenuBar::item:selected {{
    background-color: {p["surface3"]};
    color: {p["accent"]};
}}

QMenu {{
    background-color: {p["surface"]};
    color: {p["text"]};
    border: 1px solid {p["border_strong"]};
    border-radius: 8px;
    padding: 6px;
}}

QMenu::item {{
    padding: 6px 28px 6px 14px;
    border-radius: 5px;
}}

QMenu::item:selected {{
    background-color: {p["selection_bg"]};
    color: {p["selection_text"]};
}}

QMenu::item:disabled {{
    color: {p["muted"]};
}}

QMenu::separator {{
    height: 1px;
    background: {p["border"]};
    margin: 5px 10px;
}}

QMenu::indicator {{
    width: 16px;
    height: 16px;
    margin-left: 6px;
}}

/* ── ペイン(左右のカード)───────────────── */
#pane {{
    background-color: {p["surface"]};
    border: 1px solid {p["border"]};
    border-radius: 12px;
}}

#paneTitle {{
    font-size: 14px;
    font-weight: 700;
    color: {p["text"]};
    padding: 2px;
}}

#paneHint {{
    font-size: 11px;
    color: {p["muted"]};
    padding: 2px;
}}

/* ── テキスト入力・表示 ───────────────────── */
QPlainTextEdit, QTextBrowser {{
    background-color: {p["surface2"]};
    color: {p["text"]};
    border: 1px solid {p["border"]};
    border-radius: 8px;
    padding: 8px;
    selection-background-color: {p["selection_bg"]};
    selection-color: {p["selection_text"]};
}}

QPlainTextEdit:focus, QTextBrowser:focus {{
    border: 1px solid {p["accent"]};
}}

/* ── ボタン ─────────────────────────────── */
QPushButton {{
    background-color: {p["surface3"]};
    color: {p["text"]};
    border: 1px solid {p["border_strong"]};
    border-radius: 7px;
    padding: 6px 16px;
}}

QPushButton:hover {{
    border-color: {p["accent"]};
    color: {p["accent"]};
}}

QPushButton:pressed {{
    background-color: {p["surface2"]};
}}

QPushButton:disabled {{
    color: {p["muted"]};
    border-color: {p["border"]};
}}

QPushButton#smallToolButton {{
    padding: 4px 12px;
    font-size: 12px;
    border-radius: 6px;
}}

/* ── タブ ───────────────────────────────── */
QTabWidget::pane {{
    border: none;
    top: 8px;
}}

QTabBar::tab {{
    background-color: {p["surface3"]};
    color: {p["muted"]};
    padding: 7px 20px;
    border: 1px solid {p["border"]};
    border-radius: 8px;
    margin-right: 6px;
    font-weight: 600;
}}

QTabBar::tab:selected {{
    background-color: {p["accent"]};
    color: {p["accent_text"]};
    border-color: {p["accent"]};
}}

QTabBar::tab:hover:!selected {{
    color: {p["accent"]};
    border-color: {p["accent"]};
}}

/* ── ステータスバー ───────────────────────── */
QStatusBar {{
    background-color: {p["surface"]};
    color: {p["muted"]};
    border-top: 1px solid {p["border"]};
}}

QStatusBar::item {{
    border: none;
}}

#riskChip {{
    border-radius: 10px;
    padding: 3px 14px;
    font-weight: 700;
    font-size: 12px;
}}

/* ── スクロールバー ───────────────────────── */
QScrollBar:vertical {{
    background: transparent;
    width: 12px;
    margin: 2px;
}}

QScrollBar::handle:vertical {{
    background: {p["border_strong"]};
    border-radius: 4px;
    min-height: 30px;
}}

QScrollBar::handle:vertical:hover {{
    background: {p["accent"]};
}}

QScrollBar:horizontal {{
    background: transparent;
    height: 12px;
    margin: 2px;
}}

QScrollBar::handle:horizontal {{
    background: {p["border_strong"]};
    border-radius: 4px;
    min-width: 30px;
}}

QScrollBar::handle:horizontal:hover {{
    background: {p["accent"]};
}}

QScrollBar::add-line, QScrollBar::sub-line {{
    width: 0;
    height: 0;
}}

QScrollBar::add-page, QScrollBar::sub-page {{
    background: transparent;
}}

/* ── ヘルプダイアログ ─────────────────────── */
#helpNav {{
    background-color: {p["surface"]};
    border: 1px solid {p["border"]};
    border-radius: 10px;
    padding: 6px;
    outline: none;
    font-size: 13px;
}}

#helpNav::item {{
    padding: 9px 12px;
    border-radius: 7px;
    margin: 2px 2px;
}}

#helpNav::item:hover {{
    background-color: {p["surface3"]};
}}

#helpNav::item:selected {{
    background-color: {p["accent"]};
    color: {p["accent_text"]};
    font-weight: 700;
}}

QToolTip {{
    background-color: {p["surface"]};
    color: {p["text"]};
    border: 1px solid {p["accent"]};
    border-radius: 4px;
    padding: 4px 8px;
}}

QSplitter::handle {{
    background: transparent;
}}
"""
