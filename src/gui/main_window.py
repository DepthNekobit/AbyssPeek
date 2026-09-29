"""AbyssPeek メインウィンドウ。"""

from datetime import datetime
from pathlib import Path

from PySide6.QtCore import QSettings, Qt, QUrl
from PySide6.QtGui import (
    QAction,
    QBrush,
    QColor,
    QDesktopServices,
    QFont,
    QFontDatabase,
    QKeySequence,
    QTextCursor,
)
from PySide6.QtWidgets import (
    QApplication,
    QDialog,
    QDialogButtonBox,
    QFileDialog,
    QFrame,
    QHBoxLayout,
    QLabel,
    QMainWindow,
    QMessageBox,
    QPlainTextEdit,
    QPushButton,
    QTabWidget,
    QTextBrowser,
    QVBoxLayout,
    QWidget,
)

from src.gui.help_dialog import HelpDialog
from src.gui.report_builder import (
    build_decoded_html,
    build_report_html,
    decoded_placeholder_html,
    report_css,
)
from src.gui.theme import DARK_PALETTE, LIGHT_PALETTE, build_stylesheet
from src.gui.widgets import ConvertArrowButton
from src.io.file_handler import read_text, write_text
from src.usecases.analyze_mail import AnalysisResult, analyze_mail_text
from src.utils.paths import project_root
from src.version import APP_VERSION

SAMPLE_PATH = project_root() / "assets" / "sample_header.txt"
NOTICES_PATH = project_root() / "THIRD_PARTY_NOTICES.md"

APP_NAME = "AbyssPeek"
MAX_INPUT_CHARS = 2_000_000
MAX_INPUT_FILE_BYTES = 8_000_000


class MainWindow(QMainWindow):
    def __init__(self):
        super().__init__()
        self._settings = QSettings("AbyssPeek", "AbyssPeek")
        self._dark_mode = self._settings.value("dark_mode", True, type=bool)
        self._defang = self._settings.value("defang_urls", True, type=bool)
        self._result: AnalysisResult | None = None
        self._help_dialog: HelpDialog | None = None

        self.setWindowTitle(f"{APP_NAME} — メールヘッダー解析ツール")
        self.resize(1280, 800)
        self.setMinimumSize(980, 620)

        self._build_ui()
        self._build_menus()
        self._apply_theme()
        self._restore_geometry()

    # ── UI 構築 ─────────────────────────────────────────────

    def _build_ui(self) -> None:
        central = QWidget()
        root = QVBoxLayout(central)
        root.setContentsMargins(0, 0, 0, 0)
        root.setSpacing(0)

        root.addWidget(self._build_header_bar())

        content = QWidget()
        content_layout = QHBoxLayout(content)
        content_layout.setContentsMargins(16, 14, 16, 14)
        content_layout.setSpacing(12)

        content_layout.addWidget(self._build_input_pane(), stretch=1)
        content_layout.addWidget(self._build_center_column())
        content_layout.addWidget(self._build_result_pane(), stretch=1)

        root.addWidget(content, stretch=1)
        self.setCentralWidget(central)

        self._risk_chip = QLabel()
        self._risk_chip.setObjectName("riskChip")
        self._risk_chip.hide()
        self.statusBar().addPermanentWidget(self._risk_chip)
        self.statusBar().showMessage(
            "左側にメールヘッダーを貼り付けて「変換」を押してください(F1 で使い方)"
        )

    def _build_header_bar(self) -> QWidget:
        bar = QWidget()
        bar.setObjectName("headerBar")
        layout = QHBoxLayout(bar)
        layout.setContentsMargins(18, 10, 18, 10)

        title = QLabel(APP_NAME)
        title.setObjectName("appTitle")
        subtitle = QLabel("メールヘッダーを安全にデコードして、迷惑メールの兆候を解析")
        subtitle.setObjectName("appSubtitle")

        text_column = QVBoxLayout()
        text_column.setSpacing(0)
        text_column.addWidget(title)
        text_column.addWidget(subtitle)
        layout.addLayout(text_column)
        layout.addStretch(1)

        self._theme_button = QPushButton()
        self._theme_button.setObjectName("themeToggleButton")
        self._theme_button.setCursor(Qt.CursorShape.PointingHandCursor)
        self._theme_button.clicked.connect(self._toggle_theme)
        layout.addWidget(self._theme_button)
        return bar

    def _build_input_pane(self) -> QWidget:
        pane = QFrame()
        pane.setObjectName("pane")
        layout = QVBoxLayout(pane)
        layout.setContentsMargins(14, 12, 14, 14)
        layout.setSpacing(8)

        header_row = QHBoxLayout()
        title = QLabel("📥 元のメールヘッダー")
        title.setObjectName("paneTitle")
        header_row.addWidget(title)
        header_row.addStretch(1)

        open_button = QPushButton("開く…")
        open_button.setObjectName("smallToolButton")
        open_button.clicked.connect(self._open_file)
        clear_button = QPushButton("クリア")
        clear_button.setObjectName("smallToolButton")
        clear_button.clicked.connect(self._clear_input)
        header_row.addWidget(open_button)
        header_row.addWidget(clear_button)
        layout.addLayout(header_row)

        hint = QLabel("メールソフトの「メッセージのソースを表示」からコピーした内容をそのまま貼り付け")
        hint.setObjectName("paneHint")
        hint.setWordWrap(True)
        layout.addWidget(hint)

        self._input_edit = QPlainTextEdit()
        self._input_edit.setFont(self._monospace_font())
        self._input_edit.setPlaceholderText(
            "ここにメールヘッダー(またはソース全体)を貼り付けてください。\n\n"
            "例:\n"
            "Received: from mail.example.com ...\n"
            "From: =?UTF-8?B?...?= <info@example.com>\n"
            "Subject: =?UTF-8?B?...?=\n"
            "..."
        )
        self._input_edit.setLineWrapMode(QPlainTextEdit.LineWrapMode.NoWrap)
        self._input_edit.textChanged.connect(self._invalidate_result)
        layout.addWidget(self._input_edit, stretch=1)
        return pane

    def _build_center_column(self) -> QWidget:
        column = QWidget()
        layout = QVBoxLayout(column)
        layout.setContentsMargins(0, 0, 0, 0)
        layout.setSpacing(6)

        layout.addStretch(1)
        self._convert_button = ConvertArrowButton("変 換")
        self._convert_button.clicked.connect(self._convert)
        layout.addWidget(self._convert_button, alignment=Qt.AlignmentFlag.AlignHCenter)

        shortcut_hint = QLabel("Ctrl+Enter")
        shortcut_hint.setObjectName("paneHint")
        shortcut_hint.setAlignment(Qt.AlignmentFlag.AlignHCenter)
        layout.addWidget(shortcut_hint)
        layout.addStretch(1)
        return column

    def _build_result_pane(self) -> QWidget:
        pane = QFrame()
        pane.setObjectName("pane")
        layout = QVBoxLayout(pane)
        layout.setContentsMargins(14, 12, 14, 14)
        layout.setSpacing(8)

        header_row = QHBoxLayout()
        title = QLabel("📤 解析結果")
        title.setObjectName("paneTitle")
        header_row.addWidget(title)
        header_row.addStretch(1)

        copy_button = QPushButton("コピー")
        copy_button.setObjectName("smallToolButton")
        copy_button.clicked.connect(self._copy_result)
        save_button = QPushButton("保存…")
        save_button.setObjectName("smallToolButton")
        save_button.clicked.connect(self._save_decoded_text)
        header_row.addWidget(copy_button)
        header_row.addWidget(save_button)
        layout.addLayout(header_row)

        self._tabs = QTabWidget()

        self._decoded_browser = QTextBrowser()
        self._decoded_browser.setOpenExternalLinks(False)
        self._tabs.addTab(self._decoded_browser, "📄 デコード結果")

        self._report_browser = QTextBrowser()
        self._report_browser.setOpenExternalLinks(False)
        self._tabs.addTab(self._report_browser, "🛡️ 解析レポート")

        layout.addWidget(self._tabs, stretch=1)
        return pane

    @staticmethod
    def _monospace_font() -> QFont:
        font = QFontDatabase.systemFont(QFontDatabase.SystemFont.FixedFont)
        font.setPointSize(10)
        return font

    # ── メニュー ────────────────────────────────────────────

    def _build_menus(self) -> None:
        menu_bar = self.menuBar()

        file_menu = menu_bar.addMenu("ファイル(&F)")
        self._add_action(file_menu, "ヘッダーファイルを開く…", self._open_file, "Ctrl+O")
        file_menu.addSeparator()
        self._add_action(file_menu, "デコード結果をテキストで保存…", self._save_decoded_text, "Ctrl+S")
        self._add_action(file_menu, "解析レポートを HTML で保存…", self._save_report_html, "Ctrl+Shift+S")
        file_menu.addSeparator()
        self._add_action(file_menu, "終了", self.close, "Ctrl+Q")

        edit_menu = menu_bar.addMenu("編集(&E)")
        self._add_action(edit_menu, "変換を実行", self._convert, "Ctrl+Return")
        self._add_action(edit_menu, "変換を実行 (F5)", self._convert, "F5")
        edit_menu.addSeparator()
        self._add_action(edit_menu, "入力をクリア", self._clear_input, "Ctrl+L")
        self._add_action(edit_menu, "すべてクリア", self._clear_all)
        edit_menu.addSeparator()
        self._add_action(edit_menu, "デコード結果をコピー", self._copy_result)

        view_menu = menu_bar.addMenu("表示(&V)")
        self._dark_action = QAction("ダークモード", self, checkable=True)
        self._dark_action.setChecked(self._dark_mode)
        self._dark_action.setShortcut(QKeySequence("Ctrl+D"))
        self._dark_action.toggled.connect(self._set_dark_mode)
        view_menu.addAction(self._dark_action)

        self._defang_action = QAction("URL を無害化して表示 (hxxp 形式)", self, checkable=True)
        self._defang_action.setChecked(self._defang)
        self._defang_action.toggled.connect(self._set_defang)
        view_menu.addAction(self._defang_action)

        view_menu.addSeparator()
        self._add_action(view_menu, "文字を大きく", lambda: self._zoom(1), "Ctrl+=")
        self._add_action(view_menu, "文字を小さく", lambda: self._zoom(-1), "Ctrl+-")

        help_menu = menu_bar.addMenu("ヘルプ(&H)")
        self._add_action(help_menu, "使い方", self._show_help, "F1")
        self._add_action(help_menu, "サンプルヘッダーを読み込む", self._load_sample)
        help_menu.addSeparator()
        self._add_action(help_menu, "サードパーティ ライセンス", self._show_licenses)
        self._add_action(help_menu, "Qt について", lambda: QMessageBox.aboutQt(self))
        self._add_action(help_menu, f"{APP_NAME} について", self._show_about)

    def _add_action(self, menu, text: str, slot, shortcut: str | None = None) -> QAction:
        action = QAction(text, self)
        if shortcut:
            action.setShortcut(QKeySequence(shortcut))
        action.triggered.connect(slot)
        menu.addAction(action)
        return action

    # ── テーマ ──────────────────────────────────────────────

    @property
    def _palette_dict(self) -> dict:
        return DARK_PALETTE if self._dark_mode else LIGHT_PALETTE

    def _apply_theme(self) -> None:
        palette = self._palette_dict
        app = QApplication.instance()
        app.setStyleSheet(build_stylesheet(palette))
        self._convert_button.set_palette_colors(palette)
        self._theme_button.setText("☀️ ライトモード" if self._dark_mode else "🌙 ダークモード")
        self._report_browser.document().setDefaultStyleSheet(report_css(palette))
        self._decoded_browser.document().setDefaultStyleSheet(report_css(palette))
        if self._result is not None:
            self._decoded_browser.setHtml(build_decoded_html(self._result, palette))
            self._report_browser.setHtml(build_report_html(self._result, palette))
            self._update_risk_chip(self._result)
        else:
            self._decoded_browser.setHtml(decoded_placeholder_html(palette))
        if self._help_dialog is not None:
            self._help_dialog.apply_palette(palette)

    def _toggle_theme(self) -> None:
        self._dark_action.setChecked(not self._dark_mode)

    def _set_dark_mode(self, enabled: bool) -> None:
        self._dark_mode = enabled
        self._settings.setValue("dark_mode", enabled)
        self._apply_theme()

    def _set_defang(self, enabled: bool) -> None:
        self._defang = enabled
        self._settings.setValue("defang_urls", enabled)
        if self._result is not None:
            self._convert()

    def _zoom(self, direction: int) -> None:
        self._input_edit.zoomIn(direction)
        for browser in (self._decoded_browser, self._report_browser):
            if direction > 0:
                browser.zoomIn(1)
            else:
                browser.zoomOut(1)

    # ── 操作 ───────────────────────────────────────────────

    def _convert(self) -> None:
        raw_text = self._input_edit.toPlainText()
        if not raw_text.strip():
            QMessageBox.information(
                self,
                APP_NAME,
                "左側のテキストボックスにメールヘッダーを貼り付けてから「変換」を押してください。",
            )
            return
        if len(raw_text) > MAX_INPUT_CHARS:
            QMessageBox.warning(
                self,
                APP_NAME,
                "入力が大きすぎるため解析できません。\n\n"
                "添付ファイル本体を除いたメールソース、またはヘッダー部分を入力してください。",
            )
            return

        try:
            result = analyze_mail_text(raw_text, defang_urls=self._defang)
        except Exception as exc:  # 想定外の入力でも落とさない
            QMessageBox.critical(
                self,
                APP_NAME,
                f"解析中にエラーが発生しました。\n\n{type(exc).__name__}: {exc}",
            )
            return

        self._result = result
        self._decoded_browser.setHtml(build_decoded_html(result, self._palette_dict))
        self._report_browser.setHtml(build_report_html(result, self._palette_dict))
        self._update_risk_chip(result)

        level = result.security.risk_level
        subject = result.decoded.first_header("Subject") or "(件名なし)"
        self.statusBar().showMessage(
            f"変換完了 — 件名: {subject[:60]} / リスク評価: {level}"
        )

    def _update_risk_chip(self, result: AnalysisResult) -> None:
        palette = self._palette_dict
        level = result.security.risk_level
        if level == "高":
            fg, bg, text = palette["danger"], palette["danger_bg"], "⚠ リスク: 高(危険)"
        elif level == "中":
            fg, bg, text = palette["warn"], palette["warn_bg"], "⚠ リスク: 中(注意)"
        elif level == "低":
            fg, bg, text = palette["info"], palette["info_bg"], "リスク: 低"
        else:
            fg, bg, text = palette["ok"], palette["ok_bg"], "✔ 問題なし"
        self._risk_chip.setText(f"{text}(スコア {result.security.risk_score})")
        self._risk_chip.setStyleSheet(f"color: {fg}; background-color: {bg};")
        self._risk_chip.show()

    def _open_file(self) -> None:
        path_str, _ = QFileDialog.getOpenFileName(
            self,
            "ヘッダーファイルを開く",
            "",
            "テキスト / メール (*.txt *.eml);;すべてのファイル (*)",
        )
        if not path_str:
            return
        input_path = Path(path_str)
        try:
            if input_path.stat().st_size > MAX_INPUT_FILE_BYTES:
                QMessageBox.warning(
                    self,
                    APP_NAME,
                    "ファイルが大きすぎるため読み込めません。\n\n"
                    "添付ファイル本体を除いたメールソース、またはヘッダー部分を選んでください。",
                )
                return
            input_text = read_text(input_path)
            if len(input_text) > MAX_INPUT_CHARS:
                QMessageBox.warning(
                    self,
                    APP_NAME,
                    "ファイルの本文が大きすぎるため読み込めません。\n\n"
                    "添付ファイル本体を除いたメールソース、またはヘッダー部分を選んでください。",
                )
                return
            self._input_edit.setPlainText(input_text)
            self.statusBar().showMessage(f"読み込みました: {path_str}")
        except OSError as exc:
            QMessageBox.critical(self, APP_NAME, f"ファイルを読み込めませんでした。\n\n{exc}")

    def _save_decoded_text(self) -> None:
        if self._result is None:
            QMessageBox.information(self, APP_NAME, "先に「変換」を実行してください。")
            return
        default_name = f"abysspeek_decode_{datetime.now().strftime('%Y%m%d_%H%M%S')}.txt"
        path_str, _ = QFileDialog.getSaveFileName(
            self, "デコード結果を保存", default_name, "テキストファイル (*.txt)"
        )
        if not path_str:
            return
        output_path = Path(path_str)
        if not output_path.suffix:
            output_path = output_path.with_suffix(".txt")
        try:
            write_text(output_path, self._result.decoded_text)
        except OSError as exc:
            QMessageBox.critical(self, APP_NAME, f"ファイルを保存できませんでした。\n\n{exc}")
            return
        self.statusBar().showMessage(f"保存しました: {output_path}")

    def _save_report_html(self) -> None:
        if self._result is None:
            QMessageBox.information(self, APP_NAME, "先に「変換」を実行してください。")
            return
        palette = self._palette_dict
        default_name = f"abysspeek_report_{datetime.now().strftime('%Y%m%d_%H%M%S')}.html"
        path_str, _ = QFileDialog.getSaveFileName(
            self, "解析レポートを保存", default_name, "HTML ファイル (*.html)"
        )
        if not path_str:
            return
        output_path = Path(path_str)
        if not output_path.suffix:
            output_path = output_path.with_suffix(".html")
        body = build_report_html(self._result, palette)
        document = (
            "<!DOCTYPE html>\n<html lang=\"ja\"><head><meta charset=\"utf-8\">"
            f"<title>{APP_NAME} 解析レポート</title>"
            f"<style>body {{ font-family: sans-serif; max-width: 900px; margin: 24px auto; "
            f"background: {palette['surface2']}; }} {report_css(palette)}</style></head>"
            f"<body>{body}</body></html>"
        )
        try:
            write_text(output_path, document)
        except OSError as exc:
            QMessageBox.critical(self, APP_NAME, f"ファイルを保存できませんでした。\n\n{exc}")
            return
        self.statusBar().showMessage(f"保存しました: {output_path}")

    def _copy_result(self) -> None:
        if self._result is None:
            QMessageBox.information(self, APP_NAME, "先に「変換」を実行してください。")
            return
        QApplication.clipboard().setText(self._result.decoded_text)
        self.statusBar().showMessage("デコード結果をクリップボードにコピーしました")

    def _clear_input(self) -> None:
        self._input_edit.clear()
        self._input_edit.setFocus()

    def _invalidate_result(self) -> None:
        if self._result is None:
            return
        self._result = None
        self._decoded_browser.setHtml(decoded_placeholder_html(self._palette_dict))
        self._report_browser.clear()
        self._risk_chip.hide()
        self.statusBar().showMessage("入力が変更されました。もう一度「変換」を実行してください。")

    def _clear_all(self) -> None:
        self._input_edit.clear()
        self._decoded_browser.setHtml(decoded_placeholder_html(self._palette_dict))
        self._report_browser.clear()
        self._risk_chip.hide()
        self._result = None
        self.statusBar().showMessage("クリアしました")

    def _load_sample(self) -> None:
        if not SAMPLE_PATH.exists():
            QMessageBox.warning(self, APP_NAME, "サンプルファイルが見つかりませんでした。")
            return
        try:
            sample_text = read_text(SAMPLE_PATH)
        except OSError as exc:
            QMessageBox.critical(
                self, APP_NAME, f"サンプルファイルを読み込めませんでした。\n\n{exc}"
            )
            return
        self._input_edit.setPlainText(sample_text)
        self.statusBar().showMessage(
            "フィッシングメールを模したサンプルを読み込みました。「変換」を押してみてください。"
        )

    def _show_help(self) -> None:
        if self._help_dialog is None:
            self._help_dialog = HelpDialog(self._palette_dict, self)
        self._help_dialog.show()
        self._help_dialog.raise_()
        self._help_dialog.activateWindow()

    def _show_about(self) -> None:
        QMessageBox.about(
            self,
            f"{APP_NAME} について",
            f"<h3>{APP_NAME} v{APP_VERSION}</h3>"
            "<p>迷惑メールの深淵を、安全な場所から覗き込むための<br>"
            "メールヘッダー デコード & 解析ツール。</p>"
            "<p>・貼り付けた内容はローカルでのみ処理されます<br>"
            "・外部への通信は一切行いません</p>"
            "<p>MIT License / © 2026 DepthNekobit<br>"
            "Qt for Python (PySide6) を LGPLv3 の条件で使用しています。<br>"
            "詳細は「ヘルプ → サードパーティ ライセンス」を参照してください。</p>",
        )

    def _show_licenses(self) -> None:
        if not NOTICES_PATH.exists():
            QMessageBox.warning(self, APP_NAME, "ライセンス情報のファイルが見つかりませんでした。")
            return
        try:
            notices = read_text(NOTICES_PATH)
        except OSError as exc:
            QMessageBox.critical(self, APP_NAME, f"ライセンス情報を読み込めませんでした:\n{exc}")
            return

        dialog = QDialog(self)
        dialog.setWindowTitle("サードパーティ ライセンス")
        dialog.resize(760, 560)
        browser = QTextBrowser(dialog)
        # 相対リンク (licenses/*.txt 等) は同梱ファイルとして外部アプリで開く
        browser.setOpenLinks(False)
        browser.anchorClicked.connect(self._open_notice_link)
        browser.setMarkdown(notices)
        self._recolor_links(browser, self._palette_dict["accent"])
        buttons = QDialogButtonBox(QDialogButtonBox.StandardButton.Close, dialog)
        buttons.rejected.connect(dialog.reject)
        layout = QVBoxLayout(dialog)
        layout.addWidget(browser)
        layout.addWidget(buttons)
        dialog.exec()

    @staticmethod
    def _recolor_links(browser: QTextBrowser, color: str) -> None:
        # Markdown 読み込み時のリンク色はアプリ全体のパレット固定のため、テーマ色で塗り直す
        document = browser.document()
        block = document.begin()
        while block.isValid():
            it = block.begin()
            while not it.atEnd():
                fragment = it.fragment()
                fmt = fragment.charFormat()
                if fragment.isValid() and fmt.isAnchor():
                    fmt.setForeground(QBrush(QColor(color)))
                    cursor = QTextCursor(document)
                    cursor.setPosition(fragment.position())
                    cursor.setPosition(
                        fragment.position() + fragment.length(), QTextCursor.MoveMode.KeepAnchor
                    )
                    cursor.setCharFormat(fmt)
                it += 1
            block = block.next()

    def _open_notice_link(self, url: QUrl) -> None:
        if url.isRelative():
            url = QUrl.fromLocalFile(str(NOTICES_PATH.parent / url.path()))
        QDesktopServices.openUrl(url)

    # ── 状態保存 ────────────────────────────────────────────

    def _restore_geometry(self) -> None:
        geometry = self._settings.value("geometry")
        if geometry is not None:
            self.restoreGeometry(geometry)

    def closeEvent(self, event) -> None:  # noqa: N802 (Qt API)
        self._settings.setValue("geometry", self.saveGeometry())
        super().closeEvent(event)
