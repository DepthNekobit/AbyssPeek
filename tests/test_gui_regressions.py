import os
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

os.environ.setdefault("QT_QPA_PLATFORM", "offscreen")

try:
    from PySide6.QtWidgets import QApplication

    from src.gui.main_window import MainWindow
except ImportError:
    QApplication = None
    MainWindow = None


@unittest.skipIf(QApplication is None, "PySide6 is not installed")
class GuiRegressionTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.app = QApplication.instance() or QApplication([])

    def setUp(self):
        self.window = MainWindow()

    def tearDown(self):
        self.window.close()
        self.app.processEvents()

    def test_sample_read_error_is_reported_without_escaping(self):
        with tempfile.TemporaryDirectory() as directory:
            sample_path = Path(directory) / "sample_header.txt"
            sample_path.write_text("sample", encoding="utf-8")
            with (
                patch("src.gui.main_window.SAMPLE_PATH", sample_path),
                patch("src.gui.main_window.read_text", side_effect=OSError("unreadable")),
                patch("src.gui.main_window.QMessageBox.critical") as critical,
            ):
                self.window._load_sample()

        critical.assert_called_once()

    def test_license_dialog_shows_third_party_notices(self):
        with patch("src.gui.main_window.QDialog.exec") as exec_dialog:
            self.window._show_licenses()

        exec_dialog.assert_called_once()

    def test_relative_notice_links_open_bundled_files(self):
        from PySide6.QtCore import QUrl

        from src.gui.main_window import NOTICES_PATH

        with patch("src.gui.main_window.QDesktopServices.openUrl") as open_url:
            self.window._open_notice_link(QUrl("licenses/LGPL-3.0.txt"))

        opened = Path(open_url.call_args.args[0].toLocalFile())
        self.assertEqual(opened, NOTICES_PATH.parent / "licenses" / "LGPL-3.0.txt")
        self.assertTrue(opened.is_file())

    def test_missing_license_notices_are_reported(self):
        with (
            patch("src.gui.main_window.NOTICES_PATH", Path("missing_notices.md")),
            patch("src.gui.main_window.QMessageBox.warning") as warning,
        ):
            self.window._show_licenses()

        warning.assert_called_once()


if __name__ == "__main__":
    unittest.main()
