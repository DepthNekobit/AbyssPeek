import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

from src.io.file_handler import read_text, write_text


class FileHandlerTests(unittest.TestCase):
    def test_read_text_strips_utf8_bom(self):
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "mail.eml"
            path.write_bytes(b"\xef\xbb\xbfSubject: test\n")

            self.assertEqual(read_text(path), "Subject: test\n")

    def test_read_text_decodes_iso_2022_jp_before_ascii_compatible_utf8(self):
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "mail.eml"
            path.write_bytes("Subject: test\n\n日本語本文\n".encode("iso-2022-jp"))

            self.assertEqual(read_text(path), "Subject: test\n\n日本語本文\n")

    def test_failed_replace_preserves_existing_file(self):
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "report.txt"
            write_text(path, "original")

            with patch("src.io.file_handler.os.replace", side_effect=OSError("disk error")):
                with self.assertRaises(OSError):
                    write_text(path, "replacement")

            self.assertEqual(path.read_text(encoding="utf-8"), "original")
            self.assertEqual(list(path.parent.glob(f".{path.name}.*.tmp")), [])

    def test_fdopen_failure_closes_descriptor_and_removes_temp_file(self):
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "report.txt"
            temp_path = Path(directory) / ".report.txt.failed.tmp"
            temp_path.write_text("", encoding="utf-8")
            with (
                patch(
                    "src.io.file_handler.tempfile.mkstemp",
                    return_value=(12345, str(temp_path)),
                ),
                patch("src.io.file_handler.os.fdopen", side_effect=OSError("open failed")),
                patch("src.io.file_handler.os.close") as close,
            ):
                with self.assertRaisesRegex(OSError, "open failed"):
                    write_text(path, "replacement")

            close.assert_called_once_with(12345)
            self.assertFalse(temp_path.exists())


if __name__ == "__main__":
    unittest.main()
