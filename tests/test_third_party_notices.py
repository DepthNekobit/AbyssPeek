import re
import unittest
from pathlib import Path

from src.services.geoip import _OCTET_REGION, REGION_JA, describe_ip


PROJECT_ROOT = Path(__file__).resolve().parents[1]


class ThirdPartyNoticesTests(unittest.TestCase):
    def test_notices_link_only_to_existing_license_files(self):
        text = (PROJECT_ROOT / "THIRD_PARTY_NOTICES.md").read_text(encoding="utf-8")
        links = re.findall(r"\]\((licenses/[^)]+)\)", text)

        self.assertIn("licenses/LGPL-3.0.txt", links)
        self.assertIn("licenses/GPL-3.0.txt", links)
        self.assertIn("licenses/Apache-2.0.txt", links)
        self.assertIn("licenses/Qt-third-party-notices.txt", links)
        for link in links:
            with self.subTest(link=link):
                self.assertTrue((PROJECT_ROOT / link).is_file())

    def test_release_bundles_license_documents(self):
        text = (PROJECT_ROOT / ".github" / "workflows" / "release.yml").read_text(
            encoding="utf-8"
        )

        for data in ('"LICENSE;."', '"THIRD_PARTY_NOTICES.md;."', '"licenses;licenses"'):
            with self.subTest(add_data=data):
                self.assertIn(f"--add-data {data}", text)
        self.assertIn("dist\\THIRD_PARTY_NOTICES.md", text)
        self.assertIn("dist\\licenses", text)

    def test_release_build_pins_qt_version_stated_in_notices(self):
        requirements = (PROJECT_ROOT / "requirements-build.txt").read_text(encoding="utf-8")
        match = re.search(r"^PySide6-Essentials==([0-9.]+)$", requirements, re.MULTILINE)
        self.assertIsNotNone(match, "リリースビルドは PySide6-Essentials を固定バージョンで使う")
        version = match.group(1)

        notices = (PROJECT_ROOT / "THIRD_PARTY_NOTICES.md").read_text(encoding="utf-8")
        self.assertIn(f"PySide6-Essentials {version} / Qt {version}", notices)
        self.assertIn(f"PySide6-{version}-src", notices)

        qt_notices = (PROJECT_ROOT / "licenses" / "Qt-third-party-notices.txt").read_text(
            encoding="utf-8"
        )
        self.assertTrue(qt_notices.startswith(f"Qt {version} "))
        self.assertIn("copyright (C) The FreeType Project", qt_notices)


class GeoIpTableTests(unittest.TestCase):
    def test_table_entries_use_known_regions(self):
        for octet, entry in _OCTET_REGION.items():
            with self.subTest(octet=octet):
                self.assertTrue(1 <= octet <= 223)
                region, _, country = entry.partition(":")
                self.assertIn(region, REGION_JA)
                if country:
                    self.assertRegex(country, r"^[A-Z]{2}$")

    def test_well_known_blocks(self):
        self.assertEqual(describe_ip("126.1.2.3").country, "JP")
        self.assertEqual(describe_ip("200.1.2.3").region, "SA")
        self.assertEqual(describe_ip("41.1.2.3").region, "AF")


if __name__ == "__main__":
    unittest.main()
