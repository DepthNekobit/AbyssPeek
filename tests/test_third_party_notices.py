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
