"""Offline regression tests for reviewed NVD vulnerability ranges."""

import unittest
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import patch

from dependencies import Dependency, dependencies_info
from main import query_nvd


class NvdVersionRangeTests(unittest.TestCase):
    def query(self, version, ranges):
        dependency = Dependency(
            version_parser=lambda _: version,
            keyword="ngtcp2",
            nvd_vulnerable_versions=ranges,
        )
        ids = ["CVE-2024-52811", "CVE-2026-40170", "CVE-2099-99999"]
        results = [SimpleNamespace(id=id, url=f"https://example.com/{id}") for id in ids]
        with patch("main.searchCVE", return_value=results):
            return query_nvd({"ngtcp2": dependency}, None, Path("unused"))

    def test_reviewed_ranges_and_unknown_advisories(self):
        cases = {
            "1.8.0": {"CVE-2026-40170"},
            "1.9.0": {"CVE-2024-52811", "CVE-2026-40170"},
            "1.9.1": {"CVE-2026-40170"},
            "1.11.0": {"CVE-2026-40170"},
            "1.22.0": {"CVE-2026-40170"},
            "1.22.1": set(),
            "1.25.0": set(),
        }
        ranges = dependencies_info["ngtcp2"].nvd_vulnerable_versions
        for version, expected in cases.items():
            with self.subTest(version=version):
                results = self.query(version, ranges)
                self.assertEqual(
                    {v.id for v in results}, expected | {"CVE-2099-99999"}
                )
                self.assertTrue(all(v.version == version for v in results))

    def test_non_release_versions_keep_all_advisories(self):
        versions = [
            "1.9.0-DEV",
            "1.11.0-DEV",
            "1.22.1-DEV",
            "1.25.0-rc.1",
            "1.11.0-custom",
            "1.25.0+vendor.1",
            "v1.25.0",
            "1.25",
            "1.25.0.1",
            "01.25.0",
            "1.25.0\n",
            "unknown",
            "",
        ]
        ranges = dependencies_info["ngtcp2"].nvd_vulnerable_versions
        for version in versions:
            with self.subTest(version=version):
                results = self.query(version, ranges)
                self.assertEqual(
                    {v.id for v in results},
                    {"CVE-2024-52811", "CVE-2026-40170", "CVE-2099-99999"},
                )
                self.assertTrue(all(v.version == version for v in results))

    def test_dependency_without_ranges_keeps_all_advisories(self):
        self.assertEqual(
            {v.id for v in self.query("1.25.0", None)},
            {"CVE-2024-52811", "CVE-2026-40170", "CVE-2099-99999"},
        )


if __name__ == "__main__":
    unittest.main()
