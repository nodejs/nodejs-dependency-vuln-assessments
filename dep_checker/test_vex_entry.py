import json
import os
import tempfile
import unittest
from pathlib import Path

import vex_entry


class ParseCveIds(unittest.TestCase):
    def test_extracts_single_cve_from_scanner_title(self):
        self.assertEqual(
            vex_entry.parse_cve_ids("CVE-2026-78227 (ngtcp2) found on main"),
            ["CVE-2026-78227"],
        )

    def test_extracts_multiple_cves_in_order_without_duplicates(self):
        title = "cve-2025-9230, CVE-2025-9231, CVE-2025-9230, CVE-2025-9232 (OpenSSL)"
        self.assertEqual(
            vex_entry.parse_cve_ids(title),
            ["CVE-2025-9230", "CVE-2025-9231", "CVE-2025-9232"],
        )

    def test_returns_empty_list_when_no_cve(self):
        self.assertEqual(vex_entry.parse_cve_ids("GHSA-xxxx (foo) found on main"), [])


class JustificationFromLabels(unittest.TestCase):
    def test_returns_the_single_vex_label(self):
        self.assertEqual(
            vex_entry.justification_from_labels(
                ["v24.x", "vulnerable_code_not_in_execute_path"]
            ),
            "vulnerable_code_not_in_execute_path",
        )

    def test_raises_when_no_vex_label(self):
        with self.assertRaises(vex_entry.VexEntryError):
            vex_entry.justification_from_labels(["v24.x", "dont-believe-affects-nodejs"])

    def test_raises_when_multiple_vex_labels(self):
        with self.assertRaises(vex_entry.VexEntryError):
            vex_entry.justification_from_labels(
                ["component_not_present", "inline_mitigations_already_exist"]
            )


class DepsDirectory(unittest.TestCase):
    def setUp(self):
        self._tmp = tempfile.TemporaryDirectory()
        self.deps = Path(self._tmp.name)
        (self.deps / "1.json").write_text(
            json.dumps({"cve": ["CVE-2023-45853"], "reason": "vulnerable_code_not_present"})
        )
        (self.deps / "6.json").write_text(
            json.dumps({"cve": ["CVE-2025-9230", "CVE-2025-9231"], "reason": "x"})
        )
        (self.deps / "index.json").write_text("{}")

    def tearDown(self):
        self._tmp.cleanup()

    def test_existing_cves_maps_cve_to_file(self):
        self.assertEqual(
            vex_entry.existing_cves(self.deps),
            {
                "CVE-2023-45853": "1.json",
                "CVE-2025-9230": "6.json",
                "CVE-2025-9231": "6.json",
            },
        )

    def test_next_entry_number_is_max_plus_one(self):
        self.assertEqual(vex_entry.next_entry_number(self.deps), 7)

    def test_next_entry_number_starts_at_one_for_empty_dir(self):
        with tempfile.TemporaryDirectory() as empty:
            self.assertEqual(vex_entry.next_entry_number(Path(empty)), 1)


class Overview(unittest.TestCase):
    comments = [
        {"user": {"login": "alice"}, "body": "first"},
        {"user": {"login": "bob"}, "body": "bob says no"},
        {"user": {"login": "alice"}, "body": "Node.js never calls this code path."},
        {"user": {"login": "carol"}, "body": "later"},
    ]

    def test_uses_latest_comment_by_closer(self):
        self.assertEqual(
            vex_entry.overview_from_comments(self.comments, "alice"),
            "Node.js never calls this code path.",
        )

    def test_falls_back_to_default_when_closer_has_no_comment(self):
        self.assertEqual(
            vex_entry.overview_from_comments(self.comments, "dave"),
            None,
        )

    def test_default_overview_mentions_reason(self):
        text = vex_entry.default_overview("vulnerable_code_not_in_execute_path")
        self.assertIn("not in the execution path", text)


class BuildEntry(unittest.TestCase):
    def test_entry_matches_security_wg_schema(self):
        entry = vex_entry.build_entry(
            cves=["CVE-2025-9230"],
            description="OpenSSL bug",
            overview="Not reachable from Node.js.",
            ref="https://github.com/nodejs/nodejs-dependency-vuln-assessments/issues/213",
            reason="vulnerable_code_not_in_execute_path",
        )
        self.assertEqual(
            entry,
            {
                "cve": ["CVE-2025-9230"],
                "description": "OpenSSL bug",
                "overview": "Not reachable from Node.js.",
                "ref": "https://github.com/nodejs/nodejs-dependency-vuln-assessments/issues/213",
                "reason": "vulnerable_code_not_in_execute_path",
            },
        )


class DescriptionFromCveRecord(unittest.TestCase):
    def test_prefers_title_then_first_english_description(self):
        record = {
            "containers": {
                "cna": {
                    "title": "Out-of-bounds read in CMS",
                    "descriptions": [{"lang": "en", "value": "long text"}],
                }
            }
        }
        self.assertEqual(
            vex_entry.description_from_cve_record(record), "Out-of-bounds read in CMS"
        )

    def test_uses_description_when_title_missing(self):
        record = {
            "containers": {
                "cna": {"descriptions": [{"lang": "en", "value": "long text"}]}
            }
        }
        self.assertEqual(vex_entry.description_from_cve_record(record), "long text")


class MainEndToEnd(unittest.TestCase):
    def setUp(self):
        self._tmp = tempfile.TemporaryDirectory()
        root = Path(self._tmp.name)
        self.deps = root / "deps"
        self.deps.mkdir()
        (self.deps / "3.json").write_text(
            json.dumps({"cve": ["CVE-2025-9230"], "reason": "vulnerable_code_not_in_execute_path"})
        )
        self.comments = root / "comments.json"
        self.comments.write_text(
            json.dumps([{"user": {"login": "rafael"}, "body": "Node.js does not use CMS."}])
        )
        self.github_output = root / "out.txt"
        self.github_output.write_text("")
        self._old_env = os.environ.get("GITHUB_OUTPUT")
        os.environ["GITHUB_OUTPUT"] = str(self.github_output)
        self._old_fetch = vex_entry.fetch_cve_record
        vex_entry.fetch_cve_record = lambda cve: {
            "containers": {"cna": {"title": f"Title for {cve}"}}
        }

    def tearDown(self):
        vex_entry.fetch_cve_record = self._old_fetch
        if self._old_env is None:
            os.environ.pop("GITHUB_OUTPUT", None)
        else:
            os.environ["GITHUB_OUTPUT"] = self._old_env
        self._tmp.cleanup()

    def run_main(self, title, labels):
        return vex_entry.main(
            [
                "--issue-title", title,
                "--issue-url", "https://github.com/nodejs/nodejs-dependency-vuln-assessments/issues/400",
                "--labels", labels,
                "--closed-by", "rafael",
                "--comments-file", str(self.comments),
                "--deps-dir", str(self.deps),
            ]
        )

    def test_writes_next_file_for_new_cves_only(self):
        code = self.run_main(
            "CVE-2025-9230, CVE-2025-9231 (OpenSSL)", "v24.x,vulnerable_code_not_in_execute_path"
        )
        self.assertEqual(code, 0)
        written = json.loads((self.deps / "4.json").read_text())
        self.assertEqual(written["cve"], ["CVE-2025-9231"])
        self.assertEqual(written["description"], "Title for CVE-2025-9231")
        self.assertEqual(written["overview"], "Node.js does not use CMS.")
        self.assertEqual(written["reason"], "vulnerable_code_not_in_execute_path")
        self.assertIn("entry_file=4.json", self.github_output.read_text())
        self.assertIn("skipped=false", self.github_output.read_text())
        self.assertIn("branch=vex/cve-2025-9231", self.github_output.read_text())

    def test_skips_when_all_cves_already_recorded(self):
        code = self.run_main("CVE-2025-9230 (OpenSSL) found on main", "vulnerable_code_not_in_execute_path")
        self.assertEqual(code, 0)
        self.assertFalse((self.deps / "4.json").exists())
        self.assertIn("skipped=true", self.github_output.read_text())

    def test_fails_without_cve_in_title(self):
        code = self.run_main("GHSA-abcd (foo) found on main", "component_not_present")
        self.assertEqual(code, 1)
        self.assertFalse((self.deps / "4.json").exists())

    def test_fails_with_conflicting_labels(self):
        code = self.run_main(
            "CVE-2025-9231 (OpenSSL)", "component_not_present,inline_mitigations_already_exist"
        )
        self.assertEqual(code, 1)


if __name__ == "__main__":
    unittest.main()
