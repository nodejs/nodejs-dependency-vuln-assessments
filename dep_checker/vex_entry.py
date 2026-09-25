"""Generate a nodejs/security-wg `vuln/deps/<N>.json` entry from a closed issue.

When an issue in this repository is closed with one of the OpenVEX
`not_affected` justification labels, the `vex-entry` workflow runs this script
to produce the JSON file that feeds `vuln/deps/index.json` in
nodejs/security-wg, which in turn feeds the generated `node.openvex.json`.

The five accepted labels are the OpenVEX justification values, see
https://github.com/openvex/spec/blob/main/OPENVEX-SPEC.md#status-justifications
"""

from argparse import ArgumentParser
from pathlib import Path
from typing import Callable, Dict, List, Optional
from urllib.request import Request, urlopen

import json
import os
import re
import sys

JUSTIFICATIONS = (
    "component_not_present",
    "vulnerable_code_not_present",
    "vulnerable_code_not_in_execute_path",
    "vulnerable_code_cannot_be_controlled_by_adversary",
    "inline_mitigations_already_exist",
)

DEFAULT_OVERVIEWS = {
    "component_not_present": (
        "The vulnerable component is not shipped with Node.js."
    ),
    "vulnerable_code_not_present": (
        "The dependency is shipped with Node.js but the vulnerable code is not "
        "included in the Node.js build."
    ),
    "vulnerable_code_not_in_execute_path": (
        "The vulnerable code is present in the bundled dependency but is not in "
        "the execution path of Node.js."
    ),
    "vulnerable_code_cannot_be_controlled_by_adversary": (
        "The vulnerable code is reachable in Node.js but its inputs cannot be "
        "controlled by an adversary."
    ),
    "inline_mitigations_already_exist": (
        "Node.js already includes mitigations that prevent this vulnerability "
        "from being exploited."
    ),
}

CVE_RECORD_API = "https://cveawg.mitre.org/api/cve/{cve}"
CVE_PATTERN = re.compile(r"CVE-\d{4}-\d{4,}", re.IGNORECASE)


class VexEntryError(Exception):
    """Raised when an issue cannot be turned into a VEX entry."""


def parse_cve_ids(text: str) -> List[str]:
    """Return the distinct CVE ids found in `text`, uppercased, in order."""
    seen: Dict[str, None] = {}
    for match in CVE_PATTERN.findall(text):
        seen.setdefault(match.upper(), None)
    return list(seen)


def justification_from_labels(labels: List[str]) -> str:
    """Return the single OpenVEX justification label present in `labels`."""
    found = [label for label in labels if label in JUSTIFICATIONS]
    if not found:
        raise VexEntryError(
            "no VEX justification label found; expected one of: "
            + ", ".join(JUSTIFICATIONS)
        )
    if len(found) > 1:
        raise VexEntryError(
            "multiple VEX justification labels found: " + ", ".join(found)
        )
    return found[0]


def _entry_files(deps_dir: Path) -> Dict[int, Path]:
    files = {}
    for path in deps_dir.glob("*.json"):
        if path.stem.isdigit():
            files[int(path.stem)] = path
    return files


def existing_cves(deps_dir: Path) -> Dict[str, str]:
    """Map every CVE already recorded under `deps_dir` to its file name."""
    result: Dict[str, str] = {}
    for _, path in sorted(_entry_files(deps_dir).items()):
        data = json.loads(path.read_text())
        for cve in data.get("cve", []):
            result[cve.upper()] = path.name
    return result


def next_entry_number(deps_dir: Path) -> int:
    numbers = _entry_files(deps_dir)
    return max(numbers) + 1 if numbers else 1


def overview_from_comments(comments: List[dict], closer_login: str) -> Optional[str]:
    """Return the most recent comment body written by `closer_login`, if any."""
    for comment in reversed(comments):
        if comment.get("user", {}).get("login") == closer_login:
            body = comment.get("body", "").strip()
            if body:
                return body
    return None


def default_overview(reason: str) -> str:
    return DEFAULT_OVERVIEWS[reason]


def build_entry(
    cves: List[str], description: str, overview: str, ref: str, reason: str
) -> dict:
    return {
        "cve": cves,
        "description": description,
        "overview": overview,
        "ref": ref,
        "reason": reason,
    }


def description_from_cve_record(record: dict) -> str:
    cna = record.get("containers", {}).get("cna", {})
    title = cna.get("title", "").strip()
    if title:
        return title
    for item in cna.get("descriptions", []):
        if item.get("lang", "en").startswith("en") and item.get("value"):
            return item["value"].strip()
    return ""


def fetch_cve_record(cve: str) -> dict:
    request = Request(
        CVE_RECORD_API.format(cve=cve),
        headers={"User-Agent": "nodejs-dependency-vuln-assessments"},
    )
    with urlopen(request, timeout=30) as response:
        return json.load(response)


def fetch_description(cves: List[str], fetch: Optional[Callable[[str], dict]] = None) -> str:
    fetch = fetch or fetch_cve_record
    parts = []
    for cve in cves:
        try:
            text = description_from_cve_record(fetch(cve))
        except Exception as error:  # network or parse problem, reviewer can fix
            print(f"warning: could not fetch {cve}: {error}", file=sys.stderr)
            text = ""
        parts.append(text or f"{cve} (description unavailable)")
    return " ".join(parts)


def write_github_output(values: Dict[str, str]) -> None:
    output_path = os.environ.get("GITHUB_OUTPUT")
    if not output_path:
        return
    with open(output_path, "a") as output:
        for key, value in values.items():
            output.write(f"{key}={value}\n")


def main(argv: Optional[List[str]] = None) -> int:
    parser = ArgumentParser(description=__doc__.splitlines()[0])
    parser.add_argument("--issue-title", required=True)
    parser.add_argument("--issue-url", required=True)
    parser.add_argument("--labels", required=True, help="comma separated label names")
    parser.add_argument("--closed-by", required=True, help="login of the user who closed the issue")
    parser.add_argument("--comments-file", required=True, help="JSON array of issue comments from the GitHub API")
    parser.add_argument("--deps-dir", required=True, help="path to security-wg/vuln/deps")
    args = parser.parse_args(argv)

    deps_dir = Path(args.deps_dir)
    labels = [label.strip() for label in args.labels.split(",") if label.strip()]

    try:
        reason = justification_from_labels(labels)
    except VexEntryError as error:
        print(f"error: {error}", file=sys.stderr)
        return 1

    cves = parse_cve_ids(args.issue_title)
    if not cves:
        print(f"error: no CVE id found in issue title: {args.issue_title!r}", file=sys.stderr)
        return 1

    already = existing_cves(deps_dir)
    new_cves = [cve for cve in cves if cve not in already]
    skipped = {cve: already[cve] for cve in cves if cve in already}
    for cve, filename in skipped.items():
        print(f"skipping {cve}: already recorded in {filename}")

    if not new_cves:
        write_github_output({"entry_file": "", "cves": "", "skipped": "true"})
        print("nothing to do: every CVE is already in vuln/deps")
        return 0

    comments = json.loads(Path(args.comments_file).read_text())
    overview = overview_from_comments(comments, args.closed_by) or default_overview(reason)

    entry = build_entry(
        cves=new_cves,
        description=fetch_description(new_cves),
        overview=overview,
        ref=args.issue_url,
        reason=reason,
    )

    target = deps_dir / f"{next_entry_number(deps_dir)}.json"
    target.write_text(json.dumps(entry, indent=4) + "\n")
    print(f"wrote {target}")

    write_github_output(
        {
            "entry_file": target.name,
            "cves": " ".join(new_cves),
            "branch": f"vex/{new_cves[0].lower()}",
            "skipped": "false",
        }
    )
    return 0


if __name__ == "__main__":
    sys.exit(main())
