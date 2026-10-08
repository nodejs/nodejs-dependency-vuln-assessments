"""Generate VEX entry JSON file from closed issue data.

This script creates a VEX (Vulnerability Exploitability eXchange) entry
when an issue is closed with a specific label indicating the vulnerability
assessment result.
"""

import argparse
import json
import os
import re
import sys


# Maps issue labels to VEX justification values
JUSTIFICATION_MAP = {
    "vulnerable_code_not_in_execute_path": "vulnerable_code_not_in_execute_path",
    "vulnerable_code_not_present": "vulnerable_code_not_present",
    "vulnerable_code_cannot_be_controlled_by_adversary": "vulnerable_code_cannot_be_controlled_by_adversary",
    "inline_mitigations_already_exist": "inline_mitigations_already_exist",
}


def get_next_file_number(vuln_deps_path: str) -> int:
    """Find the next available VEX file number."""
    if not os.path.exists(vuln_deps_path):
        return 1

    existing = [f for f in os.listdir(vuln_deps_path) if f.endswith(".json")]
    numbers = []
    for f in existing:
        name = f.replace(".json", "")
        if name.isdigit():
            numbers.append(int(name))

    return max(numbers) + 1 if numbers else 1


def parse_cve_from_title(title: str) -> str | None:
    """Extract CVE ID from issue title."""
    match = re.search(r"CVE-\d{4}-\d+", title, re.IGNORECASE)
    return match.group(0).upper() if match else None


def get_justification(labels: str) -> str | None:
    """Get VEX justification from issue labels."""
    for label in labels.split(","):
        label = label.strip()
        if label in JUSTIFICATION_MAP:
            return JUSTIFICATION_MAP[label]
    return None


def create_vex_entry(
    issue_number: str,
    issue_title: str,
    issue_url: str,
    justification: str,
    cve_id: str,
) -> dict:
    """Create VEX entry dictionary."""
    return {
        "cve": cve_id,
        "ref": issue_url,
        "vulnerable": "n/a",
        "patched": "n/a",
        "vex": {
            "status": "not_affected",
            "justification": justification,
        },
    }


def main():
    parser = argparse.ArgumentParser(description="Generate VEX entry from issue")
    parser.add_argument("--issue-number", required=True)
    parser.add_argument("--issue-title", required=True)
    parser.add_argument("--issue-url", required=True)
    parser.add_argument("--labels", required=True)
    parser.add_argument("--output-dir", required=True)
    args = parser.parse_args()

    # Extract CVE from title
    cve_id = parse_cve_from_title(args.issue_title)
    if not cve_id:
        print(f"Error: No CVE found in title: {args.issue_title}")
        sys.exit(1)

    # Get justification from labels
    justification = get_justification(args.labels)
    if not justification:
        print(f"Error: No valid justification label found in: {args.labels}")
        sys.exit(1)

    # Verify output directory exists
    if not os.path.exists(args.output_dir):
        print(f"Error: Output directory not found: {args.output_dir}")
        sys.exit(1)

    # Create VEX entry
    vex_entry = create_vex_entry(
        args.issue_number,
        args.issue_title,
        args.issue_url,
        justification,
        cve_id,
    )

    # Write to file
    file_number = get_next_file_number(args.output_dir)
    output_file = os.path.join(args.output_dir, f"{file_number}.json")

    with open(output_file, "w") as f:
        json.dump(vex_entry, f, indent=2)
        f.write("\n")

    print(f"Created: {output_file}")


if __name__ == "__main__":
    main()
