# node-js-dependency-vuln-assessments

This repo is used to

1. Run automated checks for vulnerabilities in Node.js dependencies that have
   already been made public.
2. Track and communicate information about dependency vulnerabilities that
   are public and have not yet been addressed.


Automated checks are currently run through a GitHub action using
[dep_checker](https://github.com/nodejs/nodejs-dependency-vuln-assessments/tree/main/dep_checker).

## Triage labels

Every issue opened by the scanner must be closed with a label that records
the outcome of the triage. The labels below map one to one onto the
[OpenVEX status justifications](https://github.com/openvex/spec/blob/main/OPENVEX-SPEC.md#status-justifications)
and are the only ones that feed the Node.js VEX document.

### Not affected

Closing an issue with exactly one of these labels triggers the
[vex-entry](.github/workflows/vex-entry.yml) workflow, which opens a pull
request in [nodejs/security-wg](https://github.com/nodejs/security-wg/tree/main/vuln/deps)
adding a `vuln/deps/<N>.json` entry with `status: not_affected` and the label
as `reason`. Once that pull request is merged, `node.openvex.json` is
regenerated and scanners consuming it stop reporting the CVE.

| Label | Use when |
| --- | --- |
| `component_not_present` | The vulnerable component (library, module, or file) is not shipped in Node.js at all. |
| `vulnerable_code_not_present` | The dependency is shipped, but the vulnerable code is removed or compiled out of the Node.js build. |
| `vulnerable_code_not_in_execute_path` | The vulnerable code is compiled in, but Node.js never calls it and does not expose it through its APIs. |
| `vulnerable_code_cannot_be_controlled_by_adversary` | Node.js calls the vulnerable code, but an attacker cannot control the inputs that trigger the bug. |
| `inline_mitigations_already_exist` | Node.js calls the vulnerable code, but a mitigation elsewhere in Node.js prevents exploitation. |

The workflow builds the entry as follows:

- `cve`: every CVE id found in the issue title. CVEs already present in
  `vuln/deps` are skipped, so closing the per-release-line duplicates of the
  same CVE does not create duplicate entries.
- `description`: the CVE record title from cve.org.
- `overview`: the most recent comment on the issue written by the person who
  closed it, or a generic sentence for the label if they left no comment.
  Write the reasoning as a comment before closing, it becomes the public
  `impact_statement`.
- `ref`: the issue URL.

Review the `overview` text in the security-wg pull request before merging.
If the issue has no CVE id in its title, or more than one of these labels,
the workflow fails and comments on the issue.

### Affected

| Label | Use when |
| --- | --- |
| `confirmed` | The vulnerability affects Node.js. The fix ships in a security release and the VEX statement is produced from `vuln/core` by the security release process, not by this repository. |

### Legacy labels

`dont-believe-affects-nodejs` and `dont-fall-in-threat-model` predate the VEX
integration. They do not trigger any automation. Use one of the
`not_affected` labels above instead.

### Setup

The workflow needs a `SECURITY_WG_TOKEN` repository secret holding a token
with `contents: write` and `pull-requests: write` on nodejs/security-wg.

**DO NOT REPORT OR DISCUSS VULNERABILITIES THAT ARE NOT ALREADY
PUBLIC IN THIS REPO**. Please report new vulnerabilities either to
the projects for a specific dependency or report to the Node.js project
as outlined in the Node.js
[SECURITY.md](https://github.com/nodejs/node/blob/main/SECURITY.md) file.


