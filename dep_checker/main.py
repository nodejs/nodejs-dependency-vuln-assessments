""" Node.js dependency vulnerability checker

This script queries the National Vulnerability Database (NVD) and the GitHub Advisory Database for vulnerabilities found
in Node's dependencies.

For each dependency in Node's `deps/` folder, the script parses their version number and queries the databases to find
vulnerabilities for that specific version.

If any vulnerabilities are found, the script returns 1 and prints out a list with the ID and a link to a description of
the vulnerability. This is the case except when the ID matches one in the ignore-list (inside `dependencies.py`) in
which case the vulnerability is ignored.
"""

from argparse import ArgumentParser
from collections import defaultdict
from dependencies import (
    ignore_list,
    dependencies_info,
    Dependency,
    dependencies_per_branch,
)
from gql import gql, Client
from gql.transport.aiohttp import AIOHTTPTransport
from nvdlib import searchCVE  # type: ignore
from packaging.specifiers import SpecifierSet
from typing import Optional
from pathlib import Path

import json


class Vulnerability:
    def __init__(self, id: str, url: str, dependency: str, version: str):
        self.id = id
        self.url = url
        self.dependency = dependency
        self.version = version


class VulnerabilityEncoder(json.JSONEncoder):
    def default(self, obj):
        if isinstance(obj, Vulnerability):
            return {"id": obj.id, "url": obj.url, "dependency": obj.dependency, "version": obj.version}
        # Let the base class default method raise the TypeError
        return json.JSONEncoder.default(self, obj)


vulnerability_found_message = """For each dependency and vulnerability, check the following:
- Check that the dependency's version printed by the script corresponds to the version present in the Node repo.
If not, update dependencies.py with the actual version number and run the script again.
- If the version is correct, check the vulnerability's description to see if it applies to the dependency as
used by Node. If not, the vulnerability ID (either a CVE or a GHSA) can be added to the ignore list in
dependencies.py. IMPORTANT: Only do this if certain that the vulnerability found is a false positive.
- Otherwise, the vulnerability found must be remediated by updating the dependency in the Node repo to a
non-affected version, followed by updating dependencies.py with the new version.
"""


github_vulnerabilities_query = gql(
    """
    query($package_name:String!) {
      securityVulnerabilities(package:$package_name, last:10) {
        nodes {
          vulnerableVersionRange
          advisory {
            ghsaId
            permalink
            withdrawnAt
          }
        }
      }
    }
"""
)


def query_ghad(
    dependencies: dict[str, Dependency], gh_token: str, repo_path: Path
) -> list[Vulnerability]:
    """Queries the GitHub Advisory Database for vulnerabilities reported for Node's dependencies.

    The database supports querying by package name in the NPM ecosystem, so we only send queries for the dependencies
    that are also NPM packages.
    """

    deps_in_npm = {
        name: dep for name, dep in dependencies.items() if dep.npm_name is not None
    }

    transport = AIOHTTPTransport(
        url="https://api.github.com/graphql",
        headers={"Authorization": f"bearer {gh_token}"},
    )
    client = Client(
        transport=transport,
        fetch_schema_from_transport=True,
        serialize_variables=True,
        parse_results=True,
    )

    found_vulnerabilities: list[Vulnerability] = list()
    for name, dep in deps_in_npm.items():
        variables_package = {
            "package_name": dep.npm_name,
        }
        result = client.execute(
            github_vulnerabilities_query, variable_values=variables_package
        )
        dep_version = dep.version_parser(repo_path)
        matching_vulns = [
            v
            for v in result["securityVulnerabilities"]["nodes"]
            if v["advisory"]["withdrawnAt"] is None
            and dep_version in SpecifierSet(v["vulnerableVersionRange"])
            and v["advisory"]["ghsaId"] not in ignore_list
        ]
        if matching_vulns:
            found_vulnerabilities.extend(
                [
                    Vulnerability(
                        id=vuln["advisory"]["ghsaId"], url=vuln["advisory"]["permalink"], dependency=name, version=dep_version
                    )
                    for vuln in matching_vulns
                ]
            )

    return found_vulnerabilities


def query_nvd(
    dependencies: dict[str, Dependency], api_key: Optional[str], repo_path: Path
) -> list[Vulnerability]:
    """Queries the National Vulnerability Database for vulnerabilities reported for Node's dependencies.

    The database supports querying by CPE (Common Platform Enumeration) or by a keyword present in the CVE's
    description.
    Since some of Node's dependencies don't have an associated CPE, we use their name as a keyword in the query.
    """
    deps_in_nvd = {
        name: dep
        for name, dep in dependencies.items()
        if dep.cpe is not None or dep.keyword is not None
    }
    found_vulnerabilities: list[Vulnerability] = list()
    for name, dep in deps_in_nvd.items():
        query_results = [
            cve
            for cve in searchCVE(
                cpeMatchString=dep.get_cpe(repo_path), keyword=dep.keyword, key=api_key
            )
            if cve.id not in ignore_list
        ]
        if query_results:
            version = dep.version_parser(repo_path)
            found_vulnerabilities.extend(
                [Vulnerability(id=cve.id, url=cve.url, dependency=name, version=version) for cve in query_results]
            )

    return found_vulnerabilities


def main() -> int:
    parser = ArgumentParser(
        description="Query the NVD and the GitHub Advisory Database for new vulnerabilities in Node's dependencies"
    )
    parser.add_argument(
        "node_repo_path",
        metavar="NODE_REPO_PATH",
        type=Path,
        help="the path to Node's repository",
    )
    supported_branches = [k for k in dependencies_per_branch.keys()]
    parser.add_argument(
        "node_repo_branch",
        metavar="NODE_REPO_BRANCH",
        help=f"the current branch of the Node repository (supports {supported_branches})",
    )
    parser.add_argument(
        "--gh-token",
        help="the GitHub authentication token for querying the GH Advisory Database",
    )
    parser.add_argument(
        "--nvd-key",
        help="the NVD API key for querying the National Vulnerability Database",
    )
    parser.add_argument(
        "--json-output",
        action='store_true',
        help="the NVD API key for querying the National Vulnerability Database",
    )
    repo_path: Path = parser.parse_args().node_repo_path
    repo_branch: str = parser.parse_args().node_repo_branch
    gh_token = parser.parse_args().gh_token
    nvd_key = parser.parse_args().nvd_key
    json_output: bool = parser.parse_args().json_output
    if not repo_path.exists() or not (repo_path / ".git").exists():
        raise RuntimeError(
            "Invalid argument: '{repo_path}' is not a valid Node git repository"
        )
    if repo_branch not in dependencies_per_branch:
        raise RuntimeError(
            f"Invalid argument: '{repo_branch}' is not a supported branch. Please use one of: {supported_branches}"
        )
    if gh_token is None:
        print(
            "Warning: GitHub authentication token not provided, skipping GitHub Advisory Database queries"
        )
    if nvd_key is None:
        print(
            "Warning: NVD API key not provided, queries will be slower due to rate limiting"
        )

    dependencies = {
        name: dep
        for name, dep in dependencies_info.items()
        if name in dependencies_per_branch[repo_branch]
    }
    ghad_vulnerabilities: list[Vulnerability] = (
        {} if gh_token is None else query_ghad(dependencies, gh_token, repo_path)
    )
    nvd_vulnerabilities: list[Vulnerability] = query_nvd(
        dependencies, nvd_key, repo_path
    )

    all_vulnerabilities = {"vulnerabilities": ghad_vulnerabilities + nvd_vulnerabilities}
    no_vulnerabilities_found = not ghad_vulnerabilities and not nvd_vulnerabilities
    if json_output:
        print(json.dumps(all_vulnerabilities, cls=VulnerabilityEncoder))
        return 0 if no_vulnerabilities_found else 1
    elif no_vulnerabilities_found:
        print(f"No new vulnerabilities found ({len(ignore_list)} ignored)")
        return 0
    else:
        print("WARNING: New vulnerabilities found")
        for vuln in all_vulnerabilities["vulnerabilities"]:
            print(
                f"- {vuln.dependency} (version {vuln.version}) : {vuln.id} ({vuln.url})"
            )
        print(f"\n{vulnerability_found_message}")
        return 1


if __name__ == "__main__":
    exit(main())
