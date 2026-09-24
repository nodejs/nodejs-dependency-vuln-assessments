# node-js-dependency-vuln-assessments

This repo is used to

1. Run automated checks for vulnerabilities in Node.js dependencies that have
   already been made public.
2. Track and communicate information about dependency vulnerabilities that
   are public and have not yet been addressed.


Automated checks are currently run through a GitHub action using
[dep_checker](https://github.com/nodejs/nodejs-dependency-vuln-assessments/tree/main/dep_checker).

When issues are closed with specific labels (e.g., `vulnerable_code_not_in_execute_path`),
a VEX entry is automatically generated via
[vex-automation](https://github.com/nodejs/nodejs-dependency-vuln-assessments/tree/main/.github/workflows/vex-automation.yml).

**DO NOT REPORT OR DISCUSS VULNERABILITIES THAT ARE NOT ALREADY
PUBLIC IN THIS REPO**. Please report new vulnerabilities either to
the projects for a specific dependency or report to the Node.js project
as outlined in the Node.js
[SECURITY.md](https://github.com/nodejs/node/blob/main/SECURITY.md) file.


