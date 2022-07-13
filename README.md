# node-js-dependency-vuln-assessments

This repo is used to

1. Run automated checks for vulnerabilities in Node.js dependencies that have
   already been made public
1. Track and communicate information about vulnerabilities in depdencies that
   are public and have not yet been addressed. This maybe be to documented
   that they don't affect Node.js or what action is being taken to address
   then.


Automated checks are currently run through a GitHub action using
[dep_checker](https://github.com/nodejs/node/tree/main/tools/dep_checker).

**DO NOT REPORT OR DISCUSS VULNERABLITIES THAT ARE NOT ALREADY
PUBLIC IN THIS REPO**. Please report new vulnerabilities either to
the projects for a specific dependency or report to the Node.js project
as outlined in the Node.js project's
[SECURITY.md](https://github.com/nodejs/node/blob/main/SECURITY.md) file.


