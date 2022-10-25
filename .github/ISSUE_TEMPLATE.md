---
title: "{{ env.VULN_ID }} ({{ env.VULN_DEP_NAME }}) found on {{ env.NODEJS_STREAM }}"
asignees:
labels: "{{ env.NODEJS_STREAM }}"
---

A new vulnerability for {{ env.VULN_DEP_NAME }} {{ env.VULN_DEP_VERSION }} was found:
Vulnerability ID: {{ env.VULN_ID }}
Vulnerability URL: {{ env.VULN_URL }}
Failed run: {{ env.ACTION_URL }}
