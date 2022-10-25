---
title: New vulnerability {{ env.VULN_ID }} found on {{ env.NODEJS_STREAM }}
asignees:
labels: "{{ env.NODEJS_STREAM }}"
---
Failed run: {{ env.ACTION_URL }}
Vulnerability ID: {{ env.VULN_ID }}

Full output:
--------------------
```
{{ env.ERROR_MSG }}
```

