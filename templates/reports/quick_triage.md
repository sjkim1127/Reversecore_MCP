<!-- Fast initial assessment report for SOC teams and incident responders -->
# Quick Triage Report

**{{REPORT_ID}}** | {{DATETIME_FULL}} | {{CLASSIFICATION}}

---

## ⚡ Quick Assessment

| | |
|---|---|
| **Severity** | {{SEVERITY_EMOJI}} **{{SEVERITY}}** |
| **Family** | {{MALWARE_FAMILY}} |
| **Type** | {{FILE_TYPE}} |
| **Hash (SHA256)** | `{{SHA256}}` |

---

## 📁 Sample

- **File:** `{{FILENAME}}`
- **Size:** {{FILESIZE_HR}}
- **MD5:** `{{MD5}}`

---

## 🎯 Key Findings

{{SUMMARY}}

### MITRE Techniques ({{MITRE_COUNT}})

| Tactic | Technique | ID |
|--------|-----------|-----|
{{MITRE_TABLE}}

---

## 🚨 IOCs to Block ({{IOCS_COUNT}})

{{IOCS_MARKDOWN}}

---

## ⏱️ Timeline

- **Started:** {{ANALYSIS_START}}
- **Completed:** {{ANALYSIS_END}}
- **Duration:** {{ANALYSIS_DURATION}}

---

## 📝 Notes

{{ANALYSIS_NOTES}}

---

## ✅ Recommended Actions

- [ ] Block IOCs at firewall/proxy
- [ ] Search for hash in EDR
- [ ] Check DNS logs for domains
- [ ] Review user activity
- [ ] Escalate if severity is HIGH/CRITICAL

---

**Analyst:** {{ANALYST}} | **Session:** `{{SESSION_ID}}`

_Quick triage by {{GENERATED_BY}} | {{DATE}}_
