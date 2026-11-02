# Release-to-Release Security Regression Review Workflow

The **Security Regression Review Workflow** composes Reversecore's existing binary diffing, decompilation, patch explanation, taint analysis, and persistent memory subsystems into an automated release-to-release security audit.

Instead of flooding security analysts with thousands of syntactic diff lines, compiler register changes, or benign code-motion artifacts, this workflow answers key release engineering security questions:
- **Which functions materially changed?**
- **Did dangerous imports or security-sensitive sinks appear or disappear?**
- **Did control/data-flow around sinks change?**
- **Was an existing mitigation weakened or removed?**
- **Did a previously analyzed vulnerability survive into the new release?**

---

## Core Invariants & Decision Rules

1. **Not Every Difference is Security Relevant**:
   - Syntactic diffs, register reassignments, loop unrolling, and benign helper function refactors are classified as `BENIGN_REFACTOR` with `security_relevant = False` and severity `INFORMATIONAL`.
   - Benign changes **never** trigger a high-risk security alert.
2. **Exact Old/New Location Traceability**:
   - Every finding explicitly cites the old function/address and the new function/address along with tool provenance (`diff_binaries`, `analyze_variant_changes`, `explain_patch`, `taint_trace`).
3. **Structured Finding Lifecycle**:
   - `INTRODUCED`: New security risks or dangerous sinks added in the new version.
   - `REMOVED`: Fixed vulnerabilities or decommissioned risky code.
   - `CHANGED`: Modified control flow, added/removed bounds checks, or altered mitigations.
   - `UNCHANGED_BUT_RELEVANT`: Existing findings carried forward from previous analysis memory sessions.
4. **Memory Session Reuse**:
   - Prior analyst findings and annotations are seamlessly transferred across sessions to provide historical continuity.

---

## Finding Categories & Severity Matrix

| Lifecycle Status | Category | Example Scenario | Resulting Verdict Impact |
|---|---|---|---|
| `INTRODUCED` | `DANGEROUS_SINK` | New unauthenticated debug RPC handler calling `system()` | Escalates to `HIGH_RISK_REGRESSION` |
| `REMOVED` | `VULNERABILITY_FIX` | Added bounds check (`cmp rax, 0x200; ja overflow`) before `strcpy` | Contributes to `SECURITY_IMPROVED` |
| `CHANGED` | `BENIGN_REFACTOR` | Compiler inlining and register swap in string logger | Classified as `BENIGN_REFACTOR` (no alert) |
| `CHANGED` | `MITIGATION_CHANGE`| Stack canary or PIE flags altered between builds | Flagged as `MODERATE_RISK_CHANGES` |
| `UNCHANGED_BUT_RELEVANT` | `UNCHECKED_INPUT` | Unpatched SQL/format-string flaw carried forward from v1 | Highlighted as persistent backlog risk |

---

## Overall Review Verdicts

- **`HIGH_RISK_REGRESSION`**: One or more critical/high security risks were introduced in the new release.
- **`SECURITY_IMPROVED`**: Previous vulnerabilities were remediated with no new high-risk sinks introduced.
- **`MODERATE_RISK_CHANGES`**: Moderate behavioral alterations requiring analyst review.
- **`BENIGN_REFACTOR`**: Only harmless code motion, compiler optimizations, or non-security refactorings detected.
- **`NEUTRAL_MAINTENANCE`**: Clean maintenance release with no security-relevant discrepancies.

---

## Python API Usage

```python
from reversecore_mcp.core.security_regression import (
    build_regression_review,
    RegressionFinding,
    RegressionFindingStatus,
    FindingCategory,
    RegressionSeverity,
    LocationEvidence,
)

# 1. Initialize review dossier
review = build_regression_review(
    review_id="rev_2026_03",
    old_binary_name="app_v1.0.bin",
    old_binary_hash="a1b2c3d4...",
    new_binary_name="app_v2.0.bin",
    new_binary_hash="e5f6a7b8...",
    summary_notes="Quarterly release regression review."
)

# 2. Add structured regression findings
review.add_finding(
    RegressionFinding(
        finding_id="finding_01",
        status=RegressionFindingStatus.INTRODUCED,
        category=FindingCategory.DANGEROUS_SINK,
        severity=RegressionSeverity.CRITICAL,
        title="Command injection sink in handle_debug()",
        description="system() called with untrusted argv parameter.",
        security_relevant=True,
        old_location=None,
        new_location=LocationEvidence("app_v2.0.bin", "handle_debug", "0x405800"),
        provenance_tool="taint_trace",
    )
)

# 3. Output markdown report
print(review.format_markdown())
```

---

## Guided Prompt (`security_regression_mode`)

AI agents can activate the regression workflow using FastMCP prompt registration:

```python
security_regression_mode(
    old_binary="/app/workspace/firmware_v1.bin",
    new_binary="/app/workspace/firmware_v2.bin",
    target_function="handle_request",
)
```
