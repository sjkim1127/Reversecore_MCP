# Evidence Escalation Workflow

The **Evidence Escalation Workflow** enables analysts and AI agents to systematically verify suspicious static findings (such as dormant command execution, hidden logic branches, or dangerous API sinks) through progressive, evidence-governed verification stages.

Instead of jumping directly from a static heuristic to an unconfirmed exploit claim, this workflow establishes rigorous boundaries between **static possibility**, **control-flow reachability**, **data-flow verification**, **concrete trigger recovery**, and **runtime observation**.

---

## Verification Stages

| Stage | Verification Question | Tools Reused | Evidence Origin | Maximum Evidence Level |
|---|---|---|---|---|
| **1. Static Observation** | Is there a pattern or heuristic suggesting suspicious behavior? | `dormant_detector`, `Radare2_list_strings`, `vulnerability_hunter` | `ARTIFACT` | `POSSIBLE` (confidence ~35%) |
| **2. Structural Reachability** | Does a control-flow path connect entrypoints or exports to the suspect function? | `Radare2_xrefs_to`, `r2_cfg`, `r2_call_graph` | `STRUCTURAL` | `INFERRED` (confidence ~55%) |
| **3. Data-Flow Taint** | Does untrusted external input (stdin, network, argv) flow to the function arguments? | `taint_trace` | `CAPABILITY` | `INFERRED` (confidence ~70%) |
| **4. Symbolic Constraint** | Can path conditions be solved for concrete trigger values (SAT)? | `verify_path_and_get_args` | `CAPABILITY` | `INFERRED` (confidence ~80%) |
| **5. Emulation Runtime** | Does concrete execution under the trigger input reach the dangerous sink? | `dormant_detector`, `emulate_machine_code`, `r2_simulate_esil` | `RUNTIME` | `OBSERVED` (confidence ~95%) |

---

## Core Invariants & Decision Rules

1. **Reachability is NOT Exploitability**:
   - Recovering an incoming caller path (`Radare2_xrefs_to`) proves only that the code exists in the binary's call graph.
   - It **must not** be reported as `tainted` or `exploitable` without subsequent data-flow and constraint verification.
2. **Unsupported Steps Remain Inconclusive**:
   - If an advanced tool encounters an unsupported CPU architecture, timeout, or solver limitation, the stage outcome is `UNSUPPORTED` or `INCONCLUSIVE`.
   - Confidence **must not** increase. The finding remains at its current evidence level (`POSSIBLE` or `INFERRED`) with status `INCONCLUSIVE`.
3. **Preserve Contradictions**:
   - Contradictory evidence (e.g. 0 callers, unsatisfiable branch conditions `x > 100 && x < 50`, or CPU trap during emulation) is permanently preserved in the finding dossier.
4. **Downgrade and Refute False Positives**:
   - When a contradiction is discovered, the hypothesis transitions to `status: "refuted"`, confidence drops, and the finding is classified as a refuted false positive.
5. **Concrete Traceability**:
   - Every confidence transition cites the specific tool, address, constraint, or register state that justified the change.

---

## When to Stop: Handling Unsupported or Inconclusive Stages

Clients and agents must observe explicit stopping criteria rather than guessing or hallucinating confirmation:

| Scenario | Tool Behavior | Required Agent Action |
|---|---|---|
| **Non-x86/ARM binary** | `verify_path_and_get_args` returns unsupported architecture | Stop symbolic stage; record outcome as `UNSUPPORTED`. Keep finding as `INFERRED` (structural reachability only). Do not claim runtime confirmation. |
| **Symbolic timeout** | Solver times out after configured threshold (e.g. 60s) | Stop path exploration; record outcome as `INCONCLUSIVE`. Cap confidence at 65%. |
| **Unreferenced function** | `Radare2_xrefs_to` finds 0 incoming xrefs and no export entry | Stop immediately; mark hypothesis as `REFUTED` (dead code false positive). |
| **UNSAT branch conditions** | Solver returns `status: "UNSAT"` | Stop immediately; mark hypothesis as `REFUTED` (mutually exclusive condition false positive). |
| **Emulation divergence** | Emulation terminates on illegal instruction or invalid memory read | Record divergence in `contradictions`; set status to `INCONCLUSIVE` or `REFUTED`. |

---

## Guided Prompt (`evidence_escalation_mode`)

AI agents can activate the specialized reasoning prompt using:

```python
# FastMCP prompt invocation
evidence_escalation_mode(
    target_file="sample.exe",
    hypothesis="Function sub_401340 contains a dormant backdoor triggered by token 0x5339",
    target_function="sub_401340"
)
```

The prompt guides the model sequentially through the 5 phases, enforcing early stopping on contradictions and preventing unverified promotion.

---

## Integration with Case State & Handoff Bundles

Hypothesis escalation records are fully serialized and compatible with `CaseState` and `HandoffBundle`:

```python
from reversecore_mcp.core.evidence_escalation import (
    create_initial_hypothesis,
    VerificationStageType,
    StageOutcome,
)

# 1. Initialize hypothesis
rec = create_initial_hypothesis(
    hypothesis_id="hyp-001",
    title="Dormant command execution in sub_401340",
    initial_claim="Reachable command execution when magic config equals 0x5339",
    target_function="sub_401340",
    target_address="0x00401340",
)

# 2. Add structural reachability step
rec.add_stage(
    stage=VerificationStageType.STRUCTURAL_REACHABILITY,
    tool_name="Radare2_xrefs_to",
    outcome=StageOutcome.SUPPORTED,
    summary="Found caller path from main -> network_dispatch_loop -> sub_401340",
)

# 3. Add symbolic constraint step
rec.add_stage(
    stage=VerificationStageType.SYMBOLIC_CONSTRAINT,
    tool_name="verify_path_and_get_args",
    outcome=StageOutcome.SUPPORTED,
    summary="Symbolic solver solved path constraint to 0x00401385 with SAT condition",
    concrete_inputs={"magic_token": "0x5339"},
)

# 4. Add runtime emulation step
rec.add_stage(
    stage=VerificationStageType.EMULATION_RUNTIME,
    tool_name="dormant_detector",
    outcome=StageOutcome.SUPPORTED,
    summary="Emulation with eax=0x5339 confirmed reaching system() sink",
)

# Result: EvidenceLevel.OBSERVED, status: HypothesisStatus.VERIFIED, is_exploitable: True
print(rec.format_markdown())
```
