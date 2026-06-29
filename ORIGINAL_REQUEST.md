# Original User Request

## Initial Request — 2026-06-27T02:16:17+09:00

The project aims to improve the test coverage and robustness of low-coverage core analysis modules and utilities in Reversecore_MCP to at least 75%.

Working directory: /Users/sjkim1127/Reversecore_MCP
Integrity mode: development

## Requirements

### R1. Target Coverage Improvement
Increase the test coverage of the following target modules (and any other module under `reversecore_mcp/tools/` with less than 60% coverage) to at least 75%:
- `reversecore_mcp/tools/analysis/capa_tools.py` (currently 33%)
- `reversecore_mcp/tools/analysis/lief_tools.py` (currently 36%)
- `reversecore_mcp/tools/malware/adaptive_vaccine.py` (currently 42%)
- `reversecore_mcp/tools/common/memory_tools.py` (currently 51%)
- `reversecore_mcp/tools/common/patch_explainer.py` (currently 58%)

### R2. Isolated Unit Testing
Write unit tests utilizing robust mocking (`unittest.mock`, `pytest-mock`) for external libraries (e.g. `capa`, `lief`), database setups, and subprocess calls to ensure tests execute quickly and reliably in local and CI/CD (GitHub Actions) environments without requiring local CLI tool installations.

## Acceptance Criteria

### Coverage Thresholds
- [ ] `reversecore_mcp/tools/analysis/capa_tools.py` coverage >= 75%
- [ ] `reversecore_mcp/tools/analysis/lief_tools.py` coverage >= 75%
- [ ] `reversecore_mcp/tools/malware/adaptive_vaccine.py` coverage >= 75%
- [ ] `reversecore_mcp/tools/common/memory_tools.py` coverage >= 75%
- [ ] `reversecore_mcp/tools/common/patch_explainer.py` coverage >= 75%
- [ ] All other tool files under `reversecore_mcp/tools/` have coverage >= 60% (or >= 75% if targeted)

### Verification
- [ ] Running `pytest --cov=reversecore_mcp --cov-report=term-missing` succeeds and shows all target files meet or exceed 75% coverage.
- [ ] All tests pass successfully without leaking subprocesses or memory.

## Follow-up — 2026-06-29T16:20:43+09:00

Reversecore MCP (Model Context Protocol) 서버를 CVE 발견 및 정밀 취약점 분석이 가능한 수준으로 고도화하고 검증합니다.

Working directory: /Users/sjkim1127/Reversecore_MCP
Integrity mode: development

## Requirements

### R1. Fuzzer Campaign Loop Integration
- `generate_fuzzing_harness` 도구의 출력값을 활용해, 실제 백그라운드에서 AFL++ 퍼징 캠페인을 실행 및 제어하는 `run_fuzzing_campaign` 도구를 구현합니다.
- 퍼징 과정에서 수집된 크래시 파일을 `triage_crash` 도구와 연계해 중복을 제거하고 익스플로잇 가능성을 점수화하는 triage 파이프라인을 구축합니다.

### R2. Patch Diff Automation
- 두 버전의 바이너리를 비교하여 보안 관련 패치 패턴(예: 경계 검사 추가, 취약 함수 대체 등)을 탐지하고 변경 내역을 요약해 주는 `analyze_patch_diff_auto` 도구를 구현합니다.
- 패치된 함수를 기반으로 취약 버전에서 작동 가능한 PoC 유발 요인을 역추론하는 로직을 포함합니다.

### R3. Taint Analysis Engine
- `angr` 또는 `Triton` 라이브러리를 연동하여, 입력(Source)에서 위험 함수(Sink, 예: system, memcpy 등)까지의 흐름을 자동으로 추적하는 `taint_trace` 도구를 구현합니다.

### R4. Memory Exploit Analysis
- `pwntools` 및 `ROPgadget` 기능을 연동하여, 크래시 상태의 Heap/Stack 레이아웃을 분석하고 공격 체인을 자동 구성해주는 `analyze_heap_exploit` 및 `build_rop_chain` 도구를 완성합니다.

### R5. Autonomous Vulnerability Hunt Pipeline Integration
- 위의 모든 도구들을 하나의 엔드투엔드 워크플로우로 통합 실행하고 최종 CVE 스타일 리포트를 생성해주는 `autonomous_vuln_hunt` 파이프라인을 통합 구현합니다.

## Acceptance Criteria

### Unit & Integration Verification (Pytest)
- [ ] 신규 추가되는 모든 MCP 도구에 대해 단위 테스트(Unit Test)를 작성해야 합니다.
- [ ] 외부 라이브러리 및 바이너리 의존성(angr, Triton, AFL++, pwntools 등)은 Mocking을 사용하여 로컬 환경에서 테스트가 성공적으로 동작해야 합니다.
- [ ] 전체 테스트 커버리지가 기존 임계치(최소 55% 이상)를 유지하거나 상회해야 합니다.

### E2E Functional Verification (Docker container)
- [ ] Docker 컨테이너 (`reversecore-mcp-arm64`) 내에서 실제 도구 연동 테스트를 통과해야 합니다.
- [ ] 실제 테스트 바이너리(예: `sqlite3_linux` 또는 3.53.1 취약 버전)를 대상으로 `autonomous_vuln_hunt` 파이프라인을 실행했을 때, 오류 없이 결과 리포트 및 PoC를 생성해야 합니다.
- [ ] 퍼징 제어 및 백그라운드 작업이 고아 프로세스(zombie process)를 남기지 않고 정상적으로 정리되는지 검증해야 합니다.
