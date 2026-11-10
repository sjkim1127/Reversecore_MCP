<div align="center">

[English](README.md) · **한국어** · [日本語](README.ja.md) · [简体中文](README.zh-CN.md)

<br />

<img src="icon.png" alt="Reversecore MCP" width="440" />

# Reversecore MCP

### AI 기반 바이너리 리버스 엔지니어링 · 악성코드 분석 · 취약점 연구를 위한 엔터프라이즈 MCP 서버

**악성코드 분류(Triage), 네이티브 디컴파일, 모던 런타임 보안 감사(Go/Rust, Electron, Unity), 크래시 원인 분석, 디지털 포렌식을 바이트 수준 증거(`evidence_id`) 기반으로 수행하는 Model Context Protocol 서버입니다.**

---

[![CI/CD](https://github.com/sjkim1127/Reversecore_MCP/actions/workflows/main.yml/badge.svg)](https://github.com/sjkim1127/Reversecore_MCP/actions/workflows/main.yml)
[![Python](https://img.shields.io/badge/python-3.10%20%7C%203.11%20%7C%203.12-blue)](https://www.python.org/)
[![License: MIT](https://img.shields.io/badge/license-MIT-yellow.svg)](LICENSE)
[![Tests](https://img.shields.io/badge/tests-3086%20passed-brightgreen)](#testing)
[![Coverage](https://img.shields.io/badge/coverage-88%25-green)](#testing)
[![FastMCP](https://img.shields.io/badge/FastMCP-3.4.11-purple)](https://github.com/jlowin/fastmcp)
[![PyPI](https://img.shields.io/pypi/v/reversecore-mcp)](https://pypi.org/project/reversecore-mcp/)
[![Docker](https://img.shields.io/badge/docker-ghcr.io-blue)](https://github.com/sjkim1127/Reversecore_MCP/pkgs/container/reversecore_mcp)
[![skills.sh](https://img.shields.io/badge/skills.sh-reversecore--mcp-5c4ee5)](https://skills.sh)
[![OpenSSF Scorecard](https://api.securityscorecards.dev/projects/github.com/sjkim1127/Reversecore_MCP/badge)](https://scorecard.dev/viewer/?uri=github.com/sjkim1127/Reversecore_MCP)
[![HVTrust](https://hvtracker.net/badge/reversecore-mcp.svg)](https://hvtracker.net/agents/reversecore-mcp)

[![Watch the Demo](https://img.shields.io/badge/▶_Watch_Demo-FF0000?style=for-the-badge&logo=youtube&logoColor=white)](https://youtu.be/wJGW2bp3c5A)
[![SafeSkill Verified](https://img.shields.io/badge/SafeSkill-93%2F100_Verified_Safe-brightgreen?style=for-the-badge)](https://safeskill.dev/scan/sjkim1127-reversecore-mcp)

<br />

**[빠른 시작](#-빠른-시작-quick-start) · [보안 분석 워크플로우](#️-3대-보안-분석-워크플로우) · [분석 가능 대상](#-분석-가능한-타깃-what-you-can-analyze) · [컨텍스트 최적화](#-컨텍스트-효율성-tiered-router-compact-schema--paging) · [도구 카탈로그 (186개)](#tool-catalog-186-tools) · [FAQ](#-자주-묻는-질문-faq)**

</div>

### ⚡ 원라이너 자동 설치 (One-Line Setup)

설치된 AI 클라이언트(**Cursor, Claude Code, Windsurf, Claude Desktop, OpenAI Codex, Antigravity, Cline/Roo Code**)를 자동으로 감지하여 설정 백업과 함께 Reversecore MCP를 즉시 등록합니다:

```bash
# 옵션 1: 설치 없이 즉시 자동 등록 (권장)
pipx run reversecore-mcp setup

# 옵션 2: 원라이너 셸 인스톨러 (macOS / Linux)
curl -fsSL https://raw.githubusercontent.com/sjkim1127/Reversecore_MCP/main/install.sh | bash

# 옵션 3: 에이전트 스킬 설치 (skills.sh / Cursor / Claude Code / Codex)
npx skills add sjkim1127/Reversecore_MCP
```

> 💡 **LLM 컨텍스트 토큰 비용 94.4% 절감:** `pipx run reversecore-mcp setup --tiered`를 실행하면 일상 핵심 보안 도구 15개 + 8개 도메인 서브 에이전트 라우터를 노출하면서 186개 전체 도구를 온디맨드로 호출할 수 있습니다.

---

## Reversecore MCP란 무엇인가요?

**Reversecore MCP**는 **186개의 전문 리버스 엔지니어링·악성코드 분석·취약점 연구·디지털 포렌식 도구**를 단일 인터페이스로 통합한 [Model Context Protocol (MCP)](https://modelcontextprotocol.io/) 서버입니다.

디스어셈블러, 디컴파일러, YARA 스캐너, 메모리/네트워크 포렌식 도구의 복잡한 명령어를 일일이 다룰 필요 없이 자연어로 보안 분석 목표를 지시할 수 있습니다:

```text
"이 의심스러운 샘플의 메인 페이로드를 디컴파일하고, 자체 문자열 복호화 루틴을 분석해
 모든 C2 IOC를 추출한 뒤, MITRE ATT&CK 기법에 매핑하여 초기 대응 리포트를 생성해줘."
```

모든 분석 도구는 로컬 환경 또는 격리된 Docker 컨테이너 내부에서 안전하게 실행되며, 구조화된 `ToolResult`(`ToolSuccess` 또는 `ToolError`)와 바이트 단위 근거(`evidence_id`)를 반환하여 AI가 환각(Hallucination) 없이 다단계 보안 조사를 수행하도록 보장합니다.

---

## 🛡️ 3대 보안 분석 워크플로우

### Workflow 1: 악성코드 복호화 루틴(Cryptor / DGA) 복원 및 안전한 ESIL 에뮬레이션 검증

최신 악성코드는 C2 설정값이나 문자열을 자체 암호화 루틴(XOR, RC4 변형 등)으로 숨기거나 도메인을 동적으로 생성(DGA)합니다. 디컴파일된 C 의사코드를 수작업으로 파이썬 복호화 스크립트로 옮기면 32/64비트 정수 오버플로우나 부호 시프트 차이로 인해 복호화에 실패하기 쉽습니다. Reversecore MCP는 복호화 함수를 파이썬으로 재구성한 뒤, **실제 악성코드를 호스트에서 실행하지 않고 Radare2 ESIL CPU 에뮬레이터 내부에서 입출력 동등성을 100% 검증**합니다.

**프롬프트 예시:**
```text
"sample.bin의 0x401180에 위치한 설정 복호화 함수를 분석해서 안전한 파이썬 복호화 스크립트를 작성하고,
 ESIL 에뮬레이션을 통해 원본 바이너리와 출력이 100% 일치하는지 검증해줘."
```

**에이전트 도구 체인 및 검증 결과:**
```
1. r2_decompile("sample.bin", "0x401180", detail="summary")
   └─ 복잡도/API 요약 정보와 캐시 핸들 반환: evidence_id="ev_9a4c102f8b11"

2. inspect_analysis_view(evidence_id="ev_9a4c102f8b11", facet="lines", offset=0, limit=40)
   └─ 컨텍스트 폭발 없이 필요한 의사코드 라인만 온디맨드 페이지네이션 조회

3. reconstruct_feature_code(
       file_path="sample.bin",
       address_or_symbol="sym.decrypt_word",
       target_language="python",
       test_inputs=["0x0", "0xff", "0xffff"]
   )
   ├─ 디컴파일 및 코드 합성: r2ghidra -> 보일러플레이트가 제거된 Python 함수(decrypt_word) 생성
   ├─ 바이너리 에뮬레이션: Radare2 ESIL VM (격리된 레지스터/메모리 상태, 호스트 실행 제로)
   ├─ 동등성 판정: VERIFIED (branch_parity: true, test_vectors_evaluated: 3, emulation_successful: true)
   └─ 재구현된 Python 코드:
        def decrypt_word(param_1: Any = 0, param_2: Any = 0, *args: Any, **kwargs: Any) -> Any:
            uVar1 = (param_1 ^ param_2) * 0x45d9f3b
            return uVar1 >> 0x10 ^ uVar1
```

---

### Workflow 2: 모던 런타임 위협 및 공급망 보안 감사 (Go/Rust 악성코드, Electron ASAR, Unity)

최근 위협 그룹은 심볼이 제거(Stripped)된 **Go/Rust**로 크로스 플랫폼 랜섬웨어를 제작하거나, 변조된 **Electron(`app.asar`)** 설치 패키지를 통해 공급망 공격을 수행합니다. Reversecore MCP는 외부 무거운 SDK 없이 순수 Python 정적 파서로 스트립된 심볼을 복원하고 런타임 보안 설정 취약점을 즉시 감사합니다:

**프롬프트 예시:**
```text
"의심스러운 인스톨러에 포함된 app.asar에서 위험한 BrowserWindow 설정과 백도어 IPC 핸들러를 감사하고,
 함께 번들링된 스트립된 Go 바이너리 헬퍼의 함수 심볼을 복원해줘."
```

**에이전트 도구 체인 및 검증 결과:**
```
1. inspect_electron_asar("app.asar", search_pattern="ipcMain|child_process|shell")
   ├─ 포맷: Chromium Pickle ASAR (header_size: 48,210 bytes, 642개 파일)
   ├─ 노출된 IPC 핸들러: 메인 및 프리로드 스크립트에서 14개 채널 식별
   └─ 보안 감사 결과:
        • [HIGH] BrowserWindow 설정에서 nodeIntegration: true 감지됨 (RCE 위험)
        • [MEDIUM] 렌더러 윈도우 옵션에서 sandbox: false 감지됨

2. inspect_go_rust_binary("helper_daemon.elf")
   ├─ 감지된 런타임: Go (gopclntab 매직 0xfffffff1, Go 1.22)
   ├─ 심볼 복원: .gopclntab에서 스트립된 패키지/함수 이름 148개 복원
   └─ 식별된 의심 함수:
        • main.establishBeaconLoop @ 0x48a200
        • main.encryptLocalVolume  @ 0x48b940
```

---

### Workflow 3: 제로데이 크래시 분류, 오염 추적(Taint Analysis) 및 적응형 YARA/백신 생성

ASan/GDB 크래시 로그나 논리 폭탄(Logic Bomb)이 숨겨진 패킹 바이너리로부터 크래시 분류, Source-to-Sink 도달 가능성 증명, YARA 탐지 룰 및 바이너리 완화 패치 생성까지 전 과정을 자동화합니다.

**프롬프트 예시:**
```text
"daemon.bin의 ASan 크래시 로그를 분석하고, 외부 네트워크 입력이 취약한 memcpy 싱크까지 도달하는지
 검증한 뒤, 숨겨진 휴면 백도어를 스캔하여 YARA 탐지 룰과 완화 패치를 생성해줘."
```

**에이전트 도구 체인 및 검증 결과:**
```
1. cve_triage_crash(crash_log_or_text=asan_log)
   └─ 버그 분류: heap-buffer-overflow (READ) | CWE-125 | 결함 위치: parse_packet+0x84

2. taint_trace("daemon.bin", function_name="parse_packet", verify_with_angr=True)
   └─ Source→Sink 도달 확인: recv() → memcpy() @ 0x402190 (길이 필드 검증 누락)

3. dormant_detector("daemon.bin")
   └─ 타임봄 트리거(cmp eax, 0x67758ac0)를 포함한 고립 함수(0x404800) 1개 발견

4. adaptive_vaccine(threat_report={...}, action="both")
   ├─ 주소 변위(Displacement) 와일드카드 마스킹이 적용된 YARA 탐지 룰 생성
   └─ 취약/악성 분기를 무력화하는 바이너리 완화 패치 합성
```

---

## 🎯 분석 가능한 타깃 (What You Can Analyze)

| 분석 대상 카테고리 | 보안 및 리버스 엔지니어링 기능 | 분석 엔진 / 요구사항 |
|---|---|---|
| **네이티브 바이너리 (PE / ELF / Mach-O)** | 디스어셈블리, r2ghidra C 디컴파일, CFG, C++ RTTI, 구조체 복원, 임포트/익스포트, 섹션 엔트로피, Authenticode 서명 검증 | **Radare2 + r2ghidra + LIEF** (x86, x64, ARM32, ARM64, MIPS, RISC-V, PowerPC) |
| **악성코드 및 패킹 실행 파일** | 패커/컴파일러 식별, CAPA 행위 능력 매핑, 휴면 백도어/타임봄 탐지, IOC 추출, YARA/Sigma 룰 및 백신 패치 생성 | **YARA + CAPA + DIE + 커스텀 휴리스틱** |
| **스트립된 Go & Rust 악성코드/바이너리** | Go `.gopclntab`(`go1.2`–`go1.20+`) 심볼 복원, Rust `.dep-v0`(`cargo-auditable`) 의존성 트리 및 취약 크레이트 감사, `_ZN...E` 디맹글링 | **순수 Python 내장** (`inspect_go_rust_binary`) — Go/Rust SDK 불필요 |
| **Electron 데스크톱 앱 (`app.asar`)** | 공급망 및 클라이언트 보안 감사: Chromium Pickle VFS 파서, `ipcMain`/`contextBridge` 공격 표면 매핑, `nodeIntegration`/`contextIsolation` 점검 | **순수 Python 내장** (`inspect_electron_asar`) — 외부 의존성 없음 |
| **Unity IL2CPP 바이너리** | 모바일/클라이언트 보안 감사: `global-metadata.dat`(`0xFAB11BAF`, v24–v31+) 헤더 암호화 엔트로피 진단, C# 클래스/메서드/문자열 복원, `libil2cpp.so` 상관분석 | **순수 Python 내장** (`inspect_unity_il2cpp`) — Unity 에디터 불필요 |
| **암호화/복호화 루틴 재구현 및 검증** | 디컴파일된 루틴을 안전한 C/Python 스크립트로 변환 및 ESIL 레지스터/메모리 동등성 검증, Obligation Ledger 발행 | **r2ghidra + ESIL 시뮬레이터** (`reconstruct_feature_code`) |
| **취약점 연구 및 크래시 덤프** | ASan/GDB 크래시 분류, 델타 디버깅 PoC 최소화, Source→Sink 오염 추적, angr 심볼릭 경로 풀이, ROP 가젯 체인 생성 | **angr + pwntools + ROPgadget + GDB** |
| **메모리 · 네트워크 · 디스크 포렌식** | RAM 덤프 프로세스 및 코드 인젝션 헌팅, PCAP DNS/C2/스트림 재구성, NTFS MFT 및 삭제 파일 복구, 아티팩트 타임라인 상관분석 | **Volatility3 + Scapy + Sleuth Kit + Binwalk** |

---

## ⚡ 컨텍스트 효율성: Tiered Router, Compact Schema & Paging

대규모 보안 분석 MCP 서버는 180개 이상의 도구 스키마와 수만 줄의 디컴파일 출력으로 인해 LLM 컨텍스트를 빠르게 소진할 수 있습니다. Reversecore MCP는 **4단계 컨텍스트 최적화 아키텍처**를 제공합니다:

| 최적화 계층 | 활성화 방법 | 토큰 절감 효과 및 동작 방식 |
|---|---|---|
| **1. Tiered Router 모드** | `REVERSECORE_PROFILE=tiered`<br>*(또는 `reversecore-mcp setup --tiered`)* | **프롬프트 토큰 오버헤드 -94.4% 절감.** 일상 핵심 도구 12개 + 라우터 도구 3개(`call_expert_agent`, `search_tools`, `execute_domain_tool`)만 노출하며, 8개 도메인 전문 서브 에이전트(`vulnerability_hunter`, `forensics`, `malware_analyst`, `deobfuscator`, `symbolic_engine`, `diff_analyst`, `source_auditor`, `modern_runtime`)를 통해 186개 전체 도구를 온디맨드로 호출합니다. |
| **2. Compact Schema 프로필** | `REVERSECORE_SCHEMA_PROFILE=compact` | **`tools/list` 페이로드 약 65% 축소.** 장황한 독스트링 예시를 제거하고 깊은 `anyOf`/`oneOf` 유니온을 평탄화하며 스키마 깊이를 최대 10으로 제한합니다(서버 측 Pydantic 검증은 100% 동일하게 유지). |
| **3. Summary-First Paging** | `r2_decompile`, `Radare2_disassemble*`, `Radare2_list_strings`, `memory_extract_strings` 호출 시 `detail="summary"` 전달 | 핵심 요약 정보와 함께 `evidence_id` 핸들(`ev_<12-hex>`)을 반환합니다. 이후 `inspect_analysis_view(evidence_id, facet, offset, limit, filter_query)`로 필요한 라인·문자열·함수 페이지만 정밀 조회합니다. |
| **4. 온디맨드 가이드 검색** | 내장 도구: `search_guidance` & `read_guidance_section` | 시스템 프롬프트에 수만 줄의 매뉴얼을 넣는 대신, 에이전트가 필요한 순간에만 내장 플레이북(`playbook:target-routing`, `playbook:go-rust-reversing`, `playbook:electron-asar`, `playbook:unity-il2cpp`, `playbook:epistemological-discipline`)을 검색해 읽습니다. |

---

## Tool Catalog (186 Tools)

> 📖 **[전체 186개 도구 상세 레퍼런스 (docs/TOOLS.md)](docs/TOOLS.md)**
> 📊 **[프로필별 컨텍스트 토큰 & 메모리 벤치마크 (docs/benchmarks/profile_footprint.md)](docs/benchmarks/profile_footprint.md)**

| 프로필 (`REVERSECORE_PROFILE`) | 노출 도구 수 | 스키마 크기 | Full 대비 컨텍스트 절감 | 권장 사용 시나리오 |
|---|:---:|:---:|:---:|---|
| `tiered` | **15** | ~11.5 KB | **-94.4%** (~28,500 토큰) | ⚡ **일상 대화형 보안 분석** (12개 코어 도구 + 8개 서브 에이전트 라우터) |
| `full` | **186** | 144.2 KB | 기준 (0%) | 전체 엔터프라이즈 리버스 엔지니어링 & 보안 스위트 |
| `vuln-research` | **138** | 96.4 KB | **-33.1%** (~10,000 토큰) | 퍼징, ASan 크래시 분류, CVE 헌팅, 익스플로잇 연구 |
| `static` | **132** | 91.2 KB | **-36.8%** (~11,100 토큰) | 디스어셈블리, 디컴파일(r2ghidra), LIEF, 모던 런타임 정적 분석 |
| `malware` | **100** | 76.5 KB | **-46.9%** (~14,100 토큰) | 위협 분류, YARA 스캔, 난독화 해제, 안티 분석 탐지 |
| `forensics` | **81** | 51.8 KB | **-64.1%** (~19,300 토큰) | 메모리 포렌식(Volatility3), 네트워크 PCAP(Scapy), 디스크 분석 |

---

## 🚀 빠른 시작 (Quick Start)

### 1. 원라이너 자동 설정 (권장)

```bash
# macOS / Linux (셸 스크립트)
curl -fsSL https://raw.githubusercontent.com/sjkim1127/Reversecore_MCP/main/install.sh | bash

# 또는 uvx / pipx 사용 (별도 사전 설치 불필요)
uvx --from reversecore-mcp reversecore-setup
pipx run reversecore-mcp setup

# Windows (PowerShell)
irm https://raw.githubusercontent.com/sjkim1127/Reversecore_MCP/main/install.ps1 | iex
```

**주요 설정 플래그:**
```bash
reversecore-mcp setup --tiered   # Tiered 모드 활성화 (토큰 비용 94% 이상 절감)
reversecore-mcp setup --docker   # Docker 컨테이너 실행 모드로 클라이언트 설정
reversecore-mcp setup --dry-run  # 실제 파일을 수정하지 않고 변경 사항 미리보기
reversecore-mcp setup --list     # 감지된 AI 클라이언트 및 설정 파일 경로 확인
reversecore-mcp setup --remove   # 모든 클라이언트에서 Reversecore 등록 해제
```

### 2. Docker 실행 (모든 외부 분석 엔진 사전 설치됨)

Radare2, r2ghidra, YARA, Binwalk, Sleuth Kit, GDB 등 모든 바이너리 분석 도구가 포함된 공식 멀티 아키텍처(Intel/Apple Silicon) 이미지를 실행합니다:

```bash
docker run -i --rm \
  -v /path/to/your/samples:/app/workspace \
  -e REVERSECORE_WORKSPACE=/app/workspace \
  -e MCP_TRANSPORT=stdio \
  ghcr.io/sjkim1127/reversecore_mcp:latest
```

또는 소스 클론 후 아키텍처 자동 감지 스크립트 실행:

```bash
git clone https://github.com/sjkim1127/Reversecore_MCP.git
cd Reversecore_MCP
./scripts/run-docker.sh
```

---

## ❓ 자주 묻는 질문 (FAQ)

<details>
<summary><b>별도의 Ghidra나 Java(JDK) 설치가 필요한가요?</b></summary>

아니요. `r2ghidra` 플러그인이 Ghidra 디컴파일러 엔진을 네이티브 C++로 Radare2 내부에 직접 내장하고 있어, 무거운 JVM이나 별도의 Ghidra 프로젝트 생성 없이 즉시 디컴파일이 가능합니다. 또한 Go/Rust, Electron ASAR, Unity IL2CPP 분석기는 순수 Python으로 동작하여 외부 도구 없이도 바로 실행됩니다.
</details>

<details>
<summary><b>어떤 AI 클라이언트를 지원하나요?</b></summary>

MCP 표준을 지원하는 모든 클라이언트에서 작동합니다. `reversecore-mcp setup`은 **Cursor, Claude Code, Windsurf, Claude Desktop, OpenAI Codex CLI, Google Antigravity, VS Code (Cline / Roo Code)**를 자동으로 감지하여 설정합니다.
</details>

<details>
<summary><b>악성코드를 분석할 때 얼마나 안전한가요?</b></summary>

정적 분석 도구(Radare2, YARA, LIEF, ASAR/Go/Rust 파서)와 ESIL 에뮬레이터는 대상 바이너리를 호스트 OS에서 직접 실행하지 않습니다. 동적 분석 시에는 비루트 사용자(`appuser`), 리소스 제한, 네트워크 격리가 적용된 Docker 컨테이너 및 샌드박스 모드(`REVERSECORE_SANDBOX_ENABLED=true`) 사용을 권장합니다.
</details>

---

## 라이선스 (License)

MIT License — 자세한 내용은 [LICENSE](LICENSE) 파일을 참고하세요.
