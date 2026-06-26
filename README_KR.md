<div align="center">

<img src="icon.png" alt="Reversecore MCP" width="120" />

# Reversecore MCP

**AI 기반 리버스 엔지니어링 — Model Context Protocol 서버**

*엔터프라이즈급 바이너리 분석 서버 — 자연어로 대화하고, 전문가 수준의 리버스 엔지니어링을 받으세요.*

---

[![CI/CD](https://github.com/sjkim1127/Reversecore_MCP/actions/workflows/main.yml/badge.svg)](https://github.com/sjkim1127/Reversecore_MCP/actions/workflows/main.yml)
[![Python](https://img.shields.io/badge/python-3.10%20%7C%203.11%20%7C%203.12-blue)](https://www.python.org/)
[![License: MIT](https://img.shields.io/badge/license-MIT-yellow.svg)](LICENSE)
[![Tests](https://img.shields.io/badge/tests-1520%20passed-brightgreen)](#테스트)
[![Coverage](https://img.shields.io/badge/coverage-82%25-green)](#테스트)
[![FastMCP](https://img.shields.io/badge/FastMCP-3.2.0-purple)](https://github.com/jlowin/fastmcp)
[![Docker](https://img.shields.io/badge/docker-ghcr.io-blue)](https://github.com/sjkim1127/Reversecore_MCP/pkgs/container/reversecore_mcp)

[![데모 보기](https://img.shields.io/badge/▶_데모_보기-FF0000?style=for-the-badge&logo=youtube&logoColor=white)](https://youtu.be/wJGW2bp3c5A)
[![SafeSkill 인증](https://img.shields.io/badge/SafeSkill-93%2F100_Verified_Safe-brightgreen?style=for-the-badge)](https://safeskill.dev/scan/sjkim1127-reversecore-mcp)

[🌐 English](README.md)

</div>

---

## Reversecore MCP란?

Reversecore MCP는 Claude, Cursor 같은 AI 어시스턴트를 **전문 리버스 엔지니어링 워크스테이션**으로 변환하는 엔터프라이즈급 **[Model Context Protocol](https://modelcontextprotocol.io/)** 서버입니다.

Radare2 같은 복잡한 도구를 직접 배우거나 YARA 룰을 손으로 작성할 필요 없이, **자연어로 원하는 분석을 설명하면** AI가 알아서 실행합니다.

```
"이 악성코드 샘플의 main 함수를 디컴파일하고,
어떤 네트워크 연결을 시도하는지 파악해줘."
```

↓

*Reversecore MCP가 자동으로 `r2_decompile`, `extract_iocs`, `analyze_xrefs`를 호출하고, AI가 결과를 해석하여 설명합니다.*

---

## 아키텍처 개요

```
AI 클라이언트 (Claude / Cursor)
        │  MCP 프로토콜 (stdio 또는 HTTP)
        ▼
┌─────────────────────────────┐
│      FastMCP 서버            │  Python 3.10–3.12
│   50개 이상 등록된 도구       │  비동기, 완전한 타입 힌트
├──────────────────┬──────────┤
│   프롬프트        │  리소스   │  가이드 분석 모드
├──────────────────┴──────────┤
│       핵심 인프라             │
│  설정 · 보안 · 메트릭         │
│  R2 풀 · 예외 계층구조        │
├─────────────────────────────┤
│  Radare2 + r2ghidra 플러그인 │  바이너리 분석 엔진
│  YARA · LIEF · Capstone     │  탐지 및 파싱
│  Volatility3 · Scapy        │  포렌식 및 네트워크
└─────────────────────────────┘
```

---

## 빠른 시작

### 방법 1 — Docker (권장)

```bash
# 사전 빌드된 이미지 다운로드 및 실행
docker run -i --rm \
  -v /path/to/your/samples:/app/workspace \
  -e REVERSECORE_WORKSPACE=/app/workspace \
  -e MCP_TRANSPORT=stdio \
  ghcr.io/sjkim1127/reversecore_mcp:latest
```

### 방법 2 — 소스에서 빌드

```bash
git clone https://github.com/sjkim1127/Reversecore_MCP.git
cd Reversecore_MCP
./scripts/run-docker.sh        # Intel / Apple Silicon 자동 감지
```

---

## AI 클라이언트 연결

### Cursor / Claude Desktop

`~/.cursor/mcp.json` (또는 `claude_desktop_config.json`)에 추가:

<details>
<summary>🍎 macOS</summary>

```json
{
  "mcpServers": {
    "reversecore": {
      "command": "docker",
      "args": [
        "run", "-i", "--rm",
        "-v", "/Users/사용자이름/samples:/app/workspace",
        "-e", "REVERSECORE_WORKSPACE=/app/workspace",
        "-e", "MCP_TRANSPORT=stdio",
        "ghcr.io/sjkim1127/reversecore_mcp:latest"
      ]
    }
  }
}
```

</details>

<details>
<summary>🐧 Linux</summary>

```json
{
  "mcpServers": {
    "reversecore": {
      "command": "docker",
      "args": [
        "run", "-i", "--rm",
        "-v", "/home/사용자이름/samples:/app/workspace",
        "-e", "REVERSECORE_WORKSPACE=/app/workspace",
        "-e", "MCP_TRANSPORT=stdio",
        "ghcr.io/sjkim1127/reversecore_mcp:latest"
      ]
    }
  }
}
```

</details>

<details>
<summary>🪟 Windows</summary>

```json
{
  "mcpServers": {
    "reversecore": {
      "command": "docker",
      "args": [
        "run", "-i", "--rm",
        "-v", "C:/samples:/app/workspace",
        "-e", "REVERSECORE_WORKSPACE=/app/workspace",
        "-e", "MCP_TRANSPORT=stdio",
        "ghcr.io/sjkim1127/reversecore_mcp:latest"
      ]
    }
  }
}
```

</details>

> **⚠️ 중요 — Docker 내부 파일 경로**
>
> 로컬 폴더가 컨테이너 내부의 `/app/workspace`에 마운트됩니다.
> **파일 이름만** 사용하세요. 전체 로컬 경로를 사용하면 안 됩니다.
>
> | ❌ 잘못된 사용 | ✅ 올바른 사용 |
> |---|---|
> | `r2_decompile("/Users/john/samples/mal.exe")` | `r2_decompile("mal.exe")` |

---

## 도구 레퍼런스

### 🔍 정적 분석

| 도구 | 설명 |
|---|---|
| `run_file` | 파일 타입, 아키텍처, 컴파일러 핑거프린팅 |
| `run_strings` | 설정 가능한 제한으로 ASCII/유니코드 문자열 추출 |
| `run_binwalk` | 내장 시그니처 및 파일시스템 펌웨어 딥스캔 |
| `parse_binary_with_lief` | PE / ELF / Mach-O 헤더 및 섹션 전체 파싱 |
| `audit_source_code` | Python AST 스캐너 + C/C++ 정규식 스캐너를 통한 SAST |

### ⚙️ 디스어셈블리 & 디컴파일

| 도구 | 설명 |
|---|---|
| `run_radare2` | 연결 풀링이 적용된 Radare2 원시 명령 실행 |
| `Radare2_disassemble` | 자동 분석이 포함된 함수 디스어셈블리 |
| `r2_decompile` | r2ghidra를 통한 고품질 C 디컴파일 (JVM 불필요) |
| `r2_recover_structures` | C 구조체 자동 복원 및 SQLite 주석 DB에 영속화 |
| `r2_analyze_function` | 타입 추론이 포함된 단일 함수 심층 분석 |
| `r2_get_call_graph` | 함수의 콜 그래프 추출 |
| `r2_simulate_patch` | 바이너리 패치 적용 전 미리보기 |
| `disassemble_with_capstone` | Capstone을 통한 멀티 아키텍처 디스어셈블리 (x86/ARM/MIPS/PPC) |

### 🔗 크로스 레퍼런스 & 메모리

| 도구 | 설명 |
|---|---|
| `analyze_xrefs` | 함수 호출, 데이터 참조, 제어 흐름 추적 |
| `r2_read_memory` | 지정된 주소에서 원시 바이트 읽기 |
| `r2_list_structures` | SQLite DB에서 모든 주석 구조체 목록 |
| `r2_create_structure` | 새 구조체 주석 생성 및 영속화 |
| `r2_add_bookmark` | 주소에 코멘트 주석 추가 |
| `r2_list_bookmarks` | 모든 주소 북마크 목록 |
| `r2_list_types` | 현재 바이너리의 모든 알려진 타입 목록 |

### 🧬 동적 분석 & 에뮬레이션

| 도구 | 설명 |
|---|---|
| `emulate_machine_code` | 레지스터/메모리 트레이싱이 포함된 ESIL 기반 코드 에뮬레이션 |
| `diff_binaries` | 패치 변경 사항 추적을 위한 시맨틱 바이너리 diff |
| `match_libraries` | 함수 핑거프린트로 정적 링크 라이브러리 식별 |

### 🦠 악성코드 분석

| 도구 | 설명 |
|---|---|
| `dormant_detector` | 숨겨진 백도어, 고아 함수, 논리 폭탄 탐지 |
| `extract_iocs` | IP, URL, 도메인, 해시, 암호화폐 주소 추출 |
| `run_yara` | 커스텀 룰 지원 YARA 룰 스캐닝 |
| `adaptive_vaccine` | 위협에 대한 YARA 룰 + 바이너리 패치 생성 |
| `vulnerability_hunter` | 위험한 API 패턴 및 ROP 가젯 체인 탐지 |

### 📝 보고서 생성

| 도구 | 설명 |
|---|---|
| `generate_malware_submission` | 원샷 표준화 JSON 보고서 |
| `start_analysis_session` | 타이머가 포함된 분석 세션 시작 |
| `add_session_ioc` | 세션 중 IOC 수집 |
| `add_session_mitre` | MITRE ATT&CK 기법 문서화 |
| `end_analysis_session` | 소요 시간 계산과 함께 세션 종료 |
| `create_analysis_report` | 보고서 렌더링 (전체 / 트리아지 / IOC 요약 / 경영진) |
| `send_report_email` | SMTP로 보고서 전송 |

### 🛡️ 포렌식

| 도구 | 설명 |
|---|---|
| `analyze_memory_dump` | Volatility3 기반 메모리 포렌식 |
| `analyze_network_capture` | Scapy 기반 PCAP 분석 |
| `analyze_disk_image` | Sleuth Kit 파일시스템 포렌식 |
| `analyze_artifacts` | 브라우저 기록, 레지스트리, 이벤트 로그 파싱 |

### 📊 서버 & 모니터링

| 도구 | 설명 |
|---|---|
| `get_server_health` | 가동 시간, 메모리, 운영 상태 |
| `get_tool_metrics` | 도구별 실행 시간, 호출 횟수, 에러율 |
| `list_workspace` | 분석 워크스페이스의 파일 목록 |
| `get_file_info` | 특정 워크스페이스 파일의 메타데이터 |

---

## 가이드 분석 프롬프트

AI 클라이언트에서 이 프롬프트를 참조하여 전문가 수준의 분석 모드를 활성화하세요:

| 프롬프트 | 사용 사례 |
|---|---|
| `full_analysis_mode` | 증거 분류가 포함된 6단계 종합 악성코드 분석 |
| `basic_analysis_mode` | 초기 평가를 위한 빠른 트리아지 |
| `game_analysis_mode` | 안티치트 탐지가 포함된 게임 클라이언트 분석 |
| `firmware_analysis_mode` | IoT/임베디드 펌웨어 보안 검토 |
| `report_generation_mode` | MITRE ATT&CK 매핑이 포함된 구조화된 보고서 워크플로우 |

> **프롬프트 작동 방식:** 각 프롬프트는 AI에 전문가 페르소나, Chain-of-Thought 체크포인트, 증거 분류(`OBSERVED` / `INFERRED` / `POSSIBLE`)를 주입합니다. 이는 단순한 도구 출력이 아닌 분석가 수준의 결과물을 생성합니다.

---

## 보안 모델

| 제어 | 세부 내용 |
|---|---|
| **쉘 인젝션 방지** | 모든 서브프로세스 호출은 리스트 인자 사용, 쉘 문자열 없음 |
| **경로 검증** | 모든 파일 접근은 설정된 워크스페이스로 제한 |
| **입력 살균** | 실행 전 모든 파라미터 검증 |
| **속도 제한** | 분당 최대 요청 수 설정 가능 (HTTP 모드) |
| **제로 트러스트 CI/CD** | Gitleaks (시크릿), Bandit (SAST), pip-audit (CVE), Trivy (컨테이너), CodeQL |
| **워크스페이스 격리** | 컨테이너는 비루트 `appuser` (UID 1000)로 실행 |

---

## 개발 환경

### 설치

```bash
python -m venv venv && source venv/bin/activate
pip install -r requirements.txt
pip install -r requirements-dev.txt
pre-commit install
```

### 테스트

```bash
# 커버리지와 함께 전체 단위 테스트 실행
pytest tests/unit/ --cov=reversecore_mcp --cov-fail-under=80

# 전체 테스트 실행
pytest tests/ -v
```

**테스트 현황:**
- ✅ Python 3.10 / 3.11 / 3.12 전체에서 **1,520개 단위 테스트** 통과
- 📊 **82% 코드 커버리지** (CI에서 80% 최소 기준 강제)
- 🔒 Bandit 발견 0건 · pip-audit CVE 0건 · 컨테이너 취약점 0건

### 코드 품질

```bash
ruff check reversecore_mcp/      # 린트
ruff format reversecore_mcp/     # 포맷
mypy reversecore_mcp/            # 타입 검사 (87개 파일에서 0 에러)
bandit -r reversecore_mcp/       # 보안 스캔
```

### CI/CD 파이프라인

`main` 브랜치로의 모든 푸시는 다음 게이트를 실행합니다 — **배포 전 모두 통과해야 합니다:**

```
린트 & 보안                단위 테스트 (3.10 / 3.11 / 3.12)
  ├─ Gitleaks                ├─ pytest --cov-fail-under=80
  ├─ Hadolint                └─ (3개 매트릭스 버전 모두 통과 필요)
  ├─ Ruff check + format
  ├─ Mypy 타입 검사         Docker 검증
  ├─ Bandit (전체 심각도)    ├─ Trivy 컨테이너 스캔 (LOW→CRITICAL)
  └─ pip-audit               ├─ 통합 테스트 (컨테이너 내부)
                             └─ E2E MCP 도구 호출

CodeQL 분석              배포 (main 브랜치만)
  └─ Python SAST             └─ GHCR 푸시 + Trivy 재스캔
```

> **우회 금지 정책:** CI/CD 실패는 **절대** 파이프라인 설정을 수정하여 해결하지 않습니다. 근본 원인은 항상 소스 코드나 의존성에서 직접 수정합니다.

---

## 환경 설정

| 환경 변수 | 기본값 | 설명 |
|---|---|---|
| `MCP_TRANSPORT` | `http` | 전송 모드: `stdio` 또는 `http` |
| `REVERSECORE_WORKSPACE` | `/app/workspace` | 분석 워크스페이스 경로 |
| `REVERSECORE_READ_DIRS` | `""` | 추가 읽기 전용 디렉토리 |
| `LOG_LEVEL` | `INFO` | 로그 상세도 |
| `MCP_API_KEY` | *(미설정)* | HTTP 모드용 API 키 (선택) |
| `RATE_LIMIT` | `60` | 분당 최대 요청 수 (HTTP 모드) |

---

## 시스템 요구사항

| 구성 요소 | 최소 | 권장 |
|---|---|---|
| CPU | 4코어 | 8코어 이상 |
| RAM | 8 GB | 16 GB |
| 저장소 | 20 GB | 50 GB SSD |
| OS | Linux / macOS | Docker 환경 |

---

## 프로젝트 구조

```
reversecore_mcp/
├── core/                    # 인프라
│   ├── config.py            # 중앙 집중식 설정
│   ├── exceptions.py        # 예외 계층구조 (RCMCP-E* 코드)
│   ├── security.py          # 입력 살균 & 경로 검증
│   ├── validators.py        # 파일 & 바이너리 경로 검증기
│   ├── r2_pool.py           # Radare2 연결 풀
│   ├── r2_helpers.py        # Radare2 헬퍼 유틸리티
│   ├── metrics.py           # 도구 실행 메트릭
│   ├── decorators.py        # @log_execution, @track_metrics
│   ├── error_handling.py    # @handle_tool_errors
│   ├── memory.py            # AI 메모리 저장소 (비동기 SQLite)
│   ├── mitre_mapper.py      # MITRE ATT&CK 매핑
│   └── sast/                # 소스 코드 스캐너
│
├── tools/                   # MCP 도구 구현
│   ├── analysis/            # 정적 분석, LIEF, diff, SAST
│   ├── radare2/             # 디스어셈블리, 디컴파일, SQLite DB
│   ├── malware/             # 위협 탐지 & 방어
│   ├── forensics/           # 메모리, 디스크, 네트워크 포렌식
│   ├── report/              # 보고서 생성 & 이메일
│   └── common/              # 파일 작업, 서버 상태
│
├── prompts/                 # AI 추론 프롬프트 (5가지 모드)
├── resources.py             # 동적 MCP 리소스
└── server.py                # FastMCP 서버 진입점
```

---

## 기여하기

1. 저장소를 포크하세요
2. 기능 브랜치를 생성하세요 (`git checkout -b feat/my-feature`)
3. 코드와 함께 테스트를 작성하세요
4. `pytest`, `ruff check`, `mypy`, `bandit` 모두 통과 확인
5. 풀 리퀘스트를 열어주세요

---

## 라이선스

MIT — 자세한 내용은 [LICENSE](LICENSE)를 참조하세요.

---

<div align="center">

**[GitHub](https://github.com/sjkim1127/Reversecore_MCP)** · **[FastMCP 문서](https://github.com/jlowin/fastmcp)** · **[MCP 스펙](https://modelcontextprotocol.io/)**

</div>
