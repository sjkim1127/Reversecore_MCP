# Reversecore_MCP

![Icon](icon.png)

[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](https://opensource.org/licenses/MIT)
[![Python Version](https://img.shields.io/badge/python-3.10%2B-blue)](https://www.python.org/downloads/)
[![FastMCP](https://img.shields.io/badge/FastMCP-2.13.1-green)](https://github.com/jlowin/fastmcp)
[![Docker](https://img.shields.io/badge/docker-ready-blue)](https://www.docker.com/)
[![Tests](https://img.shields.io/badge/tests-700%2B%20passed-brightgreen)](tests/)
[![Coverage](https://img.shields.io/badge/coverage-55%25-green)](htmlcov/)

[![데모 영상 시청](https://img.shields.io/badge/데모_영상_시청-FF0000?style=for-the-badge&logo=youtube&logoColor=white)](https://youtu.be/wJGW2bp3c5A)

[🇺🇸 English](README.md)

AI 에이전트가 자연어 명령을 통해 포괄적인 바이너리 분석을 수행할 수 있게 하는 엔터프라이즈급 MCP(Model Context Protocol) 서버입니다.

## 📋 사전 요구사항

### Radare2 및 r2ghidra (디컴파일 및 분석에 필수)

디컴파일 및 분석 기능은 Radare2와 `r2ghidra` 플러그인을 사용하여 작동합니다.

**자동 설치**

제공되는 설정 스크립트나 Docker를 사용하는 것이 가장 간편하며, 이 경우 모든 의존성이 미리 구성되어 제공됩니다.

로컬 환경에 직접 설치하는 방법:
1. OS 패키지 관리자나 [radare.org](https://radare.org/)에서 **Radare2**를 설치합니다.
2. `r2pm`을 사용하여 **r2ghidra**를 설치합니다.
   ```bash
   r2pm -i r2ghidra
   ```

별도의 JDK나 JVM 설치는 필요하지 않습니다.

## 🚀 빠른 시작

### Docker (권장)

```bash
# 아키텍처 자동 감지 (Intel/AMD 또는 Apple Silicon)
./scripts/run-docker.sh

# 또는 수동으로:
# Intel/AMD
docker compose --profile x86 up -d

# Apple Silicon (M1/M2/M3/M4)/
docker compose --profile arm64 up -d
```

### MCP 클라이언트 설정 (Cursor AI)

**1단계: Docker 이미지 빌드**

통합 Dockerfile이 시스템 아키텍처를 자동으로 감지합니다:

```bash
# 자동 아키텍처 감지 (모든 플랫폼에서 작동)
docker build -t reversecore-mcp:latest .

# 또는 편의 스크립트 사용
./scripts/run-docker.sh
```

**2단계: MCP 클라이언트 설정**

`~/.cursor/mcp.json`에 추가:

<details>
<summary>🍎 <b>macOS (모든 프로세서)</b></summary>

```json
{
  "mcpServers": {
    "reversecore": {
      "command": "docker",
      "args": [
        "run", "-i", "--rm",
        "-v", "/Users/YOUR_USERNAME/Reversecore_Workspace:/app/workspace",
        "-e", "REVERSECORE_WORKSPACE=/app/workspace",
        "-e", "MCP_TRANSPORT=stdio",
        "reversecore-mcp:latest"
      ]
    }
  }
}
```
</details>

<details>
<summary>🐧 <b>Linux</b></summary>

```json
{
  "mcpServers": {
    "reversecore": {
      "command": "docker",
      "args": [
        "run", "-i", "--rm",
        "-v", "/path/to/workspace:/app/workspace",
        "-e", "REVERSECORE_WORKSPACE=/app/workspace",
        "-e", "MCP_TRANSPORT=stdio",
        "reversecore-mcp:latest"
      ]
    }
  }
}
```
</details>

<details>
<summary>🪟 <b>Windows</b></summary>

```json
{
  "mcpServers": {
    "reversecore": {
      "command": "docker",
      "args": [
        "run", "-i", "--rm",
        "-v", "C:/Reversecore_Workspace:/app/workspace",
        "-e", "REVERSECORE_WORKSPACE=/app/workspace",
        "-e", "MCP_TRANSPORT=stdio",
        "reversecore-mcp:latest"
      ]
    }
  }
}
```
</details>

> ⚠️ **중요: Docker에서의 파일 경로 사용**
>
> MCP 서버는 Docker 컨테이너 내부에서 실행됩니다. 분석 도구를 사용할 때는 **전체 로컬 경로가 아닌 파일 이름만 사용하세요**.
>
> | ❌ 잘못된 예 | ✅ 올바른 예 |
> |----------|-----------|
> | `run_file("/Users/john/Reversecore_Workspace/sample.exe")` | `run_file("sample.exe")` |
>
> **이유:** 로컬 경로(예: `/Users/.../Reversecore_Workspace/`)가 컨테이너 내부의 `/app/workspace/`로 마운트됩니다. 도구는 자동으로 작업 공간 디렉토리에서 파일을 찾습니다.
>
> **팁:** `list_workspace()`를 사용하여 작업 공간에서 사용 가능한 모든 파일을 확인하세요.

## ✨ 핵심 기능

### 🔍 정적 분석

포괄적인 파일 분석 및 메타데이터 추출:

- **파일 타입 감지**: 바이너리 형식, 아키텍처, 컴파일러 정보 식별 (`run_file`)
- **문자열 추출**: 설정 가능한 제한으로 ASCII/Unicode 문자열 추출 (`run_strings`)
- **펌웨어 분석**: 임베디드 파일 및 시그니처 심층 스캔 (`run_binwalk`)
- **바이너리 파싱**: LIEF를 사용한 PE/ELF/Mach-O 헤더 및 섹션 파싱 (`parse_binary_with_lief`)
- **소스코드 감사 (SAST)**: 소스코드 파일 및 디컴파일 결과물에 대해 설정 가능한 규칙 기반 감사 수행 (`audit_source_code`). 오탐을 줄이기 위해 Python 파일에는 AST 기반 스캐너를 사용하며, C/C++ 파일에는 정밀 정규표현식 스캐너를 적용합니다.

### ⚙️ 디스어셈블리 및 디컴파일

지능형 도구를 사용한 멀티 아키텍처 바이너리 분석:

- **Radare2 통합**: 연결 풀링을 사용한 전체 r2 명령 접근 (`run_radare2`, `Radare2_disassemble`)
- **r2ghidra 디컴파일**: Radare2용 Ghidra 디컴파일러 플러그인을 사용한 네이티브 디컴파일 (`r2_decompile`, `r2_recover_structures`, `r2_analyze_function`)
- **멀티 아키텍처 지원**: Capstone을 통한 x86, x86-64, ARM, ARM64, MIPS, PowerPC 지원 (`disassemble_with_capstone`)

### 🧬 고급 분석

심층 코드 분석 및 동작 이해:

- **크로스 레퍼런스 분석**: 함수 호출, 데이터 참조, 제어 흐름 추적 (`analyze_xrefs`)
- **구조 복구**: C 구조체를 자동 복구하고 SQLite DB에 저장 (`r2_create_structure`, `r2_list_structures`)
- **에뮬레이션**: 동적 동작 분석을 위한 ESIL 기반 코드 에뮬레이션 (`emulate_machine_code`)
- **바이너리 비교**: 바이너리 비교 및 라이브러리 함수 매칭 (`diff_binaries`, `match_libraries`)

### 🦠 악성코드 분석 및 방어

위협 탐지 및 완화를 위한 전문 도구:

- **잠복 위협 탐지**: 숨겨진 백도어, 고립된 함수, 논리 폭탄 발견 (`dormant_detector`)
- **IOC 추출**: IP, URL, 도메인, 이메일, 해시, 암호화폐 주소 자동 추출 (`extract_iocs`)
- **YARA 스캔**: 사용자 정의 규칙을 사용한 패턴 기반 악성코드 탐지 (`run_yara`)
- **적응형 백신**: 방어 조치 생성 (YARA 규칙, 바이너리 패치, NOP 주입) (`adaptive_vaccine`)
- **취약점 헌터**: 위험한 API 패턴 및 익스플로잇 경로 탐지 (`vulnerability_hunter`)

### 📊 서버 상태 및 모니터링

엔터프라이즈 환경을 위한 내장 관측 도구:

- **헬스 체크**: 가동 시간, 메모리 사용량, 운영 상태 모니터링 (`get_server_health`)
- **성능 메트릭**: 도구 실행 시간, 오류율, 호출 횟수 추적 (`get_tool_metrics`)
- **자동 복구**: 일시적 장애에 대응하는 지수 백오프 기반 자동 재시도 메커니즘

### 🖥️ 웹 대시보드 (NEW)

LLM 없이 바이너리 분석을 위한 시각적 인터페이스:

```bash
# HTTP 모드로 서버 시작
MCP_TRANSPORT=http MCP_API_KEY=your-secret-key python server.py

# 대시보드 접속
open http://localhost:8000/dashboard/
```

**기능:**
- **Overview**: 업로드된 파일 목록 및 통계
- **Analysis**: 함수 목록, 디스어셈블리 뷰어
- **IOCs**: 추출된 URL, IP, 이메일, 문자열

**보안:**
- XSS 방지를 위한 HTML 이스케이프
- 경로 탐색(Path Traversal) 방지
- API 키 인증 (선택사항)

### 📝 리포트 생성 (v3.1)

정확한 타임스탬프를 포함한 전문적인 악성코드 분석 리포트 생성:

- **원샷 제출**: 단일 명령으로 표준화된 JSON 리포트 생성 (`generate_malware_submission`)
- **세션 추적**: 자동 소요 시간 계산을 통한 분석 세션 시작/종료 (`start_analysis_session`, `end_analysis_session`)
- **IOC 수집**: 분석 중 지표 수집 및 정리 (`add_session_ioc`)
- **MITRE ATT&CK 매핑**: 적절한 프레임워크 참조로 기법 문서화 (`add_session_mitre`)
- **이메일 전송**: SMTP 지원으로 보안 팀에 리포트 직접 전송 (`send_report_email`)
- **다중 템플릿**: 전체 분석, 빠른 분류, IOC 요약, 경영진 보고서

```python
# 예시 1: 원샷 JSON 제출
generate_malware_submission(
    file_path="wannacry.exe",
    analyst_name="Hunter",
    tags="ransomware,critical"
)

# 예시 2: 대화형 세션 워크플로우
get_system_time()
start_analysis_session(sample_path="malware.exe")
add_session_ioc("ips", "192.168.1.100")
add_session_mitre("T1059.001", "PowerShell", "Execution")
end_analysis_session(summary="랜섬웨어 탐지")
create_analysis_report(template_type="full_analysis")
send_report_email(to="security-team@company.com")
```

### ⚡ 성능 및 신뢰성 (v3.1)

- **리소스 관리**:
  - **좀비 킬러(Zombie Killer)**: `try...finally` 블록으로 서브프로세스 종료 보장 및 리소스 누수 방지
  - **메모리 가드(Memory Guard)**: `strings` 등 도구 출력의 엄격한 2MB 제한으로 OOM(메모리 부족) 방지
  - **크래시 격리(Crash Isolation)**: LIEF 파서를 별도 프로세스로 격리하여 C++ 레벨 세그폴트로부터 서버 보호
- **최적화**:
  - **동적 타임아웃**: 파일 크기에 따라 자동 조절 (base + 2s/MB, 최대 +600s)
  - **경량 아키텍처**: JVM을 제거하고 네이티브 `r2ghidra`를 사용함으로써, 시작 지연시간을 낮추고 메모리 사용량을 획기적으로 줄였습니다.
  - **싱크 인식 가지치기**: 39개의 위험한 싱크 API로 지능적 경로 우선순위화
  - **트레이스 깊이 최적화**: 더 빠른 실행 경로 분석을 위해 3에서 2로 축소
- **인프라**:
  - **무상태 리포트(Stateless Reports)**: 전역 상태 변조 없는 요청별 타임존 처리로 데이터 무결성 보장
  - **강력한 재시도**: 데코레이터가 예외를 올바르게 전파하여 자동 복구 메커니즘 활성화
  - **설정 기반 검증**: 중앙 설정 파일과 동기화된 유효성 검사 제한값 적용

### 🛠️ 핵심 도구

| 카테고리 | 도구 |
|----------|------|
| **파일 작업** | `list_workspace`, `get_file_info` |
| **정적 분석** | `run_file`, `run_strings`, `run_binwalk`, `audit_source_code` |
| **디스어셈블리 및 DB** | `run_radare2`, `Radare2_disassemble`, `disassemble_with_capstone`, `r2_list_structures`, `r2_create_structure`, `r2_add_bookmark`, `r2_list_bookmarks`, `r2_list_types`, `r2_read_memory` |
| **디컴파일** | `r2_decompile`, `r2_recover_structures`, `r2_analyze_function`, `r2_get_call_graph`, `r2_simulate_patch` |
| **고급 분석** | `analyze_xrefs`, `emulate_machine_code` |
| **바이너리 파싱** | `parse_binary_with_lief` |
| **바이너리 비교** | `diff_binaries`, `match_libraries` |
| **악성코드 분석** | `dormant_detector`, `extract_iocs`, `run_yara`, `adaptive_vaccine`, `vulnerability_hunter` |
| **리포트 생성** | `get_system_time`, `set_timezone`, `start_analysis_session`, `add_session_ioc`, `add_session_mitre`, `end_analysis_session`, `create_analysis_report`, `send_report_email`, `generate_malware_submission` |
| **서버 관리** | `get_server_health`, `get_tool_metrics` |

## 📊 분석 워크플로우

```
📥 업로드 → 🔍 분류 → 🔗 X-Refs → 🏗️ 구조 → 📝 디컴파일 → 🛡️ 방어
```

**가이드 분석을 위한 내장 프롬프트 사용:**

- `full_analysis_mode` - **6단계 전문가 추론** 및 증거 분류를 갖춘 포괄적인 악성코드 분석
- `basic_analysis_mode` - 빠른 초기 평가를 위한 신속 분류
- `game_analysis_mode` - 치트 탐지 가이드를 포함한 게임 클라이언트 분석
- `firmware_analysis_mode` - 임베디드 시스템에 초점을 맞춘 IoT/펌웨어 보안 분석
- `report_generation_mode` - MITRE ATT&CK 매핑을 포함한 전문적인 리포트 생성 워크플로우

> 💡 **AI 추론 강화**: 분석 프롬프트는 전문가 페르소나 프라이밍, Chain-of-Thought 체크포인트, 구조화된 추론 단계, 증거 분류(OBSERVED/INFERRED/POSSIBLE)를 사용하여 AI 분석 능력을 극대화하고 철저한 문서화를 보장합니다.

## 🏗️ 아키텍처

```
reversecore_mcp/
├── core/                           # 인프라 및 서비스
│   ├── config.py                   # 설정 관리
│   ├── r2_helpers.py, r2_pool.py   # Radare2 연결 풀링
│   ├── security.py                 # 경로 검증 및 입력 위생화
│   ├── result.py                   # ToolSuccess/ToolError 응답 모델
│   ├── metrics.py                  # 도구 실행 메트릭
│   ├── report_generator.py         # 리포트 생성 서비스
│   ├── plugin.py                   # 확장성을 위한 플러그인 인터페이스
│   ├── decorators.py               # @log_execution, @track_metrics
│   ├── error_handling.py           # @handle_tool_errors 데코레이터
│   ├── logging_config.py           # 구조화된 로깅 설정
│   ├── memory.py                   # AI 메모리 저장소 (비동기 SQLite)
│   ├── mitre_mapper.py             # MITRE ATT&CK 프레임워크 매핑
│   ├── resource_manager.py         # 서브프로세스 수명 주기 관리
│   └── validators.py               # 입력 검증
│
├── tools/                          # MCP 도구 구현
│   ├── analysis/                   # 기본 분석 도구
│   │   ├── static_analysis.py      # file, strings, binwalk
│   │   ├── lief_tools.py           # PE/ELF/Mach-O 파싱
│   │   ├── diff_tools.py           # 바이너리 비교
│   │   └── signature_tools.py      # YARA 스캔
│   │
│   ├── radare2/                    # Radare2 & r2ghidra 통합
│   │   ├── r2_analysis.py          # 핵심 r2 분석
│   │   ├── r2ghidra_tools.py       # r2ghidra 디컴파일 및 분석
│   │   ├── r2_db.py                # SQLite 어노테이션 데이터베이스
│   │   ├── radare2_mcp_tools.py    # 고급 r2 도구 (CFG, ESIL)
│   │   └── r2_session.py           # 세션 관리
│   │
│   ├── malware/                    # 악성코드 분석 및 방어
│   │   ├── dormant_detector.py     # 숨겨진 위협 탐지
│   │   ├── adaptive_vaccine.py     # 방어 생성
│   │   ├── vulnerability_hunter.py # 취약점 탐지
│   │   ├── ioc_tools.py            # IOC 추출
│   │   └── yara_tools.py           # YARA 규칙 관리
│   │
│   ├── common/                     # 범용 관심사
│   │   ├── file_operations.py      # 작업 공간 파일 관리
│   │   ├── server_tools.py         # 헬스 체크, 메트릭
│   │   └── memory_tools.py         # AI 메모리 작업
│   │
│   └── report/                     # 리포트 생성 (v3.1)
│       ├── report_tools.py         # 핵심 리포트 엔진
│       ├── report_mcp_tools.py     # MCP 도구 등록
│       ├── session.py              # 분석 세션 추적
│       └── email.py                # SMTP 통합
│
├── prompts.py                      # AI 추론 프롬프트 (5가지 모드)
├── resources.py                    # 동적 MCP 리소스 (reversecore:// URI)
└── server.py                       # FastMCP 서버 초기화 및 HTTP 설정
```

## 🐳 Docker 배포

### 멀티 아키텍처 지원

통합 `Dockerfile`이 시스템 아키텍처를 자동으로 감지합니다:

| 아키텍처 | 자동 감지 | 지원 |
|---------|-----------|------|
| x86_64 (Intel/AMD) | ✅ | 완전 지원 |
| ARM64 (Apple Silicon M1-M4) | ✅ | 완전 지원 |

### 실행 명령

```bash
# 편의 스크립트 사용 (아키텍처 자동 감지)
./scripts/run-docker.sh              # 시작
./scripts/run-docker.sh stop         # 중지
./scripts/run-docker.sh logs         # 로그 보기
./scripts/run-docker.sh shell        # 셸 접근

# 수동 Docker 빌드 (모든 아키텍처에서 작동)
docker build -t reversecore-mcp:latest .

# 또는 Docker Compose 사용
docker compose up -d
```

### 환경 변수

| 변수 | 기본값 | 설명 |
|------|--------|------|
| `MCP_TRANSPORT` | `http` | 전송 모드 (`stdio` 또는 `http`) |
| `REVERSECORE_WORKSPACE` | `/app/workspace` | 분석 작업 공간 경로 |
| `LOG_LEVEL` | `INFO` | 로깅 레벨 |
| `REVERSECORE_SAST_RULES_PATH` | `""` | SAST 규칙을 정의한 커스텀 YAML 파일 경로 |

## 🔒 보안

- **쉘 주입 방지**: 모든 subprocess 호출은 리스트 인수 사용
- **경로 검증**: 작업 공간으로 제한된 파일 접근
- **입력 위생화**: 모든 매개변수 검증
- **속도 제한**: 설정 가능한 요청 제한 (HTTP 모드)
- **CI 검사**: Bandit(정적 분석), pip-audit(의존성 취약점), Gitleaks(시크릿 검사)

## 🧪 개발

```bash
# 의존성 설치
pip install -r requirements-dev.txt

# 테스트 실행
pytest tests/ -v

# 커버리지와 함께 실행
pytest tests/ --cov=reversecore_mcp --cov-fail-under=54

# 코드 품질
ruff check reversecore_mcp/
black reversecore_mcp/
```

### 테스트 현황

- ✅ **700+ 테스트 통과** (단위 + 통합)
- 📊 **55% 커버리지** (CI 기준 54% 이상)
- ⏱️ Bandit 보안 스캔, pip-audit 의존성 검사, pytest

## 📚 API 참조

### 도구 응답 형식

모든 도구는 구조화된 `ToolResult`를 반환:

```json
{
  "status": "success",
  "data": "...",
  "metadata": { "bytes_read": 1024 }
}
```

```json
{
  "status": "error",
  "error_code": "VALIDATION_ERROR",
  "message": "파일을 찾을 수 없음",
  "hint": "파일 경로 확인"
}
```

### 주요 오류 코드

| 코드 | 설명 |
|------|------|
| `VALIDATION_ERROR` | 잘못된 입력 매개변수 |
| `TIMEOUT` | 작업이 시간 제한 초과 |
| `PARSE_ERROR` | 도구 출력 파싱 실패 |
| `TOOL_NOT_FOUND` | 필요한 CLI 도구 없음 |

## 💻 시스템 요구 사항

| 구성 요소 | 최소 | 권장 |
|-----------|------|------|
| **CPU** | 4코어 | 8코어 이상 |
| **RAM** | 16 GB | 32 GB |
| **저장 공간** | 512 GB SSD | 1 TB NVMe |
| **OS** | Linux/macOS | Docker 환경 |

## 🤝 기여

1. 저장소 포크
2. 기능 브랜치 생성
3. 테스트와 함께 변경
4. `pytest` 및 `ruff check` 실행
5. 풀 리퀘스트 제출

## 📄 라이선스

MIT 라이선스 - 자세한 내용은 [LICENSE](LICENSE) 참조.

## 🔗 링크

- [GitHub 저장소](https://github.com/sjkim1127/Reversecore_MCP)
- [FastMCP 문서](https://github.com/jlowin/fastmcp)
- [MCP 프로토콜 사양](https://modelcontextprotocol.io/)
