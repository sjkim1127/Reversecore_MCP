# Reversecore_MCP

![Icon](icon.png)

[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](https://opensource.org/licenses/MIT)
[![Python Version](https://img.shields.io/badge/python-3.11%2B-blue)](https://www.python.org/downloads/)
[![FastMCP](https://img.shields.io/badge/FastMCP-2.13.1-green)](https://github.com/jlowin/fastmcp)
[![Docker](https://img.shields.io/badge/docker-ready-blue)](https://www.docker.com/)
[![Tests](https://img.shields.io/badge/tests-852%20passed-brightgreen)](tests/)
[![Coverage](https://img.shields.io/badge/coverage-75%25-green)](htmlcov/)

[🇺🇸 English](README.md)

AI 에이전트가 자연어 명령을 통해 포괄적인 바이너리 분석을 수행할 수 있게 하는 엔터프라이즈급 MCP(Model Context Protocol) 서버입니다.

## 🚀 빠른 시작

### Docker (권장)

```bash
# 아키텍처 자동 감지 (Intel/AMD 또는 Apple Silicon)
./scripts/run-docker.sh

# 또는 수동으로:
# Intel/AMD
docker compose --profile x86 up -d

# Apple Silicon (M1/M2/M3/M4)
docker compose --profile arm64 up -d
```

### MCP 클라이언트 설정 (Cursor AI)

`~/.cursor/mcp.json`에 추가:

```json
{
  "mcpServers": {
    "reversecore": {
      "command": "docker",
      "args": [
        "run", "-i", "--rm",
        "-v", "/path/to/workspace:/app/workspace",
        "-e", "MCP_TRANSPORT=stdio",
        "reversecore-mcp"
      ]
    }
  }
}
```

## ✨ 핵심 기능

### 🔱 Trinity Defense System

완전 자동화된 위협 탐지 및 무력화 파이프라인:

- **Phase 1 (DISCOVER)**: Ghost Trace가 숨겨진 위협 스캔
- **Phase 2 (UNDERSTAND)**: Neural Decompiler가 의도 분석
- **Phase 3 (NEUTRALIZE)**: Adaptive Vaccine이 방어 생성

### 👻 Ghost Trace

샌드박스 탐지를 우회하는 "논리 폭탄" 및 "잠복형 악성코드" 탐지:

- 고립된 함수 탐지 (숨겨진 백도어)
- 매직 값 트리거 식별
- AI 기반 부분 에뮬레이션

### 🧠 Neural Decompiler

원시 디컴파일 코드를 읽기 쉬운 형식으로 변환:

- 의미론적 변수 명명 (`iVar1` → `sock_fd`)
- 포인터 연산에서 구조체 추론
- 설명 주석이 포함된 스마트 어노테이션

### 🛠️ 핵심 도구

| 카테고리 | 도구 |
|----------|------|
| **기본 분석** | `run_file`, `run_strings`, `run_binwalk` |
| **디스어셈블리** | `run_radare2`, `disassemble_with_capstone` |
| **디컴파일** | `smart_decompile`, `get_pseudo_code` (Ghidra/r2) |
| **고급** | `analyze_xrefs`, `recover_structures`, `emulate_machine_code` |
| **방어** | `generate_yara_rule`, `adaptive_vaccine` |
| **바이너리 파싱** | `parse_binary_with_lief`, `extract_iocs` |
| **비교** | `diff_binaries`, `match_libraries` |

## 📊 분석 워크플로우

```
📥 업로드 → 🔍 분류 → 🔗 X-Refs → 🏗️ 구조 → 📝 디컴파일 → 🛡️ 방어
```

**가이드 분석을 위한 내장 프롬프트 사용:**

- `full_analysis_mode` - 포괄적인 악성코드 분석
- `basic_analysis_mode` - 빠른 분류
- `game_analysis_mode` - 게임 클라이언트 리버스 엔지니어링
- `firmware_analysis_mode` - IoT/펌웨어 분석

## 🏗️ 아키텍처

```
reversecore_mcp/
├── core/                 # 인프라
│   ├── config.py         # 설정 관리
│   ├── container.py      # 의존성 주입
│   ├── ghidra.py         # Ghidra 통합
│   ├── r2_helpers.py     # Radare2 유틸리티
│   ├── result.py         # ToolSuccess/ToolError 모델
│   └── security.py       # 입력 검증
├── tools/                # MCP 도구
│   ├── cli_tools.py      # CLI 래퍼
│   ├── decompilation.py  # 디컴파일러
│   ├── ghost_trace.py    # 숨겨진 위협 탐지
│   ├── trinity_defense.py # 자동화된 방어
│   └── ...
├── prompts.py            # 분석 프롬프트
└── resources.py          # 동적 리소스
```

## 🐳 Docker 배포

### 멀티 아키텍처 지원

| 파일 | 아키텍처 | 사용 사례 |
|------|----------|----------|
| `Dockerfile` | x86_64 (Intel/AMD) | 리눅스 서버, Intel Mac |
| `Dockerfile.arm64` | ARM64 | Apple Silicon Mac |

### 실행 명령

```bash
# 편의 스크립트 사용 (아키텍처 자동 감지)
./scripts/run-docker.sh              # 시작
./scripts/run-docker.sh stop         # 중지
./scripts/run-docker.sh logs         # 로그 보기
./scripts/run-docker.sh shell        # 셸 접근

# 수동 Docker 명령
docker build -t reversecore-mcp .
docker run -it -p 8000:8000 \
  -v $(pwd)/workspace:/app/workspace \
  reversecore-mcp
```

### 환경 변수

| 변수 | 기본값 | 설명 |
|------|--------|------|
| `MCP_TRANSPORT` | `http` | 전송 모드 (`stdio` 또는 `http`) |
| `REVERSECORE_WORKSPACE` | `/app/workspace` | 분석 작업 공간 경로 |
| `LOG_LEVEL` | `INFO` | 로깅 레벨 |
| `GHIDRA_INSTALL_DIR` | `/opt/ghidra` | Ghidra 설치 경로 |

## 🔒 보안

- **쉘 주입 방지**: 모든 subprocess 호출은 리스트 인수 사용
- **경로 검증**: 작업 공간으로 제한된 파일 접근
- **입력 위생화**: 모든 매개변수 검증
- **속도 제한**: 설정 가능한 요청 제한 (HTTP 모드)

## 🧪 개발

```bash
# 의존성 설치
pip install -r requirements-dev.txt

# 테스트 실행
pytest tests/ -v

# 커버리지와 함께 실행
pytest tests/ --cov=reversecore_mcp --cov-fail-under=72

# 코드 품질
ruff check reversecore_mcp/
black reversecore_mcp/
```

### 테스트 현황

- ✅ **852 테스트 통과**
- 📊 **75% 커버리지**
- ⏱️ ~14초 실행 시간

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
