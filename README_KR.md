# Reversecore_MCP

![Icon](icon.png)

[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](https://opensource.org/licenses/MIT)
[![Python Version](https://img.shields.io/badge/python-3.11%2B-blue)](https://www.python.org/downloads/)
[![FastMCP](https://img.shields.io/badge/FastMCP-2.13.1-green)](https://github.com/jlowin/fastmcp)
[![Docker](https://img.shields.io/badge/docker-ready-blue)](https://www.docker.com/)

[🇺🇸 English](README.md)

AI 에이전트가 자연어 명령을 통해 포괄적인 리버스 엔지니어링 워크플로우를 수행할 수 있도록 지원하는 엔터프라이즈급 MCP(Model Context Protocol) 서버입니다. 기본적인 분류(triage)부터 고급 디컴파일, 구조 복구, 상호 참조(cross-reference) 분석, 방어 시그니처 생성에 이르기까지, Reversecore_MCP는 업계 표준 리버스 엔지니어링 도구에 대한 안전하고 성능이 뛰어난 인터페이스를 제공하여 AI 어시스턴트가 엔드투엔드 맬웨어 분석 및 보안 연구를 수행할 수 있도록 합니다.

## 👻 Reversecore Signature: Ghost Trace (유령 추적기)

**"보이지 않는 것을 탐지하다"**

Ghost Trace는 정적 분석과 동적 분석의 한계를 뛰어넘는 Reversecore_MCP만의 독보적인 하이브리드 분석 기술입니다. 샌드박스 탐지를 우회하는 "논리 폭탄(Logic Bomb)"과 "잠복형 악성코드(Dormant Malware)"를 정적 코드 분석과 AI 기반 부분 에뮬레이션을 결합하여 찾아냅니다.

- **🕵️‍♂️ 고립된 함수 탐지 (Orphan Function Detection)**: 정상적인 실행 흐름에서는 호출되지 않지만 바이너리에 존재하는 은밀한 코드 블록(백도어 가능성)을 식별합니다.
- **💣 논리 폭탄 사냥꾼 (Logic Bomb Hunter)**: 악성 행위를 트리거하는 "매직 값(Magic Value)"(예: 특정 날짜, 하드코딩된 키) 조건을 스캔합니다.
- **👻 하이브리드 에뮬레이션 (Hybrid Emulation)**: `radare2` ESIL을 사용하여 의심스러운 코드 경로만 외과적으로 정밀 에뮬레이션합니다. AI가 주입한 컨텍스트를 통해 전체 프로그램을 실행하지 않고도 악성 행위를 검증합니다.

> *Ghost Trace는 아직 발생하지 않은 미래의 악성 행위를 예측할 수 있게 해줍니다.*

## 💻 시스템 요구 사항

| 범주 | 최소 사양 | 권장 사양 |
|----------|----------------------|---------------------------|
| **사용 사례** | 단일 파일 분석, 기본 CLI 도구(file, strings), 경량 YARA 스캔 | 대규모 병렬 스캔, Ghidra 디컴파일, angr 심볼릭 실행, Docker 빌드 |
| **CPU** | 4코어 이상 (Intel i5 / Ryzen 5 동급) | 8코어 이상, P-코어 포함 (M3/M4 Pro, Ryzen 7/9, Intel i7/i9) |
| **RAM** | 16 GB | 32 GB 이상 (Mac의 경우 24 GB 통합 메모리) |
| **저장 공간** | 512 GB SSD (SATA3 이상) | 1 TB NVMe SSD (PCIe 4.0+ 권장) |
| **OS** | Linux / macOS (Docker 필수) | Linux / macOS (Unix 기반 시스템 권장) |

**전체 주기 기능**: 업로드 → 분석 → X-Refs (컨텍스트) → 구조 (C++ 복구) → 시각화 (CFG) → 에뮬레이션 (ESIL) → 디컴파일 (Pseudo-C) → 방어 (YARA 규칙)

## 주요 기능

### 핵심 리버스 엔지니어링 기능
- **보안 우선 설계**: shell=True 미사용, 포괄적인 입력 검증, 경로 위생화(sanitization)
- **고성능**: 대용량 파일을 위한 스트리밍 출력, 구성 가능한 제한, 적응형 폴링
- **포괄적인 도구 세트**: Ghidra, Radare2, strings, binwalk, YARA, Capstone, LIEF 지원
- **고급 분석**: CFG 시각화, ESIL 에뮬레이션, 스마트 디컴파일
- **C++ 구조 복구**: Ghidra 데이터 유형 전파를 통해 "this + 0x4"를 "Player.health"로 변환
- **상호 참조 분석**: 코드 컨텍스트 발견 - 누가 무엇을 호출하는지, 프로그램 흐름 이해
- **방어 통합**: 분석 내용을 바탕으로 자동 YARA 규칙 생성
- **Docker 준비 완료**: 모든 의존성이 포함된 사전 구성된 컨테이너화 배포
- **MCP 호환**: Cursor AI, Claude Desktop 및 기타 MCP 클라이언트와 연동
- **프로덕션 준비 완료**: 광범위한 오류 처리, 로깅, 속도 제한 및 모니터링
- **스레드 안전성**: 비동기/동기 지원을 통한 동시성 안전 메트릭 수집
- **AI 최적화**: 업로드부터 방어 시그니처 생성까지의 전체 주기 워크플로우

### FastMCP 고급 기능 ⭐ 신규
- **진행률 표시 (Progress Reporting)**: 장시간 작업에 대한 실시간 진행 상황 표시
  - `scan_workspace`: 실시간 파일 개수 업데이트
  - `match_libraries`: 함수 분류 진행률
- **클라이언트 로깅 (Client Logging)**: 오류 메시지 및 경고를 클라이언트에 직접 표시
  - 컨텍스트가 포함된 향상된 디버깅
  - 투명한 폴백 알림
- **이미지 콘텐츠 (Image Content)**: CFG를 위한 직접 PNG 이미지 생성
  - 채팅 내 시각적 함수 흐름 그래프
  - 자동화된 graphviz 통합
- **동적 리소스 (Dynamic Resources)**: URI 템플릿을 통한 바이너리 가상 파일 시스템
  - `reversecore://{filename}/strings` - 문자열 추출
  - `reversecore://{filename}/iocs` - IOC 요약
  - `reversecore://{filename}/func/{address}/code` - 디컴파일된 코드
  - `reversecore://{filename}/func/{address}/asm` - 어셈블리
  - `reversecore://{filename}/func/{address}/cfg` - 제어 흐름 그래프
- **생명주기 관리 (Lifespan Management)**: 자동 서버 생명주기 처리
  - 시작 시 의존성 검증
  - 종료 시 임시 파일 자동 정리
- **AI 샘플링 (AI Sampling)**: 실행 중 도구가 AI에게 도움 요청 가능
  - `analyze_with_ai`: 모호한 데이터에 대한 AI 의견 얻기
  - `suggest_function_name`: AI 기반 함수 이름 제안
- **서버 합성 (Server Composition)**: 마이크로서비스 아키텍처를 위한 서브 서버 마운트
  - 모듈식 배포 지원
  - 전문 분석 서버와 쉬운 통합
- **인증 (Authentication)**: HTTP 모드용 엔터프라이즈급 API 키 인증
  - 안전한 팀 배포
  - 환경 기반 구성

### 성능 최적화 ⚡ 신규
- **연결 풀링 (Connection Pooling)**: LRU 제거 기능이 있는 영구 radare2 연결
  - 서브프로세스 생성 오버헤드 제거
  - 반복 분석 시 최대 10배 빠른 속도
- **JVM 재사용**: 영구 Ghidra JVM 생명주기 관리
  - 디컴파일당 5-10초 시작 시간 제거
  - 즉시 재사용을 위한 오픈 프로젝트 캐싱
- **바이너리 메타데이터 캐싱**: 파일 수정 추적이 포함된 지능형 캐싱
  - 변경되지 않은 파일의 중복 분석 방지
  - 파일 업데이트 시 자동 캐시 무효화
- **회로 차단기 (Circuit Breaker)**: 자동 장애 복원력
  - 도구가 불안정할 때 연쇄 장애 방지
  - 타임아웃 후 자동 복구
- **리소스 관리 (Resource Management)**: 백그라운드 정리 작업
  - 오래된 캐시 항목 주기적 정리
  - 임시 파일 자동 제거
- **향상된 메트릭 (Enhanced Metrics)**: 포괄적인 모니터링
  - 성능 튜닝을 위한 캐시 히트/미스 비율
  - 회로 차단기 상태 추적

## 📑 목차

- [개요](#overview)
- [아키텍처](#architecture)
  - [프로젝트 구조](#project-structure)
  - [설계 원칙](#design-principles)
- [기술적 결정](#technical-decisions)
  - [보안: 명령 주입 방지](#security-command-injection-prevention)
  - [확장성: FastMCP 모듈형 아키텍처](#scalability-fastmcp-modular-architecture)
  - [성능: 대용량 출력 처리](#performance-large-output-handling)
  - [의존성: 버전 관리 전략](#dependencies-version-management-strategy)
- [설치](#installation)
  - [Docker 사용 (권장)](#using-docker-recommended)
  - [로컬 설치](#local-installation)
- [MCP 클라이언트 통합](#mcp-client-integration)
  - [Cursor AI 설정](#cursor-ai-setup-stdio-standard-connection)
  - [기타 MCP 클라이언트](#other-mcp-clients)
- [사용법](#usage)
  - [프로젝트 목표](#project-goal)
  - [API 예제](#api-examples)
- [사용 가능한 도구](#available-tools)
- [성능](#performance)
- [보안](#security)
- [오류 처리](#error-handling)
- [개발](#development)
- [문제 해결](#troubleshooting)
- [FAQ](#faq)
- [기여](#contributing)
- [라이선스](#license)

## 📝 작성자 노트

이 프로젝트는 AI의 도움을 받아 만든 토이 프로젝트입니다. C++ 파일을 분석하기 위해 개발되었으며, MCP(Model Context Protocol)와 통합된 리버스 엔지니어링 도구를 교육적으로 탐구하는 목적으로 만들어졌습니다. 학습용 프로젝트로 설계되었지만, 보안, 성능 및 아키텍처 측면에서 프로덕션 수준의 모범 사례를 보여줍니다.

## AI 사용 가이드 (AI 규칙)

> 🎯 **중요**: AI 에이전트는 도구를 수동으로 호출하는 대신 **항상 내장된 프롬프트 시스템** (`/prompt`)을 사용해야 합니다.

### 프롬프트를 사용해야 하는 이유

내장된 프롬프트는 다음을 자동으로 처리합니다:
- ✅ 올바른 도구 순서 및 SOP 강제 적용
- ✅ 파일 경로 검증 (컨테이너 경로)
- ✅ 보안 규칙 (쉘 주입 방지)
- ✅ 성능 최적화 (배치 작업)
- ✅ 오류 처리 및 빠른 실패 로직

**수동 도구 호출은 오류가 발생하기 쉽고 비효율적입니다. 프롬프트를 사용하세요.**

### 사용 가능한 분석 프롬프트

분석 목표에 따라 적절한 프롬프트를 선택하세요:

#### 🔍 `full_analysis_mode`
**사용 목적**: 포괄적인 악성코드/바이너리 분석 (A부터 Z까지)
- **SOP**: 정찰 → 필터링 → 심층 분석 → 보고
- **소요 시간**: 5-15분
- **도구**: Ghidra, 디컴파일, 에뮬레이션을 포함한 모든 도구

#### ⚡ `basic_analysis_mode`
**사용 목적**: 빠른 분류 및 위협 평가
- **SOP**: 식별 → 문자열/IOC → API 요약 → 신속 보고
- **소요 시간**: 1-3분
- **도구**: 경량 도구만 사용 (Ghidra/디컴파일 제외)

#### 🎮 `game_analysis_mode`
**사용 목적**: 게임 클라이언트 리버스 엔지니어링
- **초점**: 안티치트 탐지, 구조 복구, 네트워크 프로토콜 분석
- **대상**: Unity/Unreal 게임, 게임 핵, 치트 탐지

#### 🔧 `firmware_analysis_mode`
**사용 목적**: 펌웨어 및 IoT 디바이스 분석
- **초점**: 파일 시스템 추출, 아키텍처 식별, 하드코딩된 비밀
- **대상**: 라우터 펌웨어, 임베디드 시스템, IoT 디바이스

#### 🐛 `vulnerability_research_mode`
**사용 목적**: 버그 헌팅 및 익스플로잇 개발
- **초점**: 위험한 API 사용, 보호 기법 확인, 퍼징 후보
- **대상**: 네트워크 서비스, 파서, 권한 있는 바이너리

#### 🔐 `crypto_analysis_mode`
**사용 목적**: 암호화 구현 분석
- **초점**: 알고리즘 식별, 키 관리, 약한 암호화 탐지
- **대상**: DRM, 라이선스 검증기, 암호화된 통신

### 프롬프트 사용 방법

**사용 예시:**
```
사용자: "/app/workspace/sample.exe를 악성코드 분석해줘"
AI: [full_analysis_mode 프롬프트 선택]
→ 자동 실행: 정찰 → 필터링 → 심층 분석 → 보고
```

**프롬프트 선택 가이드:**
- 알 수 없는 파일 → 먼저 `basic_analysis_mode`
- 확인된 악성코드 → `full_analysis_mode`
- 게임 클라이언트 → `game_analysis_mode`
- 펌웨어 이미지 → `firmware_analysis_mode`
- 보안 감사 → `vulnerability_research_mode`
- 라이선스/DRM 확인 → `crypto_analysis_mode`

> ⚠️ **고급 사용자 전용**: 도구를 수동으로 호출해야 하는 경우(권장하지 않음), [도구 문서](#available-tools)를 참조하고 올바른 파일 경로(`/app/workspace/...`), 쉘 메타문자 없음, 올바른 VA vs Offset 사용을 보장하세요.

## 개요


### MCP란 무엇인가요?

MCP(Model Context Protocol)는 AI 애플리케이션이 외부 데이터 소스 및 도구에 안전하게 연결할 수 있도록 하는 개방형 표준입니다. 이는 AI 어시스턴트가 보안과 성능을 유지하면서 다양한 서비스와 상호 작용할 수 있는 범용 인터페이스를 제공합니다.

### Reversecore_MCP란 무엇인가요?

Reversecore_MCP는 리버스 엔지니어링 및 맬웨어 분석 워크플로우를 위해 설계된 전문 MCP 서버입니다. AI 에이전트가 업계 표준 리버스 엔지니어링 도구와 상호 작용할 수 있는 안전하고 표준화된 인터페이스를 제공합니다:

#### CLI 도구
- **`file`**: 파일 유형 및 메타데이터 식별
- **`strings`**: 바이너리에서 출력 가능한 문자열 추출
- **`radare2`**: 바이너리 실행 파일 디스어셈블 및 분석
- **`binwalk`**: 펌웨어에서 임베디드 파일 분석 및 추출

#### Python 라이브러리
- **`yara-python`**: 패턴 매칭 및 맬웨어 탐지
- **`capstone`**: 다중 아키텍처 디스어셈블리 엔진
- **`lief`**: 바이너리 파싱 및 분석 (PE, ELF, Mach-O)

### 왜 Reversecore_MCP인가요?

전통적인 리버스 엔지니어링 워크플로우는 다음을 필요로 합니다:
- 수동 도구 호출 및 출력 파싱
- 도구별 명령 구문에 대한 깊은 지식
- 보안 문제에 대한 신중한 처리
- 대용량 파일에 대한 성능 최적화

Reversecore_MCP는 이 모든 것을 자동으로 처리하여 AI 에이전트가 도구 관리보다는 분석에 집중할 수 있도록 합니다. 서버는 다음을 제공합니다:
- ✅ 모든 입력에 대한 **자동 보안 검증**
- ✅ 대용량 파일을 위한 **스트리밍 출력** (OOM 방지)
- ✅ 사용자 친화적인 메시지와 함께 **우아한 오류 처리**
- ✅ 구성 가능한 제한을 통한 **성능 최적화**
- ✅ 디버깅 및 감사를 위한 **포괄적인 로깅**

## 아키텍처

### 프로젝트 구조

```
Reversecore_MCP/
├── reversecore_mcp/           # 메인 패키지 디렉토리
│   ├── __init__.py
│   ├── tools/                 # 도구 정의 (MCP 도구)
│   │   ├── __init__.py
│   │   ├── cli_tools.py       # CLI 도구 래퍼 (radare2, strings, file, binwalk)
│   │   └── lib_tools.py       # 라이브러리 래퍼 (YARA, Capstone, LIEF, IOC 추출)
│   └── core/                  # 핵심 유틸리티 및 인프라
│       ├── __init__.py
│       ├── command_spec.py    # 명령 사양 및 검증
│       ├── config.py          # 구성 관리
│       ├── decorators.py      # 함수 데코레이터 (로깅, 메트릭)
│       ├── error_formatting.py # 오류 메시지 포맷팅
│       ├── error_handling.py  # 오류 처리 데코레이터
│       ├── exceptions.py      # 사용자 정의 예외 클래스
│       ├── execution.py       # 안전한 서브프로세스 실행
│       ├── ghidra_helper.py   # Ghidra 통합 유틸리티
│       ├── logging_config.py  # 로깅 구성
│       ├── metrics.py         # 성능 메트릭 수집
│       ├── result.py          # 도구 결과 모델 (ToolSuccess, ToolError)
│       ├── security.py        # 입력 검증 및 경로 위생화
│       └── validators.py      # 입력 검증기
├── docs/                      # 문서
│   ├── FILE_COPY_TOOL_GUIDE.md
│   ├── PERFORMANCE_IMPROVEMENT_REPORT.md
│   ├── PERFORMANCE_IMPROVEMENT_REPORT_V2.md
│   ├── XREFS_AND_STRUCTURES_IMPLEMENTATION.md
│   └── sample_reports/        # 샘플 맬웨어 분석 보고서
├── tests/                     # 테스트 모음
│   ├── __init__.py
│   ├── conftest.py            # Pytest 구성 및 픽스처
│   ├── fixtures/              # 테스트 데이터 및 픽스처
│   ├── integration/           # 통합 테스트
│   └── unit/                  # 단위 테스트
├── server.py                  # 서버 진입점 (FastMCP 초기화)
├── Dockerfile                 # 컨테이너화 배포 구성
├── requirements.txt           # Python 의존성
├── requirements-dev.txt       # 개발 의존성
├── pytest.ini                 # Pytest 구성
├── .gitignore                 # Git 무시 패턴
├── .trivyignore              # Trivy 보안 스캐너 무시 패턴
├── LICENSE                    # MIT 라이선스
└── README.md                  # 이 파일
```

### 설계 원칙

#### 1. 모듈성
- 도구는 범주별(CLI vs 라이브러리)로 별도 모듈에 구성됩니다.
- 각 도구 모듈은 FastMCP 서버에 도구를 등록하는 등록 함수를 내보냅니다.
- `server.py`는 중앙 등록 지점 역할을 하며 모든 도구 모듈을 가져와 등록합니다.

#### 2. 보안 우선
- **`shell=True` 미사용**: 모든 서브프로세스 호출은 리스트 기반 인수를 사용하며, 절대 쉘 명령을 사용하지 않습니다.
- **리스트 인수에 `shlex.quote()` 미사용**: `subprocess.run(["cmd", arg1, arg2])`를 사용할 때 인수는 쉘 해석 없이 프로세스에 직접 전달되므로 인용 부호 처리가 불필요하며 오히려 명령을 깨뜨릴 수 있습니다.
- **입력 검증**: 파일 경로와 명령 문자열은 사용 전에 검증됩니다.
- **경로 해결**: 모든 파일 경로는 디렉토리 순회를 방지하기 위해 절대 경로로 해결됩니다.

#### 3. 견고성
- 포괄적인 오류 처리: 모든 도구 함수는 예외를 포착하고 사용자 친화적인 오류 메시지를 반환합니다.
- 처리되지 않은 예외를 MCP 계층으로 발생시키지 않습니다.
- 우아한 성능 저하: 도구는 충돌하는 대신 오류 문자열을 반환합니다.

#### 4. 성능
- **스트리밍 출력**: 대용량 출력은 OOM을 방지하기 위해 청크 단위로 스트리밍됩니다.
- **구성 가능한 제한**: 출력 크기 및 실행 시간 제한은 도구별로 구성 가능합니다.
- **잘림 경고**: 출력이 잘리면 응답에 경고가 포함됩니다.

## 기술적 결정

### 보안: 명령 주입 방지

**결정**: `subprocess.run()`에 리스트로 인수를 전달할 때 `shlex.quote()`를 사용하지 않습니다.

**근거**:
- `subprocess.run(["r2", "-q", "-c", r2_command, file_path])`를 사용할 때 인수는 쉘 해석 없이 프로세스에 직접 전달됩니다.
- `shlex.quote()`는 쉘 명령을 구성할 때만 필요합니다 (`shell=True` 사용 시).
- 리스트 인수에 `shlex.quote()`를 사용하면 radare2가 문자 그대로 해석하는 따옴표가 추가되어 `"pdf @ main"`과 같은 명령이 깨집니다.
- **모범 사례**: 항상 리스트 인수를 사용하고, `shell=True`는 절대 사용하지 않으며, 애플리케이션 계층에서 사용자 입력을 검증하고 위생화합니다.

**구현**:
- 모든 서브프로세스 호출은 리스트 기반 인수를 사용합니다.
- `core/security.py`의 입력 검증 함수는 파일 경로와 명령 문자열을 검증합니다.
- 파일 경로는 절대 경로로 해결되고 허용된 디렉토리(구성된 경우)에 대해 확인됩니다.

### 확장성: FastMCP 모듈형 아키텍처

**결정**: 도구 구성을 위해 등록 함수 패턴을 사용합니다.

**근거**:
- FastMCP에는 FastAPI의 APIRouter와 같은 라우터 시스템이 없습니다.
- FastMCP는 컴포넌트 기반 구성을 위한 `MCPMixin`을 지원하지만, 이 사용 사례에는 더 간단한 패턴이면 충분합니다.
- 각 도구 모듈은 해당 모듈의 모든 도구를 등록하는 `register_*_tools(mcp: FastMCP)` 함수를 내보냅니다.

**구현 패턴**:
```python
# tools/cli_tools.py
def register_cli_tools(mcp: FastMCP) -> None:
    mcp.tool(run_strings)
    mcp.tool(run_radare2)

# server.py
from reversecore_mcp.tools import cli_tools, lib_tools

mcp = FastMCP(name="Reversecore_MCP")
cli_tools.register_cli_tools(mcp)
lib_tools.register_lib_tools(mcp)
```

### 성능: 대용량 출력 처리

**결정**: 구성 가능한 출력 제한이 있는 스트리밍 서브프로세스 실행을 구현합니다.

**근거**:
- 대용량 파일(GB 규모)은 `capture_output=True` 사용 시 OOM을 유발할 수 있습니다.
- 스트리밍(대용량 출력용)과 전체 캡처(소용량 출력용)를 모두 지원해야 합니다.
- 구성 가능한 최대 출력 크기 제한을 제공해야 합니다.

**구현**:
- `core/execution.py`는 `execute_subprocess_streaming()` 함수를 제공합니다.
- `stdout=subprocess.PIPE`와 함께 `subprocess.Popen`을 사용합니다.
- 크기 제한과 함께 8KB 청크로 출력을 읽습니다.
- 제한에 도달하면 경고와 함께 잘린 출력을 반환합니다.
- `run_strings`와 같은 도구는 `max_output_size` 매개변수를 허용합니다.

### 의존성: 버전 관리 전략

**결정**: Dockerfile에 고정된 패키지 버전 + radare2 통합을 위한 r2pipe 사용.

**근거**:
- **서브프로세스 접근 방식**: 간단하지만 취약함 - 버전 간 CLI 출력 형식 변경
- **r2pipe 접근 방식**: 더 안정적인 API, 더 나은 오류 처리, 구조화된 데이터 액세스
- **하이브리드 접근 방식**: radare2(기본)에 r2pipe 사용, 서브프로세스를 대체 수단으로 유지
- 재현성을 보장하기 위해 Dockerfile에 버전 고정

**구현**:
- Dockerfile은 Debian 저장소(최신 안정 버전)에서 시스템 패키지를 설치합니다.
- Python 의존성은 버전 제약 조건과 함께 `requirements.txt`에 지정됩니다.
- `r2pipe`는 radare2 작업에 사용됩니다(구현된 경우).
- 서브프로세스 기반 radare2 래퍼는 대체 수단으로 유지됩니다.

## 설치

### Docker 사용 (권장)

#### Docker 이미지 빌드

```bash
# Docker 이미지 빌드
docker build -t reversecore-mcp .
```

#### 서버 실행

Reversecore_MCP는 두 가지 전송 모드를 지원합니다. **Stdio 모드가 이제 표준입니다.**

**Stdio 모드 (표준/권장):**

```bash
# stdio 전송으로 실행 (Cursor와 같은 로컬 AI 클라이언트용)
docker run -it \
  -v ./my_samples:/app/workspace \
  -e REVERSECORE_WORKSPACE=/app/workspace \
  -e MCP_TRANSPORT=stdio \
  reversecore-mcp
```

**🚀 성능 팁: RAM 디스크(tmpfs) 사용**

10배 더 빠른 분석(특히 radare2와 같이 I/O가 많은 도구의 경우)을 위해 작업 공간을 RAM 디스크로 마운트하세요:

```bash
docker run -it \
  -v ./my_samples:/app/samples:ro \
  --tmpfs /app/workspace:rw,size=4g \
  -e REVERSECORE_WORKSPACE=/app/workspace \
  -e MCP_TRANSPORT=stdio \
  reversecore-mcp
```

*참고: tmpfs 사용 시 작업 공간은 비어 있는 상태로 시작됩니다. 분석 전에 `copy_to_workspace` 도구를 사용하여 `/app/samples`에서 `/app/workspace`로 파일을 복사해야 합니다.*

**HTTP 모드 (대안):**

```bash
# 포트 8000에서 HTTP 전송으로 실행
# 샘플 디렉토리를 /app/workspace에 마운트
docker run -d \
  -p 8000:8000 \
  -v ./my_samples:/app/workspace \
  -e REVERSECORE_WORKSPACE=/app/workspace \
  -e MCP_TRANSPORT=http \
  --name reversecore-mcp \
  reversecore-mcp
```

**중요 참고 사항:**
- 분석할 모든 파일은 마운트된 작업 공간 디렉토리(`/app/workspace`)에 있어야 합니다.
- `REVERSECORE_WORKSPACE` 환경 변수는 허용된 작업 공간 경로를 설정합니다.
- YARA 규칙 파일은 `/app/rules`(읽기 전용) 또는 작업 공간 디렉토리에 배치할 수 있습니다.

### 로컬 설치

1. 시스템 의존성 설치:
   ```bash
   # Debian/Ubuntu
   sudo apt-get install radare2 yara libyara-dev binutils openjdk-17-jre-headless
   ```

2. Python 의존성 설치:
   ```bash
   pip install -r requirements.txt
   ```

3. 환경 변수 구성:
   프로젝트 루트에 다음 내용으로 `.env` 파일을 생성합니다:
   ```env
   GHIDRA_INSTALL_DIR=/path/to/ghidra_11.4.2_PUBLIC
   REVERSECORE_WORKSPACE=/path/to/workspace
   ```
   *참고: 로컬 설치를 위해서는 Ghidra 11.4.2를 수동으로 다운로드하고 압축을 해제해야 합니다.*

4. 서버 실행:
   ```bash
   # Stdio 모드 (표준)
   MCP_TRANSPORT=stdio python server.py

   # (선택 사항) HTTP 모드
   MCP_TRANSPORT=http python server.py
   ```

## MCP 클라이언트 통합

> ⚠️ **Claude Desktop 관련 참고 사항**: Reversecore_MCP를 Claude Desktop과 함께 사용하는 것은 **권장되지 않습니다**. Claude Desktop은 stdio 전송에 제한이 있고, 프로세스 수명 주기 관리가 일관되지 않으며, 안전한 리버스 엔지니어링 워크플로우에 필요한 적절한 작업 공간 격리 기능이 부족합니다. 적절한 컨테이너화를 통해 HTTP 전송을 지원하는 **Cursor AI** 또는 기타 MCP 클라이언트를 사용하는 것을 강력히 권장합니다.

Reversecore_MCP는 MCP 호환 클라이언트와 작동합니다. 이 가이드는 이 서버에 권장되는 클라이언트인 Cursor AI에 중점을 둡니다.

### Cursor AI 설정 (stdio 표준 연결)

#### 1) Cursor에 MCP 서버 추가

- Cursor → Settings → Cursor Settings → MCP → Add new global MCP server
- `~/.cursor/mcp.json` (Windows: `C:\Users\<USER>\.cursor\mcp.json`)에 다음을 추가합니다.

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
        "reversecore-mcp"
      ]
    }
  }
}
```

프로젝트별로 추가하려면 대신 프로젝트 루트에 동일한 내용으로 `.cursor/mcp.json` 파일을 생성하세요.

#### 2) 확인

- Cursor 명령 팔레트 또는 MCP 패널에서 "List available tools for server reversecore" 실행
- 도구가 나열되면(예: "Found N tools ...") 연결이 작동하는 것입니다.


#### (선택 사항) HTTP 모드 연결

HTTP 모드를 선호하는 경우 서버를 수동으로 실행하고 Cursor가 연결하도록 구성할 수 있습니다:

1. 서버 실행:
```bash
docker run -d \
  -p 8000:8000 \
  -v ./my_samples:/app/workspace \
  -e REVERSECORE_WORKSPACE=/app/workspace \
  -e MCP_TRANSPORT=http \
  --name reversecore-mcp \
  reversecore-mcp
```

2. Cursor 구성:
```json
{
  "mcpServers": {
    "reversecore": {
      "url": "http://127.0.0.1:8000/mcp"
    }
  }
}
```

서버가 올바르게 실행 중이면 브라우저에서 `http://127.0.0.1:8000/docs`를 열 수 있어야 합니다.


### 기타 MCP 클라이언트

> ⚠️ **Claude Desktop 관련 참고 사항**: Reversecore_MCP를 Claude Desktop과 함께 사용하는 것은 **권장되지 않습니다**. Claude Desktop은 stdio 전송에 제한이 있고, 프로세스 수명 주기 관리가 일관되지 않으며, 안전한 리버스 엔지니어링 워크플로우에 필요한 적절한 작업 공간 격리 기능이 부족합니다. 적절한 컨테이너화를 통해 HTTP 전송을 지원하는 **Cursor AI** 또는 기타 MCP 클라이언트를 사용하는 것을 강력히 권장합니다.

Reversecore_MCP는 표준 MCP 프로토콜을 따르며 모든 MCP 호환 클라이언트와 작동해야 합니다. 클라이언트를 다음과 같이 구성하세요:

- **Stdio 모드 (표준)**: `MCP_TRANSPORT=stdio`를 사용하고 클라이언트가 서버를 서브프로세스로 실행하도록 구성합니다. 이는 대부분의 사용 사례에 권장되는 모드입니다.
- **HTTP 모드 (대안)**: `MCP_TRANSPORT=http`로 서버를 HTTP 모드로 시작하고 클라이언트가 `http://127.0.0.1:8000/mcp` (또는 구성된 호스트/포트)를 가리키도록 합니다. 이 모드는 원격 액세스나 stdio가 지원되지 않는 경우에 유용합니다.

stdio를 통한 MCP를 지원하는 클라이언트(예: Cursor AI)의 경우 더 나은 통합을 위해 stdio 모드를 사용하세요. HTTP만 지원하는 클라이언트의 경우 Reversecore_MCP 서버가 HTTP 모드에서 실행 중이고 구성된 엔드포인트에서 액세스 가능한지 확인하세요.

## 사용법

### 프로젝트 목표

Reversecore_MCP는 AI 에이전트가 자연어 명령을 통해 리버스 엔지니어링 작업을 수행할 수 있도록 설계되었습니다. 서버는 일반적인 리버스 엔지니어링 CLI 도구와 Python 라이브러리를 래핑하여 AI 어시스턴트가 자동화된 분류 및 분석 워크플로우에 액세스할 수 있도록 합니다.

### 실제 사용 사례

#### 맬웨어 분류
의심스러운 파일을 빠르게 식별하고 침해 지표(IOC)를 추출합니다:
```
AI 에이전트: "내 작업 공간에 있는 sample.exe를 분석해줘. 어떤 유형의 파일이며 의심스러운 문자열이 포함되어 있어?"
→ run_file + run_strings를 사용하여 PE 실행 파일 식별 및 URL, IP, 의심스러운 API 호출 추출
```

#### 보안 연구
YARA 규칙을 사용하여 알려진 맬웨어 패밀리 자동 탐지:
```
AI 에이전트: "내 맬웨어 탐지 규칙으로 작업 공간의 모든 파일을 스캔해줘"
→ run_yara를 사용하여 사용자 지정 규칙 세트와 일치시키고 위협 식별
```

#### 바이너리 분석
실행 파일 구조 및 동작 심층 분석:
```
AI 에이전트: "main 함수를 디스어셈블하고 어떤 API를 호출하는지 식별해줘"
→ run_radare2를 사용하여 코드 디스어셈블 및 함수 호출 추출
```

#### 펌웨어 분석
임베디드 시스템 분석 및 펌웨어 구성 요소 추출:
```
AI 에이전트: "이 펌웨어 이미지에 어떤 파일 시스템이 포함되어 있어?"
→ run_binwalk를 사용하여 임베디드 파일 시스템, 부트로더 등 식별
```

### 분석 프롬프트 (전문가 모드)

Reversecore_MCP는 포괄적인 분석을 위한 표준 운영 절차(SOP)를 강제하는 내장 전문가 모드 프롬프트(`full_analysis_mode`)를 제공합니다.

**사용 방법:**
MCP 클라이언트에서 `full_analysis_mode` 프롬프트를 선택하고 파일 이름을 제공하세요.

**SOP 워크플로우:**
1. **정찰 (Reconnaissance)**: 파일 유형 식별(`run_file`), IOC 추출(`run_strings` + `extract_iocs`), 패커 확인.
2. **필터링 (Filtering)**: 표준 라이브러리 함수를 필터링(`match_libraries`)하여 사용자 코드에 집중.
3. **심층 분석 (Deep Analysis)**: X-Refs(`analyze_xrefs`), 구조 복구(`recover_structures`), 스마트 디컴파일(`smart_decompile`)을 사용하여 의심스러운 함수 분석. 필요 시 안전하게 코드 에뮬레이션(`emulate_machine_code`).
4. **보고 (Reporting)**: YARA 규칙 생성(`generate_yara_rule`) 및 최종 종합 보고서 작성.

**언어 지원:**
프롬프트는 기술 용어를 유지하면서 사용자의 언어(한국어, 영어, 중국어 등)에 자동으로 적응합니다.

### 기본 분석 프롬프트 (신속 모드)

빠른 분류를 위해 `basic_analysis_mode` 프롬프트를 사용하세요.

**사용 방법:**
`basic_analysis_mode` 프롬프트를 선택하고 파일 이름을 제공하세요.

**SOP 워크플로우:**
1. **식별 (Identification)**: 파일 유형 식별(`run_file`) 및 패킹 확인(`parse_binary_with_lief`).
2. **문자열 및 IOC (Strings & IOCs)**: 문자열 추출(`run_strings`) 및 IOC 식별(`extract_iocs`).
3. **기능 (Capabilities)**: 임포트 목록을 빠르게 조회(`run_radare2` "ii")하여 행위 추론.
4. **신속 분류 보고 (Quick Triage Report)**: 발견 사항 요약 및 악성 확률 추정.

### 전문 분석 프롬프트 (Specialized Analysis Prompts)

Reversecore_MCP는 특정 도메인에 특화된 분석을 위한 프롬프트를 제공합니다:

- **`game_analysis_mode`**: 게임 로직, 안티치트, 네트워크 프로토콜 분석에 중점.
- **`firmware_analysis_mode`**: 파일 시스템 추출, 아키텍처 식별, 하드코딩된 비밀 찾기에 중점.
- **`vulnerability_research_mode`**: 버그 헌팅, 위험한 API 사용, 보호 기법(Mitigation) 확인에 중점.
- **`crypto_analysis_mode`**: 암호화 상수, 알고리즘 식별, 키 관리 취약점 분석에 중점.

### API 예제


서버는 MCP 프로토콜을 통해 AI 에이전트가 호출할 수 있는 도구를 노출합니다. 다음은 각 도구를 사용하는 방법의 예입니다:

#### 1. 파일 유형 식별 (`run_file`)

**도구 호출:**
```json
{
  "tool": "run_file",
  "arguments": {
    "file_path": "/app/workspace/sample.exe"
  }
}
```

**응답:**
```json
{
  "status": "success",
  "data": "PE32 executable (GUI) Intel 80386, for MS Windows",
  "metadata": {
    "bytes_read": 128,
    "tool": "run_file"
  }
}
```

**오류 응답:**
```json
{
  "status": "error",
  "error_code": "VALIDATION_ERROR",
  "message": "File path is outside allowed directories: /tmp/payload.exe",
  "hint": "Copy the sample under REVERSECORE_WORKSPACE before calling run_file",
  "details": {
    "allowed_directories": ["/app/workspace"],
    "path": "/tmp/payload.exe"
  }
}
```

**사용 사례**: 분류 중 초기 파일 식별

#### 2. 문자열 추출 (`run_strings`)

**도구 호출:**
```json
{
  "tool": "run_strings",
  "arguments": {
    "file_path": "/app/workspace/sample.exe",
    "min_length": 4,
    "max_output_size": 10000000,
    "timeout": 300
  }
}
```

**응답:**
```json
{
  "status": "success",
  "data": "Hello World\nGetProcAddress\nLoadLibraryA\nkernel32.dll\nhttp://malicious-domain.com/payload\nC:\\Windows\\System32\\cmd.exe\n...",
  "metadata": {
    "bytes_read": 1048576,
    "tool": "run_strings"
  }
}
```

**사용 사례**: IOC 추출을 위한 URL, 파일 경로, API 이름, 디버그 문자열 추출

#### 3. radare2로 디스어셈블 (`run_radare2`)

**도구 호출:**
```json
{
  "tool": "run_radare2",
  "arguments": {
    "file_path": "/app/workspace/sample.exe",
    "r2_command": "pdf @ main",
    "max_output_size": 10000000,
    "timeout": 300
  }
}
```

**응답:**
```json
{
  "status": "success",
  "data": "            ;-- main:\n/ (fcn) sym.main 42\n|   sym.main ();\n|           0x00401000      55             push rbp\n|           0x00401001      4889e5         mov rbp, rsp\n|           0x00401004      4883ec20       sub rsp, 0x20\n|           0x00401008      488d0d...      lea rcx, str.Hello_World\n|           0x0040100f      e8...          call sym.imp.printf\n...",
  "metadata": {
    "bytes_read": 4096,
    "tool": "run_radare2"
  }
}
```

**사용 사례**: 함수 동작, 제어 흐름 분석, 악성 코드 패턴 식별

**일반적인 명령**:
- `pdf @ main` - main 함수 디스어셈블
- `afl` - 모든 함수 나열
- `ii` - 임포트 나열
- `iz` - 데이터 섹션의 문자열 나열
- `afi @ main` - 함수 정보 표시

#### 4. YARA로 스캔 (`run_yara`)

**도구 호출:**
```json
{
  "tool": "run_yara",
  "arguments": {
    "file_path": "/app/workspace/sample.exe",
    "rule_file": "/app/rules/malware.yar",
    "timeout": 300
  }
}
```

**응답:**
```json
{
  "status": "success",
  "data": {
    "matches": [
      {
        "rule": "SuspiciousPE",
        "namespace": "default",
        "tags": ["malware", "trojan"],
        "meta": {"author": "analyst", "description": "Detects suspicious PE behavior"},
        "strings": [
          {
            "identifier": "$s1",
            "offset": 1024,
            "matched_data": "48656c6c6f20576f726c64"
          },
          {
            "identifier": "$api1",
            "offset": 2048,
            "matched_data": "437265617465526d6f746554687265616445"
          }
        ]
      }
    ],
    "match_count": 1
  }
}
```

**사용 사례**: 자동화된 맬웨어 패밀리 탐지, 규정 준수 스캔, 위협 헌팅

#### 5. Capstone으로 디스어셈블 (`disassemble_with_capstone`)

**도구 호출:**
```json
{
  "tool": "disassemble_with_capstone",
  "arguments": {
    "file_path": "/app/workspace/sample.exe",
    "offset": 0,
    "size": 1024,
    "arch": "x86",
    "mode": "64"
  }
}
```

**응답:**
```json
{
  "status": "success",
  "data": "0x0:\tpush\trbp\n0x1:\tmov\trbp, rsp\n0x4:\tsub\trsp, 0x20\n0x8:\tlea\trcx, [rip + 0x100]\n0xf:\tcall\t0x200\n...",
  "metadata": {
    "instruction_count": 64
  }
}
```

**사용 사례**: 특정 코드 섹션, 쉘코드 분석의 빠른 디스어셈블리

**지원되는 아키텍처**:
- x86 (32비트 및 64비트)
- ARM, ARM64
- MIPS, PowerPC, SPARC
- 기타 등등...

#### 6. LIEF로 바이너리 파싱 (`parse_binary_with_lief`)

**도구 호출:**
```json
{
  "tool": "parse_binary_with_lief",
  "arguments": {
    "file_path": "/app/workspace/sample.exe",
    "timeout": 300
  }
}
```

**응답:**
```json
{
  "status": "success",
  "data": {
    "format": "PE",
    "architecture": "x86-64",
    "entrypoint": "0x1400",
    "sections": [
      {
        "name": ".text",
        "virtual_address": "0x1000",
        "size": 16384,
        "entropy": 6.42
      },
      {
        "name": ".data",
        "virtual_address": "0x5000",
        "size": 4096,
        "entropy": 3.21
      }
    ],
    "imports": [
      {
        "library": "kernel32.dll",
        "functions": ["CreateFileA", "ReadFile", "WriteFile"]
      }
    ],
    "exports": [],
    "security_features": {
      "has_nx": true,
      "has_aslr": true,
      "has_pie": false,
      "has_canary": true
    }
  }
}
```

**사용 사례**: 메타데이터 추출, 바이너리 구조 분석, 보안 기능 식별

### 자연어 상호 작용

AI 어시스턴트와 함께 사용할 때 직접적인 API 호출 대신 자연어를 사용할 수 있습니다:

**대화 예시**:

```
사용자: "내 작업 공간에 malware.exe라는 의심스러운 실행 파일이 있어. 
       분석해서 어떤 작업을 하는지 알려줄 수 있어?"

AI 에이전트: 
1. run_file을 사용하여 파일 유형 식별
2. run_strings를 사용하여 IOC 추출
3. run_yara를 사용하여 알려진 맬웨어 시그니처 확인
4. run_radare2를 사용하여 main 함수 분석
5. 결과가 포함된 포괄적인 보고서 제공
```

```
사용자: "랜섬웨어 지표에 대해 내 작업 공간의 모든 PE 파일을 스캔해줘"

AI 에이전트:
1. 작업 공간의 파일 나열
2. 각 PE 파일에 대해:
   - 랜섬웨어 규칙으로 run_yara 사용
   - run_strings를 사용하여 랜섬 노트 찾기
   - 의심스러운 API 호출 확인
3. 위험 평가와 함께 결과 요약
```

```
사용자: "이 바이너리에는 어떤 보안 기능이 활성화되어 있어?"

AI 에이전트:
1. parse_binary_with_lief를 사용하여 보안 정보 추출
2. ASLR, DEP/NX, 스택 카나리아, 코드 서명 상태 보고
3. 결과를 바탕으로 권장 사항 제공
```

### 모범 사례

#### AI 에이전트용
- **광범위하게 시작한 다음 좁히기**: 식별을 위해 `run_file`을 사용한 다음 대상 도구 사용
- **적절한 타임아웃 설정**: 대용량 파일은 5-10분이 필요할 수 있음
- **출력 제한 사용**: `max_output_size`로 압도적인 응답 방지
- **도구 결합**: 여러 도구가 단일 도구보다 더 나은 컨텍스트 제공

#### 사용자용
- **작업 공간 정리**: 샘플을 정리된 디렉토리에 보관
- **YARA 규칙 사용**: 일반적인 위협에 대한 규칙 라이브러리 구축
- **로그 검토**: 오류 및 성능 문제에 대한 로그 확인
- **환경 격리**: 항상 격리된 시스템에서 맬웨어 분석

## 사용 가능한 도구

### CLI 도구

#### 기본 분석 도구

- **`run_file`**: `file` 명령을 사용하여 파일 유형 식별
  - 파일 유형, 인코딩, 아키텍처 정보 반환
  - 초기 분류를 위한 빠른 식별
  - 예: `PE32 executable (GUI) Intel 80386, for MS Windows`

- **`run_strings`**: 바이너리 파일에서 출력 가능한 문자열 추출
  - 구성 가능한 최소 문자열 길이
  - 대용량 파일을 위한 스트리밍 지원
  - 구성 가능한 출력 크기 제한 (기본값: 10MB)
  - 사용 예: URL, 파일 경로, 디버그 문자열 추출

- **`run_radare2`**: 바이너리 파일에서 radare2 명령 실행
  - 함수 디스어셈블, 제어 흐름 분석
  - 함수 시그니처 및 심볼 추출
  - 구성 가능한 출력 제한 및 타임아웃
  - 예: `pdf @ main`으로 main 함수 디스어셈블

- **`run_binwalk`**: 펌웨어/이미지에서 임베디드 파일 분석 및 추출
  - 임베디드 파일 시스템 및 아카이브 식별
  - 패킹된 섹션에 대한 엔트로피 분석
  - 시그니처 기반 파일 탐지
  - 참고: v1.0에서는 추출이 활성화되지 않음 (분석 전용)

#### 작업 공간 관리 도구

- **`copy_to_workspace`**: 모든 위치에서 작업 공간으로 파일 복사
  - Claude Desktop 업로드 지원 (`/mnt/user-data/uploads`)
  - Cursor, Windsurf 및 기타 AI 플랫폼 지원
  - 사용자 지정 파일 이름 지원
  - 안전 검사 (최대 5GB 파일 크기)
  - 예: 업로드된 샘플을 분석 작업 공간으로 복사

- **`list_workspace`**: 작업 공간 디렉토리의 모든 파일 나열
  - 분석 가능한 샘플 표시
  - 파일 수 통계
  - 분석 전 파일 가용성 확인에 유용

- **`scan_workspace`**: 작업 공간의 모든 파일 일괄 스캔
  - **⚡ 배치 모드**: `run_file`, `parse_binary_with_lief`, `run_yara`를 병렬로 실행
  - **자동 검색**: 패턴과 일치하는 모든 파일 찾기 (기본값: 전체)
  - **성능**: 비동기 동시성을 사용하여 몇 초 만에 100개 이상의 파일 스캔
  - **사용 사례**: 새로운 맬웨어 세트 또는 펌웨어 이미지의 초기 분류
  - 예: `scan_workspace(["*.exe", "*.dll"])`

#### 고급 분석 도구

- **`generate_function_graph`**: 제어 흐름 그래프(CFG) 시각화 생성
  - AI 이해를 위해 **어셈블리 → 시각적 순서도 변환**
  - 다양한 출력 형식 지원:
    - `mermaid`: LLM 최적화 순서도 구문 (기본값)
    - `json`: 처리를 위한 원시 radare2 그래프 데이터
    - `dot`: 외부 렌더링을 위한 Graphviz 형식
  - 내부적으로 radare2의 `agfj` 명령 사용
  - 예: `generate_function_graph("/app/workspace/sample.exe", "main", "mermaid")`
  - **가치**: 복잡한 어셈블리를 시각적 그래프로 변환

- **`emulate_machine_code`**: ESIL을 사용한 안전한 코드 실행 시뮬레이션
  - **실행하지 않고 코드 동작 예측**
  - 가상 CPU 에뮬레이션 (실제 실행 없음)
  - 구성 가능한 명령어 수 (1-1000, 안전 제한)
  - 에뮬레이션 후 레지스터 상태 추적
  - 사용 사례:
    - 난독화 해제: XOR 암호화된 문자열 공개
    - 안전한 맬웨어 분석: 위험 없이 동작 예측
    - 레지스터 값 예측: 실행 전 결과 확인
  - 예: `emulate_machine_code("/app/workspace/malware.exe", "0x401000", 100)`
  - **보안**: 샌드박스 ESIL VM, 호스트 시스템 영향 없음

- **`smart_decompile`**: 어셈블리를 읽기 쉬운 의사(pseudo) C 코드로 변환
  - **디컴파일러 옵션:**
    - **Ghidra (기본값)**: 우수한 유형 복구 기능을 갖춘 업계 표준 디컴파일러
    - **radare2 (대체)**: 빠른 분석을 위한 경량 대안
  - **어셈블리를 깔끔한 C 스타일 코드로 변환**
  - Ghidra의 DecompInterface 엔진 또는 radare2의 `pdc` 명령 사용
  - 함수 메타데이터 추출 (변수, 인수, 복잡성, 시그니처)
  - 논리 구조 표시 (if/else, 루프, 호출)
  - 추가 정제를 위한 AI 친화적 출력
  - 자동 대체 메커니즘으로 디컴파일이 항상 작동하도록 보장
  - 사용 사례:
    - 맬웨어 분석: 악의적인 동작을 빠르게 이해
    - 취약점 연구: 바이너리 코드에서 보안 결함 발견
    - 게임 해킹: 컴파일된 코드에서 게임 메커니즘 이해
    - 소프트웨어 감사: 비공개 소스 구성 요소 검토
  - 예: `smart_decompile("/app/workspace/sample.exe", "main")`
  - radare2 예시: `smart_decompile("/app/workspace/sample.exe", "main", use_ghidra=False)`
  - **가치**: 더 나은 유형 정보로 원시 어셈블리보다 빠른 분석

- **`generate_yara_rule`**: 자동 맬웨어 시그니처 생성
  - **분석 → 방어 파이프라인 자동화**
  - 함수에서 오피코드 바이트 추출
  - 프로덕션 준비 YARA 규칙으로 포맷팅
  - 구성 가능한 바이트 길이 (1-1024, 기본값 64)
  - YARA 호환 규칙 이름 검증
  - 메타데이터 포함 (날짜, 주소, 소스 파일)
  - 사용 사례:
    - 맬웨어 탐지: 새로운 변종에 대한 시그니처 생성
    - 위협 헌팅: 시스템 전반에서 유사한 패턴 검색
    - 사고 대응: 활성 위협에 대한 탐지 규칙 배포
    - 보안 연구: 발견 사항으로 규칙 저장소 구축
  - 예: `generate_yara_rule("/app/workspace/malware.exe", "main", 64, "trojan_xyz")`
  - **가치**: 분석과 방어 사이의 격차 해소

- **`analyze_xrefs`**: 함수 및 데이터에 대한 상호 참조(X-Refs) 분석
  - **우선순위 2: 코드 컨텍스트 발견**
  - **누가 이것을 호출하고 이것이 무엇을 호출하는지 찾기** - 동작 이해에 필수적
  - 주어진 주소로의/로부터의 모든 참조 식별
  - 중요한 컨텍스트 제공: 호출자(callers), 피호출자(callees), 데이터 참조
  - 사용 사례:
    - 맬웨어 분석: "누가 이 Connect 함수를 호출하는가?"로 C2 동작 파악
    - 암호 헌팅: "어떤 함수가 이 'Password' 문자열을 참조하는가?"
    - 취약점 연구: "무엇이 이 취약한 API를 사용하는가?"
    - 게임 해킹: "Player 체력은 어디에서 액세스되는가?"
  - **AI 협업**: 호출 그래프 구축, 패턴 식별, 토큰 예산 집중
  - 지원되는 분석 유형: `"all"`, `"to"` (호출자), `"from"` (피호출자)
  - 호출자/피호출자 관계가 포함된 구조화된 JSON 반환
  - 예: `analyze_xrefs("/app/workspace/malware.exe", "sym.decrypt", "to")`
  - **가치**: 실제 코드 관계를 제공하여 환각(hallucination) 감소

- **`recover_structures`**: C++ 클래스 구조 및 데이터 유형 복구
  - **우선순위 1: C++ 분석 게임 체인저**
  - **"this + 0x4" → "Player.health" 변환** - 코드를 의미 있게 만들기
  - Ghidra의 강력한 데이터 유형 전파 사용 (또는 radare2 대체)
  - 메모리 액세스 패턴에서 구조 레이아웃 복구
  - 필드 이름과 유형이 포함된 C 구조체 정의 생성
  - C++ 바이너리에 필수적 (많은 게임 클라이언트 및 상용 앱)
  - 사용 사례:
    - 게임 해킹: Player, Entity, Weapon 구조 복구
    - 맬웨어 분석: 맬웨어 구성 구조 이해
    - 취약점 연구: 버퍼 오버플로 후보 찾기
    - 소프트웨어 감사: 문서화되지 않은 데이터 구조 문서화
  - **AI 협업**: AI가 "Vector3"와 같은 패턴을 식별하면 사용자가 정의 적용
  - Ghidra(우수함) 및 radare2(빠름) 백엔드 모두 지원
  - 예: `recover_structures("/app/workspace/game.exe", "Player::update")`
  - 예 (radare2): `recover_structures("/app/workspace/binary", "main", use_ghidra=False)`
  - **가치**: 구조 정의로 코드 이해 명확화

- **`diff_binaries`**: 두 바이너리 파일을 비교하여 코드 변경 사항 식별
  - **우선순위 1: 패치 분석을 위한 바이너리 비교**
  - **취약점 연구 및 1-day 익스플로잇 개발에 필수적**
  - radare2의 radiff2를 사용하여 바이너리 비교
  - 유사도 점수 및 상세 변경 목록 반환
  - 전체 바이너리 비교 또는 함수별 비교 지원
  - 사용 사례:
    - **패치 분석**: 패치 전후를 비교하여 보안 수정 사항 찾기
    - **게임 해킹**: 게임 업데이트 후 오프셋 변경 사항 찾기
    - **맬웨어 변종 분석**: 맬웨어 샘플 간에 변경된 내용 식별
    - **펌웨어 비교**: 라우터 펌웨어 버전을 비교하여 취약점 찾기
  - 예 (전체 바이너리): `diff_binaries("/app/workspace/v1.exe", "/app/workspace/v2.exe")`
  - 예 (함수): `diff_binaries("/app/workspace/old.exe", "/app/workspace/new.exe", "main")`
  - **출력**: 유사도 점수, 변경 유형(새/제거된/수정된 블록), 주소
  - **가치**: 버전 간 변경 사항을 찾는 지루한 프로세스 자동화

- **`match_libraries`**: 알려진 라이브러리 함수 식별 및 필터링
  - **우선순위 2: 노이즈 감소를 위한 라이브러리 시그니처 매칭**
  - **표준 라이브러리를 필터링하여 분석 범위 대폭 축소**
  - radare2의 zignatures(FLIRT 호환)를 사용하여 알려진 함수 매칭
  - strcpy, malloc, OpenSSL, zlib, MFC 등을 자동으로 식별
  - 라이브러리 함수 vs 사용자 함수 목록 반환
  - 사용 사례:
    - **대용량 바이너리 분석**: 25MB+ 파일에서 1000개 이상의 라이브러리 함수 분석 건너뛰기
    - **게임 클라이언트 분석**: Unreal Engine/Unity 표준 라이브러리 필터링
    - **맬웨어 분석**: 사용자 지정 맬웨어 코드에 집중, Windows API 래퍼 건너뛰기
    - **토큰 최적화**: 관련 코드에 집중하여 AI 토큰 사용량 감소
  - 예: `match_libraries("/app/workspace/large_app.exe")`
  - 예 (사용자 지정 DB): `match_libraries("/app/workspace/game.exe", "/app/rules/game_engine.sig")`
  - **출력**: 노이즈 감소 비율, 라이브러리 일치, 사용자 함수 목록
  - **가치**: 라이브러리 함수를 필터링하여 사용자 코드에 집중

### 라이브러리 도구

- **`run_yara`**: YARA 규칙을 사용하여 파일 스캔
  - 사용자 지정 규칙 파일 지원
  - 상세 일치 정보 반환 (규칙, 네임스페이스, 태그, 문자열)
  - 쉬운 파싱을 위한 JSON 형식 출력
  - 구성 가능한 타임아웃 (기본값: 300초)

- **`disassemble_with_capstone`**: Capstone을 사용하여 바이너리 코드 디스어셈블
  - 다중 아키텍처 지원: x86, x86-64, ARM, ARM64, MIPS 등
  - 구성 가능한 오프셋 및 크기
  - 주소가 포함된 포맷된 어셈블리 반환
  - 예: 쉘코드 또는 특정 코드 섹션 디스어셈블

- **`parse_binary_with_lief`**: LIEF로 바이너리 파일 파싱
  - PE, ELF, Mach-O 형식 지원
  - 헤더, 섹션, 임포트, 익스포트 추출
  - 보안 기능 식별 (ASLR, DEP, 코드 서명)
  - 최대 파일 크기: 1GB (구성 가능)

- **`extract_iocs`**: 텍스트에서 침해 지표 추출
  - **정규식 기반 추출**: IPv4, URL, 이메일 찾기
  - **노이즈 감소**: 대용량 출력(`strings` 등)을 실행 가능한 데이터로 필터링
  - **사용 사례**: C2 서버에 대한 문자열 출력 또는 디컴파일된 코드 분석
  - 예: `extract_iocs(run_strings_output)`

- **`trace_execution_path`**: 사용자 입력에서 위험한 싱크(sink)까지의 익스플로잇 경로 찾기
  - **취약점 도달 가능성**: `system`, `strcpy` 등에서 역방향으로 호출 추적
  - **백트레이스 분석**: 실행이 대상 함수에 도달하는 방법 매핑
  - **사용 사례**: 사용자 입력(예: `recv`)이 취약한 싱크에 도달할 수 있는지 확인
  - 예: `trace_execution_path("/app/workspace/vuln.exe", "system")`

- **`scan_for_versions`**: 오픈 소스 라이브러리 버전 및 CVE 탐지
  - **버전 탐정**: 바이너리에서 버전 문자열 스캔 (OpenSSL, GCC 등)
  - **SCA**: 소프트웨어 구성 및 잠재적 취약점 식별
  - **사용 사례**: OpenSSL 1.0.1(Heartbleed)과 같은 오래된 라이브러리 찾기
  - 예: `scan_for_versions("/app/workspace/firmware.bin")`

- **`analyze_variant_changes`**: 맬웨어 계보 및 진화 매핑
  - **계보 매퍼**: 바이너리 비교와 CFG 분석 결합
  - **진화 분석**: 변종 간에 로직이 *어떻게* 변경되었는지 식별
  - **사용 사례**: 맬웨어 진화 추적 (예: "Lazarus v1 vs v2")
  - 예: `analyze_variant_changes("old.exe", "new.exe")`

### 전체 주기 리버스 엔지니어링 워크플로우

Reversecore_MCP는 이제 완전한 엔드투엔드 분석 워크플로우를 지원합니다:

```
📥 업로드/복사 → 📊 분석 → 🔗 X-Refs (컨텍스트) → 🏗️ 구조 (C++ 복구) → 
🔍 시각화 (CFG) → 🔮 에뮬레이션 (ESIL) → 📝 디컴파일 (Pseudo-C) → 🛡️ 방어 (YARA)
```

**예시 전체 워크플로우:**

```python
# 1. 작업 공간으로 샘플 복사
copy_to_workspace("/path/to/upload/malware.exe")

# 2. 기본 분류
run_file("/app/workspace/malware.exe")
run_strings("/app/workspace/malware.exe")

# 3. 의심스러운 함수 식별
run_radare2("/app/workspace/malware.exe", "afl~decrypt")

# 4. 상호 참조 분석 - 누가 이것을 호출하고 이것이 무엇을 호출하는지
analyze_xrefs("/app/workspace/malware.exe", "sym.decrypt", "all")
# 반환값: 호출자, 피호출자, 데이터 참조 - 컨텍스트 이해

# 5. C++ 구조 복구 - "this + 0x4"를 의미 있게 만들기
recover_structures("/app/workspace/malware.exe", "sym.decrypt")
# 반환값: 오프셋을 명명된 필드로 변환하는 구조체 정의

# 6. 제어 흐름 시각화
generate_function_graph("/app/workspace/malware.exe", "sym.decrypt", "mermaid")

# 7. 난독화된 문자열을 드러내기 위해 에뮬레이션
emulate_machine_code("/app/workspace/malware.exe", "sym.decrypt", 200)

# 8. 높은 수준의 이해를 위해 디컴파일
smart_decompile("/app/workspace/malware.exe", "sym.decrypt")

# 9. 익스플로잇 경로 추적
trace_execution_path("/app/workspace/malware.exe", "system")

# 10. 탐지 시그니처 생성
generate_yara_rule("/app/workspace/malware.exe", "sym.decrypt", 128, "malware_decrypt")
```

**이 워크플로우가 효과적인 이유:**
- **X-Refs**: 컨텍스트 제공 - 누가 의심스러운 코드를 사용하는지 이해
- **구조**: C++ 바이너리를 읽기 쉽게 만듦 - 오프셋을 이름으로 변환
- **CFG**: AI 이해를 위해 로직 흐름 시각화
- **에뮬레이션**: 실행 없이 안전하게 동작 예측
- **디컴파일**: 분석을 위한 높은 수준의 의사 C 코드 확보
- **추적**: 싱크로 가는 경로를 찾아 악용 가능성 확인
- **YARA**: 탐지 시그니처로 분석 → 방어 연결

## 성능

Reversecore_MCP는 프로덕션 워크로드 및 대규모 분석을 위해 최적화되었습니다:

### 주요 성능 기능

#### 스트리밍 출력 처리
- 메모리 문제 없이 GB 규모의 파일 처리
- 구성 가능한 제한이 있는 8KB 청크 기반 읽기
- 제한 초과 시 경고와 함께 자동 잘림
- 기본 최대 출력: 도구 호출당 10MB

#### 적응형 폴링 (Windows)
- 장기 실행 작업에 대한 CPU 사용량 감소
- 50ms 폴링 간격으로 시작하여 최대 100ms까지 적응
- 데이터 수신 시 50ms로 재설정
- 리소스 사용량을 최소화하면서 응답성 유지

#### 최적화된 경로 검증
- 경로 변환 오버헤드 대폭 감소
- 반복 검증을 위한 캐시된 문자열 변환
- 일반적인 경우에 대한 조기 반환
- 최소한의 파일 시스템 호출로 효율적인 디렉토리 확인

#### YARA 처리 개선
- 대규모 결과 세트에 대한 더 빠른 일치 처리
- 중복 속성 조회 제거
- `isinstance()`를 사용한 최적화된 유형 검사
- 대규모 결과 세트에 최적화됨

#### 메모리 효율적인 작업
- 리스트 슬라이싱 대신 enumerate 기반 반복
- 대규모 데이터 세트에 대한 중간 리스트 생성 없음
- 가능한 경우 지연 평가(Lazy evaluation)
- 구성 가능한 제한으로 OOM 조건 방지

### 성능 벤치마크

| 작업 | 성능 | 비고 |
|-----------|-------------|-------|
| 파일 유형 탐지 | < 100ms | 일반적인 바이너리의 경우 |
| 문자열 추출 | 스트리밍 | 스트리밍 사용 시 메모리 제한 없음 |
| YARA 스캔 | 2,500 매치/초 | 대규모 규칙 세트 성능 |
| 경로 검증 | 1,000 검증/초 | 캐시된 변환 |
| 디스어셈블리 | 크기에 따라 다름 | 구성 가능한 출력 제한 |
| CFG 생성 | < 2초 | 50노드 그래프의 Mermaid 형식 |
| ESIL 에뮬레이션 | < 1초 | 50-200 명령어 시퀀스의 경우 |
| 스마트 디컴파일 | 2-5초 | 함수 복잡성에 따라 다름 |
| YARA 규칙 생성 | < 1초 | 64-1024 바이트 패턴의 경우 |
| 메트릭 수집 | 스레드 안전 | 1000 동시 작업 검증됨 |

### 구성

환경 변수를 통해 성능을 조정할 수 있습니다:

```bash
# 도구당 최대 출력 크기 (바이트)
TOOL_MAX_OUTPUT_SIZE=10485760  # 10MB 기본값

# LIEF 최대 파일 크기 (바이트)
LIEF_MAX_FILE_SIZE=1000000000  # 1GB 기본값

# 도구 타임아웃 (초)
TOOL_TIMEOUT=300  # 5분 기본값

# 속도 제한 (분당 요청 수, HTTP 모드 전용)
RATE_LIMIT=60  # 60 요청/분 기본값
```

## 보안

Reversecore_MCP에서는 보안이 최우선 순위입니다. 서버는 여러 보호 계층을 구현합니다:

### 보안 기능

#### 명령 주입 방지
- **shell=True 미사용**: 모든 서브프로세스 호출은 리스트 기반 인수 사용
- **쉘 해석 없음**: 인수가 프로세스에 직접 전달됨
- **shlex.quote() 미사용**: 리스트 인수에는 필요 없음 (명령을 깨뜨릴 수 있음)
- **검증된 명령**: 실행 전 모든 사용자 입력 검증

#### 경로 순회 보호
- **절대 경로 해결**: 모든 경로가 절대 형식으로 변환됨
- **디렉토리 화이트리스트**: 작업 공간 및 읽기 전용 디렉토리만 액세스 가능
- **경로 검증**: 액세스 전 허용된 디렉토리에 대해 확인
- **심볼릭 링크 처리**: 심볼릭 링크 공격을 방지하기 위해 경로 해결

#### 입력 검증
- **유형 검사**: 올바른 유형에 대해 모든 매개변수 검증
- **범위 검증**: 유효한 범위에 대해 숫자 매개변수 확인
- **명령 위생화**: 안전한 패턴에 대해 Radare2 명령 검증
- **파일 존재 확인**: 도구 실행 전 확인

#### 리소스 제한
- **출력 크기 제한**: 메모리 고갈 방지 (기본값: 10MB)
- **실행 타임아웃**: 폭주 프로세스 방지 (기본값: 300초)
- **속도 제한**: HTTP 모드 속도 제한 (기본값: 60 req/min)
- **파일 크기 제한**: LIEF 파싱 1GB로 제한

### 보안 모범 사례

Reversecore_MCP 배포 시:

1. **Docker 사용**: 컨테이너화는 프로세스 격리를 제공합니다.
2. **최소 디렉토리 마운트**: 필요한 작업 공간 경로만 마운트하세요.
3. **읽기 전용 규칙**: YARA 규칙을 읽기 전용 디렉토리에 배치하세요.
4. **네트워크 격리**: HTTP 모드에서는 방화벽 규칙 또는 리버스 프록시를 사용하세요.
5. **로그 모니터링**: 의심스러운 활동을 감지하기 위해 로깅을 활성화하세요.
6. **업데이트 유지**: 기본 이미지와 의존성을 정기적으로 업데이트하세요.

### 작업 공간 구성

```bash
# 권장 Docker 구성
docker run -d \
  -p 127.0.0.1:8000:8000 \  # 로컬호스트에만 바인딩
  -v ./samples:/app/workspace:ro \  # 가능한 경우 읽기 전용
  -v ./rules:/app/rules:ro \  # YARA 규칙 읽기 전용
  -e REVERSECORE_WORKSPACE=/app/workspace \
  -e REVERSECORE_READ_DIRS=/app/rules \
  --security-opt=no-new-privileges \  # 추가 보안
  --cap-drop=ALL \  # 모든 기능(capability) 제거
  --name reversecore-mcp \
  reversecore-mcp
```

### 보안 감사

- ✅ 코드베이스 어디에도 `shell=True` 사용 없음
- ✅ 액세스 전 모든 파일 경로 검증
- ✅ 임의 코드 실행 기능 없음
- ✅ 포괄적인 입력 검증
- ✅ 오류 메시지가 민감한 정보를 유출하지 않음
- ✅ CodeQL 보안 스캔 활성화됨

보안 문제의 경우 보안 정책을 참조하거나 유지 관리자에게 직접 문의하세요.

## 오류 처리

### ToolResult 계약 (공용 API)

모든 MCP 도구는 이제 다음으로 구성된 Pydantic `ToolResult` 유니온을 반환합니다:

- **`ToolSuccess`**: `{ "status": "success", "data": <string|dict>, "metadata": { ... } }`
- **`ToolError`**: `{ "status": "error", "error_code": "...", "message": "...", "hint": "...", "details": { ... } }`

계약은 의도적으로 작게 유지되어 AI 에이전트가 자연어 문자열을 파싱하지 않고도 `status`에 따라 분기하고 구조화된 메타데이터를 검사할 수 있습니다.

`metadata`는 일반적으로 `bytes_read`, `instruction_count` 또는 도구별 타이밍과 같은 진단 컨텍스트를 포함하며, `details`는 오류 표면(예: `allowed_directories`, `timeout_seconds`)에 대한 구조화된 필드를 전달합니다.

**성공 예시:**
```json
{
  "status": "success",
  "data": "ELF 64-bit LSB executable, x86-64, dynamically linked, not stripped",
  "metadata": {
    "bytes_read": 512,
    "tool": "run_file",
    "execution_time": 0.12
  }
}
```

**오류 예시:**
```json
{
  "status": "error",
  "error_code": "VALIDATION_ERROR",
  "message": "File path is outside allowed directories: /tmp/payload.bin",
  "hint": "Place samples under REVERSECORE_WORKSPACE or add a read-only path via REVERSECORE_READ_DIRS",
  "details": {
    "allowed_directories": ["/app/workspace"],
    "path": "/tmp/payload.bin"
  }
}
```

### 표준 오류 코드

- `VALIDATION_ERROR` – 파일 경로 또는 매개변수 검증 실패
- `TOOL_NOT_FOUND` – 필요한 CLI 바이너리(file/strings/binwalk)가 호스트에 없음
- `TIMEOUT` – 도구가 구성된 실행 기한을 초과함
- `OUTPUT_LIMIT` – 스트리밍 출력이 구성된 `max_output_size`를 초과함
- `DEPENDENCY_MISSING` – `yara` 또는 `capstone`과 같은 Python 의존성이 설치되지 않음
- `INTERNAL_ERROR` – `handle_tool_errors` 데코레이터를 통해 표면화된 예상치 못한 실패

클라이언트는 항상 `status`에 따라 분기하고 `error_code`를 검사하며 `hint`/`details`를 그대로 표면화하여 사용자가 문제를 신속하게 해결하는 방법을 알 수 있도록 해야 합니다.

## 개발

### 새 도구 추가

1. 적절한 모듈에 **도구 함수 생성**:
   - CLI 도구의 경우 `reversecore_mcp/tools/cli_tools.py`
   - 라이브러리 기반 도구의 경우 `reversecore_mcp/tools/lib_tools.py`

2. **ToolResult 패턴 따르기**:
```python
from reversecore_mcp.core.decorators import log_execution
from reversecore_mcp.core.error_handling import handle_tool_errors
from reversecore_mcp.core.metrics import track_metrics
from reversecore_mcp.core.result import ToolResult, success


@log_execution(tool_name="my_tool")
@track_metrics("my_tool")
@handle_tool_errors
def my_tool(file_path: str, param: str, timeout: int = 300) -> ToolResult:
  """MCP 클라이언트를 위한 도구 설명."""

  validated = validate_file_path(file_path)

  output, bytes_read = execute_subprocess_streaming(
    ["tool", "--flag", param, str(validated)],
    timeout=timeout,
  )

  return success(output, bytes_read=bytes_read)
```

`log_execution`은 구조화된 로깅을 추가하고, `track_metrics`는 지연 시간/오류 메트릭을 기록하며, `handle_tool_errors`는 발생한 예외를 자동으로 `ToolError` 응답으로 변환합니다.

3. 모듈의 등록 함수에 **도구 등록**:
```python
def register_cli_tools(mcp: FastMCP) -> None:
    mcp.tool(run_file)
    mcp.tool(run_strings)
    mcp.tool(my_tool)  # 여기에 도구 추가
```

4. **도구 테스트**:
```bash
pytest tests/unit/test_cli_tools.py -k test_my_tool
```

### 테스트

```bash
# 개발 의존성 설치
pip install -r requirements-dev.txt

# 모든 테스트 실행
pytest tests/

# 커버리지와 함께 실행 (목표: 80%+ 커버리지)
pytest tests/ --cov=reversecore_mcp --cov-report=html --cov-report=term --cov-fail-under=80

# 현재 테스트 통계 (최신 커밋 기준)
# - 총 테스트: 172 통과, 6 건너뜀
# - 커버리지: 87% (80% 임계값 초과)
# - 주요 테스트 모음:
#   - CFG 도구: 9 테스트 (Mermaid/JSON/DOT 형식 검증)
#   - ESIL 에뮬레이션: 11 테스트 (레지스터 상태 파싱, 안전 제한)
#   - 스마트 디컴파일: 12 테스트 (의사 C 생성, 메타데이터 추출)
#   - 스레드 안전성: 8 테스트 (동시 메트릭 수집)
#   - 명령 검증: 31 테스트 (보안 회귀 방지)

# 특정 테스트 파일 실행
pytest tests/unit/test_cli_tools.py

# 특정 테스트 모음 실행
pytest tests/unit/test_smart_decompile.py -v
pytest tests/unit/test_cfg_tools.py -v
pytest tests/unit/test_emulation_tools.py -v

# 상세 출력으로 실행
pytest tests/ -v
```

### 코드 품질

```bash
# black으로 코드 포맷팅
black reversecore_mcp/ tests/

# ruff로 린트
ruff check reversecore_mcp/ tests/

# mypy로 유형 검사
mypy reversecore_mcp/

# bandit으로 보안 스캔
bandit -r reversecore_mcp/
```

### Docker 이미지 빌드

```bash
# 이미지 빌드
docker build -t reversecore-mcp:dev .

# 이미지 테스트
docker run --rm reversecore-mcp:dev python -c "import reversecore_mcp; print('OK')"

# 컨테이너에서 테스트 실행
docker run --rm reversecore-mcp:dev pytest /app/tests/
```

## 문제 해결

### 일반적인 문제 및 해결 방법

#### MCP 클라이언트에서 "연결 실패"

**증상**: Claude Desktop 또는 Cursor에 연결 오류 표시됨

**해결 방법**:
1. Docker 실행 확인: `docker ps`
2. 컨테이너 실행 확인: `docker ps | grep reversecore`
3. 로그 보기: `docker logs reversecore-mcp`
4. 컨테이너 재시작: `docker restart reversecore-mcp`
5. 포트 바인딩 확인: `netstat -an | grep 8000` (LISTENING 표시되어야 함)

stdio 모드의 경우:
```bash
# 명령 직접 테스트
MCP_TRANSPORT=stdio python -m reversecore_mcp.server
# 즉시 종료되지 않고 입력을 기다려야 함
```

#### 파일 분석 시 "파일을 찾을 수 없음"

**증상**: 도구가 파일을 찾을 수 없다는 오류 반환

**해결 방법**:
1. 파일이 마운트된 작업 공간에 있는지 확인:
   ```bash
   ls -la /path/to/your/samples/
   ```
2. Docker 볼륨 마운트 확인:
   ```bash
   docker inspect reversecore-mcp | grep -A 10 Mounts
   ```
3. 파일 경로가 컨테이너 경로를 사용하는지 확인:
   - ✅ 올바름: `/app/workspace/sample.exe`
   - ❌ 잘못됨: `/home/user/samples/sample.exe`
4. REVERSECORE_WORKSPACE 환경 변수 확인:
   ```bash
   docker exec reversecore-mcp env | grep REVERSECORE
   ```

#### "권한 거부" 오류

**증상**: 파일 또는 디렉토리에 액세스할 수 없음

**해결 방법**:
1. 호스트의 디렉토리 권한 확인:
   ```bash
   ls -la /path/to/samples/
   # 모든 사용자 또는 UID 1000(일반적인 Docker 사용자)이 읽을 수 있어야 함
   ```
2. 필요한 경우 권한 수정:
   ```bash
   chmod -R 755 /path/to/samples/
   ```
3. Linux에서 SELinux/AppArmor 확인:
   ```bash
   # SELinux용 docker run에 :z 플래그 추가
   -v ./samples:/app/workspace:z
   ```

#### 높은 CPU 사용량

**증상**: 컨테이너가 과도한 CPU 소모

**해결 방법**:
1. 폭주 프로세스 확인:
   ```bash
   docker exec reversecore-mcp ps aux
   ```
2. 도구 타임아웃 설정 검토:
   ```bash
   # 필요한 경우 타임아웃 줄이기
   docker run -e TOOL_TIMEOUT=60 ...
   ```
3. 속도 제한 활성화 (HTTP 모드):
   ```bash
   docker run -e RATE_LIMIT=30 ...
   ```
4. 반복되는 오류에 대한 로그 검토:
   ```bash
   docker logs reversecore-mcp --tail 100
   ```

#### "모듈을 찾을 수 없음" 오류

**증상**: 서버 시작 시 임포트 오류

**해결 방법**:
1. Python 의존성 확인:
   ```bash
   docker exec reversecore-mcp pip list
   ```
2. Docker 이미지 다시 빌드:
   ```bash
   docker build --no-cache -t reversecore-mcp .
   ```
3. 로컬 설치의 경우 PYTHONPATH 확인:
   ```bash
   export PYTHONPATH=/path/to/Reversecore_MCP:$PYTHONPATH
   ```

#### Radare2 명령 실패

**증상**: r2 명령이 오류 또는 예상치 못한 출력 반환

**해결 방법**:
1. 명령 수동 테스트:
   ```bash
   r2 -q -c "pdf @ main" /path/to/binary
   ```
2. 명령 구문 확인 (쉘 메타문자 없음):
   - ✅ 올바름: `pdf @ main`
   - ❌ 잘못됨: `pdf @ main && echo done`
3. 파일이 지원되는 형식인지 확인:
   ```bash
   file /path/to/binary
   ```
4. 대용량 바이너리에 대한 타임아웃 증가:
   ```json
   {"timeout": 600}
   ```

#### YARA 스캔 문제

**증상**: YARA가 일치 항목 없음 또는 오류 반환

**해결 방법**:
1. 규칙 파일 구문 확인:
   ```bash
   yara -c /path/to/rules.yar
   ```
2. 규칙 파일 위치 확인:
   - 작업 공간의 규칙: `/app/workspace/rules.yar`
   - 읽기 전용 디렉토리의 규칙: `/app/rules/rules.yar`
3. 규칙 수동 테스트:
   ```bash
   yara /path/to/rules.yar /path/to/sample
   ```
4. 규칙 파일 권한 검토:
   ```bash
   ls -la /path/to/rules.yar
   ```

#### 대용량 파일 처리 느림

**증상**: 대용량 파일에서 도구 타임아웃 또는 멈춤

**해결 방법**:
1. 타임아웃 증가:
   ```json
   {"timeout": 900}  // 15분
   ```
2. 해당되는 경우 출력 크기 제한 줄이기:
   ```json
   {"max_output_size": 5242880}  // 5MB
   ```
3. 대상 분석 사용:
   - strings의 경우: 출력을 줄이기 위해 min_length 증가
   - r2의 경우: 전체 분석 대신 특정 명령 사용
   - LIEF의 경우: 특정 섹션만 추출
4. 가능한 경우 스트리밍 활성화

### 디버그 모드

문제 해결을 위해 상세 로깅 활성화:

```bash
# 디버그 로깅이 포함된 HTTP 모드
docker run -d \
  -p 8000:8000 \
  -v ./samples:/app/workspace \
  -e REVERSECORE_WORKSPACE=/app/workspace \
  -e MCP_TRANSPORT=http \
  -e LOG_LEVEL=DEBUG \
  -e LOG_FORMAT=json \
  --name reversecore-mcp \
  reversecore-mcp

# 로그 보기
docker logs -f reversecore-mcp
```

### 도움 받기

여기에서 다루지 않은 문제가 발생하면:

1. [GitHub Issues](https://github.com/sjkim1127/Reversecore_MCP/issues) 확인
2. 디버그 로깅 활성화 및 출력 검토
3. 다음을 포함하여 새 이슈 생성:
   - 문제에 대한 자세한 설명
   - 재현 단계
   - 로그 출력 (민감한 데이터 제거됨)
   - 환경 세부 정보 (OS, Docker 버전 등)

## FAQ

### 일반적인 질문

**Q: MCP란 무엇이며 왜 사용해야 하나요?**

A: MCP(Model Context Protocol)는 AI 어시스턴트를 외부 도구 및 데이터 소스에 연결하기 위한 표준화된 프로토콜입니다. Reversecore_MCP를 사용하면 AI 에이전트가 수동 도구 호출이나 출력 파싱 없이 리버스 엔지니어링 작업을 수행할 수 있습니다. 특히 맬웨어 분류, 바이너리 분석 및 보안 연구 워크플로우를 자동화하는 데 유용합니다.

**Q: Reversecore_MCP는 무료로 사용할 수 있나요?**

A: 네, Reversecore_MCP는 MIT 라이선스에 따른 오픈 소스입니다. 개인적, 학술적 또는 상업적 목적으로 사용할 수 있습니다.

**Q: 어떤 AI 어시스턴트가 호환되나요?**

A: Reversecore_MCP는 모든 MCP 호환 클라이언트와 작동합니다. 테스트된 클라이언트는 다음과 같습니다:
- Cursor AI (HTTP 또는 stdio 경유)
- Claude Desktop (HTTP 경유)
- 프로토콜 사양을 따르는 사용자 지정 MCP 클라이언트

**Q: 맬웨어 분석에 사용할 수 있나요?**

A: 네, 그것이 주요 사용 사례 중 하나입니다. 서버는 보안을 염두에 두고 설계되었으며(샌드박싱, 입력 검증, 코드 실행 없음) 맬웨어 분석 워크플로우에서 일반적으로 사용되는 도구를 제공합니다. 그러나 항상 격리된 환경에서 맬웨어를 분석하세요.

### 설치 및 설정

**Q: Docker를 사용해야 하나요, 아니면 로컬 설치를 해야 하나요?**

A: 다음과 같은 이유로 Docker를 강력히 권장합니다:
- 모든 의존성이 미리 설치되어 있고 버전이 고정됨
- 맬웨어 분석을 위한 격리된 환경
- 플랫폼 간 일관된 동작
- 쉬운 업데이트 및 재배포

로컬 설치는 개발용으로만 사용하거나 Docker를 사용할 수 없는 경우에만 사용하세요.

**Q: Windows에서 실행할 수 있나요?**

A: 네, Docker Desktop을 통해 가능합니다. 기본 Windows 설치도 가능하지만 도구(radare2, binwalk)를 수동으로 설치해야 하며 Windows 관련 문제가 발생할 수 있습니다. Docker는 가장 일관된 경험을 제공합니다.

**Q: 디스크 공간이 얼마나 필요한가요?**

A: 대략적으로:
- Docker 이미지용 500MB
- Docker 레이어 캐시용 1GB
- 분석 파일을 위한 추가 공간
- 선택 사항: 로그 파일을 위한 공간

**Q: 어떤 Python 버전이 필요한가요?**

A: Python 3.11 이상입니다. 이 프로젝트는 3.11+가 필요한 최신 Python 기능과 유형 힌트를 사용합니다.

### 사용법 및 기능

**Q: 분석할 수 있는 최대 파일 크기는 얼마인가요?**

A: 도구에 따라 다릅니다:
- **file, strings, radare2**: 하드 제한은 없지만 출력은 제한됨 (기본값 10MB)
- **YARA**: 파일 크기 제한 없음, 스캔은 메모리 효율적인 방법 사용
- **Capstone**: 오프셋 및 크기 지정, 실질적인 제한 없음
- **LIEF**: 1GB 기본 제한 (LIEF_MAX_FILE_SIZE를 통해 구성 가능)

매우 큰 파일의 경우 스트리밍 도구(strings, radare2)를 사용하고 출력 제한을 지정하세요.

**Q: 한 번에 여러 파일을 분석할 수 있나요?**

A: 현재 각 도구 호출은 하나의 파일을 분석합니다. 여러 파일을 분석하려면:
- 여러 도구 호출 수행 (AI 에이전트가 처리)
- 순차적으로 도구를 호출하는 사용자 지정 스크립트 구현
- 배치 처리 기능 사용 (향후 릴리스 예정)

**Q: 사용자 지정 YARA 규칙을 어떻게 추가하나요?**

A: YARA 규칙 파일을 다음 위치에 배치하세요:
1. 작업 공간 디렉토리: `/app/workspace/rules/` (읽기-쓰기)
2. 규칙 디렉토리: `/app/rules/` (읽기 전용, 권장)

REVERSECORE_READ_DIRS를 통해 추가 디렉토리 마운트:
```bash
docker run -e REVERSECORE_READ_DIRS=/app/rules,/app/custom_rules ...
```

**Q: binwalk로 파일을 추출할 수 있나요?**

A: 현재 binwalk는 보안상의 이유로 분석 전용(추출 없음)입니다. 이는 작업 공간에서 통제되지 않은 파일 생성을 방지합니다. 파일 추출은 적절한 안전 장치와 함께 향후 릴리스에 추가될 수 있습니다.

**Q: 어떤 radare2 명령이 지원되나요?**

A: 화이트리스트에 대해 검증된 읽기 전용 명령만 지원됩니다. 지원되는 명령은 다음과 같습니다:
- 디스어셈블리: `pdf`, `pd`, `pdc`
- 분석: `aaa`, `afl`, `afi`, `afv`
- 정보: `iI`, `iz`, `ii`
- 헥스덤프: `px`, `pxw`, `pxq`

파일을 수정하거나 코드를 실행하는 명령은 차단됩니다.

### 성능 및 최적화

**Q: 분석이 왜 느린가요?**

A: 일반적인 원인:
- 기본 타임아웃이 있는 대용량 파일 (타임아웃 증가)
- 비용이 많이 드는 radare2 명령 (대상 명령 사용)
- 대용량 출력 (max_output_size 줄이기 또는 strings의 경우 min_length 증가)
- 최초 컨테이너 시작 (후속 실행은 더 빠름)

최적화 팁은 [성능](#performance) 섹션을 참조하세요.

**Q: 얼마나 많은 요청을 처리할 수 있나요?**

A: HTTP 모드에서:
- 기본 속도 제한: 클라이언트당 60 요청/분
- 동시성 제한 없음 (시스템 리소스에 의해 제한됨)
- 여러 동시 클라이언트로 테스트됨

더 높은 처리량을 위해 RATE_LIMIT를 늘리거나 여러 인스턴스를 배포하세요.

**Q: 메모리가 부족해질까요?**

A: 아니요, 적절한 구성 시:
- 스트리밍 출력은 대용량 파일에서 OOM 방지
- 구성 가능한 출력 제한 (기본값 10MB)
- 도구는 메모리 효율적인 처리 사용
- LIEF는 1GB 파일 크기 제한 있음

### 보안 및 안전

**Q: 이 도구로 맬웨어를 분석하는 것이 안전한가요?**

A: 도구는 여러 안전 기능을 제공합니다:
- 임의 코드 실행 없음
- 입력 검증 및 경로 위생화
- Docker 컨테이너에서 샌드박싱
- 임의 위치에 대한 쓰기 액세스 없음

그러나 항상 전용 격리 환경(VM, 에어갭 시스템)에서 맬웨어를 분석하세요.

**Q: AI 에이전트가 임의의 명령을 실행할 수 있나요?**

A: 아니요. 서버는:
- 명령에 대해 허용 목록 접근 방식 사용
- 코드 어디에도 shell=True 없음
- 실행 전 모든 입력 검증
- 쉘 메타문자가 있는 명령 차단
- 파일 액세스를 작업 공간으로만 제한

**Q: 비밀은 어떻게 처리되나요?**

A: 비밀이나 자격 증명이 필요하지 않습니다. 파일 액세스는 다음을 통해 제어됩니다:
- Docker 볼륨 마운트 (가능한 경우 읽기 전용)
- 경로 구성을 위한 환경 변수
- 외부 리소스에 대한 네트워크 액세스 없음 (설계상)

**Q: 어떤 데이터가 기록되나요?**

A: LOG_LEVEL을 통해 구성 가능:
- INFO: 도구 호출, 오류, 성능 메트릭
- DEBUG: 전체 명령 인수, 출력 크기, 타이밍 세부 정보
- 로그에는 파일 내용이나 민감한 분석 결과가 포함되지 않음
- 구조화된 JSON 로깅 사용 가능 (LOG_FORMAT=json)

### 문제 해결

**Q: "파일을 찾을 수 없음"이 표시되지만 파일이 존재합니다**

A: 경로 매핑 확인:
- 호스트 경로: `/home/user/samples/file.exe`
- 컨테이너 경로: `/app/workspace/file.exe` (도구 호출에서 이것 사용)
- docker run에서 마운트: `-v /home/user/samples:/app/workspace`

**Q: 도구가 실제로 무엇을 하고 있는지 어떻게 확인하나요?**

A: 디버그 로깅 활성화:
```bash
docker run -e LOG_LEVEL=DEBUG ...
docker logs -f reversecore-mcp
```

이는 전체 명령줄, 타이밍 및 출력 크기를 보여줍니다.

### 개발

**Q: 새 도구를 어떻게 추가하나요?**

A: 자세한 단계는 [개발](#development) 섹션을 참조하세요. 요약하면:
1. 적절한 모듈(cli_tools.py 또는 lib_tools.py)에 함수 추가
2. @log_execution 데코레이터 사용
3. 오류 처리 패턴 따르기
4. register_*_tools() 함수에 등록
5. 테스트 추가

**Q: 어떻게 기여하나요?**

A: [기여](#contributing) 섹션을 참조하세요. 다음을 환영합니다:
- 버그 보고 및 기능 요청
- 문서 개선
- 새로운 도구 구현
- 성능 최적화
- 보안 강화

**Q: 개발 관련 도움은 어디서 받을 수 있나요?**

A: 다음을 확인하세요:
- 패턴 및 예제에 대한 기존 코드
- 사용 예제에 대한 테스트
- docs/ 디렉토리의 문서
- 토론을 위한 GitHub Issues
- 구현 세부 정보에 대한 인라인 코드 주석

## 기여

Reversecore_MCP에 대한 기여를 환영합니다! 도울 수 있는 방법은 다음과 같습니다:

### 기여 방법

- **버그 보고**: 자세한 재현 단계와 함께 이슈 열기
- **기능 제안**: 새로운 도구 또는 개선 사항 제안
- **문서 개선**: 오타 수정, 예제 추가, 지침 명확화
- **코드 제출**: 새 도구 추가, 버그 수정, 성능 최적화
- **테스트 작성**: 테스트 커버리지 및 품질 개선
- **보안**: 보안 문제를 책임감 있게 보고 (보안 정책 참조)

### 기여 가이드라인

1. **포크 및 복제**:
```bash
# 먼저 GitHub 계정으로 리포지토리를 포크한 다음 포크를 복제합니다.
git clone https://github.com/sjkim1127/Reversecore_MCP.git
cd Reversecore_MCP
```

2. **브랜치 생성**:
```bash
git checkout -b feature/your-feature-name
```

3. **변경하기**:
   - 기존 코드 스타일 및 패턴 따르기
   - 새 기능에 대한 테스트 추가
   - 필요에 따라 문서 업데이트
   - 린터 및 테스트 실행

4. **변경 사항 테스트**:
```bash
# 테스트 실행
pytest tests/

# 린터 실행
ruff check reversecore_mcp/ tests/
black --check reversecore_mcp/ tests/

# Docker 빌드 테스트
docker build -t reversecore-mcp:test .
```

5. **커밋 및 푸시**:
```bash
git add .
git commit -m "Add: descriptive commit message"
git push origin feature/your-feature-name
```

6. **풀 리퀘스트 열기**:
   - 변경 사항을 명확하게 설명
   - 관련 이슈 참조
   - 테스트 결과 포함
   - 검토 대기

### 코드 표준

- **보안 우선**: `shell=True`를 절대 사용하지 않고, 항상 입력을 검증합니다.
- **오류 처리**: 오류 문자열을 반환하고, MCP 계층으로 발생시키지 않습니다.
- **성능**: 대용량 출력에는 스트리밍을 사용하고 제한을 준수합니다.
- **문서**: 새 기능에 대한 독스트링을 추가하고 README를 업데이트합니다.
- **테스트**: 새 코드 경로에 대한 단위 테스트를 작성합니다.
- **유형 힌트**: 모든 함수 시그니처에 유형 주석을 사용합니다.

### 테스트 요구 사항

모든 PR은 다음을 충족해야 합니다:
- ✅ 모든 기존 테스트 통과
- ✅ 새 기능에 대한 테스트 포함
- ✅ 테스트 커버리지 유지 또는 개선
- ✅ 린팅 검사 통과 (ruff, black)
- ✅ 보안 스캔 통과 (해당되는 경우 CodeQL)

### 검토 프로세스

1. PR 제출 시 자동화된 테스트 실행
2. 유지 관리자가 코드를 검토하고 피드백 제공
3. 피드백 처리 및 PR 업데이트
4. 승인되면 유지 관리자가 PR 병합

### 질문이 있으신가요?

자유롭게:
- GitHub Discussions에서 토론 열기
- 관련 이슈에 댓글 달기
- 유지 관리자에게 연락하기

기여해 주셔서 감사합니다! 🙏

## 라이선스

MIT 라이선스 - 자세한 내용은 [LICENSE](LICENSE) 파일을 참조하세요.

### 타사 의존성

이 프로젝트는 여러 오픈 소스 도구 및 라이브러리를 사용합니다:

- **Radare2**: LGPL-3.0 ([radare.org](https://radare.org))
- **YARA**: Apache 2.0 ([virustotal.github.io/yara](https://virustotal.github.io/yara/))
- **Capstone**: BSD 라이선스 ([capstone-engine.org](https://www.capstone-engine.org/))
- **LIEF**: Apache 2.0 ([lief-project.github.io](https://lief-project.github.io/))
- **FastMCP**: Apache 2.0 ([github.com/jlowin/fastmcp](https://github.com/jlowin/fastmcp))
- **binwalk**: MIT 라이선스 ([github.com/ReFirmLabs/binwalk](https://github.com/ReFirmLabs/binwalk))

각 의존성의 라이선스 조건을 검토하고 준수하십시오.

---

## 감사의 말

특별히 감사드립니다:
- 강력한 리버스 엔지니어링 프레임워크를 위한 Radare2 팀
- 패턴 매칭 기능을 위한 YARA 프로젝트
- 다중 아키텍처 디스어셈블리를 위한 Capstone 팀
- 바이너리 파싱 유틸리티를 위한 LIEF 프로젝트
- MCP 프레임워크를 위한 FastMCP 유지 관리자
- Reversecore_MCP의 모든 기여자 및 사용자

---

## 샘플 분석 보고서

상세한 맬웨어 분석 예제 및 사례 연구는 [Wiki](https://github.com/sjkim1127/Reversecore_MCP/wiki)를 방문하세요.

---

**리버스 엔지니어링 및 보안 연구 커뮤니티를 위해 ❤️로 제작됨**


