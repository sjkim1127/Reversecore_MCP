# CI/CD Tool Testing 가이드

이 문서는 Reversecore MCP의 CI/CD 파이프라인에서 외부 분석 도구들이 제대로 설치되고 작동하는지 검증하는 프로세스를 설명합니다.

## 📋 개요

### CI/CD 파이프라인 구조

```
GitHub Actions Push/PR
    ↓
┌─────────────────────────────────────────┐
│ 1. 보안 스캔                               │
│    - Gitleaks (비밀번호 유출)               │
│    - Hadolint (Dockerfile 린팅)            │
│    - Bandit (Python 보안)                  │
└─────────────────────────────────────────┘
    ↓
┌─────────────────────────────────────────┐
│ 2. 환경 구성                               │
│    - Python 3.11 설치                     │
│    - 시스템 의존성 설치:                   │
│      • radare2 (r2)                      │
│      • yara                              │
│      • binwalk                           │
│      • binutils (objdump, nm)            │
│      • 기타 도구들                        │
└─────────────────────────────────────────┘
    ↓
┌─────────────────────────────────────────┐
│ 3. 도구 검증                               │
│    - 도구 설치 확인                        │
│    - 도구 버전 확인                        │
│    - 도구 호출 테스트                      │
└─────────────────────────────────────────┘
    ↓
┌─────────────────────────────────────────┐
│ 4. 단위 테스트 실행                        │
│    - tests/unit/ 모든 테스트              │
│    - 커버리지: 54% 이상                   │
└─────────────────────────────────────────┘
    ↓
┌─────────────────────────────────────────┐
│ 5. 통합 테스트 실행                        │
│    - 도구 설치 검증 테스트                 │
│    - MCP 도구 호출 테스트                 │
└─────────────────────────────────────────┘
    ↓
┌─────────────────────────────────────────┐
│ 6. 코드 분석                               │
│    - CodeQL (GitHub 보안 스캔)            │
└─────────────────────────────────────────┘
    ↓
┌─────────────────────────────────────────┐
│ 7. Docker 빌드 & 배포 (main만)             │
│    - Multi-platform 빌드                 │
│    - ghcr.io 푸시                        │
│    - Trivy 취약점 스캔                    │
└─────────────────────────────────────────┘
```

## 🔧 주요 테스트들

### 1. 도구 설치 검증 테스트

**파일:** `tests/integration/test_tool_installation.py::TestToolInstallation`

설치된 외부 도구들을 확인합니다:

```python
✓ test_radare2_installed        # r2 설치 확인
✓ test_yara_installed            # yara 설치 확인
✓ test_strings_installed         # strings 설치 확인
✓ test_file_installed            # file 설치 확인
✓ test_binwalk_installed         # binwalk 설치 확인
✓ test_objdump_installed         # objdump 설치 확인
```

**동작:**
- 각 도구의 버전 명령어 실행
- 성공 여부 확인
- 설치되지 않은 도구는 건너뛰기(skip)

### 2. 도구 호출 테스트

**파일:** `tests/integration/test_tool_installation.py::TestToolInvocation`

실제로 도구들을 호출하여 작동하는지 확인:

```python
✓ test_radare2_file_analysis      # r2로 바이너리 분석
✓ test_file_command               # file 명령어 테스트
✓ test_strings_command            # strings 추출 테스트
```

### 3. MCP 도구 호출 테스트

**파일:** `tests/integration/test_tool_installation.py::TestMCPToolCalls`

MCP 프로토콜을 통해 도구들이 호출되는지 확인:

```python
✓ test_radare2_analysis_tool      # radare2 분석 도구 호출
✓ test_file_identification_tool   # 파일 식별 도구 호출
✓ test_mcp_tool_execution         # 전체 MCP 도구 실행
```

### 4. 통합 테스트

**파일:** `tests/integration/test_tool_installation.py::TestToolIntegration`

모든 도구들이 함께 작동하는지 확인:

```python
✓ test_all_tools_accessible       # 모든 도구 가용성 확인
✓ test_basic_file_operations      # 기본 파일 작업 수행
```

## 🖥️ 로컬 개발 환경에서 테스트

### 도구 검증 스크립트 실행

```bash
# 스크립트 실행
./scripts/verify-tools.sh

# 출력 예시:
# ==========================================
# Tool Installation Verification
# ==========================================
# 
# Core Analysis Tools:
# ✓ file installed
# ✓ strings installed
# ✗ r2 not found
# ✗ yara not found
# ...
```

### 도구 설치 (macOS)

```bash
# Homebrew로 설치
brew install radare2 yara binwalk

# 또는 Docker에서 테스트
docker compose up
```

### 도구 설치 (Linux/Ubuntu)

```bash
# apt로 설치 (CI/CD 환경)
sudo apt-get update
sudo apt-get install -y radare2 yara libyara-dev binutils binwalk
```

### 특정 도구 테스트만 실행

```bash
# 도구 설치 검증만
pytest tests/integration/test_tool_installation.py::TestToolInstallation -v

# 도구 호출 테스트만
pytest tests/integration/test_tool_installation.py::TestToolInvocation -v

# 통합 테스트만
pytest tests/integration/test_tool_installation.py::TestToolIntegration -v

# 도구 없이도 실행 가능 (건너뛰기)
pytest tests/integration/test_tool_installation.py -v
```

## 📊 CI/CD 워크플로우에서의 동작

### GitHub Actions에서의 테스트 단계

```yaml
- name: Verify tool installations
  run: |
    r2 -v || echo "⚠️  radare2 not found"
    yara --version || echo "⚠️  yara not found"
    # ... 기타 도구들

- name: Run tool installation verification tests
  run: |
    pytest tests/integration/test_tool_installation.py::TestToolInstallation -v

- name: Run integration tests (tool invocation)
  run: |
    pytest tests/integration/test_tool_installation.py::TestToolInvocation -v
    pytest tests/integration/test_tool_installation.py::TestMCPToolCalls -v
```

### 실패 시 처리

- **도구 설치 실패:** 워크플로우 계속 진행 (선택적 도구)
- **MCP 호출 실패:** 경고만 표시, 테스트 계속
- **필수 도구 실패:** 전체 파이프라인 실패 (file, strings 등)

## 🎯 테스트 샘플 바이너리

테스트용 샘플 바이너리들:

```
tests/fixtures/workspace/
├── test_binary.bin      # "Hello World" 텍스트
├── sample.elf           # 최소 ELF 바이너리
└── readme.txt           # 텍스트 파일
```

## 📈 테스트 커버리지

- **단위 테스트:** 54% 이상 (필수)
- **통합 테스트:** 선택적 (도구 설치 상태에 따라)
- **전체 커버리지:** 56%+ (현재)

## 🔍 문제 해결

### "radare2 not found" 에러

**원인:** r2이 설치되지 않았음
**해결:**
```bash
# macOS
brew install radare2

# Linux
sudo apt-get install -y radare2

# Docker
docker compose up
```

### 테스트가 건너뛰어짐 (SKIPPED)

**원인:** 도구가 설치되지 않았음
**해결:** 선택적 도구이므로 무시해도 됨
```
PASSED: 선택적 도구를 사용하는 로직
SKIPPED: 도구가 설치되지 않았을 때 건너뜀
```

### MCP 도구 호출 실패

**원인:** 도구는 있지만 호출 로직 오류
**해결:** 
```bash
# 상세 로그 확인
pytest tests/integration/test_tool_installation.py -v -s --tb=long
```

## 📚 참고 자료

- [GitHub Actions Workflow](.github/workflows/main.yml)
- [테스트 파일](tests/integration/test_tool_installation.py)
- [도구 검증 스크립트](scripts/verify-tools.sh)
- [Docker 구성](docker-compose.yml)

## ✅ 체크리스트

CI/CD 실행 전 확인:

- [ ] 모든 필수 도구 설치 확인
- [ ] 도구 버전 호환성 확인
- [ ] 테스트 샘플 바이너리 생성
- [ ] 워크스페이스 권한 확인
- [ ] 환경 변수 설정 확인

## 🚀 배포 전 최종 테스트

```bash
# 전체 테스트 실행
pytest tests/unit/ -v --cov=reversecore_mcp --cov-fail-under=54
pytest tests/integration/test_tool_installation.py -v

# Docker 빌드 테스트
docker compose build
docker compose up --exit-code-from reversecore-mcp

# 도구 검증
./scripts/verify-tools.sh
```
