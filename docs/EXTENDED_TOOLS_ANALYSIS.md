# 확장 바이너리 분석 도구 (Extended Binary Analysis Tools)

## 개요

Reversecore MCP는 다양한 바이너리 분석 도구를 지원합니다. 이 문서는 각 도구의 기능, 가용성, 성능을 종합적으로 설명합니다.

---

## 1. 도구 가용성 현황

### macOS (현재 환경)

| 도구 | 상태 | 경로 | 버전 | 기능 |
|------|------|------|------|------|
| **file** | ✅ | `/usr/bin/file` | 5.41 | 파일 형식 감지 |
| **strings** | ✅ | `/usr/bin/strings` | - | 문자열 추출 |
| **objdump** | ✅ | `/usr/bin/objdump` | LLVM 17.0 | 디스어셈블리 |
| **nm** | ✅ | `/usr/bin/nm` | LLVM 호환 | 심볼 테이블 분석 |
| **otool** | ✅ | `/usr/bin/otool` | - | macOS Mach-O 분석 |
| readelf | ❌ | - | - | ELF 헤더 (Linux 전용) |
| ldd | ❌ | - | - | 라이브러리 의존성 (Linux 전용) |
| strace | ❌ | - | - | 시스템 콜 추적 (Linux/선택적) |
| ltrace | ❌ | - | - | 라이브러리 콜 추적 (Linux/선택적) |
| radare2 | ❌ | - | - | 고급 분석 (설치 필요) |

---

## 2. 도구별 상세 설명

### 2.1 file - 파일 형식 감지

**목적**: 바이너리 파일의 형식과 구조를 식별합니다.

**주요 기능**:
- ELF, PE, Mach-O 형식 감지
- 엔디언(endianness) 판단
- 아키텍처 감별

**사용 예시**:
```bash
file binary_file
file -b binary_file          # 간단한 출력
file --mime-type binary_file # MIME 타입
```

**성능**: `0.003s 평균` (매우 빠름)

**macOS에서의 예시 출력**:
```
hello_x64: Mach-O 64-bit executable x86_64
pie_x64:   Mach-O 64-bit executable x86_64
```

---

### 2.2 strings - 문자열 추출

**목적**: 바이너리에서 인쇄 가능한 문자열을 추출합니다.

**주요 기능**:
- ASCII 문자열 추출
- 최소 길이 지정 가능
- 오프셋 정보 제공

**사용 예시**:
```bash
strings binary_file              # 모든 문자열
strings -n 8 binary_file         # 8자 이상만
strings -t x binary_file         # 16진 오프셋 표시
```

**성능**: `0.010s 평균`

**활용 분야**:
- 악성코드 분석 (C&C 서버 주소, 리소스 경로 등)
- 라이선스 정보 추출
- 하드코딩된 시크릿 검색

---

### 2.3 objdump - 디스어셈블리 및 분석

**목적**: 바이너리 섹션과 명령어를 분석합니다.

**주요 기능**:
- 디스어셈블리 (-d, -D)
- 헤더 정보 (-h)
- 심볼 테이블 (-t)
- 재배치 정보 (-r)

**사용 예시**:
```bash
objdump -d binary_file                  # 디스어셈블리
objdump -S binary_file                  # 소스 코드와 함께
objdump --all-headers binary_file       # 모든 헤더
```

**성능**: `0.009s 평균`

**주의사항**: macOS의 objdump는 Mach-O 바이너리에서 제한적입니다.

---

### 2.4 nm - 심볼 테이블 분석

**목적**: 바이너리의 심볼 테이블을 분석합니다.

**주요 기능**:
- 함수/변수 심볼 나열
- 심볼 타입 구분 (T: text, D: data, U: undefined)
- 디버그 정보 활용

**사용 예시**:
```bash
nm binary_file              # 기본
nm -a binary_file          # 모든 심볼 (숨김 포함)
nm -C binary_file          # C++ 심볼 디맹글링
nm -s binary_file          # 정렬된 심볼
```

**성능**: `0.009s 평균`

**출력 형식**:
```
0000000100000f80 T _main
0000000100000f00 T _calculate
                 U _printf
```

---

### 2.5 otool - macOS Mach-O 분석

**목적**: macOS Mach-O 바이너리를 분석합니다.

**주요 기능**:
- 헤더 정보 (-h)
- 로드 커맨드 (-l)
- 연결된 라이브러리 (-L)
- 섹션 정보 (-s)

**사용 예시**:
```bash
otool -h binary_file       # 헤더
otool -l binary_file       # 로드 커맨드
otool -L binary_file       # 라이브러리
otool -s __TEXT __text binary_file  # 특정 섹션
```

**성능**: `0.011s 평균`

**macOS 전용**: macOS Mach-O 바이너리 분석에 필수적입니다.

---

## 3. Linux 환경 도구 (CI/CD)

### 3.1 readelf - ELF 파일 분석

**목적**: ELF 형식의 헤더와 섹션을 분석합니다.

**주요 기능**:
- ELF 헤더 (-h)
- 프로그램 헤더 (-l)
- 섹션 헤더 (-S)
- 심볼 테이블 (-s)

**사용 예시**:
```bash
readelf -h binary_file      # ELF 헤더
readelf -S binary_file      # 섹션 헤더
readelf -s binary_file      # 심볼 테이블
```

**Linux 전용**: Ubuntu CI/CD 환경에서 사용 가능합니다.

---

### 3.2 ldd - 동적 라이브러리 의존성

**목적**: 바이너리의 라이브러리 의존성을 표시합니다.

**주요 기능**:
- 연결된 라이브러리 나열
- 라이브러리 경로 표시
- 누락된 라이브러리 감지

**사용 예시**:
```bash
ldd binary_file             # 의존성 표시
ldd -u binary_file          # 사용 안 된 객체
```

**Linux 전용**: 동적 링크 바이너리 분석에 필수적입니다.

---

### 3.3 strace - 시스템 콜 추적

**목적**: 프로그램의 시스템 콜을 추적합니다.

**주요 기능**:
- 시스템 콜 모니터링
- 파일 접근 추적
- 네트워크 활동 감지

**사용 예시**:
```bash
strace ./binary_file                    # 모든 시스템 콜
strace -e open,read,write ./binary      # 특정 콜만
strace -o output.txt ./binary_file      # 파일로 저장
```

**Linux 전용**: 실행 시 동작 분석에 필수적입니다.

---

### 3.4 ltrace - 라이브러리 콜 추적

**목적**: 프로그램의 라이브러리 함수 호출을 추적합니다.

**주요 기능**:
- 라이브러리 함수 호출 모니터링
- 함수 인자/반환값 표시
- 타이밍 정보 제공

**사용 예시**:
```bash
ltrace ./binary_file                    # 모든 라이브러리 콜
ltrace -e printf ./binary_file          # 특정 함수만
ltrace -c ./binary_file                 # 함수 호출 통계
```

**Linux 전용**: 라이브러리 함수 호출 분석에 필수적입니다.

---

## 4. 고급 도구 (선택적)

### 4.1 radare2 - 고급 바이너리 분석

**목적**: 복잡한 바이너리 분석을 수행합니다.

**주요 기능**:
- 정적 분석
- 동적 분석
- 디버깅
- 그래프 생성

**설치**:
```bash
# macOS
brew install radare2

# Linux
apt-get install radare2
```

---

### 4.2 Yara - 악성코드 패턴 매칭

**목적**: 패턴 기반 악성코드 감지를 수행합니다.

**주요 기능**:
- 패턴 규칙 기반 매칭
- 파일 및 메모리 스캔
- 배치 처리

**설치**:
```bash
pip install yara-python
```

**사용 예시**:
```python
import yara

rules = yara.compile(source="""
rule suspicious {
    strings:
        $s = "exec" nocase
    condition:
        $s
}
""")

matches = rules.match("binary_file")
```

---

### 4.3 binwalk - 펌웨어 분석

**목적**: 펌웨어와 포함된 파일을 분석합니다.

**주요 기능**:
- 서명 기반 스캔
- 파일 추출
- 엔트로피 분석

**설치**:
```bash
pip install binwalk
```

---

## 5. 도구 비교 매트릭스

| 기능 | file | strings | objdump | nm | otool | readelf | ldd |
|------|------|---------|---------|----|----|---------|-----|
| 파일 형식 감지 | ✅ | ❌ | ✅ | ❌ | ✅ | ✅ | ❌ |
| 문자열 추출 | ❌ | ✅ | ❌ | ❌ | ❌ | ❌ | ❌ |
| 디스어셈블리 | ❌ | ❌ | ✅ | ❌ | ⚠️ | ⚠️ | ❌ |
| 심볼 분석 | ❌ | ❌ | ✅ | ✅ | ⚠️ | ✅ | ❌ |
| 헤더 정보 | ✅ | ❌ | ✅ | ❌ | ✅ | ✅ | ❌ |
| 라이브러리 의존성 | ❌ | ❌ | ❌ | ❌ | ✅ | ❌ | ✅ |
| 섹션 정보 | ❌ | ❌ | ✅ | ❌ | ⚠️ | ✅ | ❌ |

---

## 6. 성능 비교

### 테스트 환경
- 바이너리: hello_x64, hello_x64_stripped, pie_x64, loop_x64.asm
- 테스트: 각 도구가 4개 바이너리에 대해 실행

### 성능 결과

| 도구 | 평균 시간 | 최소 | 최대 | 성공률 |
|------|----------|------|------|--------|
| **file** | 0.003s | 0.002s | 0.005s | 4/4 |
| **otool** | 0.011s | 0.010s | 0.013s | 4/4 |
| **strings** | 0.010s | 0.008s | 0.013s | 4/4 |
| **nm** | 0.009s | 0.009s | 0.011s | 3/4 |
| **objdump** | 0.009s | 0.009s | 0.011s | 0/4 |

**분석**:
- `file`: 매우 빠름 (0.003s) - 프로토타이핑에 최적
- `strings/nm/otool`: 균형 잡힘 (0.009-0.011s)
- `objdump`: macOS에서 Mach-O 바이너리 지원 제한

---

## 7. 추천 사항

### 기본 분석 (모든 사용자)
```bash
# 1단계: 파일 형식 확인
file binary

# 2단계: 문자열 추출
strings binary | grep -E "(http|flag|secret)"

# 3단계: 심볼 분석
nm binary | head -20
```

### macOS 전용 분석
```bash
# macOS Mach-O 헤더
otool -h binary
otool -L binary      # 라이브러리

# 섹션 정보
otool -s __TEXT __text binary
```

### Linux 환경 (CI/CD)
```bash
# ELF 헤더
readelf -h binary

# 심볼 테이블
readelf -s binary

# 라이브러리 의존성
ldd binary

# 시스템 콜 추적
strace ./binary
```

### 고급 분석
```bash
# Yara 악성코드 탐지
yara rules.yar binary

# binwalk 펌웨어 분석
binwalk binary
```

---

## 8. 테스트 커버리지

### 작성된 테스트

#### test_extended_tools.py (27 테스트)
- **TestOtoolAnalysis** (4 테스트)
  - otool 가용성 확인
  - Mach-O 헤더 분석
  - 로드 커맨드 분석
  - 라이브러리 목록

- **TestNmSymbolAnalysis** (4 테스트)
  - nm 가용성
  - 디버그 정보 심볼 분석
  - 스트립된 바이너리 분석
  - 심볼 타입 분석

- **TestYaraIntegration** (4 테스트)
  - Yara 임포트 테스트
  - 규칙 컴파일
  - 문자열 매칭
  - 바이너리 매칭

- **TestBinwalkAnalysis** (3 테스트)
  - binwalk 임포트
  - 서명 스캔
  - 바이너리 분석

- **TestLddDependencyAnalysis** (2 테스트)
  - ldd 가용성
  - 의존성 나열

- **TestReadelfAnalysis** (3 테스트)
  - readelf 가용성
  - 헤더 분석
  - 섹션 분석

- **TestStraceAnalysis** (2 테스트)
  - strace 가용성
  - 실행 추적

- **TestLtraceAnalysis** (2 테스트)
  - ltrace 가용성
  - 라이브러리 호출 추적

- **TestExtendedToolComparison** (3 테스트)
  - 다중 도구 심볼 분석
  - 다중 도구 헤더 분석
  - 도구 출력 일관성

### 실행 결과
```
✅ 27 테스트 작성
✅ otool 테스트: 4/4 통과
✅ nm 테스트: 4/4 통과
✅ 비교 테스트: 3/3 통과
```

---

## 9. CI/CD 통합

### GitHub Actions 파이프라인

#### 1단계: 확장 도구 테스트
```yaml
- name: Run extended tool tests
  run: |
    pytest tests/integration/test_extended_tools.py -v
```

#### 2단계: 도구 분석
```yaml
- name: Run extended tool analysis
  run: |
    python3 scripts/extended-tool-analysis.py
```

#### 생성 결과
- `artifacts/extended_analysis/extended_analysis_report.json`

---

## 10. 향후 개선 계획

### Phase 3 (계획중)
1. **Yara 규칙 라이브러리**
   - 공통 악성코드 패턴
   - YARA 규칙 저장소 통합

2. **Capstone 통합 강화**
   - 여러 아키텍처 지원
   - 성능 최적화

3. **Cross-Platform 테스트**
   - Windows PE 분석
   - 아키텍처별 도구 선택

4. **성능 최적화**
   - 병렬 분석
   - 캐싱 메커니즘

---

## 참고 자료

- [GNU Binutils](https://www.gnu.org/software/binutils/)
- [LLVM Tools](https://llvm.org/)
- [Yara Documentation](https://yara.readthedocs.io/)
- [binwalk Documentation](https://github.com/ReFirmLabs/binwalk)
- [radare2 Documentation](https://radare.org/r/)

---

**마지막 업데이트**: 2026-04-18  
**테스트 환경**: macOS 12.x, Python 3.12  
**도구 가용성**: 5/10 (macOS 네이티브)
