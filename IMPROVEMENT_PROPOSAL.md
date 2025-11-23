# Reversecore_MCP 개선 제안서

> 📅 작성일: 2025-01-23  
> 🎯 목표: 성능 최적화 및 확장성 개선

---

## 🎯 핵심 개선점 요약

### 1️⃣ **도구 연결 풀(Tool Connection Pooling)** - 최우선 ⭐⭐⭐

#### 현재 구조의 문제
```
사용자 요청 → Radare2 새 프로세스 시작 → 분석 → 프로세스 종료
다음 요청 → Radare2 새 프로세스 시작 → 분석 → 프로세스 종료
```

**문제점:**
- 매 요청마다 프로세스 시작/종료 오버헤드 (0.5~2초)
- Ghidra JVM 시작은 최대 5~10초 소요
- 메모리 재로드로 인한 I/O 낭비

#### 개선 방안

**1-A. Radare2 영구 연결 (`r2pipe` 활용)**

현재 (매번 새 프로세스):
```python
# cli_tools.py
async def run_radare2(file_path, r2_command):
    cmd = ["r2", "-q", "-c", r2_command, file_path]
    output, _ = await execute_subprocess_async(cmd)  # 매번 새로 시작!
```

**개선안 (연결 재사용):**
```python
# core/r2_pool.py (신규 파일)
import r2pipe

class R2ConnectionPool:
    """Radare2 연결을 재사용하는 풀"""
    def __init__(self, max_connections=5):
        self.pool = {}  # {file_path: r2pipe_instance}
        self.max_connections = max_connections
    
    def get_connection(self, file_path):
        if file_path not in self.pool:
            # 새 연결 생성
            self.pool[file_path] = r2pipe.open(file_path)
        return self.pool[file_path]
    
    def execute(self, file_path, command):
        r2 = self.get_connection(file_path)
        return r2.cmd(command)

# cli_tools.py (수정)
r2_pool = R2ConnectionPool()

async def run_radare2(file_path, r2_command):
    # 기존 연결 재사용 - 프로세스 시작 오버헤드 없음!
    output = await asyncio.to_thread(r2_pool.execute, file_path, r2_command)
```

**예상 효과:**
- ✅ 첫 요청 후 후속 요청 **5~10배 빠름**
- ✅ 동일 파일 연속 분석 시 즉시 응답
- ✅ 메모리 사용량 감소 (중복 로드 없음)

---

**1-B. Ghidra 영구 JVM (`PyGhidra` 개선)**

현재 문제:
```python
# 매 decompile 요청마다
def smart_decompile(file_path, function):
    # PyGhidra가 내부적으로 JVM 시작 (5~10초!)
    import pyghidra
    result = pyghidra.decompile(file_path, function)
```

**개선안:**
```python
# core/ghidra_manager.py (신규)
class GhidraManager:
    """Ghidra JVM을 한번만 시작하고 재사용"""
    def __init__(self):
        self._jvm_started = False
        self._projects = {}  # 이미 로드된 프로젝트 캐싱
    
    def ensure_jvm_started(self):
        if not self._jvm_started:
            import pyghidra
            pyghidra.start()  # JVM 한번만 시작
            self._jvm_started = True
    
    def decompile(self, file_path, function):
        self.ensure_jvm_started()
        # 이미 로드된 프로젝트 재사용
        if file_path not in self._projects:
            self._projects[file_path] = load_project(file_path)
        return self._projects[file_path].decompile(function)
```

**예상 효과:**
- ✅ 첫 요청 후 **JVM 재시작 없음** (5~10초 절약)
- ✅ 대용량 바이너리도 한번만 로드

---

### 2️⃣ **다층 캐싱 전략 (Multi-level Caching)** - 매우 중요 ⭐⭐⭐

#### 현재 캐싱 현황
- ✅ `@alru_cache` - 일부 함수에만 적용
- ❌ 함수 내부 중간 결과 미캐싱
- ❌ 바이너리 메타데이터 매번 재분석

#### 개선안

**2-A. 바이너리 메타데이터 캐싱**
```python
# core/binary_cache.py (신규)
class BinaryMetadataCache:
    """파일 해시 기반 메타데이터 캐싱"""
    def __init__(self):
        self.cache = {}  # {file_hash: metadata}
    
    def get_metadata(self, file_path):
        file_hash = self._compute_hash(file_path)
        
        if file_hash in self.cache:
            return self.cache[file_hash]  # 캐시 히트!
        
        # 첫 분석 시 함수 목록, imports, strings 등 기본 정보 수집
        metadata = {
            'functions': get_functions(file_path),
            'imports': get_imports(file_path),
            'strings': get_strings(file_path),
            'file_info': get_file_info(file_path)
        }
        
        self.cache[file_hash] = metadata
        return metadata
```

**2-B. 디스크 기반 캐싱 (선택적)**
```python
# 대용량 결과는 Redis/SQLite에 저장
import sqlite3

class PersistentCache:
    """분석 결과를 DB에 저장"""
    def cache_decompilation(self, file_hash, function, code):
        # 디컴파일 결과는 크므로 DB에 저장
        cursor.execute(
            "INSERT INTO decompile_cache VALUES (?, ?, ?)",
            (file_hash, function, code)
        )
```

**예상 효과:**
- ✅ 동일 파일 재분석 시 **10~100배 빠름**
- ✅ 서버 재시작 후에도 캐시 유지 (선택적)

---

### 3️⃣ **배치 처리 최적화** - 중요 ⭐⭐

#### 현재 문제
```python
# scan_workspace - 파일 5개씩 병렬 처리
semaphore = asyncio.Semaphore(5)
```

**개선안: 도구별 배치 실행**
```python
# 여러 파일을 한 번의 radare2 실행으로 처리
async def batch_analyze_files(file_paths):
    # radare2는 한번 시작 후 여러 파일 분석 가능
    r2 = r2pipe.open()
    results = {}
    for file_path in file_paths:
        r2.cmd(f"o {file_path}")  # 파일 전환만
        results[file_path] = r2.cmd("aflj")  # 분석
    return results
```

**예상 효과:**
- ✅ 워크스페이스 스캔 **2~3배 빠름**

---

### 4️⃣ **스트리밍 및 점진적 응답** - 사용자 경험 개선 ⭐⭐

#### 현재 문제
- 대용량 출력(strings, 디컴파일)을 전부 기다린 후 반환
- 사용자는 긴 시간 동안 "응답 없음" 상태

#### 개선안
```python
# FastMCP의 streaming 기능 활용
async def run_strings_streaming(file_path, ctx: Context):
    """문자열을 찾는대로 즉시 전송"""
    process = await asyncio.create_subprocess_exec(...)
    
    async for line in process.stdout:
        # 한 줄씩 즉시 전송
        await ctx.send_progress(line)
    
    return "Complete"
```

**예상 효과:**
- ✅ 사용자가 결과를 즉시 볼 수 있음
- ✅ 긴 작업도 진행 상황 파악 가능

---

### 5️⃣ **비동기 최적화** - 기술 부채 해소 ⭐

#### 현재 문제
```python
# lib_tools.py - 동기 함수가 많음
def parse_binary_with_lief(file_path):  # sync!
    binary = lief.parse(file_path)
    # ...
```

**개선안:**
```python
# 모든 I/O 작업을 비동기로
async def parse_binary_with_lief(file_path):
    # I/O 바운드 작업은 스레드 풀에서 실행
    binary = await asyncio.to_thread(lief.parse, file_path)
    # ...
```

**예상 효과:**
- ✅ 여러 도구 동시 실행 시 블로킹 없음
- ✅ 전체 시스템 처리량 증가

---

### 6️⃣ **에러 처리 및 복원력** - 안정성 개선 ⭐⭐

#### 개선 제안

**6-A. 도구 실패 시 우아한 폴백**
```python
async def smart_decompile(file_path, function, ctx):
    try:
        # Ghidra 시도
        return await ghidra_decompile(file_path, function)
    except GhidraError as e:
        # 사용자에게 즉시 알림
        await ctx.warning(f"Ghidra failed: {e}, falling back to radare2")
        # Radare2로 폴백
        return await r2_decompile(file_path, function)
```

**6-B. 연결 풀 상태 모니터링**
```python
class R2ConnectionPool:
    async def health_check(self):
        """주기적으로 연결 상태 확인"""
        for file_path, r2 in self.pool.items():
            try:
                r2.cmd("?")  # 간단한 명령으로 확인
            except:
                # 연결 끊김 - 재연결
                self.pool[file_path] = r2pipe.open(file_path)
```

---

### 7️⃣ **리소스 관리 개선** - 메모리/디스크 최적화 ⭐

#### 개선점

**7-A. LRU 기반 연결 풀**
```python
from collections import OrderedDict

class LRUConnectionPool:
    """가장 오래 사용 안 된 연결 자동 종료"""
    def __init__(self, max_size=10):
        self.pool = OrderedDict()
        self.max_size = max_size
    
    def get(self, file_path):
        if len(self.pool) >= self.max_size:
            # 가장 오래된 연결 제거
            oldest_key = next(iter(self.pool))
            self.pool[oldest_key].quit()
            del self.pool[oldest_key]
        
        # 연결 재사용 또는 신규 생성
        ...
```

**7-B. 임시 파일 자동 정리 강화**
```python
# lifespan에서 이미 구현됨, 추가 개선:
- 분석 중 생성된 Ghidra 프로젝트 파일
- Radare2 캐시 파일 (.r2_*)
- 오래된 캐시 데이터 (7일 이상)
```

---

## 📊 개선 효과 예상

### 성능 개선
| 시나리오 | 현재 | 개선 후 | 개선율 |
|---------|------|--------|--------|
| Radare2 단일 명령 | 1.5초 | 0.3초 | **5배** |
| Ghidra 디컴파일 (첫 요청) | 8초 | 8초 | 동일 |
| Ghidra 디컴파일 (후속) | 8초 | 1초 | **8배** |
| 동일 파일 재분석 | 10초 | 0.1초 | **100배** |
| 워크스페이스 스캔 (100파일) | 120초 | 40초 | **3배** |

### 리소스 사용
- **메모리**: 중복 로드 제거로 **30~50% 감소**
- **CPU**: 프로세스 시작 오버헤드 제거로 **20~30% 감소**
- **디스크 I/O**: 캐싱으로 **50~70% 감소**

---

## 🗺️ 구현 우선순위

### Phase 1: 핵심 성능 개선 (1~2주)
1. ✅ Radare2 연결 풀 구현 (`r2pipe` 전환)
2. ✅ Ghidra JVM 재사용 구조
3. ✅ 기본 메타데이터 캐싱

**목표:** 사용자 체감 속도 **5배** 향상

### Phase 2: 고급 최적화 (2~3주)
4. ✅ 배치 처리 개선
5. ✅ 스트리밍 응답
6. ✅ 비동기 전환 완료

**목표:** 대규모 분석 처리량 **3배** 향상

### Phase 3: 안정성 및 확장성 (1~2주)
7. ✅ 에러 복원력 강화
8. ✅ 리소스 관리 자동화
9. ✅ 모니터링 대시보드

**목표:** 운영 안정성 확보

---

## 🔧 기술적 고려사항

### 호환성
- **FastMCP v2.13.1** - 최신 기능 활용
- **r2pipe 1.8+** - 연결 풀링 지원
- **PyGhidra 2.2+** - JVM 재사용 가능

### 위험 요소
- ⚠️ 연결 풀 구현 시 스레드 안전성 확보 필요
- ⚠️ 캐시 무효화 전략 명확히 (파일 수정 시)
- ⚠️ 메모리 누수 방지 (장시간 실행 시)

### 마이그레이션
- 기존 API 호환성 유지
- 점진적 전환 가능 (기능별 플래그)
- 철저한 테스트 필요

---

## 📈 성공 지표

### 정량적 지표
- [ ] Radare2 명령 평균 응답 시간 < 500ms
- [ ] Ghidra 후속 요청 응답 시간 < 2초
- [ ] 캐시 히트율 > 60%
- [ ] 메모리 사용량 < 2GB (100 파일 분석 시)

### 정성적 지표
- [ ] 사용자 피드백: "응답이 빨라졌다"
- [ ] 에러 발생률 감소
- [ ] 운영 부담 감소

---

## 🎯 결론

현재 Reversecore_MCP는 **기능적으로 완벽**하지만, **성능 최적화 여지**가 큽니다.

**가장 큰 문제:** 매 요청마다 도구를 새로 시작하는 구조  
**해결책:** 연결 풀과 캐싱으로 **5~100배** 성능 향상 가능

이 개선안을 단계적으로 적용하면:
- ✅ 사용자 경험 대폭 개선
- ✅ 서버 리소스 효율 증가
- ✅ 대규모 배포 준비 완료

---

**작성자 노트:** 이 개선안은 코드 추가 없이 순수 분석만을 담았습니다. 실제 구현 시 각 항목별로 상세 설계가 필요합니다.
