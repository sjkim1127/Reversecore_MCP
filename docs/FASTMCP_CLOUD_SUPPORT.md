# FastMCP Cloud 지원 리포트

**작성일**: 2025-11-13  
**버전**: 1.1  
**상태**: 분석 완료, 구현 대기

## 목차

1. [요약](#요약)
2. [FastMCP Cloud 개요](#fastmcp-cloud-개요)
3. [현재 아키텍처 분석](#현재-아키텍처-분석)
4. [호환성 문제 분석](#호환성-문제-분석)
5. [FastMCP Cloud 지원 요구사항](#fastmcp-cloud-지원-요구사항)
6. [구현 계획](#구현-계획)
7. [기술적 고려사항](#기술적-고려사항)
8. [보안 고려사항](#보안-고려사항)
9. [대안 및 권장사항](#대안-및-권장사항)
10. [결론](#결론)

---

## 요약

### 핵심 발견사항

**Reversecore_MCP는 현재 로컬 파일 시스템 기반 아키텍처로 설계되어 있어 FastMCP Cloud와 직접 호환되지 않습니다.**

주요 제약사항:
- ✅ **로컬 서버**: 로컬 파일 직접 접근 가능
- ❌ **FastMCP Cloud**: 클라우드 서버에서 로컬 파일 접근 불가

### 권장사항

1. **단기**: 로컬 서버 사용 유지 (현재 방식)
2. **중기**: 파일 업로드 기능 추가 검토
3. **장기**: 하이브리드 모드 지원 (로컬 + 클라우드)

---

## FastMCP Cloud 개요

### 정의

FastMCP Cloud는 FastMCP 팀이 개발한 **관리형 MCP 서버 배포 플랫폼**으로, GitHub 저장소를 연결하여 MCP 서버를 클라우드 환경에 자동 배포하는 서비스입니다.

### 주요 기능

#### 1. 제로 구성 배포
- GitHub 저장소 연결만으로 MCP 서버 배포
- 복잡한 설정 파일 불필요
- 템플릿 기반 빠른 시작

#### 2. 서버리스 확장성
- 요청 수에 따른 자동 확장
- 사용량 기반 과금 (Pay-as-you-go)
- 콜드 스타트 시간 < 1초

#### 3. 내장 OAuth 및 보안
- 기본 OAuth 인증 제공
- 별도 인증 흐름 구현 불필요
- 기존 ID 제공자 통합 지원

#### 4. Git 기반 CI/CD
- 커밋 푸시 시 자동 빌드
- PR 생성 시 브랜치 배포
- 버전 관리 및 롤백 지원

#### 5. MCP 네이티브 분석
- 요청/응답 쌍 추적
- 도구 사용량 모니터링
- 사용자 행동 분석

#### 6. 엔터프라이즈 기능
- SSO (Single Sign-On)
- SCIM 및 디렉토리 동기화
- 역할 기반 권한 제어 (RBAC)
- 감사 추적

### 요금제

| 플랜 | 가격 | 특징 |
|------|------|------|
| **Hobby** | 무료 | 개인용, 100만 요청/월 |
| **Pro** | $20/월 | 고급 분석, 더 많은 사용량, Slack 지원 |
| **Enterprise** | 문의 | RBAC, MCP 거버넌스, 자체 컴퓨팅 리소스 |

### 사용 사례

FastMCP Cloud는 다음 시나리오에 적합합니다:
- ✅ 팀 공유 MCP 서버
- ✅ 프로덕션 환경 배포
- ✅ 높은 가용성 요구사항
- ✅ 자동 확장 필요
- ✅ 중앙 집중식 관리

---

## 현재 아키텍처 분석

### 파일 접근 모델

Reversecore_MCP는 **로컬 파일 시스템 기반**으로 설계되었습니다:

```python
# reversecore_mcp/core/security.py
def validate_file_path(path: str, read_only: bool = False) -> str:
    """
    파일 경로 검증:
    1. 절대 경로로 변환
    2. 워크스페이스 디렉토리 내 파일만 허용
    3. 로컬 파일 시스템 경로만 지원
    """
    abs_path = file_path.resolve(strict=True)  # 로컬 파일 시스템 경로
    workspace_path = _get_allowed_workspace()  # REVERSECORE_WORKSPACE 환경변수
    
    # 워크스페이스 내 파일인지 확인
    if not is_path_in_directory(abs_path_str, workspace_path_str):
        raise ValidationError("File path is outside allowed directories")
```

### 워크스페이스 제약

```python
# reversecore_mcp/core/config.py
reversecore_workspace: Path = Field(
    default=Path("/app/workspace"),
    description="Allowed workspace directory for file operations",
    alias="REVERSECORE_WORKSPACE",
)
```

**특징**:
- 로컬 파일 시스템 경로만 허용
- Docker 볼륨 마운트 방식 (`-v ./samples:/app/workspace`)
- 네트워크를 통한 파일 전송 미지원
- 클라우드 스토리지 통합 없음

### 보안 모델

```python
# 보안 검증 로직
1. 경로 정규화 (symlink 제거)
2. 워크스페이스 경계 검사
3. 파일 존재 확인
4. 읽기 전용 디렉토리 지원 (YARA rules)
```

**제약사항**:
- 로컬 경로 검증에 최적화
- 클라우드 환경의 파일 접근 패턴 미지원

---

## 호환성 문제 분석

### 구조적 제약

```
┌─────────────────────────────────────────────────────────┐
│                    FastMCP Cloud                        │
│  ┌──────────────────────────────────────────────────┐  │
│  │  클라우드 서버 (AWS/GCP/Azure)                   │  │
│  │  - 독립적인 파일 시스템                          │  │
│  │  - 로컬 파일 시스템 접근 불가 ❌                  │  │
│  └──────────────────────────────────────────────────┘  │
└─────────────────────────────────────────────────────────┘
                          ↕
                    MCP Protocol
                          ↕
┌─────────────────────────────────────────────────────────┐
│              사용자 로컬 환경 (Windows)                  │
│  E:\Reversecore_Workspace\EverPlanet_KR_v1842_U_DEVM.exe│
│  - 로컬 파일 시스템                                     │
│  - 클라우드 서버에서 접근 불가 ❌                       │
└─────────────────────────────────────────────────────────┘
```

### 문제점 상세 분석

#### 1. 파일 경로 접근 불가

**현재 방식**:
```python
# 로컬 서버에서 실행
file_path = "E:\Reversecore_Workspace\sample.exe"
validate_file_path(file_path)  # ✅ 성공: 로컬 파일 접근 가능
```

**FastMCP Cloud에서 실행**:
```python
# 클라우드 서버에서 실행
file_path = "E:\Reversecore_Workspace\sample.exe"
validate_file_path(file_path)  # ❌ 실패: 클라우드 서버에 해당 경로 없음
```

#### 2. 워크스페이스 제약

**로컬 서버**:
```bash
# Docker 볼륨 마운트
docker run -v ./samples:/app/workspace reversecore-mcp
# 로컬 파일 → 컨테이너 내부 접근 가능
```

**FastMCP Cloud**:
```bash
# 클라우드 서버는 독립적인 파일 시스템
# 로컬 파일을 마운트할 수 없음
# 파일을 클라우드로 전송해야 함
```

#### 3. 보안 검증 로직

**현재 검증**:
- 로컬 경로 기반 검증
- `os.path.commonpath()` 사용
- 절대 경로 해석

**클라우드 환경 요구사항**:
- 클라우드 스토리지 경로 지원
- 업로드된 파일 식별자 기반 접근
- 임시 파일 관리

### 호환성 매트릭스

| 기능 | 로컬 서버 | FastMCP Cloud | 호환성 |
|------|----------|---------------|--------|
| 로컬 파일 접근 | ✅ | ❌ | **불가** |
| Docker 볼륨 마운트 | ✅ | ❌ | **불가** |
| 네트워크 파일 전송 | ❌ | ✅ | **필요** |
| 클라우드 스토리지 | ❌ | ✅ | **필요** |
| 경로 검증 | 로컬 경로 | 클라우드 경로 | **수정 필요** |
| 파일 업로드 | ❌ | ✅ | **필요** |

---

## FastMCP Cloud 지원 요구사항

### 기능 요구사항

#### 1. 파일 업로드 기능

**필수 기능**:
- Base64 인코딩 파일 업로드
- 멀티파트 파일 업로드
- 임시 스토리지 관리
- 파일 크기 제한 (기존 LIEF 제한: 1GB)

**제안 API**:
```python
@mcp.tool()
def upload_file(
    file_name: str,
    file_content: str,  # Base64 encoded
    file_size: int,
) -> str:
    """
    Upload a file to the cloud server for analysis.
    
    Returns:
        File identifier (UUID) for use in other tools
    """
    pass
```

**AI 에이전트 파일 업로드 메커니즘**:

AI 에이전트는 직접 파일 시스템에 접근할 수 없으므로, 다음과 같은 워크플로우가 필요합니다:

**옵션 A: MCP 클라이언트가 파일 읽기 (권장)**
```
사용자 → "이 파일을 분석해줘" (파일 경로 제공)
  ↓
AI 에이전트 → MCP 클라이언트에 파일 읽기 요청
  ↓
MCP 클라이언트 (Cursor/Claude Desktop) → 파일 읽기 및 Base64 인코딩
  ↓
AI 에이전트 → upload_file(file_name, file_content, file_size) 호출
  ↓
FastMCP Cloud → 파일 저장 및 file_id 반환
  ↓
AI 에이전트 → file_id를 사용하여 분석 도구 호출
```

**옵션 B: 사용자가 파일 내용 직접 제공**
```
사용자 → 파일을 Base64로 인코딩하여 제공
  ↓
AI 에이전트 → upload_file(file_name, file_content, file_size) 호출
  ↓
FastMCP Cloud → 파일 저장 및 file_id 반환
```

**옵션 C: 파일 URL 제공 (향후 지원)**
```
사용자 → 파일 URL 제공 (예: https://example.com/sample.exe)
  ↓
AI 에이전트 → download_and_upload(url) 도구 호출
  ↓
FastMCP Cloud → 파일 다운로드, 저장, file_id 반환
```

**현실적인 제약사항**:
- ❌ AI 에이전트는 로컬 파일 시스템에 직접 접근 불가 (보안상)
- ✅ MCP 클라이언트가 파일을 읽어서 전달해야 함
- ✅ 또는 사용자가 파일 내용을 직접 제공해야 함
- ⚠️ 대용량 파일의 경우 Base64 인코딩 오버헤드 고려 필요

**MCP 클라이언트 지원 필요**:
현재 MCP 프로토콜에는 파일 읽기 기능이 표준화되어 있지 않습니다. 따라서:
1. **Cursor/Claude Desktop 확장**: 파일 읽기 기능 추가 필요
2. **임시 해결책**: 사용자가 파일을 Base64로 인코딩하여 제공
3. **향후 개선**: MCP 프로토콜에 파일 읽기 표준 추가

#### 2. 파일 식별자 기반 접근

**변경 필요**:
- 파일 경로 대신 파일 ID 사용
- 임시 스토리지에서 파일 조회
- 파일 수명 주기 관리 (TTL)

**제안 구조**:
```python
# 기존
def run_file(file_path: str) -> str:
    validated_path = validate_file_path(file_path)
    # ...

# 변경 후
def run_file(file_path: str = None, file_id: str = None) -> str:
    if file_id:
        file_path = get_file_from_storage(file_id)
    else:
        file_path = validate_file_path(file_path)
    # ...
```

#### 3. 클라우드 스토리지 통합

**옵션 1: 임시 파일 시스템**
- 업로드된 파일을 임시 디렉토리에 저장
- TTL 기반 자동 삭제
- 메모리 기반 스토리지 (Redis) 고려

**옵션 2: 클라우드 스토리지 서비스**
- AWS S3, GCS, Azure Blob Storage
- 파일 URL 기반 접근
- 외부 의존성 증가

**옵션 3: 하이브리드**
- 작은 파일: 임시 파일 시스템
- 큰 파일: 클라우드 스토리지

#### 4. 경로 검증 로직 수정

**현재**:
```python
def validate_file_path(path: str) -> str:
    abs_path = Path(path).resolve(strict=True)
    # 로컬 경로 검증
```

**변경 후**:
```python
def validate_file_path(path: str, cloud_mode: bool = False) -> str:
    if cloud_mode:
        # 클라우드 모드: 파일 ID 또는 클라우드 경로 검증
        return validate_cloud_path(path)
    else:
        # 로컬 모드: 기존 로직
        return validate_local_path(path)
```

### 비기능 요구사항

#### 1. 성능
- 파일 업로드 시간 최소화
- 대용량 파일 스트리밍 지원
- 임시 파일 정리 오버헤드 최소화

#### 2. 보안
- 업로드 파일 검증 (바이러스 스캔)
- 파일 크기 제한
- TTL 기반 자동 삭제
- 접근 권한 제어

#### 3. 확장성
- 동시 업로드 처리
- 스토리지 용량 관리
- 파일 수명 주기 관리

---

## 구현 계획

### Phase 1: 파일 업로드 기능 추가 (필수)

**목표**: 기본 파일 업로드 및 임시 스토리지 구현

**작업 항목**:
1. 파일 업로드 도구 추가 (`upload_file`)
2. 임시 스토리지 모듈 구현 (`reversecore_mcp/core/storage.py`)
3. 파일 ID 생성 및 관리 (UUID)
4. TTL 기반 자동 삭제

**예상 작업량**: 2-3일

**파일 구조**:
```
reversecore_mcp/
├── core/
│   ├── storage.py          # 새로 추가: 임시 스토리지 관리
│   └── security.py         # 수정: 클라우드 경로 검증 추가
├── tools/
│   └── file_tools.py       # 새로 추가: 파일 업로드 도구
```

### Phase 2: 도구 함수 수정 (필수)

**목표**: 모든 도구 함수가 파일 ID 지원

**작업 항목**:
1. `run_file`: 파일 ID 지원 추가
2. `run_strings`: 파일 ID 지원 추가
3. `run_radare2`: 파일 ID 지원 추가
4. `run_binwalk`: 파일 ID 지원 추가
5. `run_yara`: 파일 ID 지원 추가
6. `disassemble_with_capstone`: 파일 ID 지원 추가
7. `parse_binary_with_lief`: 파일 ID 지원 추가

**예상 작업량**: 3-4일

**변경 패턴**:
```python
# Before
@log_execution(tool_name="run_file")
def run_file(file_path: str, timeout: int = 30) -> str:
    validated_path = validate_file_path(file_path)
    # ...

# After
@log_execution(tool_name="run_file")
def run_file(
    file_path: str = None,
    file_id: str = None,
    timeout: int = 30
) -> str:
    if file_id:
        file_path = get_file_from_storage(file_id)
    elif file_path:
        file_path = validate_file_path(file_path, cloud_mode=False)
    else:
        raise ValueError("Either file_path or file_id must be provided")
    # ...
```

### Phase 3: 설정 및 환경 감지 (선택)

**목표**: 로컬/클라우드 모드 자동 감지

**작업 항목**:
1. 환경 변수 추가 (`CLOUD_MODE`, `STORAGE_TYPE`)
2. 모드별 경로 검증 로직 분리
3. 설정 관리 업데이트

**예상 작업량**: 1일

### Phase 4: 테스트 및 문서화 (필수)

**목표**: FastMCP Cloud 배포 가이드 작성

**작업 항목**:
1. 파일 업로드 기능 테스트
2. 클라우드 모드 통합 테스트
3. FastMCP Cloud 배포 가이드 작성
4. README 업데이트

**예상 작업량**: 2일

### 전체 예상 작업량

| Phase | 작업량 | 우선순위 |
|-------|--------|----------|
| Phase 1 | 2-3일 | 높음 |
| Phase 2 | 3-4일 | 높음 |
| Phase 3 | 1일 | 중간 |
| Phase 4 | 2일 | 높음 |
| **총계** | **8-10일** | - |

---

## 기술적 고려사항

### 1. 임시 스토리지 구현

#### 옵션 A: 파일 시스템 기반

**장점**:
- 구현 간단
- 외부 의존성 없음
- 디버깅 용이

**단점**:
- 디스크 I/O 오버헤드
- 확장성 제한
- 서버 재시작 시 데이터 손실

**구현 예시**:
```python
# reversecore_mcp/core/storage.py
import tempfile
import uuid
from pathlib import Path
from datetime import datetime, timedelta

class FileStorage:
    def __init__(self, base_dir: Path = None, ttl_hours: int = 24):
        self.base_dir = base_dir or Path(tempfile.gettempdir()) / "reversecore_uploads"
        self.base_dir.mkdir(parents=True, exist_ok=True)
        self.ttl_hours = ttl_hours
        self.files = {}  # file_id -> (path, uploaded_at)
    
    def store_file(self, file_content: bytes, file_name: str) -> str:
        file_id = str(uuid.uuid4())
        file_path = self.base_dir / file_id
        file_path.write_bytes(file_content)
        self.files[file_id] = (file_path, datetime.now())
        return file_id
    
    def get_file_path(self, file_id: str) -> Path:
        if file_id not in self.files:
            raise ValueError(f"File not found: {file_id}")
        file_path, uploaded_at = self.files[file_id]
        if datetime.now() - uploaded_at > timedelta(hours=self.ttl_hours):
            self.delete_file(file_id)
            raise ValueError(f"File expired: {file_id}")
        return file_path
    
    def delete_file(self, file_id: str):
        if file_id in self.files:
            file_path, _ = self.files[file_id]
            file_path.unlink(missing_ok=True)
            del self.files[file_id]
    
    def cleanup_expired(self):
        now = datetime.now()
        expired = [
            file_id for file_id, (_, uploaded_at) in self.files.items()
            if now - uploaded_at > timedelta(hours=self.ttl_hours)
        ]
        for file_id in expired:
            self.delete_file(file_id)
```

#### 옵션 B: 메모리 기반 (Redis)

**장점**:
- 빠른 접근 속도
- 자동 TTL 지원
- 확장성 우수

**단점**:
- 외부 의존성 (Redis)
- 메모리 제한
- 대용량 파일 부적합

**구현 예시**:
```python
import redis
import uuid

class RedisFileStorage:
    def __init__(self, redis_url: str = "redis://localhost:6379", ttl_seconds: int = 86400):
        self.redis = redis.from_url(redis_url)
        self.ttl_seconds = ttl_seconds
    
    def store_file(self, file_content: bytes, file_name: str) -> str:
        file_id = str(uuid.uuid4())
        self.redis.setex(
            f"file:{file_id}",
            self.ttl_seconds,
            file_content
        )
        self.redis.setex(
            f"meta:{file_id}",
            self.ttl_seconds,
            file_name
        )
        return file_id
    
    def get_file_content(self, file_id: str) -> bytes:
        content = self.redis.get(f"file:{file_id}")
        if not content:
            raise ValueError(f"File not found: {file_id}")
        return content
```

#### 권장사항

**초기 구현**: 파일 시스템 기반 (옵션 A)
- 구현 간단
- 외부 의존성 없음
- FastMCP Cloud 환경에서도 작동

**향후 개선**: 하이브리드 접근
- 작은 파일 (< 10MB): 메모리 기반
- 큰 파일 (≥ 10MB): 파일 시스템 기반

### 2. 파일 업로드 방식

#### Base64 인코딩

**장점**:
- MCP 프로토콜과 호환
- JSON으로 전송 가능
- 구현 간단

**단점**:
- 33% 오버헤드 (인코딩)
- 대용량 파일 부적합

**사용 사례**: 작은 파일 (< 10MB)

#### 멀티파트 업로드

**장점**:
- 대용량 파일 지원
- 스트리밍 가능
- 효율적

**단점**:
- MCP 프로토콜 확장 필요
- 구현 복잡

**사용 사례**: 큰 파일 (≥ 10MB)

#### 권장사항

**초기 구현**: Base64 인코딩
- MCP 프로토콜 호환
- 빠른 구현

**향후 개선**: 멀티파트 업로드
- 대용량 파일 지원
- 성능 최적화

### 3. 파일 크기 제한

**현재 제한**:
- LIEF: 1GB
- 일반 도구: 출력 크기 제한 (10MB)

**클라우드 환경 고려사항**:
- 업로드 시간
- 스토리지 용량
- 메모리 사용량

**제안 제한**:
- 기본 업로드: 100MB
- 설정 가능: `MAX_UPLOAD_SIZE` 환경 변수
- LIEF 분석: 기존 1GB 유지

### 4. 파일 수명 주기 관리

**TTL (Time To Live)**:
- 기본: 24시간
- 설정 가능: `FILE_TTL_HOURS` 환경 변수
- 자동 정리: 백그라운드 작업

**정리 전략**:
- 주기적 정리 (cron job)
- 접근 시 TTL 확인
- 서버 종료 시 정리

---

## 보안 고려사항

### 1. 파일 업로드 검증

**필수 검증**:
- 파일 크기 제한
- 파일 타입 검증 (헤더 기반)
- 악성 파일 스캔 (선택)

**구현 예시**:
```python
def validate_uploaded_file(file_content: bytes, file_name: str):
    # 크기 검증
    max_size = get_settings().max_upload_size
    if len(file_content) > max_size:
        raise ValidationError(f"File too large: {len(file_content)} > {max_size}")
    
    # 파일 타입 검증 (매직 넘버)
    if not is_valid_binary_file(file_content):
        raise ValidationError("Invalid file type")
    
    # 파일명 검증
    if contains_path_traversal(file_name):
        raise ValidationError("Invalid file name")
```

### 2. 접근 제어

**파일 ID 기반 접근**:
- UUID 사용 (예측 불가능)
- 세션 기반 접근 제어 (선택)
- 사용자별 파일 격리 (선택)

### 3. 데이터 보호

**임시 파일 보호**:
- 적절한 파일 권한 (600)
- 암호화 저장 (선택)
- 안전한 삭제

### 4. 로깅 및 감사

**기록 항목**:
- 파일 업로드 이벤트
- 파일 접근 이벤트
- 파일 삭제 이벤트
- 오류 이벤트

**민감 정보 제외**:
- 파일 내용 로깅 금지
- 파일 경로 해시 처리

---

## 대안 및 권장사항

### 옵션 1: 로컬 서버 유지 (현재 방식) ⭐ 권장

**장점**:
- ✅ 로컬 파일 직접 접근
- ✅ 보안 제어 용이
- ✅ 오프라인 사용 가능
- ✅ 추가 개발 불필요

**단점**:
- ❌ 팀 공유 어려움
- ❌ 자동 확장 불가
- ❌ 중앙 집중식 관리 불가

**사용 사례**:
- 개인 개발 환경
- 로컬 파일 분석
- 오프라인 환경

### 옵션 2: FastMCP Cloud 지원 추가

**장점**:
- ✅ 팀 공유 가능
- ✅ 자동 확장
- ✅ 중앙 집중식 관리
- ✅ 높은 가용성

**단점**:
- ❌ 파일 업로드 필요
- ❌ 추가 개발 필요 (8-10일)
- ❌ 스토리지 관리 필요
- ❌ 보안 고려사항 증가

**사용 사례**:
- 팀 협업
- 프로덕션 환경
- 높은 가용성 요구

### 옵션 3: 하이브리드 모드

**구현**:
- 로컬 모드: 기존 방식 유지
- 클라우드 모드: 파일 업로드 지원
- 자동 감지: 환경 변수 기반

**장점**:
- ✅ 두 모드 모두 지원
- ✅ 사용자 선택 가능
- ✅ 점진적 마이그레이션

**단점**:
- ❌ 코드 복잡도 증가
- ❌ 테스트 범위 확대

### 권장사항

**단기 (현재)**:
- 로컬 서버 사용 유지
- FastMCP Cloud 지원은 선택 사항

**중기 (3-6개월)**:
- 파일 업로드 기능 추가 검토
- 사용자 요구사항 조사

**장기 (6개월 이상)**:
- 하이브리드 모드 구현
- FastMCP Cloud 공식 지원

---

## 결론

### 핵심 요약

1. **구조적 제약**: Reversecore_MCP는 로컬 파일 시스템 기반으로 설계되어 FastMCP Cloud와 직접 호환되지 않음

2. **AI 에이전트 제약**: AI 에이전트는 파일 시스템에 직접 접근할 수 없으므로, 파일 업로드를 위해서는:
   - MCP 클라이언트(Cursor/Claude Desktop)의 파일 읽기 기능 필요
   - 또는 사용자가 파일을 Base64로 인코딩하여 제공
   - 현재 MCP 프로토콜에는 파일 읽기 표준이 없음

3. **지원 가능성**: 파일 업로드 기능 추가 시 FastMCP Cloud 지원 가능 (예상 작업량: 8-10일)
   - 단, MCP 클라이언트의 파일 읽기 기능 지원이 선행되어야 함

4. **권장사항**: 현재는 로컬 서버 사용 유지, 향후 사용자 요구사항에 따라 FastMCP Cloud 지원 검토

### 실제 사용 시나리오 비교

#### 시나리오 1: 로컬 서버 (현재 방식) ✅

```
사용자: "E:\Reversecore_Workspace\sample.exe 파일을 분석해줘"
  ↓
AI 에이전트: run_file(file_path="E:\Reversecore_Workspace\sample.exe") 호출
  ↓
로컬 서버: 파일 직접 접근 → 분석 결과 반환
```

**장점**: 간단하고 직관적, 즉시 사용 가능

#### 시나리오 2: FastMCP Cloud (제안 방식) ⚠️

**현재 상태 (미지원)**:
```
사용자: "E:\Reversecore_Workspace\sample.exe 파일을 분석해줘"
  ↓
AI 에이전트: 파일 경로만 받음 → 클라우드 서버에서 접근 불가 ❌
```

**지원 시 (가정)**:
```
사용자: "이 파일을 분석해줘" (파일 경로 또는 파일 드래그 앤 드롭)
  ↓
MCP 클라이언트: 파일 읽기 및 Base64 인코딩
  ↓
AI 에이전트: upload_file(file_name, file_content, file_size) 호출
  ↓
FastMCP Cloud: 파일 저장 → file_id 반환
  ↓
AI 에이전트: run_file(file_id=file_id) 호출
  ↓
FastMCP Cloud: 파일 분석 → 결과 반환
```

**필수 조건**:
- MCP 클라이언트의 파일 읽기 기능 지원
- 또는 사용자가 파일을 Base64로 직접 제공

### 다음 단계

1. **즉시**: 로컬 서버 사용 가이드 강화
2. **단기**: 
   - MCP 클라이언트 개발팀과 파일 읽기 기능 협의
   - 사용자 피드백 수집 (FastMCP Cloud 지원 필요성)
3. **중기**: 
   - 파일 업로드 기능 프로토타입 개발
   - MCP 클라이언트 파일 읽기 기능 지원 확인
4. **장기**: 
   - 하이브리드 모드 구현
   - FastMCP Cloud 공식 지원

### 참고 자료

- [FastMCP Cloud 공식 문서](https://fastmcp.cloud)
- [FastMCP GitHub 저장소](https://github.com/jlowin/fastmcp)
- [MCP 프로토콜 사양](https://modelcontextprotocol.io)

---

**문서 버전**: 1.1  
**최종 업데이트**: 2025-11-13  
**작성자**: Reversecore_MCP 개발팀

### 변경 이력

- **v1.1 (2025-11-13)**: AI 에이전트 파일 업로드 메커니즘 섹션 추가, 실제 사용 시나리오 비교 추가
- **v1.0 (2025-11-13)**: 초기 리포트 작성

