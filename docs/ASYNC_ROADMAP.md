# Async Execution Roadmap

## Overview

This document outlines the roadmap for implementing asynchronous subprocess execution in Reversecore_MCP. Async execution will enable better concurrency, improved resource utilization, and enhanced scalability, particularly in HTTP mode.

## Current State (v1.x)

### Synchronous Execution

Currently, all subprocess operations use synchronous execution via `execute_subprocess_streaming()`:

```python
from reversecore_mcp.core.execution import execute_subprocess_streaming

# Synchronous call - blocks until complete
output, bytes_read = execute_subprocess_streaming(
    cmd=["strings", "-n", "4", "/path/to/binary"],
    max_output_size=10_000_000,
    timeout=300
)
```

**Characteristics:**
- Simple and reliable
- Easy to reason about
- Single request processed at a time
- Blocks the event loop in HTTP mode

**Limitations:**
- Cannot process multiple requests concurrently
- Inefficient resource utilization
- Poor scalability for high-traffic deployments
- MCP server must wait for long-running operations

## Future State (v2.0+)

### Asynchronous Execution

The `execute_subprocess_async()` function will provide non-blocking execution:

```python
from reversecore_mcp.core.async_execution import execute_subprocess_async

# Async call - allows concurrent execution
output, exit_code = await execute_subprocess_async(
    cmd=["strings", "-n", "4", "/path/to/binary"],
    max_output_size=10_000_000,
    timeout=300
)
```

## Implementation Plan

### Phase 1: Core Async Infrastructure (Q1 2024)

**Goal:** Implement basic async subprocess execution

Tasks:
- [ ] Implement `execute_subprocess_async()` using `asyncio.create_subprocess_exec()`
- [ ] Add async streaming output handling
- [ ] Implement timeout handling with `asyncio.wait_for()`
- [ ] Add output size limiting for async operations
- [ ] Write comprehensive unit tests
- [ ] Benchmark performance vs. sync version

**Success Criteria:**
- Async execution matches sync behavior
- No regressions in functionality
- Test coverage > 90%
- Performance equals or exceeds sync version

### Phase 2: Tool Function Migration (Q2 2024)

**Goal:** Convert tool functions to async/await pattern

Tasks:
- [ ] Create async versions of tool functions:
  - `async def run_strings_async()`
  - `async def run_radare2_async()`
  - `async def run_binwalk_async()`
- [ ] Add async decorators for logging and metrics:
  - `@async_log_execution`
  - `@async_track_metrics`
- [ ] Update MCP server to handle both sync and async tools
- [ ] Maintain backward compatibility with sync versions

**Example:**
```python
@async_log_execution(tool_name="run_strings")
@async_track_metrics("run_strings")
async def run_strings_async(
    file_path: str,
    min_length: int = 4,
    max_output_size: int = 10_000_000,
    timeout: int = 300,
) -> str:
    validated_path = validate_file_path(file_path)
    cmd = ["strings", "-n", str(min_length), validated_path]
    
    output, bytes_read = await execute_subprocess_async(
        cmd, max_output_size=max_output_size, timeout=timeout
    )
    
    return output
```

### Phase 3: HTTP Mode Optimization (Q3 2024)

**Goal:** Optimize async execution for HTTP/SSE transport

Tasks:
- [ ] Implement connection pooling for HTTP mode
- [ ] Add request queuing and prioritization
- [ ] Implement concurrent request limiting
- [ ] Add server-sent events (SSE) for progress updates
- [ ] Load testing and optimization
- [ ] Add async-specific metrics

**Concurrency Control:**
```python
import asyncio
from fastmcp import FastMCP

mcp = FastMCP(
    name="reversecore_mcp",
    max_concurrent_requests=10,  # Limit concurrent operations
    request_queue_size=100,      # Queue size for pending requests
)

# Semaphore for resource control
subprocess_semaphore = asyncio.Semaphore(5)  # Max 5 concurrent subprocesses

async def run_with_semaphore(cmd, **kwargs):
    async with subprocess_semaphore:
        return await execute_subprocess_async(cmd, **kwargs)
```

### Phase 4: Advanced Features (Q4 2024)

**Goal:** Add advanced async capabilities

Tasks:
- [ ] Streaming progress updates for long operations
- [ ] Cancellation support for in-progress operations
- [ ] Batch processing with `asyncio.gather()`
- [ ] Priority queues for urgent requests
- [ ] Resource-aware scheduling
- [ ] Auto-scaling based on load

**Progress Streaming:**
```python
async def run_yara_with_progress(
    file_path: str,
    rule_file: str,
    progress_callback=None
) -> str:
    # Stream progress updates
    async for progress in yara_scan_async(file_path, rule_file):
        if progress_callback:
            await progress_callback(progress)
    
    return results
```

## Benefits of Async Execution

### 1. Improved Concurrency

**Before (Sync):**
```
Request 1: [====================] 10s
Request 2:                       [====================] 10s
Request 3:                                            [====================] 10s
Total time: 30s for 3 requests
```

**After (Async):**
```
Request 1: [====================] 10s
Request 2: [====================] 10s
Request 3: [====================] 10s
Total time: 10s for 3 requests (concurrent execution)
```

### 2. Better Resource Utilization

- CPU: Process multiple I/O-bound operations while waiting
- Memory: Efficient handling of multiple connections
- Network: Concurrent HTTP requests without blocking

### 3. Enhanced Scalability

- Handle more concurrent users
- Better response times under load
- Reduced server infrastructure costs

## Migration Strategy

### Gradual Rollout

1. **v1.x (Current):** Sync-only execution
2. **v2.0:** Async implementation with feature flag
3. **v2.1:** Enable async by default for HTTP mode
4. **v2.2:** Deprecate sync versions
5. **v3.0:** Async-only (remove sync code)

### Feature Flag

```python
# Configuration option for v2.0
ENABLE_ASYNC_EXECUTION = os.getenv("ENABLE_ASYNC_EXECUTION", "false").lower() == "true"

if ENABLE_ASYNC_EXECUTION:
    from reversecore_mcp.core.async_execution import execute_subprocess_async
else:
    from reversecore_mcp.core.execution import execute_subprocess_streaming as execute_subprocess_async
```

### Backward Compatibility

Maintain sync versions for:
- STDIO transport (naturally synchronous)
- Legacy integrations
- Simple use cases
- Testing and debugging

## Testing Strategy

### Unit Tests

```python
import pytest
import asyncio

@pytest.mark.asyncio
async def test_execute_subprocess_async_success():
    output, exit_code = await execute_subprocess_async(
        cmd=["echo", "hello"],
        timeout=10
    )
    assert output.strip() == "hello"
    assert exit_code == 0

@pytest.mark.asyncio
async def test_execute_subprocess_async_timeout():
    with pytest.raises(asyncio.TimeoutError):
        await execute_subprocess_async(
            cmd=["sleep", "10"],
            timeout=1
        )
```

### Integration Tests

```python
@pytest.mark.asyncio
async def test_concurrent_tool_execution():
    # Run multiple tools concurrently
    results = await asyncio.gather(
        run_strings_async("/path/to/file1"),
        run_strings_async("/path/to/file2"),
        run_radare2_async("/path/to/file3", "afl"),
    )
    
    assert len(results) == 3
    assert all(r is not None for r in results)
```

### Load Tests

```python
import asyncio
import time

async def load_test_async():
    """Test 100 concurrent requests."""
    start = time.time()
    
    tasks = [
        run_strings_async("/path/to/binary")
        for _ in range(100)
    ]
    
    results = await asyncio.gather(*tasks)
    
    duration = time.time() - start
    print(f"Completed 100 requests in {duration:.2f}s")
    print(f"Average: {duration/100:.3f}s per request")
```

## Performance Targets

### Response Time (P95)

- **Sync (current):** 2000ms under load
- **Async (target):** 500ms under load

### Throughput

- **Sync (current):** 10 requests/second
- **Async (target):** 100+ requests/second

### Resource Usage

- **Memory:** <2x increase vs sync
- **CPU:** Better utilization, <1.5x under load

## Risk Mitigation

### Potential Issues

1. **Complexity:** Async code is harder to debug
   - **Mitigation:** Comprehensive logging, better error handling

2. **Compatibility:** Breaking changes for users
   - **Mitigation:** Feature flags, gradual rollout, documentation

3. **Bugs:** Race conditions, deadlocks
   - **Mitigation:** Extensive testing, code review, async best practices

4. **Performance:** Async overhead may hurt simple cases
   - **Mitigation:** Benchmarking, keep sync versions for simple use cases

## Timeline

```
Q1 2024: Phase 1 - Core Async Infrastructure
Q2 2024: Phase 2 - Tool Function Migration
Q3 2024: Phase 3 - HTTP Mode Optimization
Q4 2024: Phase 4 - Advanced Features
Q1 2025: v3.0 - Async-only release
```

## Contributing

Interested in helping implement async execution?

1. Review this roadmap
2. Check GitHub issues tagged with `async-execution`
3. Join discussions in pull requests
4. Submit PRs following the implementation plan

## References

- [Python asyncio documentation](https://docs.python.org/3/library/asyncio.html)
- [FastMCP async support](https://github.com/jlowin/fastmcp)
- [METRICS.md](./METRICS.md) - Metrics collection for async operations

## Questions?

Open an issue on GitHub with the `async-execution` label for questions or suggestions.
