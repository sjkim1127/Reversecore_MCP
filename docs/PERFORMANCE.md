# Performance Optimization Guide

This document outlines the performance optimizations implemented in Reversecore_MCP and provides guidelines for maintaining and improving performance.

## Table of Contents

1. [Overview](#overview)
2. [Implemented Optimizations](#implemented-optimizations)
3. [Performance Best Practices](#performance-best-practices)
4. [Benchmarking](#benchmarking)
5. [Future Improvements](#future-improvements)

## Overview

Reversecore_MCP is designed to handle large binary files and complex analysis tasks efficiently. Performance is critical for providing responsive AI-powered reverse engineering capabilities.

### Key Performance Metrics

- **JSON Processing**: 3-5x faster with orjson
- **File I/O**: Optimized with buffered reading (8KB buffer)
- **Async Operations**: Non-blocking subprocess execution
- **Regex Patterns**: Pre-compiled for hot paths
- **Resource Management**: Efficient cleanup with itertools.chain

## Implemented Optimizations

### 1. JSON Performance (High Impact)

**Problem**: Standard `json` module is slow for large payloads common in binary analysis.

**Solution**: Use `json_utils` module with orjson fallback.

```python
# ✅ Good - Fast JSON processing
from reversecore_mcp.core import json_utils as json
data = json.loads(large_json_string)  # 3-5x faster

# ❌ Bad - Slow standard library
import json
data = json.loads(large_json_string)
```

**Files Updated**:
- `reversecore_mcp/tools/report_tools.py`
- `reversecore_mcp/tools/report_mcp_tools.py`

**Impact**: 3-5x faster JSON parsing and serialization, especially important for:
- Report generation with large metadata
- IOC extraction results
- Analysis session data

### 2. Async Subprocess Execution (Medium Impact)

**Problem**: Synchronous `subprocess.run()` blocks the event loop, preventing concurrent operations.

**Solution**: Use `execute_subprocess_async()` for all subprocess calls.

```python
# ✅ Good - Non-blocking execution
await execute_subprocess_async(
    ["dot", "-Tpng", input_file, "-o", output_file],
    max_output_size=1_000_000,
    timeout=30,
)

# ❌ Bad - Blocks event loop
subprocess.run(
    ["dot", "-Tpng", input_file, "-o", output_file],
    check=True,
    timeout=30,
)
```

**Files Updated**:
- `reversecore_mcp/tools/r2_analysis.py` (line 589)

**Impact**:
- Enables concurrent tool execution
- Prevents blocking during image generation
- Better resource utilization in multi-tool workflows

### 3. Buffered File I/O (Low-Medium Impact)

**Problem**: Default Python file I/O can be slow for large files due to frequent system calls.

**Solution**: Use explicit buffering for better throughput.

```python
# ✅ Good - Buffered reading
with open(file_path, encoding="utf-8", errors="ignore", buffering=8192) as f:
    content = f.read()

# ❌ Bad - Default buffering (often -1, which is line-buffered for text mode)
with open(file_path, encoding="utf-8", errors="ignore") as f:
    content = f.read()
```

**Files Updated**:
- `reversecore_mcp/tools/ioc_tools.py`

**Impact**:
- Faster reading of large text files for IOC extraction
- Reduced system calls
- Better performance on network filesystems

### 4. Pre-compiled Regex Patterns (High Impact)

**Status**: Already implemented throughout the codebase.

**Files Using Pre-compiled Patterns**:
- `reversecore_mcp/tools/ghost_trace.py` (lines 30-36)
- `reversecore_mcp/tools/decompilation.py` (lines 36, 44-100)
- `reversecore_mcp/tools/neural_decompiler.py` (lines 27-45)
- `reversecore_mcp/tools/static_analysis.py` (lines 26-50)

**Benefits**:
- Avoids recompiling patterns in hot paths
- Significantly faster pattern matching
- Reduced CPU overhead

### 5. Adaptive Timeouts (Medium Impact)

**Status**: Already implemented.

**Location**: `reversecore_mcp/core/r2_helpers.py`

```python
def calculate_dynamic_timeout(file_path, base_timeout=300):
    """
    Calculate timeout based on file size.
    Base timeout + 2 seconds per MB, capped at base + 600s.
    """
    file_size_mb = os.path.getsize(file_path) / (1024 * 1024)
    dynamic_timeout = base_timeout + min(int(file_size_mb * 2), 600)
    return dynamic_timeout
```

**Benefits**:
- Prevents premature timeouts on large files
- Avoids wasting time on stuck processes
- Better user experience

### 6. LRU Caching (High Impact)

**Status**: Already implemented with `@alru_cache`.

**Usage**:
```python
from async_lru import alru_cache

@alru_cache(maxsize=128)
async def expensive_operation(file_path: str):
    # Expensive computation
    return result
```

**Benefits**:
- Avoids redundant analysis of the same binary
- Significant speedup for repeated operations
- Memory-bounded (LRU eviction)

### 7. Resource Cleanup Optimization (Low Impact)

**Problem**: Multiple glob operations and iterations were inefficient.

**Solution**: Use `itertools.chain` to combine patterns.

```python
# ✅ Good - Single iteration
from itertools import chain
temp_files = chain(
    workspace.glob("*.tmp"),
    workspace.glob(".r2_*"),
    workspace.glob("*.r2")
)
for temp_file in temp_files:
    # Process file

# ❌ Bad - Multiple iterations
for pattern in ["*.tmp", ".r2_*", "*.r2"]:
    for temp_file in workspace.glob(pattern):
        # Process file
```

**Files Updated**:
- `reversecore_mcp/core/resource_manager.py`

**Impact**:
- Faster periodic cleanup
- Reduced memory usage
- Better scalability with many temp files

## Performance Best Practices

### For Contributors

1. **Always use `json_utils` instead of standard `json`**
   ```python
   from reversecore_mcp.core import json_utils as json
   ```

2. **Use async subprocess execution**
   ```python
   from reversecore_mcp.core.execution import execute_subprocess_async
   await execute_subprocess_async(cmd, max_output_size=..., timeout=...)
   ```

3. **Pre-compile regex patterns at module level**
   ```python
   # At module level
   _PATTERN = re.compile(r"...")
   
   # In function
   matches = _PATTERN.findall(text)
   ```

4. **Use buffered I/O for large files**
   ```python
   with open(file_path, buffering=8192) as f:
       content = f.read()
   ```

5. **Use generators and itertools for large datasets**
   ```python
   from itertools import islice, chain
   
   # Instead of list slicing
   limited_items = list(islice(iterator, 100))
   
   # Instead of multiple loops
   all_items = chain(iter1, iter2, iter3)
   ```

6. **Apply `@alru_cache` to expensive pure functions**
   ```python
   from async_lru import alru_cache
   
   @alru_cache(maxsize=128)
   async def expensive_analysis(file_path: str):
       # ...
   ```

### Common Anti-patterns to Avoid

❌ **Don't block the event loop**
```python
# Bad
time.sleep(1)
subprocess.run(["command"])

# Good
await asyncio.sleep(1)
await execute_subprocess_async(["command"])
```

❌ **Don't compile regex in hot paths**
```python
# Bad - Compiles pattern every time
for line in lines:
    if re.match(r"pattern", line):
        # ...

# Good - Compile once
PATTERN = re.compile(r"pattern")
for line in lines:
    if PATTERN.match(line):
        # ...
```

❌ **Don't use `+` for string concatenation in loops**
```python
# Bad - O(n²) complexity
result = ""
for item in items:
    result += str(item) + "\n"

# Good - O(n) complexity
result = "\n".join(str(item) for item in items)
```

❌ **Don't read entire files unnecessarily**
```python
# Bad - Loads entire file into memory
with open(large_file) as f:
    all_lines = f.readlines()
    first_line = all_lines[0]

# Good - Only reads what's needed
with open(large_file) as f:
    first_line = f.readline()
```

## Benchmarking

### Running Performance Tests

```bash
# Run all performance tests
pytest tests/unit/test_performance.py -v

# Run with profiling
pytest tests/unit/test_performance.py -v --profile

# Run with coverage
pytest tests/unit/test_performance.py -v --cov=reversecore_mcp
```

### Performance Test Coverage

Current performance tests validate:
- YARA result processing with many matches
- File path validation string conversions
- LIEF output formatting
- Subprocess polling with adaptive backoff
- IOC extraction with pre-compiled patterns
- Regex pattern reuse
- islice vs list slicing

### Adding New Performance Tests

When adding new performance-critical code, add a test:

```python
def test_my_optimization(workspace_dir):
    """Test that my optimization performs well."""
    import time
    
    # Setup
    data = generate_test_data()
    
    # Benchmark
    start_time = time.time()
    for _ in range(100):
        result = my_optimized_function(data)
    elapsed = time.time() - start_time
    
    # Validate performance
    assert elapsed < 0.5, f"Too slow: {elapsed}s"
    
    # Validate correctness
    assert result.status == "success"
```

## Future Improvements

### Potential Optimizations (Not Yet Implemented)

1. **Parallel Binary Analysis**
   - Use `asyncio.gather()` for concurrent tool execution
   - Implement worker pool for CPU-intensive tasks
   - Priority: Medium, Impact: High

2. **Memory-Mapped File I/O**
   - Use `mmap` for large binary files
   - Faster random access to file contents
   - Priority: Low, Impact: Medium (for large files)

3. **Streaming JSON Processing**
   - Use `ijson` for very large JSON files
   - Reduce memory footprint
   - Priority: Low, Impact: Low (rare use case)

4. **Database Caching**
   - Cache analysis results in SQLite
   - Persist cache across server restarts
   - Priority: Medium, Impact: Medium

5. **Batch Operations**
   - Batch multiple radare2 commands
   - Reduce subprocess overhead
   - Priority: Medium, Impact: Medium

6. **JIT Compilation**
   - Use PyPy or Numba for hot paths
   - Significant speedup for computation-heavy code
   - Priority: Low, Impact: High (if applicable)

### Performance Monitoring

Consider adding:
- Prometheus metrics export
- Detailed timing breakdowns per tool
- Memory usage tracking
- Cache hit rate monitoring

## Profiling Tools

### CPU Profiling

```bash
# Profile with cProfile
python -m cProfile -o profile.stats server.py

# Analyze results
python -m pstats profile.stats
> sort time
> stats 20

# Or use snakeviz for visualization
pip install snakeviz
snakeviz profile.stats
```

### Memory Profiling

```bash
# Install memory profiler
pip install memory-profiler

# Profile memory usage
python -m memory_profiler server.py

# Or use memray
pip install memray
memray run server.py
memray flamegraph memray-*.bin
```

## Conclusion

Performance optimization is an ongoing process. Always:
1. **Measure first** - Profile before optimizing
2. **Focus on bottlenecks** - Optimize hot paths, not cold paths
3. **Test thoroughly** - Ensure optimizations don't break functionality
4. **Document changes** - Help future contributors understand the code

For questions or suggestions, please open an issue on GitHub.
