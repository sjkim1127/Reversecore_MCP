# Performance Metrics Collection

## Overview

Reversecore_MCP includes a built-in performance metrics collection system that tracks execution statistics for all tool functions. This helps monitor performance, identify bottlenecks, and optimize tool usage.

## Metrics Collected

For each tool execution, the following metrics are automatically tracked:

- **calls**: Total number of times the tool has been invoked
- **errors**: Number of failed executions (where the result contains "Error")
- **total_time**: Cumulative execution time in seconds
- **avg_time**: Average execution time per call
- **max_time**: Maximum execution time observed
- **min_time**: Minimum execution time observed

## Usage

### Automatic Collection

All tools decorated with `@track_metrics` automatically collect performance data:

```python
from reversecore_mcp.core.metrics import track_metrics

@track_metrics("my_tool_name")
def my_tool_function():
    # Tool implementation
    return "result"
```

### Accessing Metrics

Retrieve collected metrics programmatically:

```python
from reversecore_mcp.core.metrics import metrics_collector

# Get all metrics
all_metrics = metrics_collector.get_metrics()

# Access specific tool metrics
strings_metrics = all_metrics.get("run_strings", {})
print(f"Total calls: {strings_metrics['calls']}")
print(f"Average time: {strings_metrics['avg_time']:.2f}s")
print(f"Error rate: {strings_metrics['errors'] / strings_metrics['calls'] * 100:.1f}%")
```

### Resetting Metrics

Clear all collected metrics:

```python
from reversecore_mcp.core.metrics import metrics_collector

metrics_collector.reset()
```

## Tools with Metrics Tracking

The following tools have metrics tracking enabled:

1. **run_strings** - String extraction from binaries
2. **run_radare2** - Radare2 disassembly and analysis
3. **run_yara** - YARA rule scanning
4. **disassemble_with_capstone** - Capstone disassembly

## Example Output

```json
{
  "run_strings": {
    "calls": 150,
    "errors": 2,
    "total_time": 45.3,
    "avg_time": 0.302,
    "max_time": 2.1,
    "min_time": 0.05
  },
  "run_radare2": {
    "calls": 75,
    "errors": 5,
    "total_time": 120.8,
    "avg_time": 1.61,
    "max_time": 15.2,
    "min_time": 0.3
  }
}
```

## Performance Monitoring Best Practices

### 1. Regular Monitoring

Check metrics periodically to identify performance trends:

```python
# Example monitoring script
import time
from reversecore_mcp.core.metrics import metrics_collector

def monitor_performance():
    while True:
        time.sleep(300)  # Check every 5 minutes
        metrics = metrics_collector.get_metrics()
        
        for tool_name, data in metrics.items():
            if data['avg_time'] > 5.0:
                print(f"WARNING: {tool_name} average time is {data['avg_time']:.2f}s")
            
            if data['calls'] > 0:
                error_rate = (data['errors'] / data['calls']) * 100
                if error_rate > 10:
                    print(f"WARNING: {tool_name} error rate is {error_rate:.1f}%")
```

### 2. Identifying Bottlenecks

Use metrics to find slow operations:

```python
metrics = metrics_collector.get_metrics()
sorted_tools = sorted(
    metrics.items(),
    key=lambda x: x[1]['avg_time'],
    reverse=True
)

print("Slowest tools:")
for tool_name, data in sorted_tools[:5]:
    print(f"{tool_name}: {data['avg_time']:.2f}s average")
```

### 3. Error Analysis

Track which tools are failing most often:

```python
metrics = metrics_collector.get_metrics()
for tool_name, data in metrics.items():
    if data['calls'] > 0:
        error_rate = (data['errors'] / data['calls']) * 100
        print(f"{tool_name}: {error_rate:.1f}% errors ({data['errors']}/{data['calls']})")
```

## Integration with Monitoring Systems

### Prometheus Export (Future)

```python
# Future implementation
from prometheus_client import Gauge

# Create Prometheus metrics
tool_calls = Gauge('reversecore_tool_calls_total', 'Total tool calls', ['tool_name'])
tool_errors = Gauge('reversecore_tool_errors_total', 'Total tool errors', ['tool_name'])
tool_avg_time = Gauge('reversecore_tool_avg_time_seconds', 'Average execution time', ['tool_name'])

def export_to_prometheus():
    metrics = metrics_collector.get_metrics()
    for tool_name, data in metrics.items():
        tool_calls.labels(tool_name=tool_name).set(data['calls'])
        tool_errors.labels(tool_name=tool_name).set(data['errors'])
        tool_avg_time.labels(tool_name=tool_name).set(data['avg_time'])
```

## Thread Safety

The current metrics collector implementation is not thread-safe. If you're running in a multi-threaded environment, consider:

1. Using locks when accessing metrics
2. Using thread-local storage for metrics
3. Implementing a queue-based metrics collection system

## Future Enhancements

Planned improvements for v2.0:

- [ ] Thread-safe metrics collection
- [ ] Histogram-based timing distribution
- [ ] Percentile calculations (p50, p95, p99)
- [ ] Memory usage tracking
- [ ] Prometheus/StatsD export
- [ ] Real-time metrics dashboard
- [ ] Metrics persistence to disk
- [ ] Alert thresholds and notifications

## See Also

- [ASYNC_ROADMAP.md](./ASYNC_ROADMAP.md) - Future async execution plans
- [PERFORMANCE_OPTIMIZATIONS.md](./PERFORMANCE_OPTIMIZATIONS.md) - Performance optimization guide
