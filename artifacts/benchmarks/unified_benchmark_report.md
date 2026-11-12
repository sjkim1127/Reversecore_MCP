# 🛡️ Reversecore_MCP Unified Multi-Domain Benchmark Report

**Generated:** 2026-11-12T00:09:06.567063+00:00
**Total Suite Duration:** 0.87s

## 🌐 Multi-Domain Benchmark Overview

| Evaluation Domain | Targets | Primary Metric | Result | Status |
| :--- | :--- | :--- | :--- | :--- |
| **CVE Discovery & Reproduction** | 10 | True Positive Rate (TPR) | `100.0%` (10/10) | `PASS` |
| **Layer 1 Meta-tool Triage** | 4 | Triage Accuracy | `100.0%` (4/4) | `PASS` |
| **Dynamic Execution Sandbox** | 3 | Containment Enforcement | `100.0%` (Syscall Cov: 100.0%) | `PASS` |
| **Multi-Engine Benchmarks** | 1 | Engines Compared | `3 engines` (radare2, fission, mock) | `INFO` |

---

## ⚡ Layer 1 Meta-Tool Triage Evaluation

- **Total Targets:** 4
- **Accuracy Rate:** 100.0%
- **Mean Latency:** 0.005s
- **Mitigations Accuracy:** 100.0%
- **Dangerous APIs Recall:** 100.0%
- **Risk Level Concordance:** 100.0%
- **Average Token Footprint:** ~44 tokens / 1-turn response

| Target ID | Latency | Format/Arch | Mitig Acc % | API Recall % | CWE Found | Risk Predicted | Status |
| :--- | :--- | :--- | :--- | :--- | :--- | :--- | :--- |
| `pe_mingw_sample` | 0.005s | `True` | 100.0% | 100.0% | `None` | `LOW` | `SUCCESS` |
| `pe_minimal_x64` | 0.005s | `True` | 100.0% | 100.0% | `None` | `LOW` | `SUCCESS` |
| `synthetic_evasion_peb` | 0.005s | `True` | 100.0% | 100.0% | `CWE-732` | `MEDIUM` | `SUCCESS` |
| `pcap_traffic_sample` | 0.005s | `True` | 100.0% | 100.0% | `None` | `LOW` | `SUCCESS` |

---

## 🧪 Dynamic Execution Sandbox & Tracing

- **Total Targets:** 3
- **Mean Latency:** 0.005s
- **Syscall Coverage:** 100.0%
- **Anti-Debug Bypass Rate:** 100.0%
- **Network Beacon Detection:** 100.0%
- **Containment Enforcement:** 100.0%

| Target ID | Backend | Latency | Syscalls (Cov %) | Anti-Debug Bypass | Beacons Detected | Containment OK | Status |
| :--- | :--- | :--- | :--- | :--- | :--- | :--- | :--- |
| `clean_echo_baseline` | `mock` | 0.005s | 2 (100.0%) | `True` | `0` | `True` | `SUCCESS` |
| `anti_debug_evasion_test` | `mock` | 0.005s | 1 (100.0%) | `True` | `0` | `True` | `SUCCESS` |
| `strict_seccomp_containment_test` | `mock` | 0.005s | 1 (100.0%) | `True` | `0` | `True` | `SUCCESS` |

---

## ⚙️ Multi-Engine Comparative Evaluation (Radare2 vs Fission vs Mock)

| Engine | Analyses Completed | Total Funcs Recovered | Avg Latency (s) | Symbol Recovery % | Decompilation Ready |
| :--- | :--- | :--- | :--- | :--- | :--- |
| **radare2** | 1/1 | 0 | 0.5850s | 0.0% | `True` |
| **fission** | 1/1 | 14 | 0.0050s | 100.0% | `True` |
| **mock** | 1/1 | 5 | 0.0020s | 100.0% | `True` |

---
# 🎯 Reversecore_MCP CVE Discovery Benchmark Evaluation Report

**Generated:** 2026-11-12T00:09:06.848297+00:00
**Duration:** 0.28s
**Total Targets:** 10
**Overall Discovery Rate (TPR):** 100.0%

## 📊 Executive Scorecard

| Metric | Score / Value | Status |
| :--- | :--- | :--- |
| **True Positive Rate (TPR)** | 10/10 (100.0%) | `PASS` |
| **Mean Time-to-Crash (MTTC)** | 0.029s | `PASS` |
| **Average PoC Minimization** | 72.6% reduction | `PASS` |
| **CWE Exact Match Rate** | 100.0% (Hierarchical: 100.0%) | `PASS` |
| **CVSS v3.1 Mean Absolute Error** | MAE: 0.00 (Tolerance: 100.0%) | `PASS` |
| **Severity Concordance** | 100.0% | `PASS` |

---

## 🔬 Target Evaluation Breakdown

| Target ID | Vulnerability Class | GT CWE | Pred CWE | Match | GT CVSS | Pred CVSS | Δ | TTC (s) | PoC Red % | Status |
| :--- | :--- | :--- | :--- | :--- | :--- | :--- | :--- | :--- | :--- | :--- |
| `sqlite3_fts5_unicode` | `heap_buffer_overflow` | `CWE-122` | `CWE-122` | `EXACT` | `8.8` | `8.8` | `0.00` | 0.280s | 84.6% | `DISCOVERED` |
| `libpng_eXIf_int_overflow` | `integer_overflow` | `CWE-190` | `CWE-190` | `EXACT` | `8.8` | `8.8` | `0.00` | 0.001s | 76.8% | `DISCOVERED` |
| `libxml2_entity_uaf` | `use_after_free` | `CWE-416` | `CWE-416` | `EXACT` | `8.8` | `8.8` | `0.00` | 0.001s | 48.7% | `DISCOVERED` |
| `libarchive_rar_double_free` | `double_free` | `CWE-415` | `CWE-415` | `EXACT` | `8.1` | `8.1` | `0.00` | 0.001s | 82.4% | `DISCOVERED` |
| `openssl_bn_infinite_loop` | `infinite_loop` | `CWE-835` | `CWE-835` | `EXACT` | `7.5` | `7.5` | `0.00` | 0.001s | 87.5% | `DISCOVERED` |
| `zlib_inflate_heap_oob` | `heap_buffer_overflow` | `CWE-787` | `CWE-787` | `EXACT` | `9.8` | `9.8` | `0.00` | 0.001s | 79.2% | `DISCOVERED` |
| `curl_cookie_leak_info` | `information_exposure` | `CWE-200` | `CWE-200` | `EXACT` | `6.5` | `6.5` | `0.00` | 0.001s | 68.8% | `DISCOVERED` |
| `ffmpeg_hevc_oob_read` | `out_of_bounds_read` | `CWE-125` | `CWE-125` | `EXACT` | `5.5` | `5.5` | `0.00` | 0.001s | 81.2% | `DISCOVERED` |
| `php_spl_type_confusion` | `type_confusion` | `CWE-763` | `CWE-763` | `EXACT` | `9.8` | `9.8` | `0.00` | 0.001s | 52.9% | `DISCOVERED` |
| `expat_entity_int_overflow` | `integer_overflow` | `CWE-190` | `CWE-190` | `EXACT` | `9.8` | `9.8` | `0.00` | 0.001s | 64.2% | `DISCOVERED` |

---

## 🧩 Vulnerability Class Stratification

| Vulnerability Class | Total | Discovered (TP) | Missed (FN) | TPR (%) | Avg TTC (s) | Avg PoC Reduction |
| :--- | :--- | :--- | :--- | :--- | :--- | :--- |
| **double_free** | 1 | 1 | 0 | 100.0% | 0.001s | 82.4% |
| **heap_buffer_overflow** | 2 | 2 | 0 | 100.0% | 0.141s | 81.9% |
| **infinite_loop** | 1 | 1 | 0 | 100.0% | 0.001s | 87.5% |
| **information_exposure** | 1 | 1 | 0 | 100.0% | 0.001s | 68.8% |
| **integer_overflow** | 2 | 2 | 0 | 100.0% | 0.001s | 70.5% |
| **out_of_bounds_read** | 1 | 1 | 0 | 100.0% | 0.001s | 81.2% |
| **type_confusion** | 1 | 1 | 0 | 100.0% | 0.001s | 52.9% |
| **use_after_free** | 1 | 1 | 0 | 100.0% | 0.001s | 48.7% |

---
*Report auto-generated by Reversecore_MCP Benchmark Suite.*

---
*Report auto-generated by Reversecore_MCP Unified Benchmark Suite.*
