<div align="center">

[English](README.md) · [한국어](README.ko.md) · [日本語](README.ja.md) · **简体中文**

<br />

<img src="icon.png" alt="Reversecore MCP" width="440" />

# Reversecore MCP

### AI 驱动的二进制逆向工程、恶意软件分析与漏洞研究企业级 MCP 服务器

**基于字节级可验证证据（`evidence_id`），为 AI 助手提供恶意软件分类（Triage）、原生反编译、现代运行时安全审计（Go/Rust、Electron、Unity）、崩溃根因分析与数字取证能力的 Model Context Protocol 服务器。**

---

[![CI/CD](https://github.com/sjkim1127/Reversecore_MCP/actions/workflows/main.yml/badge.svg)](https://github.com/sjkim1127/Reversecore_MCP/actions/workflows/main.yml)
[![Python](https://img.shields.io/badge/python-3.10%20%7C%203.11%20%7C%203.12-blue)](https://www.python.org/)
[![License: MIT](https://img.shields.io/badge/license-MIT-yellow.svg)](LICENSE)
[![Tests](https://img.shields.io/badge/tests-3086%20passed-brightgreen)](#testing)
[![Coverage](https://img.shields.io/badge/coverage-88%25-green)](#testing)
[![FastMCP](https://img.shields.io/badge/FastMCP-3.4.11-purple)](https://github.com/jlowin/fastmcp)
[![PyPI](https://img.shields.io/pypi/v/reversecore-mcp)](https://pypi.org/project/reversecore-mcp/)
[![Docker](https://img.shields.io/badge/docker-ghcr.io-blue)](https://github.com/sjkim1127/Reversecore_MCP/pkgs/container/reversecore_mcp)
[![skills.sh](https://img.shields.io/badge/skills.sh-reversecore--mcp-5c4ee5)](https://skills.sh)
[![OpenSSF Scorecard](https://api.securityscorecards.dev/projects/github.com/sjkim1127/Reversecore_MCP/badge)](https://scorecard.dev/viewer/?uri=github.com/sjkim1127/Reversecore_MCP)
[![HVTrust](https://hvtracker.net/badge/reversecore-mcp.svg)](https://hvtracker.net/agents/reversecore-mcp)

[![Watch the Demo](https://img.shields.io/badge/▶_Watch_Demo-FF0000?style=for-the-badge&logo=youtube&logoColor=white)](https://youtu.be/wJGW2bp3c5A)
[![SafeSkill Verified](https://img.shields.io/badge/SafeSkill-93%2F100_Verified_Safe-brightgreen?style=for-the-badge)](https://safeskill.dev/scan/sjkim1127-reversecore-mcp)

<br />

**[快速开始](#-快速开始-quick-start) · [安全分析工作流](#️-三大核心安全分析工作流) · [支持的目标类型](#-支持分析的目标-what-you-can-analyze) · [上下文效率优化](#-上下文效率tiered-router-compact-schema--paging) · [工具目录 (186个)](#tool-catalog-186-tools) · [常见问题](#-常见问题-faq)**

</div>

### ⚡ 一行命令自动配置 (One-Line Setup)

自动检测已安装的 AI 客户端（**Cursor, Claude Code, Windsurf, Claude Desktop, OpenAI Codex, Antigravity, Cline/Roo Code**），自动备份原有配置并完成 Reversecore MCP 注册：

```bash
# 方式 1：免预装 CLI 自动注册（推荐）
pipx run reversecore-mcp setup

# 方式 2：一行 Shell 安装脚本 (macOS / Linux)
curl -fsSL https://raw.githubusercontent.com/sjkim1127/Reversecore_MCP/main/install.sh | bash

# 方式 3：安装 Agent Skill (skills.sh / Cursor / Claude Code / Codex)
npx skills add sjkim1127/Reversecore_MCP
```

> 💡 **降低 94.4% 的 LLM 上下文 Token 开销：** 运行 `pipx run reversecore-mcp setup --tiered` 仅暴露 15 个高频核心安全工具 + 8 个领域专家子代理路由器，同时支持按需调用全部 186 个工具。

---

## 什么是 Reversecore MCP？

**Reversecore MCP** 是一个实现了 [Model Context Protocol (MCP)](https://modelcontextprotocol.io/) 的安全分析服务器，将 **186 个专业二进制逆向工程、恶意软件分析、漏洞研究与数字取证工具**封装为统一接口。

您无需手动切换反汇编器、反编译器、YARA 扫描器和取证工具，只需用自然语言描述调查目标：

```text
“反编译这个可疑样本的主载荷，还原其自定义字符串解密函数，提取所有 C2 IOC，
 将行为映射到 MITRE ATT&CK 矩阵，并生成应急分析报告。”
```

所有分析均在本地或隔离的 Docker 容器内安全运行，并返回结构化的 `ToolResult`（`ToolSuccess` 或 `ToolError`）以及字节级证据句柄（`evidence_id`），确保 AI 能够串联多步安全调查而不会产生幻觉。

---

## 🛡️ 三大核心安全分析工作流

### Workflow 1：恶意软件解密例程（Cryptor / DGA）重构与安全 ESIL 仿真验证

现代恶意软件通常使用自定义算法（XOR、RC4 变体等）加密 C2 配置或动态生成域名（DGA）。手动将反编译的 C 伪代码改写为 Python 解密脚本时，极易因 32/64 位整数回绕或移位符号差异导致解密失败。Reversecore MCP 可将解密函数重构为 Python 脚本，并**在 Radare2 ESIL CPU 仿真器中 100% 验证输入/输出等价性**，全程无需在宿主机上实际运行恶意样本。

```
1. r2_decompile("sample.bin", "0x401180", detail="summary")
   └─ 返回紧凑复杂度/API 摘要与缓存句柄: evidence_id="ev_9a4c102f8b11"

2. inspect_analysis_view(evidence_id="ev_9a4c102f8b11", facet="lines", offset=0, limit=40)
   └─ 按需分页读取伪代码行，防止上下文窗口溢出

3. reconstruct_feature_code(
       file_path="sample.bin",
       address_or_symbol="sym.decrypt_word",
       target_language="python",
       test_inputs=["0x0", "0xff", "0xffff"]
   )
   ├─ 反编译与代码合成: r2ghidra -> 生成去噪后的 Python 函数 (decrypt_word)
   ├─ 二进制仿真: Radare2 ESIL VM（隔离寄存器/内存状态，零宿主机执行风险）
   ├─ 等价性判定: VERIFIED (branch_parity: true, test_vectors_evaluated: 3, emulation_successful: true)
   └─ 重构出的 Python 代码:
        def decrypt_word(param_1: Any = 0, param_2: Any = 0, *args: Any, **kwargs: Any) -> Any:
            uVar1 = (param_1 ^ param_2) * 0x45d9f3b
            return uVar1 >> 0x10 ^ uVar1
```

---

### Workflow 2：现代运行时威胁与供应链安全审计（Go/Rust 恶意软件、Electron ASAR、Unity）

攻击者越来越多地使用**去符号（Stripped）的 Go/Rust** 编写跨平台勒索软件，或通过篡改 **Electron（`app.asar`）** 桌面安装包发起供应链攻击。Reversecore MCP 内置纯 Python 静态解析器，无需安装外部 SDK 即可恢复剥离符号并审计运行时安全边界：

```
1. inspect_electron_asar("app.asar", search_pattern="ipcMain|child_process|shell")
   ├─ 格式: Chromium Pickle ASAR (header_size: 48,210 bytes, 642 个文件)
   ├─ 暴露的 IPC 处理器: 在 main 与 preload 脚本中识别出 14 个通道
   └─ 安全审计发现:
        • [HIGH] BrowserWindow 配置中检测到 nodeIntegration: true（存在远程代码执行风险）
        • [MEDIUM] 渲染器窗口选项中检测到 sandbox: false

2. inspect_go_rust_binary("helper_daemon.elf")
   ├─ 识别运行时: Go (gopclntab 魔数 0xfffffff1, Go 1.22)
   ├─ 符号恢复: 从 .gopclntab 恢复出 148 个被剥离的包名与函数符号
   └─ 识别出的可疑函数:
        • main.establishBeaconLoop @ 0x48a200
        • main.encryptLocalVolume  @ 0x48b940
```

---

### Workflow 3：0-Day 崩溃分析、污点追踪（Taint Analysis）与自适应 YARA/疫苗生成

从 ASan/GDB 崩溃日志或隐藏了逻辑炸弹（Logic Bomb）的加壳样本出发，自动串联崩溃分类、Source-to-Sink 污点可达性证明、YARA 检测规则生成以及二进制缓解补丁合成。

```
1. cve_triage_crash(crash_log_or_text=asan_log)
   └─ 漏洞类型: heap-buffer-overflow (READ) | CWE-125 | 触发位置: parse_packet+0x84

2. taint_trace("daemon.bin", function_name="parse_packet", verify_with_angr=True)
   └─ Source→Sink 路径确认: recv() → memcpy() @ 0x402190（未校验长度字段）

3. dormant_detector("daemon.bin")
   └─ 发现 1 个包含时间炸弹触发条件 (cmp eax, 0x67758ac0) 的孤立函数 (0x404800)

4. adaptive_vaccine(threat_report={...}, action="both")
   ├─ 生成带有地址位移（Displacement）通配符掩码的 YARA 检测规则
   └─ 合成用于阻断恶意/脆弱分支的二进制热补丁
```

---

## 🎯 支持分析的目标 (What You Can Analyze)

| 目标类别 | 安全与逆向工程能力 | 分析引擎 / 环境要求 |
|---|---|---|
| **原生二进制文件 (PE / ELF / Mach-O)** | 反汇编、r2ghidra C 反编译、控制流图 (CFG)、C++ RTTI、结构体恢复、导入/导出表、节熵值分析 | **Radare2 + r2ghidra + LIEF** (x86, x64, ARM32, ARM64, MIPS, RISC-V, PowerPC) |
| **恶意软件与加壳程序** | 壳/编译器识别、CAPA 行为能力映射、休眠后门/逻辑炸弹检测、IOC 提取、YARA/Sigma 规则与疫苗生成 | **YARA + CAPA + DIE + 自定义启发式引擎** |
| **去符号 Go & Rust 恶意软件/程序** | Go `.gopclntab` (`go1.2`–`go1.20+`) 符号恢复、Rust `.dep-v0` (`cargo-auditable`) 依赖树与漏洞 Crate 审计、`_ZN...E` 符号还原 | **内置纯 Python** (`inspect_go_rust_binary`) — 无需 Go/Rust SDK |
| **Electron 桌面应用 (`app.asar`)** | 供应链与客户端安全审计：Chromium Pickle VFS 解析、`ipcMain`/`contextBridge` 攻击面映射、`nodeIntegration` 检查 | **内置纯 Python** (`inspect_electron_asar`) — 零外部依赖 |
| **Unity IL2CPP 二进制文件** | 移动端/客户端安全审计：`global-metadata.dat` (`0xFAB11BAF`, v24–v31+) 头部加密/熵检测、C# 类/方法/字符串恢复 | **内置纯 Python** (`inspect_unity_il2cpp`) — 无需 Unity 编辑器 |
| **加解密例程重构与等价性验证** | 将反编译例程转换为安全的 C/Python 脚本，通过 ESIL 寄存器/内存仿真验证等价性并输出验证台账 | **r2ghidra + ESIL 仿真器** (`reconstruct_feature_code`) |
| **漏洞研究与崩溃转储** | ASan/GDB 崩溃分类、Delta Debugging PoC 最小化、Source→Sink 污点分析、angr 符号执行路径求解、ROP 链构建 | **angr + pwntools + ROPgadget + GDB** |
| **内存、网络与磁盘取证** | 内存转储进程与代码注入猎杀、PCAP DNS/C2/会话流重组、NTFS MFT 与已删除文件恢复、时间线关联 | **Volatility3 + Scapy + Sleuth Kit + Binwalk** |

---

## ⚡ 上下文效率：Tiered Router, Compact Schema & Paging

大型安全分析 MCP 服务器往往因为一次性暴露 180+ 个工具 Schema 或返回数万行反编译代码而迅速耗尽 LLM 上下文窗口。Reversecore MCP 提供 **4 层上下文优化架构**：

| 优化层 | 启用方式 | Token 节省效果与运行机制 |
|---|---|---|
| **1. Tiered Router 模式** | `REVERSECORE_PROFILE=tiered`<br>*(或 `reversecore-mcp setup --tiered`)* | **减少 94.4% 的提示词 Token 开销。** 仅暴露 12 个日常核心工具 + 3 个路由工具（`call_expert_agent`, `search_tools`, `execute_domain_tool`），通过 8 个领域专家子代理按需调度全部 186 个工具。 |
| **2. Compact Schema 配置** | `REVERSECORE_SCHEMA_PROFILE=compact` | **`tools/list` 负载缩小约 65%。** 剥离冗长的文档示例、扁平化深层 `anyOf`/`oneOf` 联合类型并将 Schema 深度限制在 10 层以内（服务端 Pydantic 校验保持完整）。 |
| **3. Summary-First Paging** | 调用 `r2_decompile`, `Radare2_disassemble*`, `Radare2_list_strings` 等时传入 `detail="summary"` | 返回紧凑的结构化摘要与 `evidence_id` 句柄（`ev_<12-hex>`）。随后可通过 `inspect_analysis_view(evidence_id, facet, offset, limit, filter_query)` 按需分页或过滤查询。 |
| **4. 按需指南检索** | 内置工具：`search_guidance` & `read_guidance_section` | 无需在系统提示词中塞入数万字文档，代理仅在遇到特定目标时按需检索内置手册（如 `playbook:target-routing`, `playbook:go-rust-reversing`）。 |

---

## Tool Catalog (186 Tools)

> 📖 **[全部 186 个工具完整参数参考 (docs/TOOLS.md)](docs/TOOLS.md)**
> 📊 **[各配置档案 Token 与内存基准测试 (docs/benchmarks/profile_footprint.md)](docs/benchmarks/profile_footprint.md)**

| 配置档案 (`REVERSECORE_PROFILE`) | 注册工具数 | Schema 大小 | 相比 Full 节省 Token | 推荐应用场景 |
|---|:---:|:---:|:---:|---|
| `tiered` | **15** | ~11.5 KB | **-94.4%** (~28,500 tokens) | ⚡ **日常交互式 AI 安全分析**（12 核心工具 + 8 领域子代理路由器） |
| `full` | **186** | 144.2 KB | 基准 (0%) | 完整企业级逆向工程与安全套件 |
| `vuln-research` | **138** | 96.4 KB | **-33.1%** (~10,000 tokens) | 模糊测试、ASan 崩溃分析、CVE 挖掘、漏洞利用研究 |
| `static` | **132** | 91.2 KB | **-36.8%** (~11,100 tokens) | 反汇编、反编译 (r2ghidra)、LIEF、现代运行时静态分析 |
| `malware` | **100** | 76.5 KB | **-46.9%** (~14,100 tokens) | 恶意软件分类、YARA 扫描、去混淆、反分析检测 |
| `forensics` | **81** | 51.8 KB | **-64.1%** (~19,300 tokens) | 内存取证 (Volatility3)、网络流量分析 (Scapy)、磁盘取证 |

---

## 🚀 快速开始 (Quick Start)

```bash
# macOS / Linux (Shell 脚本)
curl -fsSL https://raw.githubusercontent.com/sjkim1127/Reversecore_MCP/main/install.sh | bash

# 或使用 uvx / pipx
uvx --from reversecore-mcp reversecore-setup
pipx run reversecore-mcp setup

# Windows (PowerShell)
irm https://raw.githubusercontent.com/sjkim1127/Reversecore_MCP/main/install.ps1 | iex
```

**使用 Docker 运行（已预装所有外部逆向与取证引擎）：**
```bash
docker run -i --rm \
  -v /path/to/your/samples:/app/workspace \
  -e REVERSECORE_WORKSPACE=/app/workspace \
  -e MCP_TRANSPORT=stdio \
  ghcr.io/sjkim1127/reversecore_mcp:latest
```

---

## ❓ 常见问题 (FAQ)

<details>
<summary><b>需要单独安装 Ghidra 或 Java (JDK) 吗？</b></summary>

不需要。`r2ghidra` 插件已将 Ghidra 反编译引擎以原生 C++ 形式直接嵌入 Radare2 中，无需 JVM 或单独的 Ghidra 安装即可直接反编译。此外，Go/Rust、Electron ASAR 和 Unity IL2CPP 分析器均为纯 Python 实现，开箱即用。
</details>

<details>
<summary><b>用它分析恶意软件安全吗？</b></summary>

静态分析工具（Radare2、YARA、LIEF、ASAR/Go/Rust 解析器）以及 ESIL 指令仿真器绝不会在宿主机 OS 上直接执行目标样本。进行动态分析时，建议使用具备非 root 用户（`appuser`）、资源限制和网络隔离的 Docker 容器及沙箱模式（`REVERSECORE_SANDBOX_ENABLED=true`）。
</details>

---

## 许可证 (License)

MIT License — 详见 [LICENSE](LICENSE) 文件。
