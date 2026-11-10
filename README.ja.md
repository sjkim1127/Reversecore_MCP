<div align="center">

[English](README.md) · [한국어](README.ko.md) · **日本語** · [简体中文](README.zh-CN.md)

<br />

<img src="icon.png" alt="Reversecore MCP" width="440" />

# Reversecore MCP

### AI駆動のバイナリリバースエンジニアリング・マルウェア解析・脆弱性研究のためのエンタープライズMCPサーバー

**マルウェアのトリアージ、ネイティブ逆コンパイル、モダンランタイムのセキュリティ監査（Go/Rust、Electron、Unity）、クラッシュ原因解析、デジタルフォレンジックをバイト単位の検証可能な証拠（`evidence_id`）に基づいて実行する Model Context Protocol サーバーです。**

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

**[クイックスタート](#-クイックスタート-quick-start) · [セキュリティ解析ワークフロー](#️-3つの主要セキュリティ解析ワークフロー) · [対応ターゲット](#-解析可能なターゲット-what-you-can-analyze) · [コンテキスト最適化](#-コンテキスト効率-tiered-router-compact-schema--paging) · [ツールカタログ (186個)](#tool-catalog-186-tools) · [FAQ](#-よくある質問-faq)**

</div>

### ⚡ ワンライナー自動セットアップ (One-Line Setup)

インストール済みのAIクライアント（**Cursor, Claude Code, Windsurf, Claude Desktop, OpenAI Codex, Antigravity, Cline/Roo Code**）を自動検出し、設定のバックアップとともに Reversecore MCP を即座に登録します：

```bash
# オプション 1: 事前インストール不要の自動セットアップ（推奨）
pipx run reversecore-mcp setup

# オプション 2: ワンライナーシェルインストーラー (macOS / Linux)
curl -fsSL https://raw.githubusercontent.com/sjkim1127/Reversecore_MCP/main/install.sh | bash

# オプション 3: エージェントスキルの追加 (skills.sh / Cursor / Claude Code / Codex)
npx skills add sjkim1127/Reversecore_MCP
```

> 💡 **LLMのコンテキストトークン消費を 94.4% 削減:** `pipx run reversecore-mcp setup --tiered` を実行すると、日常のコアセキュリティツール15個＋8個の専門サブエージェントルーターのみを公開しつつ、全186個のツールをオンデマンドで呼び出せます。

---

## Reversecore MCP とは？

**Reversecore MCP** は、**186個の専門的なリバースエンジニアリング・マルウェア解析・脆弱性診断・デジタルフォレンジックツール**を単一のインターフェースに統合した [Model Context Protocol (MCP)](https://modelcontextprotocol.io/) サーバーです。

逆アセンブラ、デコンパイラ、YARAスキャナー、メモリ/ネットワーク解析ツールの複雑なコマンドライン構文を個別に操作する代わりに、自然言語で調査の目的を指示できます：

```text
"この不審な検体のメインペイロードを逆コンパイルし、独自の文字列復号ルーチンを解析して
 すべてのC2 IOCを抽出し、MITRE ATT&CKにマッピングしてトリアージレポートを作成して。"
```

すべての解析ツールはローカル環境または隔離されたDockerコンテナ内で安全に実行され、構造化された `ToolResult`（`ToolSuccess` または `ToolError`）とバイト単位の証拠（`evidence_id`）を返すことで、AIのハルシネーション（幻覚）を防ぎます。

---

## 🛡️ 3つの主要セキュリティ解析ワークフロー

### Workflow 1: マルウェア復号ルーチン（Cryptor / DGA）の再構築と安全なESILエミュレーション検証

現代のマルウェアは、C2設定や文字列を独自の暗号化ルーチン（XOR、RC4亜種など）で難読化したり、ドメインを動的に生成（DGA）したりします。逆コンパイルされたC疑似コードを手作業でPythonの復号スクリプトに移植すると、32/64ビット整数オーバーフローやビットシフトの差異により復号ミスが発生しがちです。Reversecore MCP は復号関数をPythonで再構築し、**実環境でマルウェアを実行することなく Radare2 ESIL CPUエミュレータ内で入出力の同等性を100%検証**します。

```
1. r2_decompile("sample.bin", "0x401180", detail="summary")
   └─ 複雑度/API要約とキャッシュハンドルを返却: evidence_id="ev_9a4c102f8b11"

2. inspect_analysis_view(evidence_id="ev_9a4c102f8b11", facet="lines", offset=0, limit=40)
   └─ コンテキストを圧迫せず、必要な疑似コード行のみをオンデマンドで取得

3. reconstruct_feature_code(
       file_path="sample.bin",
       address_or_symbol="sym.decrypt_word",
       target_language="python",
       test_inputs=["0x0", "0xff", "0xffff"]
   )
   ├─ 逆コンパイル＆コード合成: r2ghidra -> クリーンな Python 関数 (decrypt_word) を生成
   ├─ バイナリエミュレーション: Radare2 ESIL VM（隔離されたレジスタ/メモリ状態、ホスト実行なし）
   ├─ 同等性判定: VERIFIED (branch_parity: true, test_vectors_evaluated: 3, emulation_successful: true)
   └─ 再構築された Python コード:
        def decrypt_word(param_1: Any = 0, param_2: Any = 0, *args: Any, **kwargs: Any) -> Any:
            uVar1 = (param_1 ^ param_2) * 0x45d9f3b
            return uVar1 >> 0x10 ^ uVar1
```

---

### Workflow 2: モダンランタイム脅威・サプライチェーン監査（Go/Rust マルウェア、Electron ASAR、Unity）

近年、攻撃者はシンボルが削除（Stripped）された **Go/Rust** でクロスプラットフォーム型ランサムウェアを作成したり、改ざんされた **Electron（`app.asar`）** インストーラーでサプライチェーン攻撃を仕掛けたりしています。Reversecore MCP は外部SDK不要の純粋なPython静的パーサーにより、ストリップされたシンボルの復元とセキュリティ設定の監査を即座に行います：

```
1. inspect_electron_asar("app.asar", search_pattern="ipcMain|child_process|shell")
   ├─ フォーマット: Chromium Pickle ASAR (header_size: 48,210 bytes, 642 files)
   ├─ 公開されたIPCハンドラ: メインおよびプリロードスクリプトから14チャンネルを特定
   └─ セキュリティ監査結果:
        • [HIGH] BrowserWindow設定で nodeIntegration: true を検出（RCEリスク）
        • [MEDIUM] レンダラーウィンドウで sandbox: false を検出

2. inspect_go_rust_binary("helper_daemon.elf")
   ├─ 検出ランタイム: Go (gopclntab magic 0xfffffff1, Go 1.22)
   ├─ シンボル復元: .gopclntab からストリップされたパッケージ/関数名 148個を復元
   └─ 特定された不審な関数:
        • main.establishBeaconLoop @ 0x48a200
        • main.encryptLocalVolume  @ 0x48b940
```

---

### Workflow 3: ゼロデイクラッシュトリアージ、汚染解析（Taint Analysis）、適応型YARA/ワクチン生成

ASan/GDBクラッシュログや論理爆弾（Logic Bomb）が潜むパック済みバイナリから、クラッシュ分類、Source-to-Sink 到達可能性証明、YARA検知ルールおよびバイナリ緩和パッチの生成までを一貫して自動化します。

```
1. cve_triage_crash(crash_log_or_text=asan_log)
   └─ バグ分類: heap-buffer-overflow (READ) | CWE-125 | 原因箇所: parse_packet+0x84

2. taint_trace("daemon.bin", function_name="parse_packet", verify_with_angr=True)
   └─ Source→Sink 到達確認: recv() → memcpy() @ 0x402190（長さフィールドの境界未検証）

3. dormant_detector("daemon.bin")
   └─ タイムボム条件分岐 (cmp eax, 0x67758ac0) を含む孤立関数 (0x404800) を検出

4. adaptive_vaccine(threat_report={...}, action="both")
   ├─ アドレス変位（Displacement）をワイルドカード化したYARAルールを生成
   └─ 脆弱/悪性分岐を無力化するバイナリ緩和パッチを合成
```

---

## 🎯 解析可能なターゲット (What You Can Analyze)

| ターゲットカテゴリ | セキュリティ・リバースエンジニアリング機能 | 解析エンジン / 要件 |
|---|---|---|
| **ネイティブバイナリ (PE / ELF / Mach-O)** | 逆アセンブル、r2ghidra C逆コンパイル、CFG、C++ RTTI、構造体復元、インポート/エクスポート、セクションエントロピー | **Radare2 + r2ghidra + LIEF** (x86, x64, ARM32, ARM64, MIPS, RISC-V, PowerPC) |
| **マルウェア・パック済み実行ファイル** | パッカー/コンパイラ特定、CAPA挙動マッピング、休眠バックドア/タイムボム検知、IOC抽出、YARA/Sigmaルール・ワクチン生成 | **YARA + CAPA + DIE + 独自ヒューリスティック** |
| **ストリップ済み Go & Rust マルウェア** | Go `.gopclntab` (`go1.2`–`go1.20+`) シンボル復元、Rust `.dep-v0` (`cargo-auditable`) 依存ツリーと脆弱クレート監査、`_ZN...E` デマングル | **純粋なPython内蔵** (`inspect_go_rust_binary`) — Go/Rust SDK不要 |
| **Electron デスクトップアプリ (`app.asar`)** | サプライチェーン・クライアント監査: Chromium Pickle VFSパーサー、`ipcMain`/`contextBridge` マッピング、`nodeIntegration` 監査 | **純粋なPython内蔵** (`inspect_electron_asar`) — 外部依存ゼロ |
| **Unity IL2CPP バイナリ** | モバイル/クライアント監査: `global-metadata.dat` (`0xFAB11BAF`, v24–v31+) 暗号化/エントロピー診断、C#クラス/メソッド/文字列復元 | **純粋なPython内蔵** (`inspect_unity_il2cpp`) — Unityエディタ不要 |
| **暗号化/復号ルーチンの再構築と検証** | 逆コンパイルされたルーチンを安全なC/Pythonスクリプトに変換し、ESILレジスタ/メモリ同等性検証と検証台帳を発行 | **r2ghidra + ESILシミュレータ** (`reconstruct_feature_code`) |
| **脆弱性研究・クラッシュダンプ** | ASan/GDBクラッシュ分類、デルタデバッグによるPoC最小化、Source→Sink汚染解析、angrシンボリック実行、ROPチェーン構築 | **angr + pwntools + ROPgadget + GDB** |
| **メモリ・ネットワーク・ディスクフォレンジック** | RAMダンプのプロセス/インジェクション調査、PCAP DNS/C2/ストリーム再構成、NTFS MFT・削除ファイル復元、タイムライン相関分析 | **Volatility3 + Scapy + Sleuth Kit + Binwalk** |

---

## ⚡ コンテキスト効率: Tiered Router, Compact Schema & Paging

大規模なセキュリティ解析MCPサーバーでは、180以上のツールスキーマや数万行の逆コンパイル出力によりLLMのコンテキストが急速に枯渇することがあります。Reversecore MCP は **4層のコンテキスト最適化アーキテクチャ** を備えています：

| 最適化レイヤー | 有効化の方法 | トークン削減効果と動作 |
|---|---|---|
| **1. Tiered Router モード** | `REVERSECORE_PROFILE=tiered`<br>*(または `reversecore-mcp setup --tiered`)* | **プロンプトトークンを 94.4% 削減。** 日常のコアツール12個＋ルーターツール3個（`call_expert_agent`, `search_tools`, `execute_domain_tool`）のみを公開し、8つの専門サブエージェント経由で全186個のツールをオンデマンド実行します。 |
| **2. Compact Schema プロファイル** | `REVERSECORE_SCHEMA_PROFILE=compact` | **`tools/list` ペイロードを約65%削減。** 冗長なdocstring例を省き、深い `anyOf`/`oneOf` を平坦化してスキーマ深度を最大10に制限します（サーバー側のPydantic検証は完全に維持）。 |
| **3. Summary-First Paging** | `r2_decompile`, `Radare2_disassemble*`, `Radare2_list_strings` 等に `detail="summary"` を指定 | コンパクトな構造要約と `evidence_id` ハンドル（`ev_<12-hex>`）を返却します。`inspect_analysis_view(evidence_id, facet, offset, limit, filter_query)` で必要なページのみを取得できます。 |
| **4. オンデマンドガイド検索** | 内蔵ツール: `search_guidance` & `read_guidance_section` | システムプロンプトに膨大なマニュアルを詰め込む代わりに、エージェントが必要な時だけ内蔵プレイブック（`playbook:target-routing` 等）を検索して参照します。 |

---

## Tool Catalog (186 Tools)

> 📖 **[全186ツールの詳細リファレンス (docs/TOOLS.md)](docs/TOOLS.md)**
> 📊 **[プロファイル別トークン＆メモリベンチマーク (docs/benchmarks/profile_footprint.md)](docs/benchmarks/profile_footprint.md)**

| プロファイル (`REVERSECORE_PROFILE`) | 公開ツール数 | スキーマサイズ | Full比トークン削減 | 推奨ユースケース |
|---|:---:|:---:|:---:|---|
| `tiered` | **15** | ~11.5 KB | **-94.4%** (~28,500 tokens) | ⚡ **対話型AIセキュリティ解析**（12コア＋8サブエージェントルーター） |
| `full` | **186** | 144.2 KB | ベースライン (0%) | 全機能エンタープライズリバースエンジニアリングスイート |
| `vuln-research` | **138** | 96.4 KB | **-33.1%** (~10,000 tokens) | ファジング、ASanクラッシュトリアージ、CVEハンティング |
| `static` | **132** | 91.2 KB | **-36.8%** (~11,100 tokens) | 逆アセンブル、逆コンパイル(r2ghidra)、LIEF、モダンランタイム解析 |
| `malware` | **100** | 76.5 KB | **-46.9%** (~14,100 tokens) | マルウェアトリアージ、YARAスキャン、難読化解除、耐解析検知 |
| `forensics` | **81** | 51.8 KB | **-64.1%** (~19,300 tokens) | メモリフォレンジック(Volatility3)、PCAP解析(Scapy)、ディスク調査 |

---

## 🚀 クイックスタート (Quick Start)

```bash
# macOS / Linux (シェルスクリプト)
curl -fsSL https://raw.githubusercontent.com/sjkim1127/Reversecore_MCP/main/install.sh | bash

# uvx / pipx を使用
uvx --from reversecore-mcp reversecore-setup
pipx run reversecore-mcp setup

# Windows (PowerShell)
irm https://raw.githubusercontent.com/sjkim1127/Reversecore_MCP/main/install.ps1 | iex
```

**Docker での実行（すべての外部解析エンジンがプリインストール済み）:**
```bash
docker run -i --rm \
  -v /path/to/your/samples:/app/workspace \
  -e REVERSECORE_WORKSPACE=/app/workspace \
  -e MCP_TRANSPORT=stdio \
  ghcr.io/sjkim1127/reversecore_mcp:latest
```

---

## ❓ よくある質問 (FAQ)

<details>
<summary><b>別途 Ghidra や Java (JDK) のインストールは必要ですか？</b></summary>

不要です。`r2ghidra` プラグインが Ghidra のデコンパイラエンジンをネイティブ C++ として Radare2 に直接組み込んでいるため、JVM や Ghidra 本体なしで高速に逆コンパイルできます。また、Go/Rust、Electron ASAR、Unity IL2CPP の解析ツールは純粋な Python で動作します。
</details>

<details>
<summary><b>マルウェアを解析しても安全ですか？</b></summary>

静的解析ツール（Radare2、YARA、LIEF、ASAR/Go/Rustパーサー）および ESIL エミュレータは、対象のバイナリをホストOS上で直接実行しません。動的解析を行う場合は、非rootユーザー（`appuser`）、リソース制限、ネットワーク隔離を備えた Docker コンテナおよびサンドボックスモード（`REVERSECORE_SANDBOX_ENABLED=true`）の使用を推奨します。
</details>

---

## ライセンス (License)

MIT License — 詳細は [LICENSE](LICENSE) を参照してください。
