"""Unit tests for core.next_tool_hints module."""

from __future__ import annotations

from reversecore_mcp.core.next_tool_hints import (
    build_capa_hints,
    build_decompile_hints,
    build_dormant_hints,
    build_ioc_hints,
    build_lief_hints,
    build_vuln_hunter_hints,
    finalize_hints,
)

# ---------------------------------------------------------------------------
# build_decompile_hints
# ---------------------------------------------------------------------------


class TestBuildDecompileHints:
    def test_no_dangerous_apis_returns_empty(self):
        hints = build_decompile_hints("/workspace/clean.elf", "main", "int main() { return 0; }")
        assert hints == []

    def test_strcpy_triggers_taint_and_vuln(self):
        src = "void foo() { char buf[8]; strcpy(buf, user_input); }"
        hints = build_decompile_hints("/workspace/vuln.elf", "foo", src)
        tool_names = {h["tool"] for h in hints}
        assert "taint_trace" in tool_names
        assert "vulnerability_hunter" in tool_names

    def test_system_triggers_taint(self):
        src = "void run() { system(cmd); }"
        hints = build_decompile_hints("/workspace/cmd.elf", "run", src)
        tools = [h["tool"] for h in hints]
        assert "taint_trace" in tools

    def test_printf_triggers_vuln(self):
        src = "void log(char *s) { printf(s); }"
        hints = build_decompile_hints("/workspace/fmt.elf", "log", src)
        tools = [h["tool"] for h in hints]
        assert "vulnerability_hunter" in tools

    def test_syscall_triggers_taint(self):
        src = "void raw() { asm volatile('syscall'); }"
        hints = build_decompile_hints("/workspace/raw.elf", "raw", src)
        tools = [h["tool"] for h in hints]
        assert "taint_trace" in tools

    def test_high_confidence_for_strcpy(self):
        src = "strcpy(dst, src);"
        hints = build_decompile_hints("/workspace/vuln.elf", "foo", src)
        taint_hints = [h for h in hints if h["tool"] == "taint_trace"]
        assert taint_hints[0]["confidence"] == "high"

    def test_suggested_args_include_file_path(self):
        src = "strcpy(buf, input);"
        hints = build_decompile_hints("/workspace/target.elf", "foo", src)
        for h in hints:
            if "file_path" in h.get("suggested_args", {}):
                assert h["suggested_args"]["file_path"] == "/workspace/target.elf"
                break

    def test_priority_ordering(self):
        src = "strcpy(buf, input); printf(input);"
        hints = build_decompile_hints("/workspace/vuln.elf", "foo", src)
        priorities = [h.get("priority", 5) for h in hints]
        # taint_trace priority 1 should appear before vuln_hunter priority 3
        assert min(priorities) <= 2


# ---------------------------------------------------------------------------
# build_lief_hints
# ---------------------------------------------------------------------------


class TestBuildLiefHints:
    def test_no_high_entropy_returns_empty(self):
        sections = [
            {"name": ".text", "entropy": 5.5},
            {"name": ".data", "entropy": 3.0},
        ]
        hints = build_lief_hints("/workspace/ok.elf", sections)
        assert hints == []

    def test_high_entropy_triggers_packer_detect(self):
        sections = [
            {"name": ".text", "entropy": 7.8},
            {"name": ".data", "entropy": 3.0},
        ]
        hints = build_lief_hints("/workspace/packed.elf", sections)
        assert any(h["tool"] == "detect_packer_deep" for h in hints)

    def test_exactly_7_0_not_triggered(self):
        sections = [{"name": ".text", "entropy": 7.0}]
        hints = build_lief_hints("/workspace/borderline.elf", sections)
        # 7.0 is NOT > 7.0, so should be empty
        assert hints == []

    def test_confidence_high_above_7_5(self):
        sections = [{"name": ".upx", "entropy": 7.9}]
        hints = build_lief_hints("/workspace/upx.elf", sections)
        assert hints[0]["confidence"] == "high"

    def test_confidence_medium_between_7_and_7_5(self):
        sections = [{"name": ".packed", "entropy": 7.3}]
        hints = build_lief_hints("/workspace/maybe_packed.elf", sections)
        assert hints[0]["confidence"] == "medium"

    def test_no_entropy_field_skipped_safely(self):
        sections = [{"name": ".nope", "size": 100}]  # no entropy key
        hints = build_lief_hints("/workspace/noentropy.elf", sections)
        assert hints == []


# ---------------------------------------------------------------------------
# build_capa_hints
# ---------------------------------------------------------------------------


class TestBuildCapaHints:
    def test_encrypt_triggers_decompile(self):
        hints = build_capa_hints("/workspace/malware.exe", ["encrypt data", "create file"])
        tools = [h["tool"] for h in hints]
        assert "r2_decompile" in tools

    def test_inject_triggers_dormant(self):
        hints = build_capa_hints("/workspace/inject.exe", ["create remote thread"])
        tools = [h["tool"] for h in hints]
        assert "dormant_detector" in tools

    def test_network_triggers_extract_iocs(self):
        hints = build_capa_hints("/workspace/c2.exe", ["communicate via http"])
        tools = [h["tool"] for h in hints]
        assert "extract_iocs" in tools

    def test_persistence_triggers_vuln(self):
        hints = build_capa_hints("/workspace/persist.exe", ["modify registry", "startup"])
        tools = [h["tool"] for h in hints]
        assert "vulnerability_hunter" in tools

    def test_empty_capabilities_returns_empty(self):
        hints = build_capa_hints("/workspace/clean.exe", [])
        assert hints == []


# ---------------------------------------------------------------------------
# build_dormant_hints
# ---------------------------------------------------------------------------


class TestBuildDormantHints:
    def test_no_orphans_returns_empty(self):
        hints = build_dormant_hints("/workspace/clean.elf", [])
        assert hints == []

    def test_single_orphan_triggers_decompile(self):
        orphans = [{"address": "0x401234", "name": "secret_func"}]
        hints = build_dormant_hints("/workspace/sus.elf", orphans)
        assert any(h["tool"] == "r2_decompile" for h in hints)

    def test_suggested_args_has_address(self):
        orphans = [{"address": "0x401234", "name": "hidden"}]
        hints = build_dormant_hints("/workspace/sus.elf", orphans)
        decompile = next(h for h in hints if h["tool"] == "r2_decompile")
        assert decompile["suggested_args"]["function_address"] == "0x401234"

    def test_three_or_more_orphans_also_triggers_taint(self):
        orphans = [{"address": f"0x40{i:04x}", "name": f"orphan_{i}"} for i in range(4)]
        hints = build_dormant_hints("/workspace/many.elf", orphans)
        tools = [h["tool"] for h in hints]
        assert "taint_trace" in tools

    def test_max_5_decompile_hints(self):
        orphans = [{"address": f"0x40{i:04x}", "name": f"fn_{i}"} for i in range(10)]
        hints = build_dormant_hints("/workspace/lots.elf", orphans)
        decompile_hints = [h for h in hints if h["tool"] == "r2_decompile"]
        assert len(decompile_hints) <= 5


# ---------------------------------------------------------------------------
# build_ioc_hints
# ---------------------------------------------------------------------------


class TestBuildIocHints:
    def test_no_iocs_returns_empty(self):
        hints = build_ioc_hints("/workspace/clean.elf", {})
        assert hints == []

    def test_ip_addresses_trigger_vt(self):
        hints = build_ioc_hints("/workspace/malware.elf", {"ips": ["1.2.3.4"]})
        tools = [h["tool"] for h in hints]
        assert "vt_lookup" in tools

    def test_hashes_trigger_vt(self):
        hints = build_ioc_hints("/workspace/malware.elf", {"hashes": ["a" * 32]})
        tools = [h["tool"] for h in hints]
        assert "vt_lookup" in tools

    def test_urls_trigger_vt_and_strings(self):
        hints = build_ioc_hints("/workspace/malware.elf", {"urls": ["http://evil.com/payload"]})
        tools = [h["tool"] for h in hints]
        assert "vt_lookup" in tools

    def test_suggested_args_has_ioc_list(self):
        hints = build_ioc_hints("/workspace/malware.elf", {"ips": ["1.2.3.4", "5.6.7.8"]})
        vt = next(h for h in hints if h["tool"] == "vt_lookup")
        assert "iocs" in vt["suggested_args"]
        assert isinstance(vt["suggested_args"]["iocs"], list)


# ---------------------------------------------------------------------------
# build_vuln_hunter_hints
# ---------------------------------------------------------------------------


class TestBuildVulnHunterHints:
    def test_empty_findings_returns_empty(self):
        hints = build_vuln_hunter_hints("/workspace/clean.elf", [])
        assert hints == []

    def test_high_severity_triggers_poc(self):
        findings = [{"severity": "high", "vulnerability_type": "buffer_overflow"}]
        hints = build_vuln_hunter_hints("/workspace/vuln.elf", findings)
        tools = [h["tool"] for h in hints]
        assert "generate_poc_exploit" in tools

    def test_buffer_overflow_triggers_rop(self):
        findings = [{"severity": "high", "vulnerability_type": "buffer_overflow", "cwe": "CWE-120"}]
        hints = build_vuln_hunter_hints("/workspace/bof.elf", findings)
        tools = [h["tool"] for h in hints]
        assert "build_rop_chain" in tools

    def test_three_high_sev_triggers_autonomous_hunt(self):
        findings = [
            {"severity": "high", "vulnerability_type": "buffer_overflow"},
            {"severity": "critical", "vulnerability_type": "format_string"},
            {"severity": "high", "vulnerability_type": "use_after_free"},
        ]
        hints = build_vuln_hunter_hints("/workspace/crit.elf", findings)
        tools = [h["tool"] for h in hints]
        assert "autonomous_vuln_hunt" in tools

    def test_low_severity_no_poc(self):
        findings = [{"severity": "low", "vulnerability_type": "info_leak"}]
        hints = build_vuln_hunter_hints("/workspace/low.elf", findings)
        tools = [h["tool"] for h in hints]
        assert "generate_poc_exploit" not in tools


# ---------------------------------------------------------------------------
# finalize_hints
# ---------------------------------------------------------------------------


class TestFinalizeHints:
    def test_deduplicates_by_tool(self):
        hints = [
            {"tool": "taint_trace", "reason": "first", "priority": 2},
            {"tool": "taint_trace", "reason": "second", "priority": 1},
        ]
        result = finalize_hints(hints)
        taint = [h for h in result if h["tool"] == "taint_trace"]
        assert len(taint) == 1
        # Should keep the one with priority=1 (lowest number = highest priority)
        assert taint[0]["priority"] == 1

    def test_sorts_by_priority(self):
        hints = [
            {"tool": "b", "priority": 3},
            {"tool": "a", "priority": 1},
            {"tool": "c", "priority": 2},
        ]
        result = finalize_hints(hints)
        assert [h["tool"] for h in result] == ["a", "c", "b"]

    def test_empty_input(self):
        assert finalize_hints([]) == []
