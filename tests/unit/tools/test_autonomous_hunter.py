"""Unit tests for autonomous_hunter._should_analyze and _extract_offset_from_triage.

autonomous_vuln_hunt itself is an integration function that calls radare2,
angr, and pwntools. Those external pipelines are tested in integration tests.
Here we test the two pure-Python helper functions exhaustively.
"""

from __future__ import annotations

from reversecore_mcp.tools.malware.autonomous_hunter import (
    _extract_offset_from_triage,
    _should_analyze,
)

# ---------------------------------------------------------------------------
# _should_analyze
# ---------------------------------------------------------------------------


class TestShouldAnalyze:
    """Tests for the function-filtering predicate."""

    def test_normal_function_passes(self):
        func = {"name": "sym.main", "size": 128}
        assert _should_analyze(func) is True

    def test_size_below_threshold_filtered(self):
        func = {"name": "sym.main", "size": 15}
        assert _should_analyze(func) is False

    def test_size_exactly_16_passes(self):
        func = {"name": "sym.check_auth", "size": 16}
        assert _should_analyze(func) is True

    def test_size_zero_filtered(self):
        func = {"name": "sym.init", "size": 0}
        assert _should_analyze(func) is False

    def test_missing_size_filtered(self):
        func = {"name": "sym.init"}
        assert _should_analyze(func) is False

    def test_sym_imp_prefix_filtered(self):
        func = {"name": "sym.imp.strcpy", "size": 64}
        assert _should_analyze(func) is False

    def test_fcn_0_prefix_filtered(self):
        func = {"name": "fcn.00401234", "size": 256}
        assert _should_analyze(func) is False

    def test_entry0_filtered(self):
        func = {"name": "entry0", "size": 128}
        assert _should_analyze(func) is False

    def test_entry1_filtered(self):
        func = {"name": "entry1", "size": 128}
        assert _should_analyze(func) is False

    def test_dunder_prefix_filtered(self):
        func = {"name": "__libc_start_main", "size": 200}
        assert _should_analyze(func) is False

    def test_sym_underscore_prefix_filtered(self):
        func = {"name": "sym._fini", "size": 64}
        assert _should_analyze(func) is False

    def test_loc_prefix_filtered(self):
        func = {"name": "loc.80481a0", "size": 100}
        assert _should_analyze(func) is False

    def test_dbg_prefix_filtered(self):
        func = {"name": "dbg.main", "size": 200}
        assert _should_analyze(func) is False

    def test_reloc_prefix_filtered(self):
        func = {"name": "reloc.printf", "size": 64}
        assert _should_analyze(func) is False

    def test_empty_name_passes_if_large_enough(self):
        """Empty name does not match any skip prefix — treated as analysable."""
        func = {"name": "", "size": 64}
        assert _should_analyze(func) is True

    def test_missing_name_passes_if_large_enough(self):
        func = {"size": 64}
        assert _should_analyze(func) is True

    def test_partial_prefix_not_filtered(self):
        """A function named 'symbol' should not be filtered by 'sym._' prefix."""
        func = {"name": "symbol", "size": 100}
        assert _should_analyze(func) is True

    def test_real_app_function(self):
        func = {"name": "sym.process_login", "size": 512}
        assert _should_analyze(func) is True


# ---------------------------------------------------------------------------
# _extract_offset_from_triage
# ---------------------------------------------------------------------------


class TestExtractOffsetFromTriage:
    """Tests for crash offset extraction from dynamic_verification data.

    The implementation reads only the 'offset' key from the dict.
    Other keys (crash_offset, overflow_offset) are not recognised.
    """

    def test_none_input_returns_zero(self):
        assert _extract_offset_from_triage(None) == 0

    def test_non_dict_string_returns_zero(self):
        assert _extract_offset_from_triage("not a dict") == 0

    def test_non_dict_int_returns_zero(self):
        assert _extract_offset_from_triage(42) == 0

    def test_non_dict_list_returns_zero(self):
        assert _extract_offset_from_triage([1, 2, 3]) == 0

    def test_empty_dict_returns_zero(self):
        assert _extract_offset_from_triage({}) == 0

    def test_offset_key_extracted(self):
        """The 'offset' key is the canonical key read by the implementation."""
        data = {"offset": 128}
        assert _extract_offset_from_triage(data) == 128

    def test_unrecognised_key_returns_zero(self):
        """Keys other than 'offset' are not recognised → defaults to 0."""
        data = {"crash_offset": 64}
        assert _extract_offset_from_triage(data) == 0

    def test_overflow_offset_key_not_recognised(self):
        """'overflow_offset' is not a recognised key → 0."""
        data = {"overflow_offset": 256}
        assert _extract_offset_from_triage(data) == 0

    def test_offset_wins_when_mixed_with_unknown_keys(self):
        """'offset' is returned when present alongside unknown keys."""
        data = {"crash_offset": 72, "offset": 100}
        assert _extract_offset_from_triage(data) == 100

    def test_string_offset_converted_to_int(self):
        data = {"offset": "144"}
        assert _extract_offset_from_triage(data) == 144

    def test_invalid_string_falls_back_to_zero(self):
        data = {"offset": "not_a_number"}
        assert _extract_offset_from_triage(data) == 0

    def test_zero_offset_returned_as_zero(self):
        data = {"offset": 0}
        assert _extract_offset_from_triage(data) == 0

    def test_nested_dict_without_offset_returns_zero(self):
        """Nested dict without top-level 'offset' key → returns 0."""
        data = {"inner": {"offset": 88}}
        assert _extract_offset_from_triage(data) == 0

    def test_negative_offset_returned(self):
        data = {"offset": -1}
        assert _extract_offset_from_triage(data) == -1
