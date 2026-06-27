"""Unit tests for capa_tools module."""

from unittest.mock import patch

import pytest

from reversecore_mcp.core.result import ToolError, ToolSuccess, failure, success


class TestCapaAvailability:
    """Tests for CAPA availability check."""

    def test_is_capa_available_returns_bool(self):
        """Test that _is_capa_available returns a boolean."""
        from reversecore_mcp.tools.analysis.capa_tools import _is_capa_available

        result = _is_capa_available()
        assert isinstance(result, bool)

    def test_is_capa_available_true(self):
        """Test _is_capa_available when capa is available."""
        import sys

        # Mocking sys.modules to simulate presence of capa
        with patch.dict(sys.modules, {"capa": patch}):
            from reversecore_mcp.tools.analysis.capa_tools import _is_capa_available

            assert _is_capa_available() is True

    def test_is_capa_available_false(self):
        """Test _is_capa_available when capa is not available."""
        import sys

        # Mocking sys.modules to simulate absence of capa
        with patch.dict(sys.modules, {"capa": None}):
            from reversecore_mcp.tools.analysis.capa_tools import _is_capa_available

            assert _is_capa_available() is False


class TestRunCapa:
    """Tests for run_capa tool."""

    @pytest.mark.asyncio
    async def test_run_capa_not_installed(self):
        """Test when CAPA is not installed."""
        from reversecore_mcp.tools.analysis.capa_tools import run_capa

        with patch(
            "reversecore_mcp.tools.analysis.capa_tools._is_capa_available",
            return_value=False,
        ):
            with patch(
                "reversecore_mcp.tools.analysis.capa_tools.validate_file_path",
                return_value="/path/to/file.exe",
            ):
                result = await run_capa("/path/to/file.exe")
                assert isinstance(result, ToolError)
                assert "not installed" in result.message.lower()

    @pytest.mark.asyncio
    @patch(
        "reversecore_mcp.tools.analysis.capa_tools._is_capa_available",
        return_value=True,
    )
    @patch(
        "reversecore_mcp.tools.analysis.capa_tools.validate_file_path",
        return_value="/mock/bin",
    )
    async def test_run_capa_success(self, mock_validate, mock_avail):
        """Test the successful CAPA analysis execution path using mocked classes."""
        import sys
        from unittest.mock import MagicMock

        from reversecore_mcp.tools.analysis.capa_tools import run_capa

        # Mock objects for capa submodules
        mock_capa = MagicMock()
        mock_loader = MagicMock()
        mock_main = MagicMock()
        mock_rules = MagicMock()

        # Bind submodules as attributes to avoid import cache issues
        mock_capa.loader = mock_loader
        mock_capa.main = mock_main
        mock_capa.rules = mock_rules

        # Set default root and backend constant
        mock_main.get_default_root.return_value = "/mock/rules"
        mock_main.BACKEND_VIV = "vivisect"

        # Mock three rule objects with varying properties:
        # Rule 1: High-risk namespace, MITRE ATT&CK technique and MBC technique
        mock_rule1 = MagicMock()
        mock_rule1.meta = {
            "namespace": "defense-evasion/obfuscation",
            "description": "Obfuscated code",
            "scope": "basic block",
            "att&ck": ["T1027"],
            "mbc": ["B0002"],
        }

        # Rule 2: High-risk namespace, duplicate MITRE ATT&CK technique to verify duplication prevention
        mock_rule2 = MagicMock()
        mock_rule2.meta = {
            "namespace": "persistence/registry",
            "description": "Registry Run Key",
            "scope": "function",
            "att&ck": ["T1027"],  # duplicate
            "mbc": ["B0003"],
        }

        # Rule 3: Non-high-risk namespace, no att&ck or mbc metadata to verify missing metadata handling
        mock_rule3 = MagicMock()
        mock_rule3.meta = {
            "namespace": "file-system",
            "description": "Check file exists",
            "scope": "function",
        }

        # rules, _ = capa.rules.get_rules([rules_path])
        mock_rules.get_rules.return_value = (
            {
                "rule1": mock_rule1,
                "rule2": mock_rule2,
                "rule3": mock_rule3,
            },
            None,
        )

        # extractor = capa.loader.get_extractor(...)
        mock_extractor = MagicMock()
        mock_loader.get_extractor.return_value = mock_extractor

        # capabilities, counts = capa.main.find_capabilities(rules, extractor)
        mock_capabilities = {
            "rule1": ["match1"],
            "rule2": ["match1", "match2"],
            "rule3": ["match1"],
        }
        mock_main.find_capabilities.return_value = (mock_capabilities, {})

        with patch.dict(
            sys.modules,
            {
                "capa": mock_capa,
                "capa.loader": mock_loader,
                "capa.main": mock_main,
                "capa.rules": mock_rules,
            },
        ):
            result = await run_capa("/mock/bin")
            assert isinstance(result, ToolSuccess)
            assert result.status == "success"

            data = result.data
            assert "capabilities" in data
            assert len(data["capabilities"]) == 3

            # Verify MITRE ATT&CK mapping and deduplication
            assert len(data["mitre_attack"]) == 1
            assert "T1027" in data["mitre_attack"]

            # Verify MBC mapping
            assert len(data["mbc"]) == 2
            assert "B0002" in data["mbc"]
            assert "B0003" in data["mbc"]

            # Verify namespace counting and high-risk calculation (defense-evasion & persistence are high-risk)
            assert result.metadata["high_risk_count"] == 2
            assert result.metadata["mitre_count"] == 1
            assert "2 high-risk" in result.metadata["message"]

            caps_by_name = {cap["name"]: cap for cap in data["capabilities"]}
            assert caps_by_name["rule1"]["match_count"] == 1
            assert caps_by_name["rule1"]["namespace"] == "defense-evasion/obfuscation"
            assert caps_by_name["rule1"]["scope"] == "basic block"

            assert caps_by_name["rule2"]["match_count"] == 2
            assert caps_by_name["rule2"]["namespace"] == "persistence/registry"

            assert caps_by_name["rule3"]["match_count"] == 1
            assert caps_by_name["rule3"]["namespace"] == "file-system"
            assert caps_by_name["rule3"]["description"] == "Check file exists"
            assert caps_by_name["rule3"]["scope"] == "function"

    @pytest.mark.asyncio
    @patch(
        "reversecore_mcp.tools.analysis.capa_tools._is_capa_available",
        return_value=True,
    )
    @patch(
        "reversecore_mcp.tools.analysis.capa_tools.validate_file_path",
        return_value="/mock/bin",
    )
    async def test_run_capa_rules_load_failed(self, mock_validate, mock_avail):
        """Test failure when get_rules raises an exception."""
        import sys
        from unittest.mock import MagicMock

        from reversecore_mcp.tools.analysis.capa_tools import run_capa

        mock_capa = MagicMock()
        mock_loader = MagicMock()
        mock_main = MagicMock()
        mock_rules = MagicMock()

        # Bind submodules as attributes to avoid import cache issues
        mock_capa.loader = mock_loader
        mock_capa.main = mock_main
        mock_capa.rules = mock_rules

        mock_main.get_default_root.return_value = "/mock/rules"
        mock_rules.get_rules.side_effect = Exception("Rules database not found or corrupted")

        with patch.dict(
            sys.modules,
            {
                "capa": mock_capa,
                "capa.loader": mock_loader,
                "capa.main": mock_main,
                "capa.rules": mock_rules,
            },
        ):
            result = await run_capa("/mock/bin")
            assert isinstance(result, ToolError)
            assert result.error_code == "CAPA_RULES_LOAD_FAILED"
            assert "Rules database not found or corrupted" in result.message

    @pytest.mark.asyncio
    @patch(
        "reversecore_mcp.tools.analysis.capa_tools._is_capa_available",
        return_value=True,
    )
    @patch(
        "reversecore_mcp.tools.analysis.capa_tools.validate_file_path",
        return_value="/mock/bin",
    )
    async def test_run_capa_file_load_failed(self, mock_validate, mock_avail):
        """Test failure when get_extractor raises an exception."""
        import sys
        from unittest.mock import MagicMock

        from reversecore_mcp.tools.analysis.capa_tools import run_capa

        mock_capa = MagicMock()
        mock_loader = MagicMock()
        mock_main = MagicMock()
        mock_rules = MagicMock()

        # Bind submodules as attributes to avoid import cache issues
        mock_capa.loader = mock_loader
        mock_capa.main = mock_main
        mock_capa.rules = mock_rules

        mock_main.get_default_root.return_value = "/mock/rules"
        mock_rules.get_rules.return_value = ({}, None)
        mock_loader.get_extractor.side_effect = Exception("Invalid binary format")

        with patch.dict(
            sys.modules,
            {
                "capa": mock_capa,
                "capa.loader": mock_loader,
                "capa.main": mock_main,
                "capa.rules": mock_rules,
            },
        ):
            result = await run_capa("/mock/bin")
            assert isinstance(result, ToolError)
            assert result.error_code == "CAPA_LOAD_FILE_FAILED"
            assert "Invalid binary format" in result.message

    @pytest.mark.asyncio
    @patch(
        "reversecore_mcp.tools.analysis.capa_tools._is_capa_available",
        return_value=True,
    )
    @patch(
        "reversecore_mcp.tools.analysis.capa_tools.validate_file_path",
        return_value="/mock/bin",
    )
    async def test_run_capa_general_exception(self, mock_validate, mock_avail):
        """Test general exception handling (e.g. find_capabilities raises unexpected exception)."""
        import sys
        from unittest.mock import MagicMock

        from reversecore_mcp.tools.analysis.capa_tools import run_capa

        mock_capa = MagicMock()
        mock_loader = MagicMock()
        mock_main = MagicMock()
        mock_rules = MagicMock()

        # Bind submodules as attributes to avoid import cache issues
        mock_capa.loader = mock_loader
        mock_capa.main = mock_main
        mock_capa.rules = mock_rules

        mock_main.get_default_root.return_value = "/mock/rules"
        mock_rules.get_rules.return_value = ({}, None)
        mock_loader.get_extractor.return_value = MagicMock()
        mock_main.find_capabilities.side_effect = RuntimeError("Fatal hardware memory fault")

        with patch.dict(
            sys.modules,
            {
                "capa": mock_capa,
                "capa.loader": mock_loader,
                "capa.main": mock_main,
                "capa.rules": mock_rules,
            },
        ):
            result = await run_capa("/mock/bin")
            assert isinstance(result, ToolError)
            assert result.error_code == "CAPA_ANALYSIS_FAILED"
            assert "Fatal hardware memory fault" in result.message


class TestRunCapaQuick:
    """Tests for run_capa_quick tool."""

    @pytest.mark.asyncio
    async def test_run_capa_quick_filters_high_risk(self):
        """Test that quick scan filters to high-risk capabilities."""
        from reversecore_mcp.tools.analysis.capa_tools import run_capa_quick

        mock_result = success(
            data={
                "capabilities": [
                    {"name": "encrypt data", "namespace": "defense-evasion"},
                    {"name": "delete file", "namespace": "impact"},
                    {
                        "name": "read file size",
                        "namespace": "file-system",
                    },  # Not high-risk
                ],
                "mitre_attack": ["T1486"],
            },
            message="test",
        )

        with patch(
            "reversecore_mcp.tools.analysis.capa_tools.run_capa",
            return_value=mock_result,
        ):
            result = await run_capa_quick("/path/to/file.exe")
            assert isinstance(result, ToolSuccess)
            # Should have filtered out non-high-risk
            assert len(result.data["high_risk_capabilities"]) == 2

    @pytest.mark.asyncio
    async def test_run_capa_quick_propagates_error(self):
        """Test that errors from run_capa are propagated."""
        from reversecore_mcp.tools.analysis.capa_tools import run_capa_quick

        mock_result = failure(
            error_code="CAPA_ERROR",
            message="CAPA analysis failed",
        )

        with patch(
            "reversecore_mcp.tools.analysis.capa_tools.run_capa",
            return_value=mock_result,
        ):
            result = await run_capa_quick("/path/to/file.exe")
            assert isinstance(result, ToolError)


class TestHighRiskNamespaces:
    """Tests for high-risk namespace filtering."""

    @pytest.mark.asyncio
    async def test_anti_analysis_is_high_risk(self):
        """Test that anti-analysis is marked as high risk."""
        from reversecore_mcp.tools.analysis.capa_tools import run_capa_quick

        mock_result = success(
            data={
                "capabilities": [
                    {
                        "name": "detect debugger",
                        "namespace": "anti-analysis/anti-debugging",
                    },
                ],
                "mitre_attack": [],
            },
            message="test",
        )

        with patch(
            "reversecore_mcp.tools.analysis.capa_tools.run_capa",
            return_value=mock_result,
        ):
            result = await run_capa_quick("/path/to/file.exe")
            assert isinstance(result, ToolSuccess)
            assert len(result.data["high_risk_capabilities"]) == 1

    @pytest.mark.asyncio
    async def test_persistence_is_high_risk(self):
        """Test that persistence is marked as high risk."""
        from reversecore_mcp.tools.analysis.capa_tools import run_capa_quick

        mock_result = success(
            data={
                "capabilities": [
                    {"name": "create service", "namespace": "persistence/service"},
                ],
                "mitre_attack": [],
            },
            message="test",
        )

        with patch(
            "reversecore_mcp.tools.analysis.capa_tools.run_capa",
            return_value=mock_result,
        ):
            result = await run_capa_quick("/path/to/file.exe")
            assert isinstance(result, ToolSuccess)
            assert len(result.data["high_risk_capabilities"]) == 1
