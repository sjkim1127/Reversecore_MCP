"""Unit tests for Harness and Dictionary Synthesizer."""

from pathlib import Path

import pytest

from reversecore_mcp.core.security import get_workspace_config
from reversecore_mcp.tools.cve_hunter.cve_hunter_tools import cve_synthesize_harness
from reversecore_mcp.tools.cve_hunter.harness_synthesizer import (
    build_afl_dictionary,
    extract_format_tokens_from_sample,
    generate_libfuzzer_harness,
    parse_header_for_parser_functions,
    synthesize_fuzz_harness_impl,
)


@pytest.fixture
def workspace_file():
    ws = get_workspace_config().workspace

    def _create(filename: str, content: bytes = b"\x90" * 100) -> Path:
        f = ws / filename
        f.write_bytes(content)
        return f

    return _create


@pytest.mark.unit
class TestHarnessSynthesizer:
    """Tests for harness synthesis and dictionary token extraction."""

    def test_extract_format_tokens(self):
        # Sample PNG header with IHDR chunk
        png_sample = b"\x89PNG\r\n\x1a\n\x00\x00\x00\rIHDR\x00\x00\x01\x00"
        tokens = extract_format_tokens_from_sample(png_sample)
        assert len(tokens) >= 1
        assert any("PNG" in t or "IHDR" in t for t in tokens)

    def test_build_afl_dictionary(self):
        tokens = ['"PNG"', '"IHDR"', '"IDAT"']
        dict_text = build_afl_dictionary(tokens)
        assert 'token_0 = "PNG"' in dict_text
        assert 'token_1 = "IHDR"' in dict_text
        assert 'token_2 = "IDAT"' in dict_text

    def test_parse_header_functions(self):
        header_src = """
        #ifndef PARSER_H
        #define PARSER_H
        int parse_image_chunk(const uint8_t *data, size_t size, int flags);
        void decode_audio_frame(char *buffer, int len);
        int helper_init();
        #endif
        """
        funcs = parse_header_for_parser_functions(header_src)
        assert len(funcs) >= 2
        func_names = [f["function_name"] for f in funcs]
        assert "parse_image_chunk" in func_names
        assert "decode_audio_frame" in func_names

    def test_generate_libfuzzer_harness(self):
        harness = generate_libfuzzer_harness(
            header_include="my_parser.h",
            target_function="parse_image_chunk",
            parameters="const uint8_t *data, size_t size, int flags",
        )
        assert "LLVMFuzzerTestOneInput" in harness
        assert '#include "my_parser.h"' in harness
        assert "parse_image_chunk((const uint8_t *)Data, Size, 0);" in harness

    @pytest.mark.asyncio
    async def test_invalid_path_raises(self):
        res = await synthesize_fuzz_harness_impl("/non/existent/header.h")
        assert res.status == "error"

    @pytest.mark.asyncio
    async def test_invalid_path_via_tool_wrapper(self):
        res = await cve_synthesize_harness("/non/existent/header.h")
        assert res.status == "error"

    @pytest.mark.asyncio
    async def test_synthesize_fuzz_harness_success(self, workspace_file):
        header_src = """
        int parse_packet(const uint8_t *buffer, size_t length);
        """
        header_path = workspace_file("test_parser.h", content=header_src.encode())
        sample_path = workspace_file("sample_input.bin", content=b"PK\x03\x04testpayload")

        res = await synthesize_fuzz_harness_impl(
            header_or_binary_path=str(header_path),
            sample_file_path=str(sample_path),
        )
        assert res.status == "success"
        data = res.data
        assert data is not None
        assert data["selected_target_function"] == "parse_packet"
        assert "LLVMFuzzerTestOneInput" in data["harness_source_code"]
        assert data["dictionary_token_count"] >= 1
