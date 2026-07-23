#!/usr/bin/env python3
"""Validate function addresses before opening a Radare2 session."""

from pathlib import Path

root = Path(__file__).resolve().parents[1]
path = root / "reversecore_mcp/tools/radare2/radare2_mcp_tools.py"
text = path.read_text()

old = '''            session = await self._get_or_create_session(file_path)
            if not session.is_open:
                return {"status": "error", "message": "Failed to open file"}

            if address:
                # Validate address format
                try:
                    validate_address_format(address)
                except ValidationError as e:
                    return {"status": "error", "message": str(e)}
                result = await self._run_session_cmd(session, f"afi @ {address}")
            else:
                result = await self._run_session_cmd(session, "afi")
'''
new = '''            if address:
                # Validate request parameters before opening an external process.
                try:
                    validate_address_format(address)
                except ValidationError as e:
                    return {"status": "error", "message": str(e)}

            session = await self._get_or_create_session(file_path)
            if not session.is_open:
                return {"status": "error", "message": "Failed to open file"}

            if address:
                result = await self._run_session_cmd(session, f"afi @ {address}")
            else:
                result = await self._run_session_cmd(session, "afi")
'''
if text.count(old) != 1:
    raise RuntimeError("show-function-details validation block not found exactly once")
path.write_text(text.replace(old, new, 1))

(root / "scripts/reorder_r2_function_detail_validation.py").unlink()
(root / ".github/workflows/reorder-r2-function-validation.yml").unlink()
