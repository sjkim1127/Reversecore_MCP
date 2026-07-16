"""Make reversecore_pip_audit_policy importable in unit tests.

The policy package lives at ``ci/pip_audit_policy/src/`` and is NOT installed
in the main project venv by design (it is a CI-only tool).  This conftest
inserts its ``src`` directory at the front of sys.path so pytest can collect
the tests without requiring ``pip install -e ci/pip_audit_policy/``.
"""

from __future__ import annotations

import sys
from pathlib import Path

_POLICY_SRC = Path(__file__).resolve().parents[3] / "ci" / "pip_audit_policy" / "src"

if str(_POLICY_SRC) not in sys.path:
    sys.path.insert(0, str(_POLICY_SRC))
