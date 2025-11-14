"""
Unit tests for Result type.
"""

import pytest
from reversecore_mcp.core.result import (
    Success,
    Failure,
    Result,
    is_success,
    is_failure,
    success,
    failure,
    result_to_string,
    result_to_dict,
)


class TestSuccess:
    """Tests for Success type."""
    
    def test_success_creation(self):
        """Test creating a Success instance."""
        s = Success(data="test output")
        assert s.status == "success"
        assert s.data == "test output"
        assert s.metadata is None
    
    def test_success_with_metadata(self):
        """Test creating a Success with metadata."""
        s = Success(data="output", metadata={"bytes_read": 1024})
        assert s.status == "success"
        assert s.data == "output"
        assert s.metadata == {"bytes_read": 1024}
    
    def test_success_to_dict(self):
        """Test converting Success to dictionary."""
        s = Success(data="output", metadata={"key": "value"})
        d = s.to_dict()
        assert d == {
            "status": "success",
            "data": "output",
            "metadata": {"key": "value"}
        }
    
    def test_success_to_dict_no_metadata(self):
        """Test converting Success without metadata."""
        s = Success(data="output")
        d = s.to_dict()
        assert d == {
            "status": "success",
            "data": "output",
        }


class TestFailure:
    """Tests for Failure type."""
    
    def test_failure_creation(self):
        """Test creating a Failure instance."""
        f = Failure(error_code="TEST_ERROR", message="Test failed")
        assert f.status == "error"
        assert f.error_code == "TEST_ERROR"
        assert f.message == "Test failed"
        assert f.hint is None
        assert f.details is None
    
    def test_failure_with_hint(self):
        """Test creating a Failure with hint."""
        f = Failure(
            error_code="TOOL_NOT_FOUND",
            message="Tool not found",
            hint="Install with: apt-get install tool"
        )
        assert f.hint == "Install with: apt-get install tool"
    
    def test_failure_with_details(self):
        """Test creating a Failure with details."""
        f = Failure(
            error_code="VALIDATION_ERROR",
            message="Invalid path",
            details={"path": "/invalid/path"}
        )
        assert f.details == {"path": "/invalid/path"}
    
    def test_failure_to_dict(self):
        """Test converting Failure to dictionary."""
        f = Failure(
            error_code="ERROR",
            message="Failed",
            hint="Try again",
            details={"code": 1}
        )
        d = f.to_dict()
        assert d == {
            "status": "error",
            "error_code": "ERROR",
            "message": "Failed",
            "hint": "Try again",
            "details": {"code": 1}
        }
    
    def test_failure_to_dict_minimal(self):
        """Test converting minimal Failure."""
        f = Failure(error_code="ERROR", message="Failed")
        d = f.to_dict()
        assert d == {
            "status": "error",
            "error_code": "ERROR",
            "message": "Failed",
        }


class TestResultHelpers:
    """Tests for Result helper functions."""
    
    def test_is_success(self):
        """Test is_success helper."""
        s = Success(data="output")
        f = Failure(error_code="ERROR", message="Failed")
        
        assert is_success(s) is True
        assert is_success(f) is False
    
    def test_is_failure(self):
        """Test is_failure helper."""
        s = Success(data="output")
        f = Failure(error_code="ERROR", message="Failed")
        
        assert is_failure(s) is False
        assert is_failure(f) is True
    
    def test_success_helper(self):
        """Test success() helper function."""
        s = success("output", bytes_read=1024, execution_time=1.5)
        assert isinstance(s, Success)
        assert s.data == "output"
        assert s.metadata == {"bytes_read": 1024, "execution_time": 1.5}
    
    def test_success_helper_no_metadata(self):
        """Test success() without metadata."""
        s = success("output")
        assert isinstance(s, Success)
        assert s.data == "output"
        assert s.metadata is None
    
    def test_failure_helper(self):
        """Test failure() helper function."""
        f = failure(
            "TOOL_NOT_FOUND",
            "Tool not found",
            hint="Install it",
            path="/usr/bin/tool"
        )
        assert isinstance(f, Failure)
        assert f.error_code == "TOOL_NOT_FOUND"
        assert f.message == "Tool not found"
        assert f.hint == "Install it"
        assert f.details == {"path": "/usr/bin/tool"}
    
    def test_failure_helper_minimal(self):
        """Test failure() with minimal arguments."""
        f = failure("ERROR", "Something failed")
        assert isinstance(f, Failure)
        assert f.error_code == "ERROR"
        assert f.message == "Something failed"
        assert f.hint is None
        assert f.details is None


class TestResultConversion:
    """Tests for Result conversion functions."""
    
    def test_result_to_string_success(self):
        """Test converting Success to string."""
        s = Success(data="output data")
        result = result_to_string(s)
        assert result == "output data"
    
    def test_result_to_string_failure(self):
        """Test converting Failure to string."""
        f = Failure(
            error_code="ERROR",
            message="Something failed"
        )
        result = result_to_string(f)
        assert "Error: Something failed" in result
    
    def test_result_to_string_failure_with_hint(self):
        """Test converting Failure with hint to string."""
        f = Failure(
            error_code="ERROR",
            message="Something failed",
            hint="Try this fix"
        )
        result = result_to_string(f)
        assert "Error: Something failed" in result
        assert "Hint: Try this fix" in result
    
    def test_result_to_dict_success(self):
        """Test converting Success to dict."""
        s = Success(data="output", metadata={"key": "value"})
        d = result_to_dict(s)
        assert d == {
            "status": "success",
            "data": "output",
            "metadata": {"key": "value"}
        }
    
    def test_result_to_dict_failure(self):
        """Test converting Failure to dict."""
        f = Failure(
            error_code="ERROR",
            message="Failed",
            hint="Fix it"
        )
        d = result_to_dict(f)
        assert d == {
            "status": "error",
            "error_code": "ERROR",
            "message": "Failed",
            "hint": "Fix it"
        }


class TestResultTypeAnnotations:
    """Tests for Result type annotations."""
    
    def test_result_union_type(self):
        """Test that Result can hold either Success or Failure."""
        s: Result = Success(data="output")
        f: Result = Failure(error_code="ERROR", message="Failed")
        
        assert isinstance(s, Success)
        assert isinstance(f, Failure)
