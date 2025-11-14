"""
Result type for structured error handling.

This module provides a Result type pattern that allows tools to return
structured success/failure responses instead of mixing output and error
strings. This improves type safety and makes it easier for AI agents to
distinguish between successful results and errors.
"""

from dataclasses import dataclass, asdict
from typing import Literal, Union, Optional, Any, Dict


@dataclass
class Success:
    """Represents a successful tool execution."""
    
    data: Union[str, Dict[str, Any]]
    status: Literal["success"] = "success"
    metadata: Optional[Dict[str, Any]] = None
    
    def to_dict(self) -> Dict[str, Any]:
        """Convert to dictionary for JSON serialization."""
        result = {
            "status": self.status,
            "data": self.data,
        }
        if self.metadata:
            result["metadata"] = self.metadata
        return result


@dataclass
class Failure:
    """Represents a failed tool execution."""
    
    error_code: str
    message: str
    status: Literal["error"] = "error"
    hint: Optional[str] = None
    details: Optional[Dict[str, Any]] = None
    
    def to_dict(self) -> Dict[str, Any]:
        """Convert to dictionary for JSON serialization."""
        result = {
            "status": self.status,
            "error_code": self.error_code,
            "message": self.message,
        }
        if self.hint:
            result["hint"] = self.hint
        if self.details:
            result["details"] = self.details
        return result


# Result type is a union of Success and Failure
Result = Union[Success, Failure]

# For type hints in function signatures, use these generic types
from typing import TypeVar

T = TypeVar('T', str, Dict[str, Any])  # Allow str or dict data types


def is_success(result: Result) -> bool:
    """Check if a result is successful."""
    return isinstance(result, Success)


def is_failure(result: Result) -> bool:
    """Check if a result is a failure."""
    return isinstance(result, Failure)


def success(data: Union[str, Dict[str, Any]], **metadata) -> Success:
    """
    Create a Success result.
    
    Args:
        data: The successful output data (str or dict)
        **metadata: Additional metadata (e.g., bytes_read, execution_time)
        
    Returns:
        Success instance
    """
    return Success(data=data, metadata=metadata if metadata else None)


def failure(
    error_code: str,
    message: str,
    hint: Optional[str] = None,
    **details
) -> Failure:
    """
    Create a Failure result.
    
    Args:
        error_code: Error code (e.g., "TOOL_NOT_FOUND", "TIMEOUT")
        message: Error message
        hint: Optional hint for resolving the error
        **details: Additional error details
        
    Returns:
        Failure instance
    """
    return Failure(
        error_code=error_code,
        message=message,
        hint=hint,
        details=details if details else None
    )


def result_to_string(result: Result) -> str:
    """
    Convert a Result to a string representation for backward compatibility.
    
    This is used when tools need to return strings but we want to use
    the Result type internally.
    
    Args:
        result: Result instance
        
    Returns:
        String representation of the result
    """
    import json
    
    if isinstance(result, Success):
        # If data is a dict, convert to JSON string
        if isinstance(result.data, dict):
            return json.dumps(result.data, indent=2)
        return result.data
    else:
        # Format as error message
        msg = f"Error: {result.message}"
        if result.hint:
            msg += f"\nHint: {result.hint}"
        return msg


def result_to_dict(result: Result) -> Dict[str, Any]:
    """
    Convert a Result to a dictionary for JSON serialization.
    
    Args:
        result: Result instance
        
    Returns:
        Dictionary representation
    """
    return result.to_dict()
