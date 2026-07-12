"""
FastAPI endpoints for Reversecore MCP HTTP transport.
"""

import os
import platform
import re
import shutil
import sys
import time
import uuid
from importlib.metadata import PackageNotFoundError, version

import aiofiles
from fastapi import APIRouter, File, UploadFile
from fastapi.responses import JSONResponse

from reversecore_mcp.core.audit import AuditAction, audit_logger
from reversecore_mcp.core.config import get_config
from reversecore_mcp.core.logging_config import get_logger
from reversecore_mcp.core.metrics import metrics_collector
from reversecore_mcp.core.security import invalidate_path_cache

logger = get_logger(__name__)

router = APIRouter()

# Global check for python-magic
try:
    import magic
except ImportError:
    magic = None


async def _validate_file_magic(file_path: str, filename: str):
    """
    Validate file content matches extension using libmagic or fallback signature checks.
    """
    ext = filename.lower().split(".")[-1] if "." in filename else ""
    is_safe_ext = ext in [
        "txt",
        "pdf",
        "json",
        "yml",
        "yaml",
        "md",
        "csv",
        "log",
        "png",
        "jpg",
        "jpeg",
        "gif",
    ]

    if not magic:
        logger.warning("python-magic not installed. Using fallback header validation.")
        try:
            async with aiofiles.open(file_path, "rb") as f:
                header = await f.read(8)

            EXECUTABLE_HEADERS = [
                (b"MZ", "DOS/PE executable"),
                (b"\x7fELF", "ELF executable"),
                (b"\xca\xfe\xba\xbe", "Mach-O universal"),
                (b"\xcf\xfa\xed\xfe", "Mach-O 64-bit"),
                (b"\xce\xfa\xed\xfe", "Mach-O 32-bit"),
                (b"\xfe\xed\xfa\xce", "Mach-O 32-bit (BE)"),
                (b"\xfe\xed\xfa\xcf", "Mach-O 64-bit (BE)"),
            ]

            for magic_bytes, desc in EXECUTABLE_HEADERS:
                if header.startswith(magic_bytes):
                    if is_safe_ext:
                        raise ValueError(
                            f"Security Alert: File {filename} contains {desc} code but has safe extension. Upload rejected."
                        )
                    return
            return
        except ValueError:
            raise
        except Exception as e:
            logger.warning(f"Fallback magic validation failed: {e}")
            return

    try:
        mime = magic.from_file(file_path, mime=True)
        is_executable = mime in [
            "application/x-dosexec",
            "application/x-executable",
            "application/x-elf",
            "application/x-mach-binary",
        ]
        if is_executable and is_safe_ext:
            logger.warning(f"SECURITY: Executable content detected in {filename} (MIME: {mime})")
            raise ValueError(
                f"Security Alert: File {filename} contains executable code but has safe extension. Upload rejected."
            )
    except Exception as e:
        if "Security Alert" in str(e):
            raise
        logger.warning(f"Magic validation failed for {filename}: {e}")
        raise


@router.get("/health")
async def health():
    """Health check endpoint with dynamic dependency status and metadata-resolved version."""
    settings = get_config()

    # Dynamically resolve package version using importlib.metadata
    try:
        package_version = version("reversecore-mcp")
    except PackageNotFoundError:
        package_version = "2.1.0"  # fallback if not installed via pip/setuptools yet

    health_status = {
        "status": "healthy",
        "service": "Reversecore_MCP",
        "transport": "http",
        "version": package_version,
        "timestamp": time.time(),
        "python_version": sys.version,
        "platform": platform.system(),
        "workspace": str(settings.workspace),
        "workspace_exists": settings.workspace.exists(),
        "dependencies": {},
    }

    deps = health_status["dependencies"]

    # radare2
    if shutil.which("radare2"):
        deps["radare2"] = {
            "status": "available",
            "path": shutil.which("radare2"),
        }
    else:
        deps["radare2"] = {"status": "unavailable"}
        health_status["status"] = "degraded"

    # Java (for Ghidra)
    if shutil.which("java"):
        deps["java"] = {"status": "available", "path": shutil.which("java")}
    else:
        deps["java"] = {"status": "unavailable"}

    # Graphviz
    if shutil.which("dot"):
        deps["graphviz"] = {"status": "available", "path": shutil.which("dot")}
    else:
        deps["graphviz"] = {"status": "unavailable"}

    # YARA
    if shutil.which("yara"):
        deps["yara"] = {"status": "available", "path": shutil.which("yara")}
    else:
        deps["yara"] = {"status": "unavailable"}

    # binwalk
    if shutil.which("binwalk"):
        deps["binwalk"] = {
            "status": "available",
            "path": shutil.which("binwalk"),
        }
    else:
        deps["binwalk"] = {"status": "unavailable"}

    return JSONResponse(content=health_status)


@router.get("/health/live")
async def liveness():
    """Kubernetes liveness probe endpoint."""
    return JSONResponse(content={"status": "alive"})


@router.get("/health/ready")
async def readiness():
    """Kubernetes readiness probe endpoint."""
    settings = get_config()
    is_ready = settings.workspace.exists() and shutil.which("radare2") is not None
    if is_ready:
        return JSONResponse(content={"status": "ready", "ready": True})
    return JSONResponse(
        status_code=503,
        content={
            "status": "not_ready",
            "ready": False,
            "reason": "Dependencies not available",
        },
    )


@router.get("/metrics")
async def metrics():
    """Metrics endpoint returning collected tool metrics."""
    return JSONResponse(content=metrics_collector.get_metrics())


@router.post("/upload")
async def upload_file(file: UploadFile = File(...)):
    """
    Upload a file to the workspace for analysis.
    """
    settings = get_config()

    # Dynamic capability to disable file upload via env / config
    upload_enabled = os.getenv("REVERSECORE_UPLOAD_ENABLED", "true").lower() == "true"
    if not upload_enabled:
        return JSONResponse(
            status_code=400,
            content={
                "status": "error",
                "message": "File upload is disabled on this server.",
            },
        )

    def _secure_filename(filename: str) -> str:
        """Sanitize filename to prevent path traversal and injection."""
        filename = filename.replace("/", "_").replace("\\", "_")
        filename = re.sub(r"[^\w\-.]", "_", filename)
        if len(filename) > 200:
            name, ext = filename.rsplit(".", 1) if "." in filename else (filename, "")
            filename = name[:195] + ("." + ext if ext else "")
        return filename or "unnamed_file"

    try:
        upload_dir = settings.workspace / "uploads"
        upload_dir.mkdir(parents=True, exist_ok=True)

        original_filename = file.filename or "unnamed"
        safe_filename = f"{uuid.uuid4().hex[:8]}_{_secure_filename(original_filename)}"
        file_path = upload_dir / safe_filename

        max_size = getattr(settings, "max_upload_size", 100_000_000)
        total_size = 0
        async with aiofiles.open(file_path, "wb") as out_file:
            while content := await file.read(1024 * 64):  # 64KB chunks
                total_size += len(content)
                if total_size > max_size:
                    file_path.unlink(missing_ok=True)
                    invalidate_path_cache()
                    return JSONResponse(
                        status_code=413,
                        content={
                            "status": "error",
                            "message": f"File exceeds maximum upload size of {max_size} bytes",
                        },
                    )
                await out_file.write(content)

        try:
            await _validate_file_magic(str(file_path), safe_filename)
        except Exception as e:
            audit_logger.log_event(
                AuditAction.FILE_UPLOAD,
                safe_filename,
                "FAILURE",
                details={"error": str(e), "path": str(file_path)},
            )
            try:
                file_path.unlink()
            finally:
                invalidate_path_cache()
            raise

        audit_logger.log_event(
            AuditAction.FILE_UPLOAD,
            safe_filename,
            "SUCCESS",
            details={"path": str(file_path)},
        )
        invalidate_path_cache()

        logger.info(f"File uploaded successfully: {safe_filename} ({file_path})")
        return JSONResponse(
            content={
                "status": "success",
                "message": "File uploaded successfully",
                "filename": safe_filename,
                "original_filename": original_filename,
                "size": file_path.stat().st_size,
            }
        )
    except Exception as e:
        logger.error(f"File upload failed: {e}")
        return JSONResponse(
            status_code=500,
            content={
                "status": "error",
                "message": "File upload failed due to an internal error.",
            },
        )
