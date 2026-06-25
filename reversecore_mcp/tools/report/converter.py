"""
Report Converter Module for Reversecore_MCP

Provides functionality to convert Markdown reports into:
- Styled HTML (with print-friendly CSS)
- PDF (via xhtml2pdf)
- JSON (structured dictionary representation)
"""

import re
from pathlib import Path
from typing import Any

import markdown
from xhtml2pdf import pisa

from reversecore_mcp.core.logging_config import get_logger

logger = get_logger(__name__)

# CSS Stylesheet for HTML and PDF outputs
# Uses print-friendly, standard CSS supported by xhtml2pdf (CSS 2.1 subset)
REPORT_CSS = """
body {
    font-family: Helvetica, Arial, sans-serif;
    color: #333333;
    line-height: 1.5;
    margin: 0;
    padding: 20px;
    font-size: 12px;
}
@page {
    size: a4;
    margin: 2cm;
}
.container {
    max-width: 800px;
    margin: 0 auto;
}
h1, h2, h3, h4, h5, h6 {
    color: #1e293b;
    font-weight: bold;
    margin-top: 20px;
    margin-bottom: 10px;
}
h1 {
    font-size: 20px;
    border-bottom: 2px solid #3b82f6;
    padding-bottom: 5px;
    margin-top: 0;
}
h2 {
    font-size: 16px;
    border-bottom: 1px solid #e2e8f0;
    padding-bottom: 4px;
}
h3 {
    font-size: 13px;
}
p {
    margin-top: 0;
    margin-bottom: 10px;
}
table {
    width: 100%;
    border-collapse: collapse;
    margin-bottom: 15px;
    margin-top: 10px;
    font-size: 11px;
}
th, td {
    border: 1px solid #cbd5e1;
    padding: 6px 10px;
    text-align: left;
}
th {
    background-color: #f1f5f9;
    color: #1e293b;
    font-weight: bold;
}
code {
    font-family: monospace;
    background-color: #f1f5f9;
    padding: 2px 4px;
    font-size: 10px;
    color: #0f172a;
}
pre {
    background-color: #f1f5f9;
    padding: 10px;
    border: 1px solid #e2e8f0;
    margin-bottom: 15px;
}
pre code {
    background-color: transparent;
    padding: 0;
    font-size: 10px;
}
blockquote {
    border-left: 4px solid #3b82f6;
    background-color: #eff6ff;
    padding: 8px 15px;
    margin: 0 0 15px 0;
    color: #1e40af;
}
ul, ol {
    margin-top: 0;
    margin-bottom: 15px;
    padding-left: 20px;
}
li {
    margin-bottom: 4px;
}
"""


def markdown_to_html(md_content: str, title: str = "Analysis Report") -> str:
    """
    Convert Markdown content into a styled HTML document.

    Args:
        md_content: Raw Markdown content
        title: Title of the HTML document

    Returns:
        Full HTML document string
    """
    # Convert markdown to HTML body
    # Use extra extension for tables, code blocks, etc.
    html_body = markdown.markdown(md_content, extensions=["extra", "sane_lists"])

    # Wrap in full HTML document template with CSS injected
    html_document = f"""<!DOCTYPE html>
<html>
<head>
    <meta charset="utf-8">
    <title>{title}</title>
    <style>
        {REPORT_CSS}
    </style>
</head>
<body>
    <div class="container">
        {html_body}
    </div>
</body>
</html>"""
    return html_document


def html_to_pdf(html_content: str, output_pdf_path: Path) -> bool:
    """
    Convert HTML content into a PDF file using xhtml2pdf.

    Args:
        html_content: HTML document string
        output_pdf_path: Target path to write PDF to

    Returns:
        True if conversion was successful, False otherwise
    """
    try:
        # Create output directories if they don't exist
        output_pdf_path.parent.mkdir(parents=True, exist_ok=True)

        with open(output_pdf_path, "wb") as pdf_file:
            pisa_status = pisa.CreatePDF(html_content, dest=pdf_file)

        if pisa_status.err:
            logger.error(f"xhtml2pdf error: {pisa_status.err}")
            return False
        return True
    except Exception as e:
        logger.error(f"Failed to convert HTML to PDF: {e}")
        return False


def markdown_to_json(md_content: str, report_id: str) -> dict[str, Any]:
    """
    Parse Markdown report content into a structured JSON/dict representation.

    Extracts key fields, header sections, and lists (like IOCs and findings).

    Args:
        md_content: Raw Markdown content
        report_id: The ID of the report

    Returns:
        Structured dictionary
    """
    data: dict[str, Any] = {
        "report_id": report_id,
        "title": "Malware Analysis Report",
        "metadata": {},
        "sections": {},
        "raw_markdown": md_content,
    }

    # Try to extract the main title
    title_match = re.search(r"^#\s+(.+)$", md_content, re.MULTILINE)
    if title_match:
        data["title"] = title_match.group(1).strip()

    # Extract metadata block (usually formatted as key-value lines or tables)
    # Common format: **Report ID:** MAR-20260625-123456
    metadata_matches = re.findall(r"\*\*([^*]+):\*\*\s*(.+)$", md_content, re.MULTILINE)
    for key, value in metadata_matches:
        cleaned_key = key.strip().lower().replace(" ", "_")
        cleaned_value = re.sub(r"<[^>]+>", "", value.strip())  # remove any html tags
        # Clean markdown bold/italic markers
        cleaned_value = cleaned_value.replace("**", "").replace("_", "")
        data["metadata"][cleaned_key] = cleaned_value

    # Extract section-by-section based on Markdown headers (##)
    sections = re.split(r"^##\s+", md_content, flags=re.MULTILINE)
    # The first split part is the content before the first ## header
    if sections:
        header_intro = sections.pop(0)
        # Check if there is a TLP classification or severity badge in intro
        classification_match = re.search(r"TLP:\w+", header_intro)
        if classification_match:
            data["metadata"]["classification"] = classification_match.group(0)

    for section in sections:
        lines = section.split("\n")
        if not lines:
            continue
        section_title = lines[0].strip()
        # Lowercase, replace spaces, map att&ck to attack, remove ampersands, and filter out other special characters
        section_key = (
            section_title.lower().replace(" ", "_").replace("att&ck", "attack").replace("&", "")
        )
        section_key = re.sub(r"[^a-z0-9_]", "", section_key)
        section_content = "\n".join(lines[1:]).strip()

        # Parse common sections specifically
        if "ioc" in section_key or "indicator" in section_key:
            # Parse IOC items from bullet points or tables
            iocs = []
            # Extract bullet points: - `TYPE: VALUE` or - TYPE: VALUE
            bullet_iocs = re.findall(
                r"^-\s*(?:`?)([^`:\n]+)(?:`?):\s*(.+)$", section_content, re.MULTILINE
            )
            for ioc_type, ioc_val in bullet_iocs:
                # Clean up markdown formatting in key/value
                cleaned_type = ioc_type.strip().strip("`").strip("*")
                cleaned_val = ioc_val.strip().strip("`").strip("*")
                iocs.append({"type": cleaned_type, "value": cleaned_val})

            # If no bullet points match, try table rows
            if not iocs:
                # Expecting | Type | Value | description |
                rows = re.findall(
                    r"^\|\s*([^|\n]+)\s*\|\s*([^|\n]+)\s*\|",
                    section_content,
                    re.MULTILINE,
                )
                for r_type, r_val in rows:
                    r_type_clean = r_type.strip()
                    r_val_clean = r_val.strip()
                    if (
                        r_type_clean
                        and r_val_clean
                        and r_type_clean != "Type"
                        and not r_type_clean.startswith("-")
                    ):
                        iocs.append({"type": r_type_clean, "value": r_val_clean})

            data["sections"][section_key] = {
                "title": section_title,
                "content": section_content,
                "iocs": iocs,
            }
        elif "mitre" in section_key or "technique" in section_key:
            # Parse MITRE ATT&CK techniques
            techniques = []
            # Parse table rows | ID | Name | Tactic |
            rows = re.findall(
                r"^\|\s*([^|\n]+)\s*\|\s*([^|\n]+)\s*\|\s*([^|\n]+)\s*\|",
                section_content,
                re.MULTILINE,
            )
            for t_id, t_name, t_tactic in rows:
                t_id_clean = t_id.strip()
                if t_id_clean and t_id_clean != "ID" and not t_id_clean.startswith("-"):
                    techniques.append(
                        {
                            "id": t_id_clean,
                            "name": t_name.strip(),
                            "tactic": t_tactic.strip(),
                        }
                    )
            data["sections"][section_key] = {
                "title": section_title,
                "content": section_content,
                "techniques": techniques,
            }
        else:
            # General text section
            data["sections"][section_key] = {
                "title": section_title,
                "content": section_content,
            }

    return data


def convert_report(report_path: Path, output_format: str) -> Path:
    """
    Convert a Markdown report to the specified format and save it in a cache/temp directory.

    Args:
        report_path: Path to the source Markdown report
        output_format: Target format ('html', 'pdf', 'json', or 'markdown')

    Returns:
        Path to the converted file
    """
    if not report_path.exists():
        raise FileNotFoundError(f"Source report not found: {report_path}")

    output_format = output_format.lower()

    # If format is markdown, just return the original path
    if output_format == "markdown" or output_format == "md":
        return report_path

    # Read Markdown content
    with open(report_path, encoding="utf-8") as f:
        md_content = f.read()

    report_id = report_path.stem

    # Setup cache directory in workspace/tmp/report_cache
    from reversecore_mcp.core.config import get_config

    settings = get_config()
    cache_dir = settings.workspace / "tmp" / "report_cache"
    cache_dir.mkdir(parents=True, exist_ok=True)

    if output_format == "html":
        output_path = cache_dir / f"{report_id}.html"
        html_content = markdown_to_html(md_content, title=f"Report {report_id}")
        with open(output_path, "w", encoding="utf-8") as f:
            f.write(html_content)
        return output_path

    elif output_format == "pdf":
        output_path = cache_dir / f"{report_id}.pdf"
        html_content = markdown_to_html(md_content, title=f"Report {report_id}")
        success = html_to_pdf(html_content, output_path)
        if not success:
            raise RuntimeError(f"Failed to generate PDF for report: {report_id}")
        return output_path

    elif output_format == "json":
        output_path = cache_dir / f"{report_id}.json"
        import orjson

        json_data = markdown_to_json(md_content, report_id)
        with open(output_path, "wb") as f:
            f.write(orjson.dumps(json_data, option=orjson.OPT_INDENT_2))
        return output_path

    else:
        raise ValueError(f"Unsupported conversion format: {output_format}")
