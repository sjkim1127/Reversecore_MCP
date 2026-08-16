"""CWE Taxonomy Hierarchy and Taxonomic Distance Engine.

Provides hierarchical graph representations of Common Weakness Enumerations (CWEs)
and computes standardized taxonomic concordance scores between predicted and ground-truth
vulnerability classifications.
"""

from __future__ import annotations

import re

# Comprehensive parent-child mappings for vulnerability CWEs
CWE_PARENTS: dict[str, list[str]] = {
    # Memory Corruption / Buffer Bounds
    "CWE-122": ["CWE-787"],  # Heap-based Buffer Overflow -> Out-of-bounds Write
    "CWE-121": ["CWE-787"],  # Stack-based Buffer Overflow -> Out-of-bounds Write
    "CWE-125": ["CWE-119"],  # Out-of-bounds Read -> Buffer Bounds Errors
    "CWE-126": ["CWE-125"],  # Buffer Over-read -> Out-of-bounds Read
    "CWE-127": ["CWE-125"],  # Buffer Under-read -> Out-of-bounds Read
    "CWE-120": ["CWE-119"],  # Classic Buffer Overflow -> Buffer Bounds Errors
    "CWE-787": ["CWE-119"],  # Out-of-bounds Write -> Buffer Bounds Errors
    "CWE-788": ["CWE-119"],  # Access After End of Buffer -> Buffer Bounds Errors
    "CWE-786": ["CWE-119"],  # Access Before Start of Buffer -> Buffer Bounds Errors
    "CWE-805": ["CWE-119"],  # Buffer Access with Incorrect Length -> Buffer Bounds Errors
    "CWE-119": [
        "CWE-664"
    ],  # Improper Restriction of Operations within Buffer Bounds -> Resource Lifetime
    # Resource Lifecycle / Memory Management
    "CWE-416": ["CWE-672"],  # Use After Free -> Expired Resource
    "CWE-415": [
        "CWE-672",
        "CWE-761",
    ],  # Double Free -> Expired Resource / Free Non-Heap
    "CWE-761": ["CWE-672"],  # Free of Pointer not on the Heap -> Expired Resource
    "CWE-401": ["CWE-672"],  # Missing Release of Memory (Leak) -> Expired Resource
    "CWE-672": [
        "CWE-664"
    ],  # Operation on Resource after Expiration or Release -> Resource Lifetime
    # Arithmetic & Calculation Errors
    "CWE-190": ["CWE-682"],  # Integer Overflow or Wraparound -> Incorrect Calculation
    "CWE-191": ["CWE-682"],  # Integer Underflow -> Incorrect Calculation
    "CWE-682": [],  # Incorrect Calculation (Root Category)
    # Pointer & Initialization Errors
    "CWE-476": ["CWE-665"],  # NULL Pointer Dereference -> Improper Initialization
    "CWE-562": ["CWE-664"],  # Return of Stack Variable Address -> Resource Lifetime
    "CWE-824": ["CWE-665"],  # Access of Uninitialized Pointer -> Initialization
    "CWE-908": ["CWE-665"],  # Use of Uninitialized Resource -> Improper Initialization
    "CWE-665": [],  # Improper Initialization (Root Category)
    # Pillars & Root Classes
    "CWE-664": [],  # Improper Control of a Resource Through its Lifetime (Root Category)
    "CWE-703": [],  # Improper Check or Handling of Exceptional Conditions
    "CWE-707": [],  # Improper Neutralization
    # Injection Classes
    "CWE-79": ["CWE-707"],  # Cross-site Scripting -> Improper Neutralization
    "CWE-89": ["CWE-707"],  # SQL Injection -> Improper Neutralization
    "CWE-78": ["CWE-707"],  # OS Command Injection -> Improper Neutralization
}

# Canonical Human-Readable CWE Names
CWE_NAMES: dict[str, str] = {
    "CWE-122": "Heap-based Buffer Overflow",
    "CWE-121": "Stack-based Buffer Overflow",
    "CWE-125": "Out-of-bounds Read",
    "CWE-787": "Out-of-bounds Write",
    "CWE-119": "Improper Restriction of Operations within the Bounds of a Memory Buffer",
    "CWE-416": "Use After Free",
    "CWE-415": "Double Free",
    "CWE-761": "Free of Pointer not on the Heap",
    "CWE-672": "Operation on a Resource after Expiration or Release",
    "CWE-190": "Integer Overflow or Wraparound",
    "CWE-191": "Integer Underflow (Wrap or Wraparound)",
    "CWE-682": "Incorrect Calculation",
    "CWE-476": "NULL Pointer Dereference",
    "CWE-562": "Return of Stack Variable Address",
    "CWE-664": "Improper Control of a Resource Through its Lifetime",
    "CWE-665": "Improper Initialization",
    "CWE-703": "Improper Check or Handling of Exceptional Conditions",
    "CWE-707": "Improper Neutralization",
}

_CWE_PATTERN = re.compile(r"^CWE-\d+$")


def normalize_cwe_id(cwe_id: str | None) -> str:
    """Normalize input string to standard format 'CWE-XXX'.

    Examples:
        - " cwe-415 " -> "CWE-415"
        - "  cwe122  " -> "CWE-122"
        - "190" -> "CWE-190"
        - "CWE_190" -> "CWE-190"
        - "UNKNOWN" -> "UNKNOWN"
        - None -> ""

    Args:
        cwe_id: Raw CWE string or identifier.

    Returns:
        Normalized string in standard format or stripped uppercase string.
    """
    if not cwe_id:
        return ""
    raw = str(cwe_id).strip().upper()
    if not raw:
        return ""
    if raw.startswith("CWE-"):
        return raw
    if raw.startswith("CWE_"):
        return f"CWE-{raw[4:]}"
    if raw.startswith("CWE") and len(raw) > 3 and raw[3:].isdigit():
        return f"CWE-{raw[3:]}"
    if raw.isdigit():
        return f"CWE-{raw}"
    return raw


def get_cwe_parents(cwe_id: str) -> list[str]:
    """Retrieve direct parent CWE identifiers for a given CWE.

    Args:
        cwe_id: Normalized or raw CWE identifier.

    Returns:
        List of direct parent CWE strings.
    """
    norm = normalize_cwe_id(cwe_id)
    return list(CWE_PARENTS.get(norm, []))


def get_cwe_children(cwe_id: str) -> list[str]:
    """Retrieve direct child CWE identifiers for a given CWE.

    Args:
        cwe_id: Normalized or raw CWE identifier.

    Returns:
        List of direct child CWE strings.
    """
    norm = normalize_cwe_id(cwe_id)
    children: list[str] = []
    for child, parents in CWE_PARENTS.items():
        if norm in parents:
            children.append(child)
    return children


def get_cwe_ancestors(cwe_id: str) -> set[str]:
    """Retrieve all ancestor CWE identifiers recursively via graph traversal.

    Args:
        cwe_id: Normalized or raw CWE identifier.

    Returns:
        Set of all ancestor CWE strings.
    """
    cwe = normalize_cwe_id(cwe_id)
    ancestors: set[str] = set()
    queue = list(CWE_PARENTS.get(cwe, []))
    while queue:
        parent = queue.pop(0)
        if parent not in ancestors:
            ancestors.add(parent)
            queue.extend(CWE_PARENTS.get(parent, []))
    return ancestors


def get_cwe_descendants(cwe_id: str) -> set[str]:
    """Retrieve all descendant CWE identifiers recursively.

    Args:
        cwe_id: Normalized or raw CWE identifier.

    Returns:
        Set of all descendant CWE strings.
    """
    norm = normalize_cwe_id(cwe_id)
    descendants: set[str] = set()
    queue = get_cwe_children(norm)
    while queue:
        child = queue.pop(0)
        if child not in descendants:
            descendants.add(child)
            queue.extend(get_cwe_children(child))
    return descendants


def calculate_cwe_taxonomic_score(
    predicted_cwe: str | None, ground_truth_cwe: str | None
) -> tuple[float, bool]:
    """Calculate hierarchical match score between predicted and ground-truth CWE:

    - Exact match: 1.0 (is_match=True)
    - Direct parent/child relationship: 0.75 (is_match=True)
    - Shared ancestor / Class-level match: 0.50 (is_match=True)
    - Unrelated / Mismatch / Unknown: 0.0 (is_match=False)

    Args:
        predicted_cwe: Predicted CWE identifier.
        ground_truth_cwe: Ground-truth reference CWE identifier.

    Returns:
        Tuple of (score: float, is_hierarchical_match: bool).
    """
    pred = normalize_cwe_id(predicted_cwe)
    gt = normalize_cwe_id(ground_truth_cwe)

    if not pred or not gt or pred == "UNKNOWN" or gt == "UNKNOWN":
        return 0.0, False

    if not _CWE_PATTERN.match(pred) or not _CWE_PATTERN.match(gt):
        return 0.0, False

    # Exact Match
    if pred == gt:
        return 1.0, True

    # Direct Parent / Child Match
    if gt in get_cwe_parents(pred) or pred in get_cwe_parents(gt):
        return 0.75, True

    # Ancestor / Descendant or Shared Ancestor Class Match
    pred_ancestors = get_cwe_ancestors(pred)
    gt_ancestors = get_cwe_ancestors(gt)

    if gt in pred_ancestors or pred in gt_ancestors:
        return 0.50, True

    shared_ancestors = pred_ancestors.intersection(gt_ancestors)
    if shared_ancestors:
        return 0.50, True

    return 0.0, False
