#!/usr/bin/env python3
"""Taxonomy and DAG stress test."""

from reversecore_mcp.benchmarks.taxonomy import (
    CWE_PARENTS,
    calculate_cwe_taxonomic_score,
    get_cwe_ancestors,
    get_cwe_children,
    get_cwe_descendants,
    get_cwe_parents,
)


def test_taxonomy_dag():
    print("Testing all known CWE entries in CWE_PARENTS...")
    for cwe in CWE_PARENTS:
        parents = get_cwe_parents(cwe)
        _children = get_cwe_children(cwe)
        ancestors = get_cwe_ancestors(cwe)
        descendants = get_cwe_descendants(cwe)
        score_self, hier_self = calculate_cwe_taxonomic_score(cwe, cwe)
        assert score_self == 1.0
        assert hier_self is True
        # Ensure no self in ancestors
        assert cwe not in ancestors, f"Self in ancestors for {cwe}"
        print(
            f"{cwe}: parents={parents}, ancestors={len(ancestors)}, descendants={len(descendants)}"
        )

    print("\nTesting cross-matrix score computation for all CWE pairs...")
    all_cwes = list(CWE_PARENTS.keys())
    for c1 in all_cwes:
        for c2 in all_cwes:
            score, is_hier = calculate_cwe_taxonomic_score(c1, c2)
            assert 0.0 <= score <= 1.0
            if c1 == c2:
                assert score == 1.0 and is_hier is True

    print("Taxonomy DAG stress test passed cleanly!")


if __name__ == "__main__":
    test_taxonomy_dag()
