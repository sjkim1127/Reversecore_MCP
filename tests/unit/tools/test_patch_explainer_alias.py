import reversecore_mcp.tools.common.patch_explainer as common_module
import reversecore_mcp.tools.patch_explainer as alias_module


def test_patch_explainer_alias_exports():
    # Verify everything is correctly exported and identical
    assert alias_module.explain_patch == common_module.explain_patch
    assert alias_module._generate_explanation == common_module._generate_explanation
    assert alias_module._generate_diff_snippet == common_module._generate_diff_snippet
    assert "explain_patch" in alias_module.__all__
