/*
 * Test YARA rule for integration testing
 */

rule TestRule {
    meta:
        description = "Simple test rule for Reversecore_MCP tests"
        author = "Reversecore_MCP Test Suite"
    
    strings:
        $test_string = "test"
        $hello = "Hello"
    
    condition:
        any of them
}

