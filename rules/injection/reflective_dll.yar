/*
 * Modular YARA Rule: Reflective DLL Injection / In-Memory PE Loading
 * Category: injection
 */

rule Injection_Reflective_DLL_Loader {
    meta:
        description = "Detects Reflective DLL injection loader stub, in-memory PE parser, and PEB traversal"
        category = "injection"
        technique = "T1055.001"
        confidence = "high"
    strings:
        // Export / Symbol names
        $sym_ref1 = "ReflectiveLoader" ascii wide
        $sym_ref2 = "?ReflectiveLoader@@" ascii wide
        $sym_ref3 = "_ReflectiveLoader@" ascii wide

        // x86 PEB lookup: fs:[0x30] -> Ldr -> InMemoryOrderModuleList
        $peb_x86 = { 64 A1 30 00 00 00 8B [1-2] 0C 8B [1-2] 1C }
        // x64 PEB lookup: gs:[0x60] -> Ldr -> InMemoryOrderModuleList
        $peb_x64 = { 65 48 8B 04 25 60 00 00 00 48 8B [1-2] 18 48 8B [1-2] 20 }

        // ROR13 API hash computation loop: ror edx, 13; add edx, eax
        $ror13_loop1 = { C1 C? 0D 03 ?? }
        $ror13_loop2 = { C1 CF 0D 03 F8 }

        // In-memory PE header parsing: e_lfanew lookup (offset 0x3C) and PE signature comparison
        $pe_parse1 = { 8B ?? 3C 00 00 00 81 ?? 50 45 00 00 }
        $pe_parse2 = { 48 8B ?? 3C 00 00 00 81 ?? 50 45 00 00 }
    condition:
        any of ($sym_ref*) or
        ($peb_x86 and ($ror13_loop1 or $ror13_loop2) and any of ($pe_parse*)) or
        ($peb_x64 and ($ror13_loop1 or $ror13_loop2) and any of ($pe_parse*))
}
