/*
 * Modular YARA Rule: Direct & Indirect Syscall Stubs (Syswhispers, Hell's Gate, Halo's Gate)
 * Category: injection
 */

rule Injection_Direct_Syscall_Stub {
    meta:
        description = "Detects direct x64 user-mode syscall invocation stubs bypassing user-mode EDR hooks"
        category = "injection"
        technique = "T1106"
        confidence = "high"
    strings:
        // mov r10, rcx; mov eax, <sys_id>; syscall; ret
        $stub_direct_1 = { 4C 8B D1 B8 ?? ?? 00 00 0F 05 C3 }
        // mov r10, rcx; mov eax, <sys_id>; test dword ptr [...], 1; jne ...; syscall; ret (Syswhispers2)
        $stub_direct_2 = { 4C 8B D1 B8 ?? ?? 00 00 [0-10] 0F 05 C3 }
        // x86 WOW64 direct syscall: mov eax, <id>; call fs:[0xc0]; ret
        $stub_wow64 = { B8 ?? ?? 00 00 64 FF 15 C0 00 00 00 C2 }
    condition:
        any of ($stub_direct_*) or $stub_wow64
}

rule Injection_Indirect_Syscall_Stub {
    meta:
        description = "Detects indirect syscall stubs jumping to ntdll.dll syscall instruction (Hell's Gate / Halo's Gate / Tartarus' Gate)"
        category = "injection"
        technique = "T1106"
        confidence = "high"
    strings:
        // mov r10, rcx; mov eax, <sys_id>; jmp qword ptr [rip + offset] / jmp rcx/r11
        $stub_indirect_1 = { 4C 8B D1 B8 ?? ?? 00 00 [0-12] FF 25 ?? ?? ?? ?? }
        $stub_indirect_2 = { 4C 8B D1 B8 ?? ?? 00 00 [0-12] ( FF E1 | FF E2 | 41 FF E3 ) }
    condition:
        $stub_indirect_1 or $stub_indirect_2
}
