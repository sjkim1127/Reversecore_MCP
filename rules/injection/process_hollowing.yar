/*
 * Modular YARA Rule: Process Hollowing / RunPE Injection Sequence
 * Category: injection
 */

rule Injection_Process_Hollowing {
    meta:
        description = "Detects Process Hollowing / RunPE injection via unmapping target process image, reallocating memory, and hijacking thread context"
        category = "injection"
        technique = "T1055.012"
        confidence = "high"
    strings:
        $create_proc_a = "CreateProcessA" ascii wide
        $create_proc_w = "CreateProcessW" ascii wide
        $create_proc_i = "CreateProcessInternalW" ascii wide

        $unmap_nt = "NtUnmapViewOfSection" ascii wide
        $unmap_zw = "ZwUnmapViewOfSection" ascii wide

        $alloc_va = "VirtualAllocEx" ascii wide
        $alloc_nt = "NtAllocateVirtualMemory" ascii wide

        $write_wpm = "WriteProcessMemory" ascii wide
        $write_nt  = "NtWriteVirtualMemory" ascii wide

        $context_gtc = "GetThreadContext" ascii wide
        $context_stc = "SetThreadContext" ascii wide
        $context_nt  = "NtSetContextThread" ascii wide

        $resume_rt   = "ResumeThread" ascii wide
        $resume_nt   = "NtResumeThread" ascii wide
    condition:
        // Core mandatory signature: unmapping + memory writing + context adjustment
        (any of ($unmap_*) and any of ($write_*) and any of ($context_*)) or
        // Correlated full API set (at least 4 stages present)
        (
            (any of ($create_proc_*)) and
            (any of ($unmap_*)) and
            (any of ($alloc_*)) and
            (any of ($write_*)) and
            (any of ($context_*) or any of ($resume_*))
        )
}
