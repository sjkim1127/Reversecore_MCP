/*
 * Modular YARA Rule: Early Bird & Asynchronous Procedure Call (APC) Injection
 * Category: injection
 */

rule Injection_APC_EarlyBird {
    meta:
        description = "Detects Early Bird APC queueing into newly spawned suspended processes before main thread execution"
        category = "injection"
        technique = "T1055.004"
        confidence = "high"
    strings:
        $apc_quser = "QueueUserAPC" ascii wide
        $apc_nt    = "NtQueueApcThread" ascii wide
        $apc_zw    = "ZwQueueApcThread" ascii wide

        $create_p_a = "CreateProcessA" ascii wide
        $create_p_w = "CreateProcessW" ascii wide

        $alloc_va   = "VirtualAllocEx" ascii wide
        $alloc_nt   = "NtAllocateVirtualMemory" ascii wide

        $write_wpm  = "WriteProcessMemory" ascii wide
        $write_nt   = "NtWriteVirtualMemory" ascii wide

        $resume_rt  = "ResumeThread" ascii wide
        $resume_nt  = "NtResumeThread" ascii wide
        $resume_ar  = "NtAlertResumeThread" ascii wide
    condition:
        // Core APC API combined with target process memory preparation and thread resumption
        (any of ($apc_*)) and
        (any of ($alloc_*) or any of ($write_*)) and
        (any of ($create_p_*) or any of ($resume_*))
}
