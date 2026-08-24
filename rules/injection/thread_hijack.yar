/*
 * Modular YARA Rule: Thread Hijacking / Thread Execution State Modification
 * Category: injection
 */

rule Injection_Thread_Hijacking {
    meta:
        description = "Detects Thread Hijacking via suspending an existing thread, capturing/modifying instruction pointer (Rip/Eip), and resuming"
        category = "injection"
        technique = "T1055.003"
        confidence = "high"
    strings:
        $open_t_k32 = "OpenThread" ascii wide
        $open_t_nt  = "NtOpenThread" ascii wide

        $suspend_k32 = "SuspendThread" ascii wide
        $suspend_nt  = "NtSuspendThread" ascii wide

        $gtc_k32 = "GetThreadContext" ascii wide
        $gtc_nt  = "NtGetContextThread" ascii wide

        $stc_k32 = "SetThreadContext" ascii wide
        $stc_nt  = "NtSetContextThread" ascii wide

        $resume_k32 = "ResumeThread" ascii wide
        $resume_nt  = "NtResumeThread" ascii wide
    condition:
        // Must contain suspension, context modification, and resumption
        (any of ($suspend_*)) and
        (any of ($stc_*)) and
        (any of ($resume_*)) and
        (any of ($open_t_*) or any of ($gtc_*))
}
