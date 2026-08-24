"""Generator for synthetic evasion and anti-analysis test fixtures."""

import struct
from pathlib import Path


def create_minimal_pe32(code: bytes, strings: list[bytes] | None = None) -> bytes:
    """Create a valid minimal 32-bit PE binary with code and optional data strings."""
    if strings is None:
        strings = []

    # Calculate payload sizes
    data_payload = b"\x00".join(strings) + (b"\x00" if strings else b"")
    data_len = max(len(data_payload), 0x200)

    # DOS Header (64 bytes)
    dos_header = bytearray(64)
    dos_header[0:2] = b"MZ"
    dos_header[60:64] = struct.pack("<I", 64)  # e_lfanew

    # PE Signature (4 bytes)
    pe_sig = b"PE\x00\x00"

    # COFF Header (20 bytes)
    num_sections = 2 if strings else 1
    coff_header = struct.pack("<HHIIIHH", 0x14C, num_sections, 0, 0, 0, 224, 0x102)

    # Standard Optional Header (28 bytes)
    code_size = ((len(code) + 0x1FF) // 0x200) * 0x200
    std_fields = struct.pack(
        "<HBBIIIIII",
        0x10B,  # PE32
        1,
        0,  # Linker major/minor
        code_size,
        data_len if strings else 0,
        0,  # Uninit data
        0x1000,  # Entrypoint RVA
        0x1000,  # Base of code
        0x2000,  # Base of data
    )

    # Windows Specific Fields (68 bytes, 21 items)
    image_size = 0x3000 if strings else 0x2000
    win_fields = struct.pack(
        "<IIIHHHHHHIIIIHHIIIIII",
        0x400000,  # ImageBase
        0x1000,  # SectionAlignment
        0x200,  # FileAlignment
        4,
        0,  # OS version 4.0
        0,
        0,  # Image version
        4,
        0,  # Subsystem version 4.0
        0,  # Win32Version
        image_size,  # SizeOfImage
        0x200,  # SizeOfHeaders
        0,  # Checksum
        3,  # Subsystem: Windows Console
        0,  # DllCharacteristics
        0x100000,  # SizeOfStackReserve
        0x1000,  # SizeOfStackCommit
        0x100000,  # SizeOfHeapReserve
        0x1000,  # SizeOfHeapCommit
        0,  # LoaderFlags
        16,  # NumberOfRvaAndSizes
    )

    # Data Directories (16 * 8 = 128 bytes)
    data_dirs = b"\x00" * 128
    opt_header = std_fields + win_fields + data_dirs

    # Section Headers
    # 1. .text Section Header (40 bytes)
    text_raw_size = max(((len(code) + 0x1FF) // 0x200) * 0x200, 0x200)
    sec_text = struct.pack(
        "<8sIIIIIIHHI",
        b".text\x00\x00\x00",
        len(code),
        0x1000,  # VirtualAddress
        text_raw_size,  # SizeOfRawData
        0x200,  # PointerToRawData
        0,
        0,
        0,
        0,
        0x60000020,  # CODE | EXECUTE | READ
    )

    sec_rdata = b""
    if strings:
        # 2. .rdata Section Header (40 bytes)
        rdata_raw_size = max(((len(data_payload) + 0x1FF) // 0x200) * 0x200, 0x200)
        sec_rdata = struct.pack(
            "<8sIIIIIIHHI",
            b".rdata\x00\x00",
            len(data_payload),
            0x2000,  # VirtualAddress
            rdata_raw_size,  # SizeOfRawData
            0x200 + text_raw_size,  # PointerToRawData
            0,
            0,
            0,
            0,
            0x40000040,  # INITIALIZED_DATA | READ
        )

    headers = dos_header + pe_sig + coff_header + opt_header + sec_text + sec_rdata
    headers = headers.ljust(0x200, b"\x00")

    text_data = code.ljust(text_raw_size, b"\x90")
    if strings:
        rdata_raw_size = max(((len(data_payload) + 0x1FF) // 0x200) * 0x200, 0x200)
        rdata_data = data_payload.ljust(rdata_raw_size, b"\x00")
        return headers + text_data + rdata_data

    return headers + text_data


def generate_fixtures(output_dir: Path) -> dict[str, Path]:
    """Generate all synthetic evasion sample fixtures."""
    output_dir.mkdir(parents=True, exist_ok=True)
    generated = {}

    # 1. Clean Reference Binary (Normal code, no anti-debug, no VM artifacts)
    # Simple addition function: mov eax, [esp+4]; add eax, [esp+8]; ret
    clean_code = (
        b"\x8b\x44\x24\x04"  # mov eax, [esp+4]
        b"\x03\x44\x24\x08"  # add eax, [esp+8]
        b"\xc3"  # ret
    )
    clean_pe = create_minimal_pe32(clean_code, [b"Hello, World!\n", b"Standard application.\n"])
    clean_path = output_dir / "clean_reference.exe"
    clean_path.write_bytes(clean_pe)
    generated["clean_reference"] = clean_path

    # 2. PEB BeingDebugged & NtGlobalFlag Anti-Debug Sample
    # mov eax, fs:[0x30] (PEB)
    # cmp byte ptr [eax+2], 0 (BeingDebugged)
    # jne 0x401015 (exit evasive)
    # mov ecx, [eax+0x68] (NtGlobalFlag)
    # and ecx, 0x70
    # cmp ecx, 0x70
    # jne 0x40101e
    # ret
    peb_code = (
        b"\x64\xa1\x30\x00\x00\x00"  # mov eax, fs:[0x30]
        b"\x80\x78\x02\x00"  # cmp byte ptr [eax+2], 0
        b"\x75\x0f"  # jne +15
        b"\x8b\x48\x68"  # mov ecx, [eax+0x68]
        b"\x83\xe1\x70"  # and ecx, 0x70
        b"\x83\xf9\x70"  # cmp ecx, 0x70
        b"\x74\x06"  # je +6
        b"\x31\xc0\xc3"  # xor eax, eax; ret (benign return)
        b"\xb8\x01\x00\x00\x00\xc3"  # mov eax, 1; ret (debugger detected)
    )
    peb_pe = create_minimal_pe32(peb_code)
    peb_path = output_dir / "synthetic_peb_debug.exe"
    peb_path.write_bytes(peb_pe)
    generated["peb_debug"] = peb_path

    # 3. RDTSC Timing Anomaly Sample
    # rdtsc
    # mov esi, eax
    # mov edi, edx
    # nop; nop; nop; nop
    # rdtsc
    # sub eax, esi
    # cmp eax, 0x500
    # ja 0x40101b (exit evasive)
    # ret
    rdtsc_code = (
        b"\x0f\x31"  # rdtsc
        b"\x89\xc6"  # mov esi, eax
        b"\x89\xd7"  # mov edi, edx
        b"\x90\x90\x90\x90"  # nops
        b"\x0f\x31"  # rdtsc
        b"\x29\xf0"  # sub eax, esi
        b"\x3d\x00\x05\x00\x00"  # cmp eax, 0x500
        b"\x77\x04"  # ja +4
        b"\x31\xc0\xc3"  # xor eax, eax; ret
        b"\xb8\xff\x00\x00\x00\xc3"  # mov eax, 0xff; ret
    )
    rdtsc_pe = create_minimal_pe32(rdtsc_code)
    rdtsc_path = output_dir / "synthetic_rdtsc_timing.exe"
    rdtsc_path.write_bytes(rdtsc_pe)
    generated["rdtsc_timing"] = rdtsc_path

    # 4. CPUID Hypervisor & VMware I/O Port Backdoor Sample
    # mov eax, 1; cpuid; bt ecx, 31; jc 0x40101a
    # mov eax, 0x564d5868 ('VMXh'); mov dx, 0x5658 ('VX'); in eax, dx
    # ret
    cpuid_code = (
        b"\xb8\x01\x00\x00\x00"  # mov eax, 1
        b"\x0f\xa2"  # cpuid
        b"\x0f\xba\xe1\x1f"  # bt ecx, 31
        b"\x72\x10"  # jc +16
        b"\xb8\x68\x58\x4d\x56"  # mov eax, 0x564d5868 ('VMXh')
        b"\xba\x58\x56\x00\x00"  # mov edx, 0x5658 ('VX')
        b"\xed"  # in eax, dx
        b"\x31\xc0\xc3"  # xor eax, eax; ret
        b"\xb8\x01\x00\x00\x00\xc3"  # mov eax, 1; ret
    )
    vm_strings = [
        b"VMwareVMware",
        b"VBoxVBoxVBox",
        b"00:05:69:11:22:33",
        b"vboxmouse.sys",
        b"HARDWARE\\DEVICEMAP\\Scsi\\Scsi Port 0",
        b"VBoxService.exe",
    ]
    cpuid_pe = create_minimal_pe32(cpuid_code, vm_strings)
    cpuid_path = output_dir / "synthetic_cpuid_vm.exe"
    cpuid_path.write_bytes(cpuid_pe)
    generated["cpuid_vm"] = cpuid_path

    # 5. Opaque Predicates & SEH Chain Overwrite Sample
    # mov fs:[0], esp (SEH overwrite)
    # xor eax, eax; test eax, eax; jz 0x401013 (Opaque invariant)
    # stc; jnc 0x40101a
    # ret
    opaque_code = (
        b"\x64\x89\x25\x00\x00\x00\x00"  # mov dword ptr fs:[0], esp
        b"\x31\xc0"  # xor eax, eax
        b"\x85\xc0"  # test eax, eax
        b"\x74\x05"  # jz +5 (always taken)
        b"\x90\x90\x90\x90\x90"  # junk
        b"\xf9"  # stc
        b"\x73\x05"  # jnc +5 (never taken)
        b"\x31\xc0\xc3"  # xor eax, eax; ret
        b"\xb8\x02\x00\x00\x00\xc3"  # mov eax, 2; ret
    )
    opaque_pe = create_minimal_pe32(opaque_code)
    opaque_path = output_dir / "synthetic_opaque_seh.exe"
    opaque_path.write_bytes(opaque_pe)
    generated["opaque_seh"] = opaque_path

    # 6. Combined Heavily Evasive Sample (All 4 pillars active)
    combined_code = peb_code + rdtsc_code + cpuid_code + opaque_code
    combined_pe = create_minimal_pe32(
        combined_code,
        [
            b"VMwareVMware",
            b"08:00:27:aa:bb:cc",
            b"vmmouse.sys",
            b"SANDBOX",
            b"SOFTWARE\\Oracle\\VirtualBox Guest Additions",
        ],
    )
    combined_path = output_dir / "synthetic_combined_evasion.exe"
    combined_path.write_bytes(combined_pe)
    generated["combined_evasion"] = combined_path

    return generated


if __name__ == "__main__":
    fixtures_dir = Path(__file__).parent
    res = generate_fixtures(fixtures_dir)
    for name, path in res.items():
        print(f"Generated {name}: {path} ({path.stat().st_size} bytes)")
