#!/usr/bin/env python3
"""
Synthetic packer fixture generator for Reversecore_MCP testing.

Generates deterministic synthetic binary fixtures representing:
1. UPX packed PE binary (W+X sections, SizeOfRawData=0, UPX signatures).
2. VMProtect packed PE binary (.vmp sections, VMProtect markers, high entropy).
3. ConfuserEx protected .NET PE binary (#Strings, Confuser.Core, ConfusedByAttribute).
4. PyInstaller bundled PE binary (MEI magic, _MEIPASS, base_library.zip overlay).
5. Authenticode signed PE binary (Security Directory WIN_CERTIFICATE in overlay).
6. Clean reference PE binary (MSVC compiler, standard sections, zero overlay, normal entropy).
7. Clean reference ELF binary (GCC compiler, standard sections, zero overlay, normal entropy).
"""

from __future__ import annotations

import os
import struct
from pathlib import Path

FIXTURES_DIR = Path(__file__).parent


def _build_pe_headers(
    is_64: bool = False,
    num_sections: int = 1,
    entry_point_rva: int = 0x1000,
    image_base: int = 0x00400000,
    section_alignment: int = 0x1000,
    file_alignment: int = 0x200,
    size_of_image: int = 0x10000,
    size_of_headers: int = 0x400,
    security_dir_rva: int = 0,
    security_dir_size: int = 0,
    sections: list[dict] | None = None,
) -> bytes:
    """Construct minimal valid PE DOS + COFF + Optional + Section headers."""
    # DOS Header (64 bytes)
    e_lfanew = 0x80  # PE header at offset 128
    dos_header = bytearray(b"\x00" * 0x80)
    dos_header[0:2] = b"MZ"
    struct.pack_into("<I", dos_header, 0x3C, e_lfanew)

    # PE Signature
    pe_sig = b"PE\x00\x00"

    # COFF Header (20 bytes)
    machine = 0x8664 if is_64 else 0x14C
    sec_count = len(sections) if sections else num_sections
    opt_hdr_size = 0xF0 if is_64 else 0xE0
    characteristics = 0x0102 if not is_64 else 0x0022  # Executable image

    coff_header = struct.pack(
        "<HHIIIHH",
        machine,
        sec_count,
        0x66C00000,  # Timestamp
        0,  # PointerToSymbolTable
        0,  # NumberOfSymbols
        opt_hdr_size,
        characteristics,
    )

    # Optional Header (Standard + Windows + DataDirectories)
    magic = 0x20B if is_64 else 0x10B
    major_linker = 14
    minor_linker = 29
    size_of_code = 0x1000
    size_of_init_data = 0x1000
    size_of_uninit_data = 0

    if not is_64:
        standard_opt = struct.pack(
            "<HBBIIIIII",
            magic,
            major_linker,
            minor_linker,
            size_of_code,
            size_of_init_data,
            size_of_uninit_data,
            entry_point_rva,
            0x1000,  # BaseOfCode
            0x2000,  # BaseOfData
        )
        windows_opt = struct.pack(
            "<IIIHHHHHHIIIIHHIIIIII",
            image_base,
            section_alignment,
            file_alignment,
            6,  # MajorOS
            0,  # MinorOS
            0,  # MajorImage
            0,  # MinorImage
            6,  # MajorSubsys
            0,  # MinorSubsys
            0,  # Win32Version
            size_of_image,
            size_of_headers,
            0,  # CheckSum
            2,  # Subsystem (GUI=2, Console=3)
            0x8140,  # DllCharacteristics
            0x100000,  # SizeOfStackReserve
            0x1000,  # SizeOfStackCommit
            0x100000,  # SizeOfHeapReserve
            0x1000,  # SizeOfHeapCommit
            0,  # LoaderFlags
            16,  # NumberOfRvaAndSizes
        )
    else:
        standard_opt = struct.pack(
            "<HBBIIIII",
            magic,
            major_linker,
            minor_linker,
            size_of_code,
            size_of_init_data,
            size_of_uninit_data,
            entry_point_rva,
            0x1000,  # BaseOfCode
        )
        windows_opt = struct.pack(
            "<QIIHHHHHHIIIIHHQQQQII",
            image_base,
            section_alignment,
            file_alignment,
            6,
            0,
            0,
            0,
            6,
            0,
            0,
            size_of_image,
            size_of_headers,
            0,
            3,  # Subsystem (Console)
            0x8140,
            0x100000,
            0x1000,
            0x100000,
            0x1000,
            0,
            16,
        )

    # 16 Data Directories (8 bytes each)
    data_dirs = bytearray(16 * 8)
    if security_dir_rva > 0 or security_dir_size > 0:
        # Index 4 = IMAGE_DIRECTORY_ENTRY_SECURITY
        struct.pack_into("<II", data_dirs, 4 * 8, security_dir_rva, security_dir_size)

    # Section Headers (40 bytes each)
    sec_headers = bytearray()
    if sections:
        for s in sections:
            name = s.get("name", "").encode("ascii")[:8].ljust(8, b"\x00")
            v_size = s.get("virtual_size", 0x1000)
            v_addr = s.get("virtual_address", 0x1000)
            r_size = s.get("raw_size", 0x200)
            r_ptr = s.get("raw_offset", 0x400)
            chars = s.get("characteristics", 0x60000020)

            sec_headers += struct.pack(
                "<8sIIIIIIHHI",
                name,
                v_size,
                v_addr,
                r_size,
                r_ptr,
                0,  # PointerToRelocations
                0,  # PointerToLinenumbers
                0,  # NumberOfRelocations
                0,  # NumberOfLinenumbers
                chars,
            )

    header_block = (
        dos_header + pe_sig + coff_header + standard_opt + windows_opt + data_dirs + sec_headers
    )
    if len(header_block) < size_of_headers:
        header_block += b"\x00" * (size_of_headers - len(header_block))

    return bytes(header_block)


def _generate_high_entropy_bytes(size: int, seed: int = 42) -> bytes:
    """Generate deterministic high-entropy pseudo-random bytes (~7.92 bits/byte)."""
    # Linear congruential generator with byte shuffling
    out = bytearray(size)
    state = seed & 0xFFFFFFFF
    for i in range(size):
        state = (1664525 * state + 1013904223) & 0xFFFFFFFF
        out[i] = (state >> 16) & 0xFF
    return bytes(out)


def create_synthetic_upx() -> bytes:
    """Build synthetic UPX packed PE binary."""
    sections = [
        {
            "name": "UPX0",
            "virtual_size": 0x10000,
            "virtual_address": 0x1000,
            "raw_size": 0,  # 0 Raw Size anomaly
            "raw_offset": 0x400,
            "characteristics": 0xE0000080,  # W+X+R (Uninitialized Data)
        },
        {
            "name": "UPX1",
            "virtual_size": 0x6000,
            "virtual_address": 0x11000,
            "raw_size": 0x2000,
            "raw_offset": 0x400,
            "characteristics": 0xE0000020,  # W+X+R (Code / W⊕X violation)
        },
        {
            "name": ".rsrc",
            "virtual_size": 0x1000,
            "virtual_address": 0x17000,
            "raw_size": 0x400,
            "raw_offset": 0x2400,
            "characteristics": 0xC0000040,  # Initialized data
        },
    ]

    headers = _build_pe_headers(
        is_64=False,
        entry_point_rva=0x12000,  # Entry point in UPX1
        sections=sections,
        size_of_headers=0x400,
        size_of_image=0x18000,
    )

    # Section 1 (UPX1) data: high entropy payload with UPX signatures
    upx1_payload = bytearray(_generate_high_entropy_bytes(0x2000, seed=1234))
    # Stamp UPX signature and info string
    upx_sig = b"$Info: This file is packed under the UPX protocol www.upx.org $\x00"
    upx1_payload[0x100 : 0x100 + len(upx_sig)] = upx_sig
    upx1_payload[0x1000 : 0x1000 + 4] = b"UPX!"
    upx1_payload[0x1004:0x1008] = b"\x03\x96\x0e\x00"  # UPX 3.96 version tag

    # Section 2 (.rsrc) data
    rsrc_payload = b"\x00" * 0x400

    return headers + bytes(upx1_payload) + rsrc_payload


def create_synthetic_vmprotect() -> bytes:
    """Build synthetic VMProtect protected PE64 binary."""
    sections = [
        {
            "name": ".text",
            "virtual_size": 0x1000,
            "virtual_address": 0x1000,
            "raw_size": 0x400,
            "raw_offset": 0x400,
            "characteristics": 0x60000020,  # Code R+X
        },
        {
            "name": ".vmp0",
            "virtual_size": 0x8000,
            "virtual_address": 0x2000,
            "raw_size": 0x4000,
            "raw_offset": 0x800,
            "characteristics": 0xE0000060,  # Code+Data W+X+R
        },
        {
            "name": ".vmp1",
            "virtual_size": 0x2000,
            "virtual_address": 0xA000,
            "raw_size": 0x800,
            "raw_offset": 0x4800,
            "characteristics": 0xC0000040,  # Data W+R
        },
    ]

    headers = _build_pe_headers(
        is_64=True,
        entry_point_rva=0x2500,  # Entry point in .vmp0
        sections=sections,
        size_of_headers=0x400,
        size_of_image=0xC000,
    )

    text_data = b"\x90" * 0x400

    # .vmp0 high entropy virtualized bytecode with VMProtect markers
    vmp0_data = bytearray(_generate_high_entropy_bytes(0x4000, seed=5678))
    vmp_begin = b"VMProtect begin\x00"
    vmp_marker = b"VMProtect marker\x00"
    vmp0_data[0x200 : 0x200 + len(vmp_begin)] = vmp_begin
    vmp0_data[0x600 : 0x600 + len(vmp_marker)] = vmp_marker

    vmp1_data = _generate_high_entropy_bytes(0x800, seed=9012)

    return headers + text_data + bytes(vmp0_data) + vmp1_data


def create_synthetic_confuserex() -> bytes:
    """Build synthetic ConfuserEx protected .NET PE binary."""
    sections = [
        {
            "name": ".text",
            "virtual_size": 0x3000,
            "virtual_address": 0x2000,
            "raw_size": 0x2000,
            "raw_offset": 0x400,
            "characteristics": 0x60000020,  # Code R+X
        },
        {
            "name": ".rsrc",
            "virtual_size": 0x1000,
            "virtual_address": 0x5000,
            "raw_size": 0x400,
            "raw_offset": 0x2400,
            "characteristics": 0x40000040,  # Data R
        },
        {
            "name": ".reloc",
            "virtual_size": 0x1000,
            "virtual_address": 0x6000,
            "raw_size": 0x200,
            "raw_offset": 0x2800,
            "characteristics": 0x42000040,  # Discardable
        },
    ]

    headers = _build_pe_headers(
        is_64=False,
        entry_point_rva=0x2250,
        sections=sections,
        size_of_headers=0x400,
        size_of_image=0x7000,
    )

    # .text contains .NET metadata tables and ConfuserEx signature markers
    text_data = bytearray(b"\x00" * 0x2000)
    # .NET CLI header markers
    net_markers = (
        b"BSJB\x01\x00\x01\x00\x00\x00\x00\x00v4.0.30319\x00\x00#~#Strings#US#GUID#Blob\x00"
    )
    text_data[0x100 : 0x100 + len(net_markers)] = net_markers

    confuser_strs = (
        b"ConfuserEx v1.0.0\x00"
        b"ConfusedByAttribute\x00"
        b"Confuser.Core 1.6.0\x00"
        b".NET Framework 4.8\x00"
        b"mscoree.dll\x00_CorExeMain\x00"
    )
    text_data[0x300 : 0x300 + len(confuser_strs)] = confuser_strs

    rsrc_data = b"\x00" * 0x400
    reloc_data = b"\x00" * 0x200

    return headers + bytes(text_data) + rsrc_data + reloc_data


def create_synthetic_pyinstaller() -> bytes:
    """Build synthetic PyInstaller bundled PE binary with MEI overlay."""
    sections = [
        {
            "name": ".text",
            "virtual_size": 0x1000,
            "virtual_address": 0x1000,
            "raw_size": 0x400,
            "raw_offset": 0x400,
            "characteristics": 0x60000020,
        },
        {
            "name": ".data",
            "virtual_size": 0x1000,
            "virtual_address": 0x2000,
            "raw_size": 0x200,
            "raw_offset": 0x800,
            "characteristics": 0xC0000040,
        },
    ]

    headers = _build_pe_headers(
        is_64=False,
        entry_point_rva=0x1050,
        sections=sections,
        size_of_headers=0x400,
        size_of_image=0x3000,
    )

    text_data = b"\x90" * 0x400
    data_data = b"\x00" * 0x200

    # Overlay starts at extent 0xA00 (headers 0x400 + text 0x400 + data 0x200)
    mei_magic = b"MEI\x0c\x0b\x0a\x0b\x0e"
    pyinstaller_overlay = (
        mei_magic
        + b"_MEIPASS\x00"
        + b"pyimod01_os_path\x00"
        + b"base_library.zip\x00"
        + _generate_high_entropy_bytes(0x1000, seed=777)
    )

    return headers + text_data + data_data + pyinstaller_overlay


def create_synthetic_authenticode() -> bytes:
    """Build synthetic Authenticode signed PE binary with Security Directory in overlay."""
    extent = 0xA00  # 0x400 headers + 0x400 .text + 0x200 .data
    cert_size = 0x200

    sections = [
        {
            "name": ".text",
            "virtual_size": 0x1000,
            "virtual_address": 0x1000,
            "raw_size": 0x400,
            "raw_offset": 0x400,
            "characteristics": 0x60000020,
        },
        {
            "name": ".data",
            "virtual_size": 0x1000,
            "virtual_address": 0x2000,
            "raw_size": 0x200,
            "raw_offset": 0x800,
            "characteristics": 0xC0000040,
        },
    ]

    headers = _build_pe_headers(
        is_64=False,
        entry_point_rva=0x1050,
        sections=sections,
        size_of_headers=0x400,
        size_of_image=0x3000,
        security_dir_rva=extent,
        security_dir_size=cert_size,
    )

    text_data = b"\x90" * 0x400
    data_data = b"\x00" * 0x200

    # WIN_CERTIFICATE struct at offset 0xA00:
    # dwLength (0x200), wRevision (0x0200), wCertificateType (0x0002 PKCS#7)
    win_cert = struct.pack("<IHH", cert_size, 0x0200, 0x0002) + (b"\x30\x82" + b"\xaa" * 0x1F8)

    return headers + text_data + data_data + win_cert


def create_synthetic_clean_pe() -> bytes:
    """Build clean reference PE binary (MSVC compiled, standard sections, zero overlay)."""
    sections = [
        {
            "name": ".text",
            "virtual_size": 0x1000,
            "virtual_address": 0x1000,
            "raw_size": 0x600,
            "raw_offset": 0x400,
            "characteristics": 0x60000020,  # Code R+X
        },
        {
            "name": ".rdata",
            "virtual_size": 0x1000,
            "virtual_address": 0x2000,
            "raw_size": 0x400,
            "raw_offset": 0xA00,
            "characteristics": 0x40000040,  # Data R
        },
        {
            "name": ".data",
            "virtual_size": 0x1000,
            "virtual_address": 0x3000,
            "raw_size": 0x200,
            "raw_offset": 0xE00,
            "characteristics": 0xC0000040,  # Data W+R
        },
    ]

    headers = _build_pe_headers(
        is_64=False,
        entry_point_rva=0x1100,
        sections=sections,
        size_of_headers=0x400,
        size_of_image=0x4000,
    )

    # Standard x86 assembly code (mov, push, call, ret)
    text_data = (
        b"\x55\x8b\xec\x83\xec\x10\x53\x56\x57\xe8\x00\x00\x00\x00\x58\x83\xc0\x0e"
        + b"\x90" * (0x600 - 18)
    )

    # Read-only string constants
    rdata = b"Microsoft Visual C/C++ 2019 MSVCR140.dll\x00Hello, World!\x00" + b"\x00" * (
        0x400 - 45
    )

    # Initialized data
    data_data = b"\x01\x00\x00\x00\x02\x00\x00\x00" + b"\x00" * (0x200 - 8)

    return headers + text_data + rdata + data_data


def create_synthetic_clean_elf() -> bytes:
    """Build clean reference ELF64 binary (GCC compiled, standard sections, zero overlay)."""
    # ELF64 Header (64 bytes)
    e_ident = b"\x7fELF\x02\x01\x01\x00\x00\x00\x00\x00\x00\x00\x00\x00"
    e_type = 2  # ET_EXEC
    e_machine = 62  # EM_X86_64
    e_version = 1
    e_entry = 0x401000
    e_phoff = 64  # Program headers immediately after ELF header
    e_shoff = 0x300  # Section headers at 0x300
    e_flags = 0
    e_ehsize = 64
    e_phentsize = 56
    e_phnum = 1
    e_shentsize = 64
    e_shnum = 4  # null, .text, .rodata, .shstrtab
    e_shstrndx = 3

    elf_hdr = e_ident + struct.pack(
        "<HHIQQQIHHHHHH",
        e_type,
        e_machine,
        e_version,
        e_entry,
        e_phoff,
        e_shoff,
        e_flags,
        e_ehsize,
        e_phentsize,
        e_phnum,
        e_shentsize,
        e_shnum,
        e_shstrndx,
    )

    # Program Header (PT_LOAD)
    # p_type, p_flags (R+X=5), p_offset, p_vaddr, p_paddr, p_filesz, p_memsz, p_align
    ph = struct.pack("<IIQQQQQQ", 1, 5, 0, 0x400000, 0x400000, 0x400, 0x400, 0x1000)

    # Shstrtab content
    shstrtab = b"\x00.text\x00.rodata\x00.shstrtab\x00"

    # Section Headers (4 entries)
    # 0: NULL
    sh0 = b"\x00" * 64
    # 1: .text (offset 1 in shstrtab)
    sh1 = struct.pack(
        "<IIQQQQIIQQ",
        1,  # name offset ".text"
        1,  # SHT_PROGBITS
        6,  # SHF_ALLOC | SHF_EXECINSTR
        0x401000,  # addr
        0x100,  # offset
        0x80,  # size
        0,
        0,
        16,
        0,
    )
    # 2: .rodata (offset 7 in shstrtab)
    sh2 = struct.pack(
        "<IIQQQQIIQQ",
        7,  # name offset ".rodata"
        1,  # SHT_PROGBITS
        2,  # SHF_ALLOC
        0x402000,
        0x180,
        0x60,
        0,
        0,
        4,
        0,
    )
    # 3: .shstrtab (offset 15 in shstrtab)
    sh3 = struct.pack(
        "<IIQQQQIIQQ",
        15,  # name offset ".shstrtab"
        3,  # SHT_STRTAB
        0,
        0,
        0x200,
        len(shstrtab),
        0,
        0,
        1,
        0,
    )

    body = bytearray(b"\x00" * 0x400)
    body[0:64] = elf_hdr
    body[64:120] = ph

    # .text at 0x100
    text_bytes = b"\x48\x31\xc0\x48\x89\xc7\x48\x8d\x35\x00\x00\x00\x00\x0f\x05\xc3" + b"\x90" * 112
    body[0x100 : 0x100 + len(text_bytes)] = text_bytes

    # .rodata at 0x180
    rodata_bytes = (
        b"GCC: (Ubuntu 11.4.0-1ubuntu1~22.04) 11.4.0\x00Hello Linux ELF\x00" + b"\x00" * 38
    )
    body[0x180 : 0x180 + len(rodata_bytes)] = rodata_bytes

    # .shstrtab at 0x200
    body[0x200 : 0x200 + len(shstrtab)] = shstrtab

    # Section Headers at 0x300
    sh_block = sh0 + sh1 + sh2 + sh3
    body[0x300 : 0x300 + len(sh_block)] = sh_block

    return bytes(body)


def generate_all_fixtures(output_dir: Path | None = None) -> dict[str, Path]:
    """Generate all synthetic packer fixtures to disk."""
    out = output_dir or FIXTURES_DIR
    out.mkdir(parents=True, exist_ok=True)

    fixtures = {
        "synthetic_upx.exe": create_synthetic_upx(),
        "synthetic_vmprotect.exe": create_synthetic_vmprotect(),
        "synthetic_confuserex.exe": create_synthetic_confuserex(),
        "synthetic_pyinstaller.exe": create_synthetic_pyinstaller(),
        "synthetic_authenticode.exe": create_synthetic_authenticode(),
        "synthetic_clean_pe.exe": create_synthetic_clean_pe(),
        "synthetic_clean_elf": create_synthetic_clean_elf(),
    }

    generated_paths = {}
    for filename, content in fixtures.items():
        filepath = out / filename
        filepath.write_bytes(content)
        # Make ELF executable
        if "elf" in filename:
            os.chmod(filepath, 0o755)
        generated_paths[filename] = filepath

    return generated_paths


if __name__ == "__main__":
    paths = generate_all_fixtures()
    for name, p in paths.items():
        print(f"Generated fixture: {name} ({p.stat().st_size} bytes)")
