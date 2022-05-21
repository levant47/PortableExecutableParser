#include <mystd\include_windows.h>

#pragma pack(push, 1)

void __chkstk() { }

struct PeParser
{
    u64 index;
    ListView<byte> source;
};

PeParser construct_pe_parser(ListView<byte> source)
{
    PeParser result;
    result.index = 0;
    result.source = source;
    return result;
}

Option<String> parse_dos_header(PeParser* parser)
{
    if (parser->index != 0)
    {
        auto error = String::allocate();
        error.push("Expected DOS header at location 0, not 0x");
        error.push(parser->index, 16);
        return Option<String>::construct(error);
    }
    if (parser->source.size < 0x40)
    {
        auto error = String::allocate();
        error.push("Expected DOS header to be at least 0x40, actual size 0x");
        error.push(parser->source.size, 16);
        return Option<String>::construct(error);
    }

    // check the signature
    if (parser->source.data[0] != 'M' || parser->source.data[1] != 'Z')
    {
        auto error = String::allocate();
        error.push("Expected MZ signature at the beginning of DOS header, instead got '");
        error.push((char)parser->source.data[0]);
        error.push((char)parser->source.data[1]);
        error.push("' (0x");
        error.push((u64)parser->source.data[0], 16);
        error.push(", 0x");
        error.push((u64)parser->source.data[1], 16);
        error.push(")");
        return Option<String>::construct(error);
    }

    auto pe_header_offset = *(u32*)(parser->source.data + 0x3c);
    if (pe_header_offset != 0xc0)
    {
        auto error = String::allocate();
        error.push("Expected PE header offset to be equal to 0xc0, actual value: 0x");
        error.push((u64)pe_header_offset, 16);
        return Option<String>::construct(error);
    }

    parser->index = 0x40;
    return Option<String>::empty();
}

Option<String> parse_dos_stub(PeParser* parser)
{
    if (parser->index != 0x40 || parser->source.size < 0xc0)
    {
        auto error = String::allocate();
        error.push("Expected DOS stub to be located at byte 0x40 and to be at least of size 0xc0, actual location: 0x");
        error.push(parser->index, 16);
        error.push(", actual size: 0x");
        error.push(parser->source.size, 16);
        return Option<String>::construct(error);
    }

    char stub_message[] = "This program cannot be run in DOS mode.\r\r\n";
    for (u64 i = 0; i < ARRAY_SIZE(stub_message) - 1 /* null terminator */; i++)
    {
        if (parser->source.data[parser->index + 14 + i] != stub_message[i])
        {
            auto error = String::allocate();
            error.push("Expected to find the follwing message at location 0x");
            error.push(parser->index + 14, 16);
            error.push(":\n\"");
            error.push((CString)stub_message);
            error.push("\"\ninstead got\n\"");
            error.push(StringView::construct(ARRAY_SIZE(stub_message), (char*)(parser->source.data + parser->index + 14)));
            error.push("\"\n(differing at position ");
            error.push(i + 1);
            error.push("/");
            error.push(ARRAY_SIZE(stub_message) - 1);
            error.push(", expected = 0x");
            error.push((u64)stub_message[i], 16);
            error.push(", got = 0x");
            error.push((u64)parser->source.data[parser->index + 14 + i], 16);
            error.push(")");
            return Option<String>::construct(error);
        }
    }
    parser->index = 0xc0;
    return Option<String>::empty();
}

enum PeMachineType : u16
{
    PeMachineType_UNKNOWN = 0x0, // The content of this field is assumed to be applicable to any machine type
    PeMachineType_AM33 = 0x1d3, // Matsushita AM33
    PeMachineType_AMD64 = 0x8664, // x64
    PeMachineType_ARM = 0x1c0, // ARM little endian
    PeMachineType_ARM64 = 0xaa64, // ARM64 little endian
    PeMachineType_ARMNT = 0x1c4, // ARM Thumb-2 little endian
    PeMachineType_EBC = 0xebc, // EFI byte code
    PeMachineType_I386 = 0x14c, // Intel 386 or later processors and compatible processors
    PeMachineType_IA64 = 0x200, // Intel Itanium processor family
    PeMachineType_LOONGARCH32 = 0x6232, // LoongArch 32-bit processor family
    PeMachineType_LOONGARCH64 = 0x6264, // LoongArch 64-bit processor family
    PeMachineType_M32R = 0x9041, // Mitsubishi M32R little endian
    PeMachineType_MIPS16 = 0x266, // MIPS16
    PeMachineType_MIPSFPU = 0x366, // MIPS with FPU
    PeMachineType_MIPSFPU16 = 0x466, // MIPS16 with FPU
    PeMachineType_POWERPC = 0x1f0, // Power PC little endian
    PeMachineType_POWERPCFP = 0x1f1, // Power PC with floating point support
    PeMachineType_R4000 = 0x166, // MIPS little endian
    PeMachineType_RISCV32 = 0x5032, // RISC-V 32-bit address space
    PeMachineType_RISCV64 = 0x5064, // RISC-V 64-bit address space
    PeMachineType_RISCV128 = 0x5128, // RISC-V 128-bit address space
    PeMachineType_SH3 = 0x1a2, // Hitachi SH3
    PeMachineType_SH3DSP = 0x1a3, // Hitachi SH3 DSP
    PeMachineType_SH4 = 0x1a6, // Hitachi SH4
    PeMachineType_SH5 = 0x1a8, // Hitachi SH5
    PeMachineType_THUMB = 0x1c2, // Thumb
    PeMachineType_WCEMIPSV2 = 0x169, // MIPS little-endian WCE v2
};

String to_string(PeMachineType machine)
{
    auto result = String::allocate();
    switch (machine)
    {
        case PeMachineType_UNKNOWN: result.push("UNKNOWN"); break;
        case PeMachineType_AM33: result.push("AM33"); break;
        case PeMachineType_AMD64: result.push("AMD64"); break;
        case PeMachineType_ARM: result.push("ARM"); break;
        case PeMachineType_ARM64: result.push("ARM64"); break;
        case PeMachineType_ARMNT: result.push("ARMNT"); break;
        case PeMachineType_EBC: result.push("EBC"); break;
        case PeMachineType_I386: result.push("I386"); break;
        case PeMachineType_IA64: result.push("IA64"); break;
        case PeMachineType_LOONGARCH32: result.push("LOONGARCH32"); break;
        case PeMachineType_LOONGARCH64: result.push("LOONGARCH64"); break;
        case PeMachineType_M32R: result.push("M32R"); break;
        case PeMachineType_MIPS16: result.push("MIPS16"); break;
        case PeMachineType_MIPSFPU: result.push("MIPSFPU"); break;
        case PeMachineType_MIPSFPU16: result.push("MIPSFPU16"); break;
        case PeMachineType_POWERPC: result.push("POWERPC"); break;
        case PeMachineType_POWERPCFP: result.push("POWERPCFP"); break;
        case PeMachineType_R4000: result.push("R4000"); break;
        case PeMachineType_RISCV32: result.push("RISCV32"); break;
        case PeMachineType_RISCV64: result.push("RISCV64"); break;
        case PeMachineType_RISCV128: result.push("RISCV128"); break;
        case PeMachineType_SH3: result.push("SH3"); break;
        case PeMachineType_SH3DSP: result.push("SH3DSP"); break;
        case PeMachineType_SH4: result.push("SH4"); break;
        case PeMachineType_SH5: result.push("SH5"); break;
        case PeMachineType_THUMB: result.push("THUMB"); break;
        case PeMachineType_WCEMIPSV2: result.push("WCEMIPSV2"); break;
        default:
        {
            print("to_string(PeMachineType) received an invalid argument: 0x");
            print(String::from_number((u64)machine, 16));
            print("\n");
            ExitProcess(1);
        }
    }
    return result;
}

enum PeCharacteristic : u16
{
    PeCharacteristic_RELOCS_STRIPPED = 0x0001, // Image only, Windows CE, and Microsoft Windows NT and later. This indicates that the file does not contain base relocations and must therefore be loaded at its preferred base address. If the base address is not available, the loader reports an error. The default behavior of the linker is to strip base relocations from executable (EXE) files.
    PeCharacteristic_EXECUTABLE_IMAGE = 0x0002, // Image only. This indicates that the image file is valid and can be run. If this flag is not set, it indicates a linker error.
    PeCharacteristic_LINE_NUMS_STRIPPED = 0x0004, // COFF line numbers have been removed. This flag is deprecated and should be zero.
    PeCharacteristic_LOCAL_SYMS_STRIPPED = 0x0008, // COFF symbol table entries for local symbols have been removed. This flag is deprecated and should be zero.
    PeCharacteristic_AGGRESSIVE_WS_TRIM = 0x0010, // Obsolete. Aggressively trim working set. This flag is deprecated for Windows 2000 and later and must be zero.
    PeCharacteristic_LARGE_ADDRESS_AWARE = 0x0020, // Application can handle > 2-GB addresses.
    PeCharacteristic_BYTES_REVERSED_LO = 0x0080, // Little endian: the least significant bit (LSB) precedes the most significant bit (MSB) in memory. This flag is deprecated and should be zero.
    PeCharacteristic_32BIT_MACHINE = 0x0100, // Machine is based on a 32-bit-word architecture.
    PeCharacteristic_DEBUG_STRIPPED = 0x0200, // Debugging information is removed from the image file.
    PeCharacteristic_REMOVABLE_RUN_FROM_SWAP = 0x0400, // If the image is on removable media, fully load it and copy it to the swap file.
    PeCharacteristic_NET_RUN_FROM_SWAP = 0x0800, // If the image is on network media, fully load it and copy it to the swap file.
    PeCharacteristic_SYSTEM = 0x1000, // The image file is a system file, not a user program.
    PeCharacteristic_DLL = 0x2000, // The image file is a dynamic-link library (DLL). Such files are considered executable files for almost all purposes, although they cannot be directly run.
    PeCharacteristic_UP_SYSTEM_ONLY = 0x4000, // The file should be run only on a uniprocessor machine.
    PeCharacteristic_BYTES_REVERSED_HI = 0x8000, // Big endian: the MSB precedes the LSB in memory. This flag is deprecated and should be zero.
};

String to_string(PeCharacteristic characteristic)
{
    auto result = String::allocate();
    for (u64 i = 0; i < sizeof(PeCharacteristic) * 8; i++)
    {
        u64 bit = 1 << i;
        if ((characteristic & bit) != 0)
        {
            if (bit == PeCharacteristic_RELOCS_STRIPPED) { result.push("RELOCS_STRIPPED | "); }
            else if (bit == PeCharacteristic_EXECUTABLE_IMAGE) { result.push("EXECUTABLE_IMAGE | "); }
            else if (bit == PeCharacteristic_LINE_NUMS_STRIPPED) { result.push("LINE_NUMS_STRIPPED | "); }
            else if (bit == PeCharacteristic_LOCAL_SYMS_STRIPPED) { result.push("LOCAL_SYMS_STRIPPED | "); }
            else if (bit == PeCharacteristic_AGGRESSIVE_WS_TRIM) { result.push("AGGRESSIVE_WS_TRIM | "); }
            else if (bit == PeCharacteristic_LARGE_ADDRESS_AWARE) { result.push("LARGE_ADDRESS_AWARE | "); }
            else if (bit == PeCharacteristic_BYTES_REVERSED_LO) { result.push("BYTES_REVERSED_LO | "); }
            else if (bit == PeCharacteristic_32BIT_MACHINE) { result.push("32BIT_MACHINE | "); }
            else if (bit == PeCharacteristic_DEBUG_STRIPPED) { result.push("DEBUG_STRIPPED | "); }
            else if (bit == PeCharacteristic_REMOVABLE_RUN_FROM_SWAP) { result.push("REMOVABLE_RUN_FROM_SWAP | "); }
            else if (bit == PeCharacteristic_NET_RUN_FROM_SWAP) { result.push("NET_RUN_FROM_SWAP | "); }
            else if (bit == PeCharacteristic_SYSTEM) { result.push("SYSTEM | "); }
            else if (bit == PeCharacteristic_DLL) { result.push("DLL | "); }
            else if (bit == PeCharacteristic_UP_SYSTEM_ONLY) { result.push("UP_SYSTEM_ONLY | "); }
            else if (bit == PeCharacteristic_BYTES_REVERSED_HI) { result.push("BYTES_REVERSED_HI | "); }
            else // it's some other bit that is set, better report it
            {
                result.push("UNKNOWN_BIT_");
                result.push(i);
                result.push(" | ");
            }
        }
    }
    if (result.size == 0)
    {
        result.push("0");
    }
    else
    {
        result.size -= 3; // remove the pipe
    }
    return result;
}

struct CoffHeader
{
    PeMachineType machine;
    u16 sections_count;
    u32 timestamp;
    u32 symbol_table_offset;
    u32 symbols_count;
    u16 optional_header_size;
    PeCharacteristic characteristics;
};

String to_string(CoffHeader source)
{
    auto result = String::allocate();
    result.push("COFF header\n");
    result.push("\tmachine = ");
    auto machine_string = to_string(source.machine);
    result.push(machine_string);
    machine_string.deallocate();
    result.push("\n\tsections_count = ");
    result.push((u64)source.sections_count);
    result.push("\n\ttimestamp = ");
    result.push((u64)source.timestamp);
    result.push("\n\tsymbol_table_offset = 0x");
    result.push((u64)source.symbol_table_offset, 16);
    result.push("\n\tsymbols_count = ");
    result.push((u64)source.symbols_count);
    result.push("\n\toptional_header_size = 0x");
    result.push((u64)source.optional_header_size, 16);
    result.push("\n\tcharacteristics = ");
    auto characteristics_string = to_string(source.characteristics);
    result.push(characteristics_string);
    characteristics_string.deallocate();
    result.push("\n");
    return result;
}

Result<CoffHeader, String> parse_coff_header(PeParser* parser)
{
    if (parser->index != 0xc0 || parser->source.size < parser->index + 20)
    {
        auto error = String::allocate();
        error.push("Expected COFF header to be located at byte 0xc0 and the whole file to be at least of size 0xc0 + 20, actual location: 0x");
        error.push(parser->index, 16);
        error.push(", actual size: 0x");
        error.push(parser->source.size, 16);
        return Result<CoffHeader, String>::fail(error);
    }

    if ((*(u32*)(parser->source.data + parser->index)) != 0x4550)
    {
        auto error = String::allocate();
        error.push("Expected COFF header signature 0x00004550 at location 0xc0, got 0x");
        error.push(*(u32*)(parser->source.data[parser->index]), 16);
        return Result<CoffHeader, String>::fail(error);
    }

    CoffHeader header;
    copy_memory(parser->source.data + parser->index + 4, sizeof(header), &header);

    if (!(header.characteristics & PeCharacteristic_EXECUTABLE_IMAGE))
    {
        auto error = String::allocate();
        error.push("Only image files (executables) are supported, characteristics = ");
        auto characteristics_string = to_string(header.characteristics);
        error.push(characteristics_string);
        characteristics_string.deallocate();
        return Result<CoffHeader, String>::fail(error);
    }

    parser->index += 4 + sizeof(header);
    return Result<CoffHeader, String>::success(header);
}

enum PeType : u16
{
    PeTypePe32 = 0x10b,
    PeTypePe32Plus = 0x20b,
};

String to_string(PeType type)
{
    switch (type)
    {
        case PeTypePe32: return String::copy_from_c_string("PE32");
        case PeTypePe32Plus: return String::copy_from_c_string("PE32+");
        default:
        {
            auto error = String::allocate();
            error.push("to_string(PeType) received an invalid argument: 0x");
            error.push((u64)type, 16);
            error.push("\n");
            print(error);
            ExitProcess(1);
            return {};
        }
    }
}

enum WindowsSubsystem : u16
{
    WindowsSubsystem_UNKNOWN = 0, // An unknown subsystem
    WindowsSubsystem_NATIVE = 1, // Device drivers and native Windows processes
    WindowsSubsystem_WINDOWS_GUI = 2, // The Windows graphical user interface (GUI) subsystem
    WindowsSubsystem_WINDOWS_CUI = 3, // The Windows character subsystem
    WindowsSubsystem_OS2_CUI = 5, // The OS/2 character subsystem
    WindowsSubsystem_POSIX_CUI = 7, // The Posix character subsystem
    WindowsSubsystem_NATIVE_WINDOWS = 8, // Native Win9x driver
    WindowsSubsystem_WINDOWS_CE_GUI = 9, // Windows CE
    WindowsSubsystem_EFI_APPLICATION = 10, // An Extensible Firmware Interface (EFI) application
    WindowsSubsystem_EFI_BOOT_SERVICE_DRIVER = 11, // An EFI driver with boot services
    WindowsSubsystem_EFI_RUNTIME_DRIVER = 12, // An EFI driver with run-time services
    WindowsSubsystem_EFI_ROM = 13, // An EFI ROM image
    WindowsSubsystem_XBOX = 14, // XBOX
    WindowsSubsystem_WINDOWS_BOOT_APPLICATION = 16, // Windows boot application.
};

String to_string(WindowsSubsystem subsystem)
{
    switch (subsystem)
    {
        case WindowsSubsystem_UNKNOWN: return String::copy_from_c_string("UNKNOWN");
        case WindowsSubsystem_NATIVE: return String::copy_from_c_string("NATIVE");
        case WindowsSubsystem_WINDOWS_GUI: return String::copy_from_c_string("WINDOWS_GUI");
        case WindowsSubsystem_WINDOWS_CUI: return String::copy_from_c_string("WINDOWS_CUI");
        case WindowsSubsystem_OS2_CUI: return String::copy_from_c_string("OS2_CUI");
        case WindowsSubsystem_POSIX_CUI: return String::copy_from_c_string("POSIX_CUI");
        case WindowsSubsystem_NATIVE_WINDOWS: return String::copy_from_c_string("NATIVE_WINDOWS");
        case WindowsSubsystem_WINDOWS_CE_GUI: return String::copy_from_c_string("WINDOWS_CE_GUI");
        case WindowsSubsystem_EFI_APPLICATION: return String::copy_from_c_string("EFI_APPLICATION");
        case WindowsSubsystem_EFI_BOOT_SERVICE_DRIVER: return String::copy_from_c_string("EFI_BOOT_SERVICE_DRIVER");
        case WindowsSubsystem_EFI_RUNTIME_DRIVER: return String::copy_from_c_string("EFI_RUNTIME_DRIVER");
        case WindowsSubsystem_EFI_ROM: return String::copy_from_c_string("EFI_ROM");
        case WindowsSubsystem_XBOX: return String::copy_from_c_string("XBOX");
        case WindowsSubsystem_WINDOWS_BOOT_APPLICATION: return String::copy_from_c_string("WINDOWS_BOOT_APPLICATION");
        default:
        {
            auto error = String::allocate();
            error.push("to_string(WindowsSubsystem) received an invalid argument: ");
            error.push((u64)subsystem);
            error.push("\n");
            print(error);
            ExitProcess(1);
            return {};
        }
    }
}

enum DllCharacteristic : u16
{
    DllCharacteristic_HIGH_ENTROPY_VA = 0x0020, // Image can handle a high entropy 64-bit virtual address space.
    DllCharacteristic_DYNAMIC_BASE = 0x0040, // DLL can be relocated at load time.
    DllCharacteristic_FORCE_INTEGRITY = 0x0080, // Code Integrity checks are enforced.
    DllCharacteristic_NX_COMPAT = 0x0100, // Image is NX compatible.
    DllCharacteristic_NO_ISOLATION = 0x0200, // Isolation aware, but do not isolate the image.
    DllCharacteristic_NO_SEH = 0x0400, // Does not use structured exception (SE) handling. No SE handler may be called in this image.
    DllCharacteristic_NO_BIND = 0x0800, // Do not bind the image.
    DllCharacteristic_APPCONTAINER = 0x1000, // Image must execute in an AppContainer.
    DllCharacteristic_WDM_DRIVER = 0x2000, // A WDM driver.
    DllCharacteristic_GUARD_CF = 0x4000, // Image supports Control Flow Guard.
    DllCharacteristic_TERMINAL_SERVER_AWARE = 0x8000, // Terminal Server aware.
};

String to_string(DllCharacteristic characteristics)
{
    auto result = String::allocate();
    for (u64 i = 0; i < sizeof(DllCharacteristic) * 8; i++)
    {
        auto bit = 1 << i;
        if ((characteristics & bit) != 0)
        {
            if (bit == DllCharacteristic_HIGH_ENTROPY_VA) { result.push("HIGH_ENTROPY_VA | "); }
            else if (bit == DllCharacteristic_DYNAMIC_BASE) { result.push("DYNAMIC_BASE | "); }
            else if (bit == DllCharacteristic_FORCE_INTEGRITY) { result.push("FORCE_INTEGRITY | "); }
            else if (bit == DllCharacteristic_NX_COMPAT) { result.push("NX_COMPAT | "); }
            else if (bit == DllCharacteristic_NO_ISOLATION) { result.push("NO_ISOLATION | "); }
            else if (bit == DllCharacteristic_NO_SEH) { result.push("NO_SEH | "); }
            else if (bit == DllCharacteristic_NO_BIND) { result.push("NO_BIND | "); }
            else if (bit == DllCharacteristic_APPCONTAINER) { result.push("APPCONTAINER | "); }
            else if (bit == DllCharacteristic_WDM_DRIVER) { result.push("WDM_DRIVER | "); }
            else if (bit == DllCharacteristic_GUARD_CF) { result.push("GUARD_CF | "); }
            else if (bit == DllCharacteristic_TERMINAL_SERVER_AWARE) { result.push("TERMINAL_SERVER_AWARE | "); }
            else // it's some unknown bit that is set, better report it
            {
                result.push("UNKNOWN_BIT_");
                result.push(i);
                result.push(" | ");
            }
        }
    }
    if (result.size == 0)
    {
        result.push("0");
    }
    else
    {
        result.size -= 3; // remove the pipe
    }
    return result;
}

struct CoffFields
{
    PeType magic;
    u8 major_linker_version;
    u8 minor_linker_version;
    u32 code_size;
    u32 initialized_data_size;
    u32 uninitialized_data_size;
    u32 entry_point;
    u32 code_offset;
    // Windows specific fields:
    u64 image_base;
    u32 section_alignment;
    u32 file_alignment;
    u16 major_os_version;
    u16 minor_os_version;
    u16 major_image_version;
    u16 minor_image_version;
    u16 major_subsystem_version;
    u16 minor_subsystem_version;
    u32 win32_version; // zero
    u32 image_size;
    u32 headers_size;
    u32 checksum; // zero for images (executables)
    WindowsSubsystem subsystem;
    DllCharacteristic dll_characteristics;
    u64 stack_reserve_size;
    u64 stack_commit_size;
    u64 heap_reserve_size;
    u64 heap_commit_size;
    u32 loader_flags; // zero
    u32 rva_and_sizes_count;
};

String to_string(CoffFields fields)
{
    auto result = String::allocate();

    result.push("COFF fields:\n");
    result.push("\tmagic = ");
    auto magic_string = to_string(fields.magic);
    result.push(magic_string);
    magic_string.deallocate();
    result.push("\n\tmajor_linker_version = ");
    result.push((u64)fields.major_linker_version);
    result.push("\n\tminor_linker_version = ");
    result.push((u64)fields.minor_linker_version);
    result.push("\n\tcode_size = ");
    result.push((u64)fields.code_size);
    result.push("\n\tinitialized_data_size = ");
    result.push((u64)fields.initialized_data_size);
    result.push("\n\tuninitialized_data_size = ");
    result.push((u64)fields.uninitialized_data_size);
    result.push("\n\tentry_point = ");
    result.push((u64)fields.entry_point);
    result.push("\n\tcode_offset = ");
    result.push((u64)fields.code_offset);
    result.push("\n\timage_base = 0x");
    result.push((u64)fields.image_base, 16);
    result.push("\n\tsection_alignment = ");
    result.push((u64)fields.section_alignment);
    result.push("\n\tfile_alignment = ");
    result.push((u64)fields.file_alignment);
    result.push("\n\tmajor_os_version = ");
    result.push((u64)fields.major_os_version);
    result.push("\n\tminor_os_version = ");
    result.push((u64)fields.minor_os_version);
    result.push("\n\tmajor_image_version = ");
    result.push((u64)fields.major_image_version);
    result.push("\n\tminor_image_version = ");
    result.push((u64)fields.minor_image_version);
    result.push("\n\tmajor_subsystem_version = ");
    result.push((u64)fields.major_subsystem_version);
    result.push("\n\tminor_subsystem_version = ");
    result.push((u64)fields.minor_subsystem_version);
    result.push("\n\twin32_version = ");
    result.push((u64)fields.win32_version);
    result.push("\n\timage_size = ");
    result.push((u64)fields.image_size);
    result.push("\n\theaders_size = ");
    result.push((u64)fields.headers_size);
    result.push("\n\tchecksum = ");
    result.push((u64)fields.checksum);
    result.push("\n\tsubsystem = ");
    auto subsystem_string = to_string(fields.subsystem);
    result.push(subsystem_string);
    subsystem_string.deallocate();
    result.push("\n\tdll_characteristics = ");
    auto dll_characteristics_string = to_string(fields.dll_characteristics);
    result.push(dll_characteristics_string);
    dll_characteristics_string.deallocate();
    result.push("\n\tstack_reserve_size = ");
    result.push((u64)fields.stack_reserve_size);
    result.push("\n\tstack_commit_size = ");
    result.push((u64)fields.stack_commit_size);
    result.push("\n\theap_reserve_size = ");
    result.push((u64)fields.heap_reserve_size);
    result.push("\n\theap_commit_size = ");
    result.push((u64)fields.heap_commit_size);
    result.push("\n\tloader_flags = ");
    result.push((u64)fields.loader_flags);
    result.push("\n\trva_and_sizes_count = ");
    result.push((u64)fields.rva_and_sizes_count);
    result.push("\n");

    return result;
}

Result<CoffFields, String> parse_coff_fields(PeParser* parser)
{
    if (parser->index != 0xd8)
    {
        auto error = String::allocate();
        error.push("Expected COFF fields to start at byte 0xb8, actual location: 0x");
        error.push(parser->index, 16);
        return Result<CoffFields, String>::fail(error);
    }
    if (parser->source.size < parser->index + sizeof(CoffFields))
    {
        auto error = String::allocate();
        error.push("Expected file to have at least 0x");
        error.push(sizeof(CoffFields), 16);
        error.push(" bytes for COFF fields, file actually has 0x");
        error.push(parser->source.size - parser->index, 16);
        error.push(" bytes left for COFF fields (total file size: 0x");
        error.push(parser->source.size, 16);
        error.push(" bytes, expected total file size to be at least 0x");
        error.push(0xd8 + sizeof(CoffFields));
        error.push(" bytes)");
        return Result<CoffFields, String>::fail(error);
    }

    CoffFields fields;
    copy_memory(parser->source.data + parser->index, sizeof(fields), &fields);

    if (fields.rva_and_sizes_count != 16)
    {
        auto error = String::allocate();
        error.push("Expected RVA and sizes count to be 16, got ");
        error.push((u64)fields.rva_and_sizes_count);
        return Result<CoffFields, String>::fail(error);
    }

    parser->index += sizeof(CoffFields);
    return Result<CoffFields, String>::success(fields);
}

struct PeDataDirectory
{
    u32 address;
    u32 size;
};

struct PeDataDirectories
{
    PeDataDirectory export_table;
    PeDataDirectory import_table;
    PeDataDirectory resource_table;
    PeDataDirectory exception_table;
    PeDataDirectory certificate_table;
    PeDataDirectory base_relocation_table;
    PeDataDirectory debug;
    PeDataDirectory architecture;
    PeDataDirectory global_ptr;
    PeDataDirectory tls_table;
    PeDataDirectory load_config_table;
    PeDataDirectory bound_import;
    PeDataDirectory iat;
    PeDataDirectory delay_import_descriptor;
    PeDataDirectory clr_runtime_header;
    PeDataDirectory reserved;
};

String to_string(PeDataDirectories data_directories)
{
    auto result = String::allocate();
    result.push("Data directories:");
    result.push("\n\texport_table: address = 0x");
    result.push((u64)data_directories.export_table.address, 16);
    result.push(", size = 0x");
    result.push((u64)data_directories.export_table.size, 16);
    result.push("\n\timport_table: address = 0x");
    result.push((u64)data_directories.import_table.address, 16);
    result.push(", size = 0x");
    result.push((u64)data_directories.import_table.size, 16);
    result.push("\n\tresource_table: address = 0x");
    result.push((u64)data_directories.resource_table.address, 16);
    result.push(", size = 0x");
    result.push((u64)data_directories.resource_table.size, 16);
    result.push("\n\texception_table: address = 0x");
    result.push((u64)data_directories.exception_table.address, 16);
    result.push(", size = 0x");
    result.push((u64)data_directories.exception_table.size, 16);
    result.push("\n\tcertificate_table: address = 0x");
    result.push((u64)data_directories.certificate_table.address, 16);
    result.push(", size = 0x");
    result.push((u64)data_directories.certificate_table.size, 16);
    result.push("\n\tbase_relocation_table: address = 0x");
    result.push((u64)data_directories.base_relocation_table.address, 16);
    result.push(", size = 0x");
    result.push((u64)data_directories.base_relocation_table.size, 16);
    result.push("\n\tdebug: address = 0x");
    result.push((u64)data_directories.debug.address, 16);
    result.push(", size = 0x");
    result.push((u64)data_directories.debug.size, 16);
    result.push("\n\tarchitecture: address = 0x");
    result.push((u64)data_directories.architecture.address, 16);
    result.push(", size = 0x");
    result.push((u64)data_directories.architecture.size, 16);
    result.push("\n\tglobal_ptr: address = 0x");
    result.push((u64)data_directories.global_ptr.address, 16);
    result.push(", size = 0x");
    result.push((u64)data_directories.global_ptr.size, 16);
    result.push("\n\ttls_table: address = 0x");
    result.push((u64)data_directories.tls_table.address, 16);
    result.push(", size = 0x");
    result.push((u64)data_directories.tls_table.size, 16);
    result.push("\n\tload_config_table: address = 0x");
    result.push((u64)data_directories.load_config_table.address, 16);
    result.push(", size = 0x");
    result.push((u64)data_directories.load_config_table.size, 16);
    result.push("\n\tbound_import: address = 0x");
    result.push((u64)data_directories.bound_import.address, 16);
    result.push(", size = 0x");
    result.push((u64)data_directories.bound_import.size, 16);
    result.push("\n\tiat: address = 0x");
    result.push((u64)data_directories.iat.address, 16);
    result.push(", size = 0x");
    result.push((u64)data_directories.iat.size, 16);
    result.push("\n\tdelay_import_descriptor: address = 0x");
    result.push((u64)data_directories.delay_import_descriptor.address, 16);
    result.push(", size = 0x");
    result.push((u64)data_directories.delay_import_descriptor.size, 16);
    result.push("\n\tclr_runtime_header: address = 0x");
    result.push((u64)data_directories.clr_runtime_header.address, 16);
    result.push(", size = 0x");
    result.push((u64)data_directories.clr_runtime_header.size, 16);
    result.push("\n");
    return result;
}

Result<PeDataDirectories, String> parse_data_directories(PeParser* parser)
{
    if (parser->index != 0x148)
    {
        auto error = String::allocate();
        error.push("Expected data directories to start at byte 0x148, not at 0x");
        error.push(parser->index, 16);
        return Result<PeDataDirectories, String>::fail(error);
    }
    if (parser->source.size < parser->index + sizeof(PeDataDirectories))
    {
        auto error = String::allocate();
        error.push("Not enough space in the file for data directories, expected at least 0x");
        error.push(parser->index + sizeof(PeDataDirectories), 16);
        error.push(" bytes, actual size: 0x");
        error.push(parser->source.size, 16);
        error.push(" bytes");
        return Result<PeDataDirectories, String>::fail(error);
    }

    PeDataDirectories directories;
    copy_memory(parser->source.data + parser->index, sizeof(directories), &directories);

    parser->index += sizeof(PeDataDirectories);
    return Result<PeDataDirectories, String>::success(directories);
}

enum PeSectionFlag : u32
{
    PeSectionFlag_TYPE_NO_PAD = 0x00000008, // The section should not be padded to the next boundary. This flag is obsolete and is replaced by IMAGE_SCN_ALIGN_1BYTES. This is valid only for object files.
    PeSectionFlag_CNT_CODE = 0x00000020, // The section contains executable code.
    PeSectionFlag_CNT_INITIALIZED_DATA = 0x00000040, // The section contains initialized data.
    PeSectionFlag_CNT_UNINITIALIZED_DATA = 0x00000080, // The section contains uninitialized data.
    PeSectionFlag_LNK_OTHER = 0x00000100, // Reserved for future use.
    PeSectionFlag_LNK_INFO = 0x00000200, // The section contains comments or other information. The .drectve section has this type. This is valid for object files only.
    PeSectionFlag_LNK_REMOVE = 0x00000800, // The section will not become part of the image. This is valid only for object files.
    PeSectionFlag_LNK_COMDAT = 0x00001000, // The section contains COMDAT data. For more information, see COMDAT Sections (Object Only). This is valid only for object files.
    PeSectionFlag_GPREL = 0x00008000, // The section contains data referenced through the global pointer (GP).
    PeSectionFlag_MEM_PURGEABLE = 0x00020000, // Reserved for future use.
    PeSectionFlag_MEM_16BIT = 0x00020000, // Reserved for future use.
    PeSectionFlag_MEM_LOCKED = 0x00040000, // Reserved for future use.
    PeSectionFlag_MEM_PRELOAD = 0x00080000, // Reserved for future use.
    PeSectionFlag_ALIGN_1BYTES = 0x00100000, // Align data on a 1-byte boundary. Valid only for object files.
    PeSectionFlag_ALIGN_2BYTES = 0x00200000, // Align data on a 2-byte boundary. Valid only for object files.
    PeSectionFlag_ALIGN_4BYTES = 0x00300000, // Align data on a 4-byte boundary. Valid only for object files.
    PeSectionFlag_ALIGN_8BYTES = 0x00400000, // Align data on an 8-byte boundary. Valid only for object files.
    PeSectionFlag_ALIGN_16BYTES = 0x00500000, // Align data on a 16-byte boundary. Valid only for object files.
    PeSectionFlag_ALIGN_32BYTES = 0x00600000, // Align data on a 32-byte boundary. Valid only for object files.
    PeSectionFlag_ALIGN_64BYTES = 0x00700000, // Align data on a 64-byte boundary. Valid only for object files.
    PeSectionFlag_ALIGN_128BYTES = 0x00800000, // Align data on a 128-byte boundary. Valid only for object files.
    PeSectionFlag_ALIGN_256BYTES = 0x00900000, // Align data on a 256-byte boundary. Valid only for object files.
    PeSectionFlag_ALIGN_512BYTES = 0x00A00000, // Align data on a 512-byte boundary. Valid only for object files.
    PeSectionFlag_ALIGN_1024BYTES = 0x00B00000, // Align data on a 1024-byte boundary. Valid only for object files.
    PeSectionFlag_ALIGN_2048BYTES = 0x00C00000, // Align data on a 2048-byte boundary. Valid only for object files.
    PeSectionFlag_ALIGN_4096BYTES = 0x00D00000, // Align data on a 4096-byte boundary. Valid only for object files.
    PeSectionFlag_ALIGN_8192BYTES = 0x00E00000, // Align data on an 8192-byte boundary. Valid only for object files.
    PeSectionFlag_LNK_NRELOC_OVFL = 0x01000000, // The section contains extended relocations.
    PeSectionFlag_MEM_DISCARDABLE = 0x02000000, // The section can be discarded as needed.
    PeSectionFlag_MEM_NOT_CACHED = 0x04000000, // The section cannot be cached.
    PeSectionFlag_MEM_NOT_PAGED = 0x08000000, // The section is not pageable.
    PeSectionFlag_MEM_SHARED = 0x10000000, // The section can be shared in memory.
    PeSectionFlag_MEM_EXECUTE = 0x20000000, // The section can be executed as code.
    PeSectionFlag_MEM_READ = 0x40000000, // The section can be read.
    PeSectionFlag_MEM_WRITE = 0x80000000, // The section can be written to.
};

String to_string(PeSectionFlag characteristic)
{
    auto result = String::allocate();
    for (u64 i = 0; i < sizeof(PeSectionFlag) * 8; i++)
    {
        u64 bit = 1 << i;
        if ((characteristic & bit) != 0)
        {
            if (bit == PeSectionFlag_TYPE_NO_PAD) { result.push("TYPE_NO_PAD | "); }
            else if (bit == PeSectionFlag_CNT_CODE) { result.push("CNT_CODE | "); }
            else if (bit == PeSectionFlag_CNT_INITIALIZED_DATA) { result.push("CNT_INITIALIZED_DATA | "); }
            else if (bit == PeSectionFlag_CNT_UNINITIALIZED_DATA) { result.push("CNT_UNINITIALIZED_DATA | "); }
            else if (bit == PeSectionFlag_LNK_OTHER) { result.push("LNK_OTHER | "); }
            else if (bit == PeSectionFlag_LNK_INFO) { result.push("LNK_INFO | "); }
            else if (bit == PeSectionFlag_LNK_REMOVE) { result.push("LNK_REMOVE | "); }
            else if (bit == PeSectionFlag_LNK_COMDAT) { result.push("LNK_COMDAT | "); }
            else if (bit == PeSectionFlag_GPREL) { result.push("GPREL | "); }
            else if (bit == PeSectionFlag_MEM_PURGEABLE) { result.push("MEM_PURGEABLE | "); }
            else if (bit == PeSectionFlag_MEM_16BIT) { result.push("MEM_16BIT | "); }
            else if (bit == PeSectionFlag_MEM_LOCKED) { result.push("MEM_LOCKED | "); }
            else if (bit == PeSectionFlag_MEM_PRELOAD) { result.push("MEM_PRELOAD | "); }
            else if (bit == PeSectionFlag_ALIGN_1BYTES) { result.push("ALIGN_1BYTES | "); }
            else if (bit == PeSectionFlag_ALIGN_2BYTES) { result.push("ALIGN_2BYTES | "); }
            else if (bit == PeSectionFlag_ALIGN_4BYTES) { result.push("ALIGN_4BYTES | "); }
            else if (bit == PeSectionFlag_ALIGN_8BYTES) { result.push("ALIGN_8BYTES | "); }
            else if (bit == PeSectionFlag_ALIGN_16BYTES) { result.push("ALIGN_16BYTES | "); }
            else if (bit == PeSectionFlag_ALIGN_32BYTES) { result.push("ALIGN_32BYTES | "); }
            else if (bit == PeSectionFlag_ALIGN_64BYTES) { result.push("ALIGN_64BYTES | "); }
            else if (bit == PeSectionFlag_ALIGN_128BYTES) { result.push("ALIGN_128BYTES | "); }
            else if (bit == PeSectionFlag_ALIGN_256BYTES) { result.push("ALIGN_256BYTES | "); }
            else if (bit == PeSectionFlag_ALIGN_512BYTES) { result.push("ALIGN_512BYTES | "); }
            else if (bit == PeSectionFlag_ALIGN_1024BYTES) { result.push("ALIGN_1024BYTES | "); }
            else if (bit == PeSectionFlag_ALIGN_2048BYTES) { result.push("ALIGN_2048BYTES | "); }
            else if (bit == PeSectionFlag_ALIGN_4096BYTES) { result.push("ALIGN_4096BYTES | "); }
            else if (bit == PeSectionFlag_ALIGN_8192BYTES) { result.push("ALIGN_8192BYTES | "); }
            else if (bit == PeSectionFlag_LNK_NRELOC_OVFL) { result.push("LNK_NRELOC_OVFL | "); }
            else if (bit == PeSectionFlag_MEM_DISCARDABLE) { result.push("MEM_DISCARDABLE | "); }
            else if (bit == PeSectionFlag_MEM_NOT_CACHED) { result.push("MEM_NOT_CACHED | "); }
            else if (bit == PeSectionFlag_MEM_NOT_PAGED) { result.push("MEM_NOT_PAGED | "); }
            else if (bit == PeSectionFlag_MEM_SHARED) { result.push("MEM_SHARED | "); }
            else if (bit == PeSectionFlag_MEM_EXECUTE) { result.push("MEM_EXECUTE | "); }
            else if (bit == PeSectionFlag_MEM_READ) { result.push("MEM_READ | "); }
            else if (bit == PeSectionFlag_MEM_WRITE) { result.push("MEM_WRITE | "); }
            else // unknown bit set, better report it
            {
                result.push("UNKNOWN_BIT_");
                result.push(i);
                result.push(" | ");
            }
        }
    }
    if (result.size == 0)
    {
        result.push("0");
    }
    else
    {
        result.size -= 3; // remove the last pipe
    }
    return result;
}

struct PeSectionHeader
{
    char name[8];
    u32 virtual_size;
    u32 virtual_address;
    u32 raw_data_size;
    u32 raw_data_pointer;
    u32 relocations_pointer;
    u32 line_numbers_pointer;
    u16 relocations_count;
    u16 line_numbers_count;
    PeSectionFlag characteristics;
};

Result<PeSectionHeader, String> parse_section_header(PeParser* parser)
{
    return Result<PeSectionHeader, String>::fail(String::copy_from_c_string("Parsing section table is not implemented yet!"));
}

struct PortableExecutable
{
    CoffHeader coff_header;
    CoffFields coff_fields;
    PeDataDirectories data_directories;
    List<PeSectionHeader> section_headers;
};

String to_string(PortableExecutable* pe)
{
    auto result = String::allocate();
    result.push("Portable executable:\n\t");

    auto coff_header_string = to_string(pe->coff_header);
    for (u64 i = 0; i < coff_header_string.size; i++)
    {
        result.push(coff_header_string.data[i]);
        if (coff_header_string.data[i] == '\n')
        {
            result.push('\t');
        }
    }
    coff_header_string.deallocate();

    auto coff_fields_string = to_string(pe->coff_fields);
    for (u64 i = 0; i < coff_fields_string.size; i++)
    {
        result.push(coff_fields_string.data[i]);
        if (coff_fields_string.data[i] == '\n')
        {
            result.push('\t');
        }
    }
    coff_fields_string.deallocate();

    auto data_directories_string = to_string(pe->data_directories);
    for (u64 i = 0; i < data_directories_string.size; i++)
    {
        result.push(data_directories_string.data[i]);
        if (data_directories_string.data[i] == '\n' && i != data_directories_string.size - 1)
        {
            result.push('\t');
        }
    }
    data_directories_string.deallocate();

    // TODO: show section headers

    return result;
}

Result<PortableExecutable*, String> parse_pe(ListView<byte> source)
{
    auto parser = construct_pe_parser(source);

    auto parse_dos_header_error = parse_dos_header(&parser);
    if (parse_dos_header_error.has_data) { return Result<PortableExecutable*, String>::fail(parse_dos_header_error.value); }
    auto parse_dos_stub_error = parse_dos_stub(&parser);
    if (parse_dos_stub_error.has_data) { return Result<PortableExecutable*, String>::fail(parse_dos_stub_error.value); }
    auto parse_coff_header_result = parse_coff_header(&parser);
    if (!parse_coff_header_result.is_success) { return Result<PortableExecutable*, String>::fail(parse_coff_header_result.error); }
    auto parse_coff_fields_result = parse_coff_fields(&parser);
    if (!parse_coff_fields_result.is_success) { return Result<PortableExecutable*, String>::fail(parse_coff_fields_result.error); }
    auto parse_data_directories_result = parse_data_directories(&parser);
    if (!parse_data_directories_result.is_success) { return Result<PortableExecutable*, String>::fail(parse_data_directories_result.error); }

    auto coff_header = parse_coff_header_result.value;
    auto section_headers = List<PeSectionHeader>::allocate(coff_header.sections_count); // leak in case parsing fails
    for (u64 i = 0; i < coff_header.sections_count; i++)
    {
        auto parse_section_header_result = parse_section_header(&parser);
        if (!parse_section_header_result.is_success) { return Result<PortableExecutable*, String>::fail(parse_section_header_result.error); }
        section_headers.push(parse_section_header_result.value);
    }

    auto pe = (PortableExecutable*)default_allocate(sizeof(PortableExecutable));
    pe->coff_header = parse_coff_header_result.value;
    pe->coff_fields = parse_coff_fields_result.value;
    pe->data_directories = parse_data_directories_result.value;
    pe->section_headers = section_headers;
    return Result<PortableExecutable*, String>::success(pe);
}

int main()
{
    auto target_file = CreateFile(
        "hello.exe",
        GENERIC_READ,
        FILE_SHARE_WRITE,
        nullptr,
        OPEN_EXISTING,
        0,
        nullptr
    );
    assert_winapi(target_file != INVALID_HANDLE_VALUE, "CreateFile");

    auto target_file_size = GetFileSize(target_file, nullptr);
    assert_winapi(target_file_size != INVALID_FILE_SIZE, "GetFileSize");

    auto target_file_contents = ListView<byte>::construct(target_file_size, default_allocate(target_file_size));
    auto read_target_file_result = ReadFile(
        target_file,
        target_file_contents.data,
        target_file_contents.size,
        nullptr,
        nullptr
    );
    assert_winapi(read_target_file_result != 0, "ReadFile");

    auto close_target_file_result = CloseHandle(target_file);
    assert_winapi(close_target_file_result != 0, "CloseHandle");

    auto parse_result = parse_pe(target_file_contents);
    if (!parse_result.is_success)
    {
        print(parse_result.error, "\n");
        ExitProcess(1);
    }
    auto pe = parse_result.value;
    auto pe_string = to_string(pe);
    print(pe_string);
    pe_string.deallocate();
    default_deallocate(pe);

    default_deallocate(target_file_contents.data);

    print("Success\n");

    return 0;
}
