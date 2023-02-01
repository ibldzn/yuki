#pragma once

#if !defined(_WIN32) || !defined(_WIN64)
#  error "Windows only.."
#endif

#include "defines.hpp"
#include "fnv1a.hpp"
#include "mem.hpp"
#include "pointer.hpp"
#include "str.hpp"
#include <optional>
#include <span>
#include <string_view>

#pragma push_macro("WIN32_LEAN_AND_MEAN")
#if !defined(WIN32_LEAN_AND_MEAN)
#  define WIN32_LEAN_AND_MEAN
#endif
#include <windows.h>
#include <winnt.h>
#include <winternl.h>
#pragma pop_macro("WIN32_LEAN_AND_MEAN")

namespace yuki {
    namespace internal {
        extern "C" IMAGE_DOS_HEADER __ImageBase;
    }

    struct Module {
        struct Section {
            Pointer rva = {};
            std::size_t size = {};
        };

        constexpr Module() = default;

        constexpr Module(Pointer base_address)
            : m_base_address(base_address)
        {
        }

        constexpr Pointer get() const;
        constexpr bool operator!() const;
        explicit constexpr operator bool() const;
        static Module self();

        IMAGE_DOS_HEADER* get_dos_header() const;
        IMAGE_NT_HEADERS* get_nt_headers() const;
        IMAGE_DATA_DIRECTORY* get_image_directory(unsigned long directory) const;

        Section get_section_info(fnv1a::type sect_name_hash) const;
        Pointer get_proc_addr(fnv1a::type proc_name_hash) const;

        Pointer pattern_scan(std::span<const std::optional<std::uint8_t>> byte_array) const;
        Pointer pattern_scan(fnv1a::type sect_name_hash, std::span<const std::optional<std::uint8_t>> byte_array) const;

        Pointer find_string(
            fnv1a::type string_hash,
            std::size_t max_length = static_cast<std::size_t>(-1),
            fnv1a::type section_to_search = FNV_CT(".rdata")
        ) const;

        std::vector<Pointer> get_xrefs_to(Pointer target) const;
        std::vector<Pointer> get_xrefs_to(Pointer target, fnv1a::type section_hash) const;
        std::vector<Pointer> get_xrefs_to(Pointer target, Pointer start, std::size_t size) const;

        std::vector<Pointer> get_string_xrefs(
            fnv1a::type string_hash,
            std::size_t max_length = static_cast<std::size_t>(-1),
            fnv1a::type section_to_search = FNV_CT(".rdata")
        ) const;

        Pointer get_vtable_ptr(fnv1a::type type_descriptor_hash) const;

        template <typename Fn>
        static void enum_modules(Fn fn);
        static Module find(std::string_view module_name, bool lowercase = true);
        static Module find(fnv1a::type module_name_hash, bool lowercase = true);
        static Module find_or_load(const char* module_name, bool lowercase = true);

        static PEB* get_peb();

    private:
        static Pointer handle_forwarded_export(Pointer export_addr);

    private:
        Pointer m_base_address = nullptr;
    };

    YUKI_FORCE_INLINE constexpr Pointer Module::get() const
    {
        return m_base_address;
    }

    YUKI_FORCE_INLINE constexpr bool Module::operator!() const
    {
        return !m_base_address;
    }

    YUKI_FORCE_INLINE constexpr Module::operator bool() const
    {
        return m_base_address != nullptr;
    }

    YUKI_FORCE_INLINE Module Module::self()
    {
        return { &internal::__ImageBase };
    }

    YUKI_FORCE_INLINE IMAGE_DOS_HEADER* Module::get_dos_header() const
    {
        auto dos = m_base_address.as<IMAGE_DOS_HEADER*>();

        if (!dos || dos->e_magic != IMAGE_DOS_SIGNATURE) {
            return nullptr;
        }

        return dos;
    }

    YUKI_FORCE_INLINE IMAGE_NT_HEADERS* Module::get_nt_headers() const
    {
        const auto dos = get_dos_header();
        if (!dos) {
            return nullptr;
        }

        auto nt = m_base_address.offset(dos->e_lfanew).as<IMAGE_NT_HEADERS*>();
        if (!nt || nt->Signature != IMAGE_NT_SIGNATURE) {
            return nullptr;
        }

        return nt;
    }

    YUKI_FORCE_INLINE IMAGE_DATA_DIRECTORY* Module::get_image_directory(unsigned long directory) const
    {
        if (directory > IMAGE_DIRECTORY_ENTRY_COM_DESCRIPTOR /*14*/) {
            return nullptr;
        }

        const auto nt = get_nt_headers();
        if (!nt) {
            return nullptr;
        }

        switch (nt->OptionalHeader.Magic) {
            case IMAGE_NT_OPTIONAL_HDR32_MAGIC: {
                IMAGE_OPTIONAL_HEADER32* ioh = reinterpret_cast<IMAGE_OPTIONAL_HEADER32*>(&nt->OptionalHeader);
                return &ioh->DataDirectory[directory];
            }
            case IMAGE_NT_OPTIONAL_HDR64_MAGIC: {
                IMAGE_OPTIONAL_HEADER64* ioh = reinterpret_cast<IMAGE_OPTIONAL_HEADER64*>(&nt->OptionalHeader);
                return &ioh->DataDirectory[directory];
            }
        }

        return nullptr;
    }

    YUKI_FORCE_INLINE Module::Section Module::get_section_info(fnv1a::type sect_name_hash) const
    {
        const auto nt = get_nt_headers();
        if (!nt) {
            return {};
        }

        // @MSDN: https://learn.microsoft.com/en-us/windows/win32/api/winnt/ns-winnt-image_section_header
        //
        // An 8-byte, null-padded UTF-8 string. There is no terminating null character
        // if the string is exactly eight characters long. For longer names, this member
        // contains a forward slash (/) followed by an ASCII representation of a decimal
        // number that is an offset into the string table. Executable images do not use
        // a string table and do not support section names longer than eight characters.
        constexpr auto get_sect_name = [](BYTE* sect_name) {
            std::size_t i = 0;
            for (; i < 8; ++i) {
                if (sect_name[i] == '\0') {
                    break;
                }
            }
            return std::string_view { reinterpret_cast<const char*>(sect_name), i };
        };

        IMAGE_SECTION_HEADER* sect_header = IMAGE_FIRST_SECTION(nt);
        for (unsigned short i = 0, sect_count = nt->FileHeader.NumberOfSections; i < sect_count; ++i, ++sect_header) {
            if (FNV_RT(get_sect_name(sect_header->Name)) == sect_name_hash) {
                return { sect_header->PointerToRawData, sect_header->SizeOfRawData };
            }
        }

        return {};
    }

    YUKI_FORCE_INLINE Pointer Module::get_proc_addr(fnv1a::type proc_name_hash) const
    {
        const auto exp_dir = get_image_directory(IMAGE_DIRECTORY_ENTRY_EXPORT);
        if (!exp_dir || exp_dir->Size == 0) {
            return nullptr;
        }

        const auto exp_base = m_base_address.offset(exp_dir->VirtualAddress);
        const auto ied = exp_base.as<IMAGE_EXPORT_DIRECTORY*>();
        if (!ied) [[YUKI_ATTR_UNLIKELY]] {
            return nullptr;
        }

        const auto names = m_base_address.offset(ied->AddressOfNames).as<unsigned long*>();
        const auto funcs = m_base_address.offset(ied->AddressOfFunctions).as<unsigned long*>();
        const auto ords = m_base_address.offset(ied->AddressOfNameOrdinals).as<unsigned short*>();
        if (!names || !funcs || !ords) [[YUKI_ATTR_UNLIKELY]] {
            return nullptr;
        }

        // if it is by ordinal
        if (proc_name_hash <= static_cast<unsigned short>(-1)) {
            const auto proc_addr = m_base_address.offset(funcs[proc_name_hash - ied->Base]).as<std::uintptr_t>();

            if (
                proc_addr >= exp_base.as<std::uintptr_t>()
                && proc_addr < exp_base.offset(exp_dir->Size).as<std::uintptr_t>()
            ) {
                return handle_forwarded_export(proc_addr);
            }

            return proc_addr;
        }

        for (unsigned long i = 0, num_of_names = ied->NumberOfNames; i < num_of_names; ++i) {
            const std::string_view proc_name = m_base_address.offset(names[i]).as<const char*>();
            if (FNV_RT(proc_name) != proc_name_hash) {
                continue;
            }

            const auto ord = m_base_address.offset(ords[i]).as<unsigned short>();
            const auto proc_addr = m_base_address.offset(funcs[ord]).as<std::uintptr_t>();

            // handle forwarded export
            if (
                proc_addr >= exp_base.as<std::uintptr_t>()
                && proc_addr < exp_base.offset(exp_dir->Size).as<std::uintptr_t>()
            ) {
                return handle_forwarded_export(proc_addr);
            }

            return proc_addr;
        }

        return nullptr;
    }

    inline Pointer Module::pattern_scan(std::span<const std::optional<std::uint8_t>> byte_array) const
    {
        const auto nt = get_nt_headers();
        if (!nt) {
            return nullptr;
        }
        return yuki::pattern_scan(m_base_address, nt->OptionalHeader.SizeOfImage, byte_array);
    }

    inline Pointer Module::pattern_scan(fnv1a::type sect_name_hash, std::span<const std::optional<std::uint8_t>> byte_array) const
    {
        const auto [sect_rva, sect_size] = get_section_info(sect_name_hash);
        if (!sect_rva || !sect_size) {
            return nullptr;
        }
        return yuki::pattern_scan(m_base_address.offset(sect_rva.as<std::ptrdiff_t>()), sect_size, byte_array);
    }

    inline Pointer Module::find_string(
        fnv1a::type string_hash,
        std::size_t max_length,
        fnv1a::type section_to_search
    ) const
    {
        const auto [sect_rva, sect_size] = get_section_info(section_to_search);
        if (!sect_rva || !sect_size) {
            return nullptr;
        }

        auto begin = m_base_address.offset(sect_rva.as<std::ptrdiff_t>()).as<const byte*>();
        const auto end = begin + sect_size;
        const auto have_max_length = max_length != static_cast<std::size_t>(-1);

        for (; begin < end; ++begin) {
            const Pointer cur = begin;

            const auto str = have_max_length
                ? std::string_view { cur.as<const char*>(), max_length }
                : std::string_view { cur.as<const char*>() };

            if (string_hash == FNV_RT(str)) {
                return cur;
            }

            begin += str.length();
        }

        return nullptr;
    }

    inline std::vector<Pointer> Module::get_xrefs_to(Pointer target) const
    {
        const auto nt = get_nt_headers();
        if (!nt) {
            return {};
        }
        return get_xrefs_to(target, m_base_address, nt->OptionalHeader.SizeOfImage);
    }

    inline std::vector<Pointer> Module::get_xrefs_to(Pointer target, fnv1a::type section_hash) const
    {
        const auto [sect_rva, sect_size] = get_section_info(section_hash);
        if (!sect_rva || !sect_size) {
            return {};
        }
        return get_xrefs_to(target, m_base_address.offset(sect_rva.as<std::ptrdiff_t>()), sect_size);
    }

    inline std::vector<Pointer> Module::get_xrefs_to(Pointer target, Pointer start, std::size_t size) const
    {
        std::vector<Pointer> ret;

#if defined(YUKI_ARCH_X86_64)
        auto begin = start.as<const byte*>();
        const auto end = begin + size - sizeof(std::int32_t);

        for (; begin && begin < end; ++begin) {
            if (const Pointer cur = begin;
                cur.relative() == target
                || m_base_address.offset(cur.deref<std::int32_t>()) == target) {
                ret.push_back(cur);
                begin += sizeof(std::int32_t) - 1;
            }
        }
#elif defined(YUKI_ARCH_X86)
        const auto ida_pattern = address_to_ida_pattern(&target, sizeof(Pointer));
        const auto bytes = pattern_to_bytes(ida_pattern);

        auto begin = start.as<std::uintptr_t>();
        const auto end = begin + size;

        while (begin && begin < end) {
            const auto xref = yuki::pattern_scan(begin, size, bytes);
            if (!xref) {
                break;
            }

            ret.push_back(xref);
            begin = xref.offset(sizeof(Pointer)).as<decltype(begin)>();
        }
#endif

        return ret;
    }

    inline std::vector<Pointer> Module::get_string_xrefs(
        fnv1a::type string_hash,
        std::size_t max_length,
        fnv1a::type section_to_search
    ) const
    {
        const Pointer string = find_string(string_hash, max_length, section_to_search);
        if (!string) {
            return {};
        }
        return get_xrefs_to(string);
    }

    inline Pointer Module::get_vtable_ptr(fnv1a::type type_descriptor_hash) const
    {
        Pointer rtti_type_desc = find_string(type_descriptor_hash, static_cast<std::size_t>(-1), FNV_CT(".data"));
        if (!rtti_type_desc) {
            return nullptr;
        }

        rtti_type_desc.self_offset(-static_cast<std::ptrdiff_t>(sizeof(Pointer)) * 2);

        for (const auto& xref : get_xrefs_to(rtti_type_desc, FNV_CT(".rdata"))) {
            const auto offset_from_class = xref.offset(-0x8).deref<std::int32_t>();
            if (offset_from_class != 0) {
                continue;
            }

            const auto object_locator = xref.offset(-0xC);
            const auto bytes = pattern_to_bytes(address_to_ida_pattern(&object_locator, sizeof(Pointer)));

            const auto vtable_address = pattern_scan(FNV_CT(".rdata"), bytes);
            if (!vtable_address) {
                return {};
            }

            return vtable_address.offset(sizeof(Pointer));
        }

        return nullptr;
    }

    template <typename Fn>
    YUKI_FORCE_INLINE void Module::enum_modules(Fn fn)
    {
        const PEB* peb = get_peb();
        if (!peb || !peb->Ldr) [[YUKI_ATTR_UNLIKELY]] {
            return;
        }

        const LIST_ENTRY* list_head = &peb->Ldr->InMemoryOrderModuleList;
        if (!list_head || !list_head->Flink) [[YUKI_ATTR_UNLIKELY]] {
            return;
        }

        for (LIST_ENTRY* cur = list_head->Flink; cur != list_head; cur = cur->Flink) {
            const LDR_DATA_TABLE_ENTRY* entry = CONTAINING_RECORD(cur, LDR_DATA_TABLE_ENTRY, InMemoryOrderLinks);
            if (!entry) [[YUKI_ATTR_UNLIKELY]] {
                continue;
            }

            const auto dll = [&] {
                const std::wstring_view dll = entry->FullDllName.Buffer;
                const std::size_t sep_index = dll.find_last_of(L'\\');
                return sep_index == std::wstring_view::npos
                    ? dll
                    : dll.substr(sep_index + 1);
            }();

            if (fn(to_utf8(dll), entry->DllBase)) {
                return;
            }
        }
    }

    YUKI_FORCE_INLINE Module Module::find(std::string_view module_name, bool lowercase)
    {
        return find(FNV_RT(lowercase ? to_ascii_lowercase(module_name) : module_name), lowercase);
    }

    YUKI_FORCE_INLINE Module Module::find(fnv1a::type module_name_hash, bool lowercase)
    {
        if (module_name_hash == 0) {
            const PEB* peb = get_peb();
            if (!peb) [[YUKI_ATTR_UNLIKELY]] {
                return { nullptr };
            }
            // peb->ImageBaseAddress
            // http://undocumented.ntinternals.net/index.html?page=UserMode%2FUndocumented%20Functions%2FNT%20Objects%2FProcess%2FPEB.html
            return { peb->Reserved3[1] };
        }

        Pointer ret = nullptr;

        enum_modules([&](std::string_view mod_name, Pointer mod_address) {
            const auto hash = fnv1a::get_with(
                mod_name.cbegin(),
                mod_name.cend(),
                [lowercase](byte b) -> byte {
                    return lowercase && b >= 'A' && b <= 'Z' ? (b | (1 << 5)) : b;
                }
            );

            if (hash == module_name_hash) {
                ret = mod_address;
                return true;
            }

            return false;
        });

        return ret;
    }

    YUKI_FORCE_INLINE Module Module::find_or_load(const char* module_name, bool lowercase)
    {
        // clang-format off
        static const auto load_library_a =
            Module::find(FNV_CT("kernel32.dll"))
                .get_proc_addr(FNV_CT("LoadLibraryA"))
                .get_or(reinterpret_cast<void*>(LoadLibraryA))
                .as<decltype(&LoadLibraryA)>();
        // clang-format on

        return find(module_name, lowercase)
            .get()
            .get_or_else([&] { return Pointer(load_library_a(module_name)); });
    }

    YUKI_FORCE_INLINE PEB* Module::get_peb()
    {
        const TEB* teb = NtCurrentTeb();
        if (!teb) [[YUKI_ATTR_UNLIKELY]] {
            return nullptr;
        }
        return teb->ProcessEnvironmentBlock;
    }

    YUKI_FORCE_INLINE Pointer Module::handle_forwarded_export(Pointer export_addr)
    {
        static constexpr auto str_to_ushort = [](std::string_view str) {
            unsigned short res = 0;

            for (const char ch : str) {
                const int num = dctoi(ch);
                if (num == -1) {
                    break;
                }
                res = res * 10 + static_cast<decltype(res)>(num);
            }

            return res;
        };

        const std::string_view forward_str = export_addr.as<const char*>();
        const std::size_t dot_index = forward_str.find_last_of('.');

        if (dot_index == std::string_view::npos) [[YUKI_ATTR_UNLIKELY]] {
            // unlikely to happen
            // if it does happen then just return whatever is from the forwarder
            return export_addr;
        }

        const std::string forward_module_name { forward_str.substr(0, dot_index) };
        const std::string_view forward_proc_name = forward_str.substr(dot_index + 1);
        const bool by_ordinal = !forward_proc_name.empty() && forward_proc_name[0] == '#';

        const Module forward_module = find_or_load(forward_module_name.c_str(), false);
        if (!forward_module) {
            return nullptr;
        }

        return forward_module.get_proc_addr(
            by_ordinal ? str_to_ushort(forward_proc_name.substr(1))
                       : FNV_RT(forward_proc_name)
        );
    }
}
