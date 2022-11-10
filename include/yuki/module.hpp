#pragma once

#if !defined(_WIN32) || !defined(_WIN64)
#  error "Windows only.."
#endif

#include "defines.hpp"
#include "fnv1a.hpp"
#include "pointer.hpp"
#include "str.hpp"
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

        template <typename Fn>
        static void enum_modules(Fn fn);
        static Module find_module(std::string_view module_name, bool lowercase = true);
        static Module find_module(fnv1a::type module_name_hash, bool lowercase = true);

        static PEB* get_peb();

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

        IMAGE_SECTION_HEADER* sect_header = IMAGE_FIRST_SECTION(nt);
        for (unsigned short i = 0, sect_count = nt->FileHeader.NumberOfSections; i < sect_count; ++i, ++sect_header) {
            const std::string_view sect_name = reinterpret_cast<char*>(sect_header->Name);
            if (FNV_RT(sect_name) == sect_name_hash) {
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

        for (unsigned long i = 0, num_of_names = ied->NumberOfNames; i < num_of_names; ++i) {
            const std::string_view proc_name = m_base_address.offset(names[i]).as<const char*>();
            if (FNV_RT(proc_name) != proc_name_hash) {
                continue;
            }

            const auto ord = m_base_address.offset(ords[i]).as<unsigned short>();
            const auto proc_addr = m_base_address.offset(funcs[ord]).as<std::uintptr_t>();

            // handle forwarded export
            if (proc_addr >= exp_base.as<std::uintptr_t>() && proc_addr < exp_base.offset(exp_dir->Size).as<std::uintptr_t>()) {
                const std::string_view forward_str = Pointer { proc_addr }.as<const char*>();
                const std::size_t dot_index = forward_str.find('.');

                if (dot_index != std::string_view::npos) [[YUKI_ATTR_LIKELY]] {
                    const std::string_view forward_module_name = forward_str.substr(0, dot_index);
                    const std::string_view forward_proc_name = forward_str.substr(dot_index + 1);

                    const auto forward_module_name_hash = fnv1a::get_with(
                        forward_module_name,
                        [](byte b) -> byte {
                            return b >= 'A' && b <= 'Z' ? (b | (1 << 5)) : b;
                        }
                    );

                    Module forward_module { nullptr };

                    enum_modules([&](std::string_view mod_name, Pointer mod_address) {
                        if (const std::size_t dot_index = mod_name.find_last_of('.'); dot_index != std::string_view::npos) [[YUKI_ATTR_LIKELY]] {
                            mod_name = mod_name.substr(0, dot_index);
                        }

                        const auto hash = fnv1a::get_with(
                            mod_name,
                            [](byte b) -> byte {
                                return b >= 'A' && b <= 'Z' ? (b | (1 << 5)) : b;
                            }
                        );

                        if (forward_module_name_hash == hash) {
                            forward_module = mod_address;
                            return true;
                        }

                        return false;
                    });

                    if (forward_module) {
                        return forward_module.get_proc_addr(FNV_RT(forward_proc_name));
                    }
                }
            }

            return proc_addr;
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

    YUKI_FORCE_INLINE Module Module::find_module(std::string_view module_name, bool lowercase)
    {
        return find_module(FNV_RT(lowercase ? to_ascii_lowercase(module_name) : module_name), lowercase);
    }

    YUKI_FORCE_INLINE Module Module::find_module(fnv1a::type module_name_hash, bool lowercase)
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

    YUKI_FORCE_INLINE PEB* Module::get_peb()
    {
        const TEB* teb = NtCurrentTeb();
        if (!teb) [[YUKI_ATTR_UNLIKELY]] {
            return nullptr;
        }
        return teb->ProcessEnvironmentBlock;
    }
}
