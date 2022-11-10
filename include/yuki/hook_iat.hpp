#pragma once

#if !defined(_WIN32) || !defined(_WIN64)
#  error "Windows only.."
#endif

#include "defines.hpp"
#include "fnv1a.hpp"
#include "module.hpp"
#include "protect.hpp"

namespace yuki {
    struct IATHook {
        IATHook(fnv1a::type mod_hash, fnv1a::type api_hash);
        ~IATHook();

        IATHook(const IATHook&) = delete;
        IATHook& operator=(const IATHook&) = delete;

        bool apply(fnv1a::type target_mod_hash, Pointer new_func);
        bool unhook();
        bool is_hooked() const;
        Pointer get_original() const;

    private:
        bool m_hooked = false;
        Pointer m_original = nullptr;
        fnv1a::type m_mod_hash = {};
        fnv1a::type m_api_hash = {};
        IMAGE_THUNK_DATA* m_thunk_data = nullptr;
    };

    YUKI_FORCE_INLINE IATHook::IATHook(fnv1a::type mod_hash, fnv1a::type api_hash)
        : m_hooked(false)
        , m_original(nullptr)
        , m_mod_hash(mod_hash)
        , m_api_hash(api_hash)
        , m_thunk_data(nullptr)
    {
    }

    inline bool IATHook::apply(fnv1a::type target_mod_hash, Pointer new_func)
    {
        const auto target_mod = Module::find_module(target_mod_hash);
        if (!target_mod) {
            return false;
        }

        const IMAGE_DATA_DIRECTORY* import_dir = target_mod.get_image_directory(IMAGE_DIRECTORY_ENTRY_IMPORT);
        if (!import_dir || import_dir->Size == 0) {
            return false;
        }

        const Pointer target_mod_base = target_mod.get();

        for (
            IMAGE_IMPORT_DESCRIPTOR* import_desc = target_mod_base.offset(import_dir->VirtualAddress).as<IMAGE_IMPORT_DESCRIPTOR*>();
            import_desc && import_desc->Characteristics;
            ++import_desc
        ) {
            const std::string_view mod_name = target_mod_base.offset(import_desc->Name).as<const char*>();
            const auto hash = fnv1a::get_with(
                mod_name,
                [](byte b) -> byte {
                    return b >= 'A' && b <= 'Z' ? (b | (1 << 5)) : b;
                }
            );

            if (m_mod_hash != hash) {
                continue;
            }

            const Module mod = Module::find_module(hash);
            const auto mod_nt = mod.get_nt_headers();
            // module should've been loaded by the PE loader by now.
            // pretty unnecessary but better than a random segfault.
            if (!mod_nt) [[YUKI_ATTR_UNLIKELY]] {
                return false;
            }

            IMAGE_THUNK_DATA* original_first_thunk = target_mod_base.offset(import_desc->OriginalFirstThunk).as<IMAGE_THUNK_DATA*>();
            IMAGE_THUNK_DATA* first_thunk = target_mod_base.offset(import_desc->FirstThunk).as<IMAGE_THUNK_DATA*>();
            if (!original_first_thunk || !first_thunk) [[YUKI_ATTR_UNLIKELY]] {
                continue;
            }

            for (; original_first_thunk->u1.AddressOfData; ++original_first_thunk, ++first_thunk) {
                if (IMAGE_SNAP_BY_ORDINAL(original_first_thunk->u1.Ordinal)) {
                    continue;
                }

                // clang-format off
                IMAGE_IMPORT_BY_NAME* name = target_mod_base.offset(
                    static_cast<std::ptrdiff_t>(original_first_thunk->u1.AddressOfData)
                ).as<IMAGE_IMPORT_BY_NAME*>();
                // clang-format on
                if (m_api_hash != FNV_RT(name->Name)) {
                    continue;
                }

                const auto mod_base = mod.get();
                const auto mod_end = mod_base.offset(mod_nt->OptionalHeader.SizeOfImage);
                if (
                    first_thunk->u1.Function < mod_base.as<std::uintptr_t>()
                    || first_thunk->u1.Function >= mod_end.as<std::uintptr_t>()
                ) {
                    return false;
                }

                m_thunk_data = first_thunk;
                m_original = first_thunk->u1.Function;

                if (const auto protect = ScopedProtect { &first_thunk->u1.Function, sizeof(decltype(first_thunk->u1.Function)), ProtFlags::RW }) {
                    first_thunk->u1.Function = new_func.as<decltype(first_thunk->u1.Function)>();
                    m_hooked = true;
                    return true;
                }

                return false;
            }
        }

        return false;
    }

    YUKI_FORCE_INLINE IATHook::~IATHook()
    {
        unhook();
    }

    YUKI_FORCE_INLINE bool IATHook::unhook()
    {
        if (!is_hooked()) {
            return false;
        }

        if (const auto protect = ScopedProtect { &m_thunk_data->u1.Function, sizeof(decltype(m_thunk_data->u1.Function)), ProtFlags::RW }) {
            m_thunk_data->u1.Function = m_original.as<decltype(m_thunk_data->u1.Function)>();
            m_hooked = false;
            return true;
        }

        return false;
    }

    YUKI_FORCE_INLINE bool IATHook::is_hooked() const
    {
        return m_hooked;
    }

    YUKI_FORCE_INLINE Pointer IATHook::get_original() const
    {
        return m_original;
    }
}