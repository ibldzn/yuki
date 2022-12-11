#pragma once

#include "defines.hpp"
#include "pointer.hpp"
#include <atomic>
#include <minhook/minhook.h>

namespace yuki {
    struct Detour {
        bool hook(Pointer target_function, Pointer detour);
        Pointer get_original() const;
        bool is_hooked() const;

    private:
        bool m_hooked = false;
        Pointer m_original = nullptr;
        Pointer m_function = nullptr;
        inline static std::atomic_size_t ref_count = 0;
    };

    inline bool Detour::hook(Pointer target_function, Pointer detour)
    {
        if (is_hooked()) {
            return false;
        }

        if (!target_function || !detour) {
            return false;
        }

        if (ref_count++ == 0 && MH_Initialize() != MH_OK) {
            return false;
        }

        if (MH_CreateHook(target_function, detour, reinterpret_cast<void**>(&m_original)) != MH_OK) {
            return false;
        }

        if (MH_EnableHook(target_function) != MH_OK) {
            return false;
        }

        m_function = target_function;
        m_hooked = true;

        return true;
    }

    YUKI_FORCE_INLINE Pointer Detour::get_original() const
    {
        return m_original;
    }

    YUKI_FORCE_INLINE bool Detour::is_hooked() const
    {
        return m_hooked;
    }
}