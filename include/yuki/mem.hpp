#pragma once

#include "defines.hpp"
#include "pointer.hpp"
#include "protect.hpp"
#include <algorithm>
#include <cstdint>
#include <cstring>
#include <vector>

namespace yuki {
    bool is_bad_read_ptr(Pointer ptr);
    Pointer get_vfunc(Pointer vtable, std::size_t index);
    std::size_t get_vtable_length(Pointer vtable);
    std::vector<Pointer> clone_vtable(Pointer vtable, bool include_rtti = true, std::size_t max_count = static_cast<std::size_t>(-1));

    YUKI_FORCE_INLINE bool is_bad_read_ptr(Pointer ptr)
    {
        if (!ptr) {
            return true;
        }

        if (const auto prot = protect_query(ptr); prot != ProtFlags::INVALID) {
            if (prot & (ProtFlags::G | ProtFlags::NONE)) {
                return true;
            }

            if (prot & ProtFlags::RWXC) {
                return false;
            }
        }

        return true;
    }

    YUKI_FORCE_INLINE Pointer get_vfunc(Pointer vtable, std::size_t index)
    {
        if (!vtable) {
            return {};
        }
        return vtable.as<void**>()[index];
    }

    YUKI_FORCE_INLINE std::size_t get_vtable_length(Pointer vtable)
    {
        if (!vtable) {
            return 0;
        }

        constexpr auto is_intresource = [](Pointer ptr) {
            return (ptr.as<std::uintptr_t>() >> 16) == 0;
        };

        std::size_t length = 0;

        for (Pointer vfunc = get_vfunc(vtable, length); vfunc; vfunc = get_vfunc(vtable, ++length)) {
            if (is_intresource(vfunc)) {
                break;
            }
        }

        return length;
    }

    inline std::vector<Pointer> clone_vtable(Pointer vtable, bool include_rtti, std::size_t max_count)
    {
        if (!vtable) {
            return {};
        }

        std::size_t count = max_count == static_cast<std::size_t>(-1) ? get_vtable_length(vtable) : max_count;
        if (count == 0) {
            return {};
        }

        if (include_rtti) {
            vtable.self_offset(-static_cast<std::ptrdiff_t>(sizeof(Pointer)));
            count += 1;
        }

        std::vector<Pointer> ret(count, nullptr);
        std::memcpy(&ret[0], vtable, count * sizeof(Pointer) + (include_rtti ? sizeof(Pointer) : 0));

        return ret;
    }
}