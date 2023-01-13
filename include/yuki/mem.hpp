#pragma once

#include "defines.hpp"
#include "pointer.hpp"
#include "protect.hpp"
#include "str.hpp"
#include <algorithm>
#include <cstdint>
#include <cstring>
#include <iomanip>
#include <optional>
#include <span>
#include <sstream>
#include <string>
#include <vector>

namespace yuki {
    bool is_bad_read_ptr(Pointer ptr);
    Pointer get_vfunc(Pointer vtable, std::size_t index);
    std::size_t get_vtable_length(Pointer vtable);
    std::vector<Pointer> clone_vtable(Pointer vtable, bool include_rtti = true, std::size_t max_count = static_cast<std::size_t>(-1));
    Pointer pattern_scan(Pointer begin, std::size_t size, std::span<const std::optional<std::uint8_t>> byte_array);
    std::vector<std::optional<std::uint8_t>> pattern_to_bytes(std::string_view pattern, char wildcard);
    std::string address_to_ida_pattern(Pointer address, std::size_t size);

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

    inline Pointer pattern_scan(Pointer begin, std::size_t size, std::span<const std::optional<std::uint8_t>> byte_array)
    {
        if (!begin || size == 0) {
            return nullptr;
        }

        auto start = begin.as<const std::uint8_t*>();
        const auto end = start + size;

        for (; start != end; ++start) {
            bool found = true;

            for (std::size_t i = 0; i < byte_array.size(); ++i) {
                if (start + i == end) {
                    return nullptr;
                }

                if (const auto& cur = byte_array[i]; cur.has_value() && *cur != start[i]) {
                    found = false;
                    break;
                }
            }

            if (found) {
                return start;
            }
        }

        return nullptr;
    }

    inline std::vector<std::optional<std::uint8_t>> pattern_to_bytes(std::string_view pattern, char wildcard = '?')
    {
        std::vector<std::optional<std::uint8_t>> ret;

        for (auto it = pattern.cbegin(), end = pattern.cend(); it != end; ++it) {
            if (*it == ' ') {
                continue;
            }

            if (*it == wildcard) {
                if (++it != end) {
                    ++it;
                }

                ret.emplace_back(std::nullopt);
            } else if (it + 1 != end) {
                const auto first = xctoi(*it++);
                const auto second = xctoi(*it++);

                ret.emplace_back(static_cast<std::uint8_t>(first << 4 | second));
            } else {
                return {};
            }
        }

        return ret;
    }

    inline std::string address_to_ida_pattern(Pointer address, std::size_t size)
    {
        auto bytes = address.as<const std::uint8_t*>();

        std::stringstream ida_pattern;
        ida_pattern << std::hex << std::setfill('0');

        for (std::size_t i = 0; i < size; ++i) {
            ida_pattern << std::setw(2) << static_cast<std::int32_t>(bytes[i]);
            if (i + 1 != size) {
                ida_pattern << ' ';
            }
        }

        return ida_pattern.str();
    }

}