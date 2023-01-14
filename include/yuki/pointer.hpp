#pragma once

#include "defines.hpp"
#include <cstdint>
#include <type_traits>

namespace yuki {
    struct Pointer {
        constexpr Pointer() = default;

        constexpr Pointer(std::uintptr_t ptr)
            : m_ptr(ptr)
        {
        }

        Pointer(const void* ptr)
            : m_ptr(reinterpret_cast<std::uintptr_t>(ptr))
        {
        }

        operator void*() const;
        constexpr bool operator!() const;
        constexpr explicit operator bool() const;

        Pointer& self_relative();
        constexpr Pointer& self_offset(std::ptrdiff_t val);

        Pointer relative() const;
        constexpr Pointer offset(std::ptrdiff_t val) const;

        template <typename Fn>
        constexpr Pointer get_or_else(Fn fn) const;
        constexpr Pointer get_or(Pointer pointer) const;

        template <typename T>
        T as() const;

        template <typename T>
        T deref() const;

    private:
        std::uintptr_t m_ptr = 0;
    };

    static_assert(sizeof(Pointer) == sizeof(void*), "Invalid pointer size.");

    YUKI_FORCE_INLINE Pointer::operator void*() const
    {
        return as<void*>();
    }

    YUKI_FORCE_INLINE constexpr bool Pointer::operator!() const
    {
        return !m_ptr;
    }

    YUKI_FORCE_INLINE constexpr Pointer::operator bool() const
    {
        return m_ptr != 0;
    }

    YUKI_FORCE_INLINE Pointer& Pointer::self_relative()
    {
        *this = relative();
        return *this;
    }

    YUKI_FORCE_INLINE constexpr Pointer& Pointer::self_offset(std::ptrdiff_t val)
    {
        *this = offset(val);
        return *this;
    }

    YUKI_FORCE_INLINE Pointer Pointer::relative() const
    {
        constexpr auto instruction_size = 4;
        const auto displacement = deref<std::int32_t>();

        return offset(instruction_size + displacement);
    }

    YUKI_FORCE_INLINE constexpr Pointer Pointer::offset(std::ptrdiff_t val) const
    {
        return m_ptr + static_cast<std::uintptr_t>(val);
    }

    template <typename Fn>
    YUKI_FORCE_INLINE constexpr Pointer Pointer::get_or_else(Fn fn) const
    {
        if (!m_ptr) {
            return fn();
        }
        return m_ptr;
    }

    YUKI_FORCE_INLINE constexpr Pointer Pointer::get_or(Pointer pointer) const
    {
        if (!m_ptr) {
            return pointer;
        }
        return m_ptr;
    }

    template <typename T>
    YUKI_FORCE_INLINE T Pointer::as() const
    {
        using type = std::remove_cv_t<T>;
        if constexpr (std::is_lvalue_reference_v<type>) {
            return *reinterpret_cast<std::add_pointer_t<T>>(m_ptr);
        } else if constexpr (std::is_pointer_v<type>) {
            return reinterpret_cast<T>(m_ptr);
        } else {
            return static_cast<T>(m_ptr);
        }
    }

    template <typename T>
    YUKI_FORCE_INLINE T Pointer::deref() const
    {
        return as<std::add_lvalue_reference_t<T>>();
    }
}
