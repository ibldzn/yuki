#pragma once

#include <cstddef>
#include <type_traits>
#include <utility>

namespace yuki {
    template <typename CharT, std::size_t N>
    struct CTStr {
        template <std::size_t... Indices>
        constexpr CTStr(const CharT* str, std::index_sequence<Indices...>)
            : m_chars { str[Indices]... }
        {
        }

        constexpr CTStr(const CharT (&str)[N])
            : CTStr(str, std::make_index_sequence<N> {})
        {
        }

        constexpr std::size_t length() const { return N - 1; }
        constexpr auto& operator[](std::size_t index) { return m_chars[index]; }
        constexpr const auto& operator[](std::size_t index) const { return m_chars[index]; }

        CharT m_chars[N];
    };
}