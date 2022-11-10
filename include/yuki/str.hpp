#pragma once

#include "defines.hpp"

#if defined(_WIN32)
#  pragma push_macro("WIN32_LEAN_AND_MEAN")
#  if !defined(WIN32_LEAN_AND_MEAN)
#    define WIN32_LEAN_AND_MEAN
#  endif
#  include <windows.h>
#  pragma pop_macro("WIN32_LEAN_AND_MEAN")
#else
#  if defined(_MSC_VER)
#    pragma push_macro("_SILENCE_CXX17_CODECVT_HEADER_DEPRECATION_WARNING")
#    if !defined(_SILENCE_CXX17_CODECVT_HEADER_DEPRECATION_WARNING)
#      define _SILENCE_CXX17_CODECVT_HEADER_DEPRECATION_WARNING
#    endif
#  endif
#  include <codecvt>
#  include <locale>
#  if defined(_MSC_VER)
#    pragma pop_macro("_SILENCE_CXX17_CODECVT_HEADER_DEPRECATION_WARNING")
#  endif
#endif

#include <algorithm>
#include <string>
#include <string_view>

namespace yuki {
    constexpr int xctoi(char ch);
    constexpr int dctoi(char ch);
    constexpr int octoi(char ch);

    std::string to_ascii_lowercase(std::string_view str);
    std::string to_ascii_uppercase(std::string_view str);
    std::string to_utf8(std::wstring_view wstr);
    std::wstring to_unicode(std::string_view str);

    YUKI_FORCE_INLINE constexpr int xctoi(char ch)
    {
        if (ch >= '0' && ch <= '9') {
            return static_cast<int>(ch - '0');
        }

        if (ch >= 'a' && ch <= 'f') {
            return static_cast<int>(ch - 'a' + 10);
        }

        if (ch >= 'A' && ch <= 'F') {
            return static_cast<int>(ch - 'A' + 10);
        }

        // compile time error
        YUKI_IF_IS_CONSTANT_EVALUATED({
            throw "Invalid value!";
        });

        return -1;
    }

    YUKI_FORCE_INLINE constexpr int dctoi(char ch)
    {
        if (ch >= '0' && ch <= '9') {
            return static_cast<int>(ch - '0');
        }

        // compile time error
        YUKI_IF_IS_CONSTANT_EVALUATED({
            throw "Invalid value!";
        });

        return -1;
    }

    YUKI_FORCE_INLINE constexpr int octoi(char ch)
    {
        if (ch >= '0' && ch <= '7') {
            return static_cast<int>(ch - '0');
        }

        // compile time error
        YUKI_IF_IS_CONSTANT_EVALUATED({
            throw "Invalid value!";
        });

        return -1;
    }

    inline std::string to_ascii_lowercase(std::string_view str)
    {
        std::string ret { str };
        std::transform(ret.cbegin(), ret.cend(), ret.begin(), [](char ch) -> char {
            return ch >= 'A' && ch <= 'Z' ? (ch | (1 << 5)) : ch;
        });
        return ret;
    }

    inline std::string to_ascii_uppercase(std::string_view str)
    {
        std::string ret { str };
        std::transform(ret.cbegin(), ret.cend(), ret.begin(), [](char ch) -> char {
            return ch >= 'a' && ch <= 'z' ? (ch & ~(1 << 5)) : ch;
        });
        return ret;
    }

    inline std::string to_utf8(std::wstring_view wstr)
    {
        if (wstr.empty()) {
            return {};
        }

#if defined(_WIN32)
        int size_needed = WideCharToMultiByte(
            CP_UTF8,
            0,
            &wstr[0],
            static_cast<int>(wstr.length()),
            nullptr,
            0,
            nullptr,
            nullptr
        );
        if (size_needed == 0) {
            return {};
        }

        std::string ret(static_cast<std::size_t>(size_needed), 0);
        if (
            WideCharToMultiByte(
                CP_UTF8,
                0,
                &wstr[0],
                static_cast<int>(wstr.length()),
                &ret[0],
                size_needed,
                nullptr,
                nullptr
            )
            == 0
        ) {
            return {};
        }

        return ret;
#else
        std::wstring_convert<std::codecvt_utf8_utf16<wchar_t>> converter = {};
        return converter.to_bytes(&wstr[0], &wstr[0] + wstr.length());
#endif
    }

    inline std::wstring to_unicode(std::string_view str)
    {
        if (str.empty()) {
            return {};
        }

#if defined(_WIN32)
        int size_needed = MultiByteToWideChar(
            CP_UTF8,
            0,
            &str[0],
            static_cast<int>(str.length()),
            nullptr,
            0
        );
        if (size_needed == 0) {
            return {};
        }

        std::wstring ret(static_cast<std::size_t>(size_needed), 0);
        if (
            MultiByteToWideChar(
                CP_UTF8,
                0,
                &str[0],
                static_cast<int>(str.length()),
                &ret[0],
                size_needed
            )
            == 0
        ) {
            return {};
        }

        return ret;
#else
        std::wstring_convert<std::codecvt_utf8_utf16<wchar_t>> converter = {};
        return converter.from_bytes(&str[0], &str[0] + str.length());
#endif
    }
}