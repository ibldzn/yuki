#pragma once

#include "defines.hpp"
#include <type_traits>

#define YUKI_DEFINE_ENUM_FLAG_OPERATORS(ENUMTYPE)                                                                                      \
  YUKI_FORCE_INLINE constexpr ENUMTYPE operator|(ENUMTYPE a, ENUMTYPE b) noexcept                                                      \
  {                                                                                                                                    \
    return static_cast<ENUMTYPE>(static_cast<std::underlying_type_t<ENUMTYPE>>(a) | static_cast<std::underlying_type_t<ENUMTYPE>>(b)); \
  }                                                                                                                                    \
  YUKI_FORCE_INLINE constexpr ENUMTYPE& operator|=(ENUMTYPE& a, ENUMTYPE b) noexcept                                                   \
  {                                                                                                                                    \
    return a = a | b;                                                                                                                  \
  }                                                                                                                                    \
  YUKI_FORCE_INLINE constexpr ENUMTYPE operator&(ENUMTYPE a, ENUMTYPE b) noexcept                                                      \
  {                                                                                                                                    \
    return static_cast<ENUMTYPE>(static_cast<std::underlying_type_t<ENUMTYPE>>(a) & static_cast<std::underlying_type_t<ENUMTYPE>>(b)); \
  }                                                                                                                                    \
  YUKI_FORCE_INLINE constexpr ENUMTYPE& operator&=(ENUMTYPE& a, ENUMTYPE b) noexcept                                                   \
  {                                                                                                                                    \
    return a = a & b;                                                                                                                  \
  }                                                                                                                                    \
  YUKI_FORCE_INLINE constexpr ENUMTYPE operator^(ENUMTYPE a, ENUMTYPE b) noexcept                                                      \
  {                                                                                                                                    \
    return static_cast<ENUMTYPE>(static_cast<std::underlying_type_t<ENUMTYPE>>(a) ^ static_cast<std::underlying_type_t<ENUMTYPE>>(b)); \
  }                                                                                                                                    \
  YUKI_FORCE_INLINE constexpr ENUMTYPE& operator^=(ENUMTYPE& a, ENUMTYPE b) noexcept                                                   \
  {                                                                                                                                    \
    return a = a ^ b;                                                                                                                  \
  }                                                                                                                                    \
  YUKI_FORCE_INLINE constexpr ENUMTYPE operator~(ENUMTYPE a) noexcept                                                                  \
  {                                                                                                                                    \
    return static_cast<ENUMTYPE>(~static_cast<std::underlying_type_t<ENUMTYPE>>(a));                                                   \
  }
