#pragma once

#include <type_traits>

#if defined(__x86_64__) || defined(_M_AMD64) || defined(_M_X64)
#  define YUKI_ARCH_X86_64
#elif defined(__i386) || defined(_M_IX86)
#  define YUKI_ARCH_X86
#endif

#if defined(__GNUC__) || defined(__clang__)
#  define YUKI_FORCE_INLINE __attribute__((always_inline)) inline
#elif defined(_MSC_VER)
#  define YUKI_FORCE_INLINE __pragma(warning(suppress : 4714)) __forceinline
#else
#  define YUKI_FORCE_INLINE inline
#endif

#if defined(__GNUC__) || defined(__clang__)
#  define YUKI_NOINLINE __attribute__((noinline))
#elif defined(_MSC_VER)
#  define YUKI_NOINLINE __declspec(noinline)
#else
#  define YUKI_NOINLINE
#endif

#if defined(__GNUC__) || defined(__clang__)
#  define YUKI_LIKELY(x) __builtin_expect(static_cast<bool>(x), 1)
#  define YUKI_UNLIKELY(x) __builtin_expect(static_cast<bool>(x), 0)
#else
#  define YUKI_LIKELY(x) static_cast<bool>(x)
#  define YUKI_UNLIKELY(x) static_cast<bool>(x)
#endif

#if defined(__cplusplus) && defined(__has_cpp_attribute)
#  define YUKI_HAS_ATTRIBUTE(attrib, value) (__has_cpp_attribute(attrib) >= value)
#else
#  define YUKI_HAS_ATTRIBUTE(attrib, value) (0)
#endif

#if YUKI_HAS_ATTRIBUTE(likely, 201803L)
#  define YUKI_ATTR_LIKELY likely
#else
#  define YUKI_ATTR_LIKELY
#endif

#if YUKI_HAS_ATTRIBUTE(unlikely, 201803L)
#  define YUKI_ATTR_UNLIKELY unlikely
#else
#  define YUKI_ATTR_UNLIKELY
#endif

#define YUKI_STRINGIFY_IMPL(x) #x
#define YUKI_STRINGIFY(x) YUKI_STRINGIFY_IMPL(x)

#define YUKI_EXPAND_IMPL(x, y) x##y
#define YUKI_EXPAND(x, y) YUKI_EXPAND_IMPL(x, y)

#if defined(__cpp_lib_is_constant_evaluated)
#  define YUKI_IF_IS_CONSTANT_EVALUATED(x) \
    if (std::is_constant_evaluated()) {    \
      x                                    \
    }
#else
#  define YUKI_IF_IS_CONSTANT_EVALUATED(x)
#endif

#include <climits>

#if CHAR_BIT != 8
#  error "Expecting char bits to be 8"
#endif

namespace yuki {
    using byte = unsigned char;
}