#pragma once

#include "defines.hpp"
#include <string_view>
#include <utility>

namespace yuki {
    template <typename T, T BASIS, T PRIME>
    struct basic_fnv1a {
        using type = T;

        basic_fnv1a() = delete;

        static constexpr YUKI_FORCE_INLINE T get(std::string_view str)
        {
            return get_impl(str.cbegin(), str.cend());
        }

        template <typename Fn>
        static constexpr YUKI_FORCE_INLINE T get_with(std::string_view str, Fn&& fn)
        {
            return get_with_impl(str.cbegin(), str.cend(), std::forward<Fn>(fn));
        }

        template <typename ForwardIter>
        static constexpr YUKI_FORCE_INLINE T get(ForwardIter begin, ForwardIter end)
        {
            return get_impl(begin, end);
        }

        template <typename ForwardIter, typename Fn>
        static constexpr YUKI_FORCE_INLINE T get_with(ForwardIter begin, ForwardIter end, Fn&& fn)
        {
            return get_with_impl(begin, end, std::forward<Fn>(fn));
        }

    private:
        template <typename ForwardIter>
        static constexpr YUKI_FORCE_INLINE T get_impl(ForwardIter begin, ForwardIter end)
        {
            return get_with_impl(begin, end, [](const auto b) { return b; });
        }

        template <typename ForwardIter, typename Fn>
        static constexpr YUKI_FORCE_INLINE T get_with_impl(ForwardIter begin, ForwardIter end, Fn fn)
        {
            T val = BASIS;
            while (begin != end) {
                val ^= static_cast<T>(fn(static_cast<byte>(*begin++)));
                val *= PRIME;
            }
            return val;
        }
    };

    using fnv1a32 = basic_fnv1a<std::uint32_t, 0x811c9dc5, 0x1000193>;
    using fnv1a64 = basic_fnv1a<std::uint64_t, 0xcbf29ce484222325, 0x00000100000001b3>;

#if defined(YUKI_ARCH_X86_64)
    using fnv1a = fnv1a64;
#else
    using fnv1a = fnv1a32;
#endif

#define FNV_CT(str) ([&] { constexpr auto res = yuki::fnv1a::get(str); return res; }())
#define FNV_RT(str) (yuki::fnv1a::get(str))
}
