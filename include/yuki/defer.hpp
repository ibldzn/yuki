#pragma once

#include "defines.hpp"
#include <type_traits>
#include <utility>

namespace yuki {
    template <typename Fn>
    struct Defer {
        static_assert(!std::is_reference_v<Fn> && !std::is_const_v<Fn> && !std::is_volatile_v<Fn>);

        Defer(const Defer&) = delete;
        Defer& operator=(Defer&&) = delete;
        Defer& operator=(const Defer&) = delete;

        [[nodiscard]] constexpr Defer(Fn fn)
            : m_fn(std::move(fn))
            , m_invoke(true)
        {
        }

        [[nodiscard]] constexpr Defer(Defer&& other)
            : m_fn(std::move(other.m_fn))
            , m_invoke(std::exchange(other.m_invoke, false))
        {
        }

        ~Defer()
        {
            if (m_invoke) {
                m_fn();
            }
        }

    private:
        Fn m_fn = {};
        bool m_invoke = true;
    };

    struct Deferrer {
        template <typename Fn>
        [[nodiscard]] Defer<std::remove_cv_t<std::remove_reference_t<Fn>>> operator<<(Fn&& fn)
        {
            return Defer<std::remove_cv_t<std::remove_reference_t<Fn>>>(std::forward<Fn>(fn));
        }
    };

#define YUKI_DEFER const auto YUKI_EXPAND(deferrer_lambda__, __COUNTER__) = yuki::Deferrer {} << [&]
}
