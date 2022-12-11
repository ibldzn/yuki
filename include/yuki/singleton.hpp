#pragma once

namespace yuki {
    template <typename Ty>
    struct Singleton {
        Singleton(Singleton&&) = delete;
        Singleton(const Singleton&) = delete;

        Singleton& operator=(Singleton&&) = delete;
        Singleton& operator=(const Singleton&) = delete;

        static Ty& instance()
        {
            static Ty inst = {};
            return inst;
        }

    protected:
        Singleton() { }
    };
}