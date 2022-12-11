#pragma once

#include "defines.hpp"
#include "fnv1a.hpp"
#include "module.hpp"
#include "singleton.hpp"
#include <functional>
#include <mutex>
#include <utility>
#include <vector>

namespace yuki {
    struct Input : Singleton<Input> {
        ~Input();
        bool init(void* window);
        bool init(fnv1a::type class_name_hash);

        using callback_t = std::function<void(HWND, UINT, WPARAM, LPARAM)>;

        void register_wndproc_callback(callback_t callback);

    private:
        static LRESULT wndproc_callback(HWND hwnd, UINT msg, WPARAM wparam, LPARAM lparam);

    private:
        void* m_window = nullptr;
        void* m_original_wndproc = nullptr;
        std::vector<callback_t> m_wndproc_callbacks = {};
    };

    inline Input::~Input()
    {
        if (m_original_wndproc) {
            SetWindowLongPtr(
                static_cast<HWND>(m_window),
                GWLP_WNDPROC,
                reinterpret_cast<LONG_PTR>(m_original_wndproc)
            );
        }
    }

    inline bool Input::init(void* window)
    {
        if (!m_original_wndproc) {
            m_window = window;
            m_original_wndproc = reinterpret_cast<void*>(
                SetWindowLongPtr(
                    static_cast<HWND>(m_window),
                    GWLP_WNDPROC,
                    reinterpret_cast<LONG_PTR>(wndproc_callback)
                )
            );
        }

        return m_original_wndproc != nullptr;
    }

    inline bool Input::init(fnv1a::type class_name_hash)
    {
        // if it has been initialized before
        if (m_original_wndproc) {
            return false;
        }

        struct Data {
            fnv1a::type hash = 0;
            HWND window = nullptr;
        };

        Data data { class_name_hash, nullptr };

        constexpr auto enum_wndproc_callback = [](HWND hwnd, LPARAM lparam) -> BOOL {
            const auto data = reinterpret_cast<Data*>(lparam);
            char class_name[256] = {};

            if (
                GetClassNameA(hwnd, class_name, sizeof(class_name))
                && FNV_RT(class_name) == data->hash
            ) {
                data->window = hwnd;
                return FALSE;
            }

            return TRUE;
        };

        // EnumWindows will return 0 if it fails or
        // if the callback returns 0 which is the only way to stop the enumeration
        // that's why we also need to check whether the window was found
        if (
            !EnumWindows(enum_wndproc_callback, reinterpret_cast<LPARAM>(&data))
            && !data.window
        ) {
            return false;
        }

        return init(data.window);
    }

    inline void Input::register_wndproc_callback(callback_t callback)
    {
        static std::mutex mtx;
        std::lock_guard lock(mtx);
        m_wndproc_callbacks.emplace_back(std::move(callback));
    }

    inline LRESULT Input::wndproc_callback(HWND hwnd, UINT msg, WPARAM wparam, LPARAM lparam)
    {
        const auto& inst = Input::instance();

        for (const auto& cb : inst.m_wndproc_callbacks) {
            cb(hwnd, msg, wparam, lparam);
        }

        return reinterpret_cast<WNDPROC>(inst.m_original_wndproc)(
            hwnd,
            msg,
            wparam,
            lparam
        );
    }
}