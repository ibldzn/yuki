#define YUKI_DONT_FORCE_INLINE
#include "../include/yuki/hook_iat.hpp"
#include "../include/yuki/stba.hpp"
#define WIN32_LEAN_AND_MEAN
#include <Windows.h>
#include <iostream>
#include <memory>

using namespace yuki;

struct Bar {
    virtual int get_bar()
    {
        return 5;
    }

    virtual int get_baz()
    {
        return 42;
    }
};

IATHook msgbox(FNV_CT("user32.dll"), FNV_CT("MessageBoxA"));

int my_msgboxa(HWND hWnd, LPCSTR lpText, LPCSTR lpCaption, UINT uType)
{
    std::cout << lpText << '\n';
    return msgbox.get_original().as<decltype(&MessageBoxA)>()(hWnd, "hijacked lol", lpCaption, uType | MB_ICONASTERISK);
}

int main()
{
    constexpr auto sig = YUKI_SIG("E8 ?");
    static_assert(sig[0] == 0xE8);
    msgbox.apply(0, reinterpret_cast<void*>(my_msgboxa));

    MessageBoxA(nullptr, "This is the message", "This is the title", MB_OK);

    const auto self = Module::self();
    for (const auto& xref : self.get_string_xrefs(FNV_CT("This is the title"))) {
        std::cout << xref.relative().as<const char*>() << " (" << xref.as<void*>() << ")\n";
    }

    std::cout << Module::find(FNV_CT("kernel32.dll")).get_proc_addr(FNV_CT("EnterCriticalSection")).as<void*>()
              << ' '
              << Module::find(FNV_CT("ntdll.dll")).get_proc_addr(FNV_CT("RtlEnterCriticalSection")).as<void*>()
              << '\n';

    const auto ws = Module::find_or_load("ws2_32.dll");
    std::cout << ws.get_proc_addr(FNV_CT("WSAConnect")).as<void*>() << ' ' << ws.get_proc_addr(0x2E) << '\n';

    auto bar = std::make_unique<Bar>();
    std::cout << bar->get_bar() << '\n';
    std::cout << self.find_string(FNV_CT("ws2_32.dll")) << '\n';
}
