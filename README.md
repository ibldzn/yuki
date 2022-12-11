# Yuki

Yuki (雪) is an opiniated library that could be used for malware development, game hacking, etc.

It has some fancy features like:

- Generating an array of bytes from string at compile time

```c++
int main()
{
    constexpr auto sig = YUKI_SIG("AA ?? CC DD ??");
    static_assert(sig[0] == 0xAA);
    static_assert(sig[1] == std::nullopt);
    static_assert(sig[2] == 0xCC);
    static_assert(sig[3] == 0xDD);
    static_assert(sig[4] == std::nullopt);
}
```

- Getting a module base address / exported API with hash

```c++
int main()
{
    const auto load_library = Module::find(FNV_CT("kernel32.dll"))
        .get_proc_addr(FNV_CT("LoadLibraryA"))
        .as<decltype(&LoadLibraryA)>();
    assert(load_library == GetProcAddress(GetModuleHandleA("kernel32.dll", "LoadLibraryA")));
}
```

- Hooking import address table by patching the pointer in target module's import directory

```c++
IATHook msgbox(FNV_CT("user32.dll"), FNV_CT("MessageBoxA"));

int my_msgboxa(HWND hWnd, LPCSTR lpText, LPCSTR lpCaption, UINT uType)
{
    std::cout << lpText << '\n';
    return msgbox.get_original().as<decltype(&MessageBoxA)>()(hWnd, "Hijacked", lpCaption, uType | MB_ICONASTERISK);
}

int main()
{
    assert(msgbox.apply(0, reinterpret_cast<void*>(my_msgboxa)));
    MessageBoxA(nullptr, "This is the message", "This is the title", MB_OK);
}
```

- And a lot of other stuff

There's currently no documentation, god knows if I'll ever write one. You can always read the code base as it is pretty smol.

# Acknowledgements

- [0x1F9F1](https://github.com/0x1F9F1) for [mem](https://github.com/0x1F9F1/mem), some stuff were ~~stolen~~ borrowed from them.
- [TsudaKageyu](https://github.com/TsudaKageyu) for [minhook](https://github.com/TsudaKageyu/minhook).
