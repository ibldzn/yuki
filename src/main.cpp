#include "../include/yuki/stba.hpp"
#include <iostream>

using namespace yuki;

template <CTStr str>
constexpr void foo() { }

int main()
{
    // foo<"E">();
    constexpr CTStr str = "Hello!!!";
    constexpr auto sig = YUKI_SIG("E9 ?? AA");
    static_assert(sig[0] == 0xE9);
    static_assert(sig[1] == std::nullopt);
    constexpr auto sum = [](auto&&... values) { return (values + ...); };
    constexpr auto result = sum(
        1, 2, 3, 4, 5,
        6, 7, 8, 9, 10
    );
    std::cout << result << '\n';
}
