#pragma once

#include "ct_str.hpp"
#include "defines.hpp"
#include "str.hpp"
#include <array>
#include <cstdint>
#include <optional>

namespace yuki {
    template <CTStr sig, char wildcard = '?', char delimiter = ' '>
    constexpr auto sig2ba()
    {
        constexpr auto begin = [] {
            for (std::size_t i = 0, len = sig.length(); i < len; ++i) {
                if (sig[i] != delimiter) {
                    return i;
                }
            }
            throw 0xDEADBEEF;
        }();

        constexpr auto end = [] {
            for (std::size_t i = sig.length() - 1; i > begin; --i) {
                if (sig[i] != delimiter) {
                    return i;
                }
            }
            throw 0xDEADBEEF;
        }();

        constexpr auto size = [] {
            std::size_t ret = 1;
            bool was_delimiter = false;

            for (std::size_t i = begin; i < end; ++i) {
                if (sig[i] == delimiter) {
                    if (!was_delimiter) {
                        ret += 1;
                        was_delimiter = true;
                    }
                } else {
                    was_delimiter = false;
                }
            }

            return ret;
        }();

        std::array<std::optional<std::uint8_t>, size> arr;

        for (std::size_t i = 0, indexer = 0, len = sig.length(); i < len; ++i) {
            if (sig[i] == delimiter) {
                continue;
            }

            if (sig[i] == wildcard) {
                i += 1;

                if (i < len && sig[i] == wildcard) {
                    i += 1;
                }

                arr[indexer++] = std::nullopt;
            } else if (i < len - 1) {
                arr[indexer++] = static_cast<std::uint8_t>((xctoi(sig[i]) << 4) | xctoi(sig[i + 1]));
                i += 2;
            } else {
                YUKI_IF_IS_CONSTANT_EVALUATED({
                    throw "Premature sig!";
                });
            }
        }

        return arr;
    }

#define YUKI_SIG(sig) ([] { constexpr auto result = yuki::sig2ba<sig>(); return result; }())
}