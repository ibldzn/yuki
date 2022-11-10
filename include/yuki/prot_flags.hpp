#pragma once

#if defined(_WIN32)
#  pragma push_macro("WIN32_LEAN_AND_MEAN")
#  if !defined(WIN32_LEAN_AND_MEAN)
#    define WIN32_LEAN_AND_MEAN
#  endif
#  include <windows.h>
#  pragma pop_macro("WIN32_LEAN_AND_MEAN")
#elif defined(__unix__)
#  include <sys/mman.h>
#else
#  error "Unknown platform"
#endif

#include "bitwise_enum.hpp"
#include "defines.hpp"
#include <cstdint>

namespace yuki {
    namespace enums {
        enum ProtFlags : std::uint32_t {
            // clang-format off

            NONE = 0x0, // No access

            R = 1 << 0, // Read
            W = 1 << 1, // Write
            X = 1 << 2, // Execute
            C = 1 << 3, // Copy on write

            G = 1 << 4, // Guard
            INVALID = static_cast<std::uint32_t>(1 << (sizeof(std::uint32_t) * 8 - 1)), // Invalid (0x80000000)

            RW   = R | W,
            RX   = R     | X,
            RWX  = R | W | X,
            RWC  = R | W     | C,
            RWXC = R | W | X | C,

            // clang-format on
        };

        YUKI_DEFINE_ENUM_FLAG_OPERATORS(ProtFlags);
    }

    using enums::ProtFlags;

#if defined(_WIN32)
    using native_prot = DWORD;
#elif defined(__unix__)
    using native_prot = int;
#endif

    constexpr native_prot from_prot_flags(ProtFlags flags);
    constexpr ProtFlags to_prot_flags(native_prot flags);

    inline constexpr native_prot from_prot_flags(ProtFlags flags)
    {
#if defined(_WIN32)
        native_prot result = PAGE_NOACCESS;

        // clang-format off
        if (flags & ProtFlags::X) {
            if      (flags & ProtFlags::C) { result = PAGE_EXECUTE_WRITECOPY; }
            else if (flags & ProtFlags::W) { result = PAGE_EXECUTE_READWRITE; }
            else if (flags & ProtFlags::R) { result = PAGE_EXECUTE_READ;      }
            else                           { result = PAGE_EXECUTE;           }
        } else {
            if      (flags & ProtFlags::C) { result = PAGE_WRITECOPY; }
            else if (flags & ProtFlags::W) { result = PAGE_READWRITE; }
            else if (flags & ProtFlags::R) { result = PAGE_READONLY;  }
            else                           { result = PAGE_NOACCESS;  }
        }

        if (flags & ProtFlags::G) {
            result |= PAGE_GUARD;
        }

        return result;
#elif defined(__unix__)
        native_prot result = 0;

        if (flags & ProtFlags::R) { result |= PROT_READ;  }
        if (flags & ProtFlags::W) { result |= PROT_WRITE; }
        if (flags & ProtFlags::X) { result |= PROT_EXEC;  }

        return result;
#endif
        // clang-format on
    }

    inline constexpr ProtFlags to_prot_flags(native_prot flags)
    {
#if defined(_WIN32)
        ProtFlags result = ProtFlags::INVALID;

#  define YUKI_PROT_FLAGS_CASE(fl, res) \
    case fl:                            \
      result = res;                     \
      break

        switch (flags & 0xFF) {
            // clang-format off
            YUKI_PROT_FLAGS_CASE(PAGE_EXECUTE,           ProtFlags::X);
            YUKI_PROT_FLAGS_CASE(PAGE_EXECUTE_READ,      ProtFlags::RX);
            YUKI_PROT_FLAGS_CASE(PAGE_EXECUTE_READWRITE, ProtFlags::RWX);
            YUKI_PROT_FLAGS_CASE(PAGE_EXECUTE_WRITECOPY, ProtFlags::RWXC);
            YUKI_PROT_FLAGS_CASE(PAGE_NOACCESS,          ProtFlags::NONE);
            YUKI_PROT_FLAGS_CASE(PAGE_READONLY,          ProtFlags::R);
            YUKI_PROT_FLAGS_CASE(PAGE_READWRITE,         ProtFlags::RW);
            YUKI_PROT_FLAGS_CASE(PAGE_WRITECOPY,         ProtFlags::RWC);
            // clang-format on
        }

        if (flags & PAGE_GUARD) {
            result |= ProtFlags::G;
        }

        return result;

#  undef YUKI_PROT_FLAGS_CASE

#elif defined(__unix__)
        ProtFlags result = ProtFlags::INVALID;

        // clang-format off
        if (flags & PROT_READ)  { result |= ProtFlags::R; }
        if (flags & PROT_WRITE) { result |= ProtFlags::W; }
        if (flags & PROT_EXEC)  { result |= ProtFlags::X; }
        // clang-format on

        return result;
#endif
    }
}