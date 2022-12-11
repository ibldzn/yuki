#pragma once

#include <utility>
#if defined(_WIN32)
#  pragma push_macro("WIN32_LEAN_AND_MEAN")
#  if !defined(WIN32_LEAN_AND_MEAN)
#    define WIN32_LEAN_AND_MEAN
#  endif
#  include <windows.h>
#  pragma pop_macro("WIN32_LEAN_AND_MEAN")
#elif defined(__unix__)
#  pragma push_macro("_GNU_SOURCE")
#  if !defined(_GNU_SOURCE)
#    define _GNU_SOURCE
#  endif
#  pragma pop_macro("_GNU_SOURCE")
#  include <cinttypes>
#  include <sys/mman.h>
#  include <unistd.h>
#else
#  error "Unknown platform"
#endif

#include "pointer.hpp"
#include "prot_flags.hpp"
#include <cstdint>
#include <memory>

namespace yuki {
    struct ScopedProtect {
        ScopedProtect(Pointer address, std::size_t size, ProtFlags flags);
        ~ScopedProtect();

        ScopedProtect(ScopedProtect&& other);
        ScopedProtect(const ScopedProtect&) = delete;
        ScopedProtect& operator=(ScopedProtect&&) = delete;
        ScopedProtect& operator=(const ScopedProtect&) = delete;

        explicit operator bool() const;

    private:
        void* m_address = nullptr;
        std::size_t m_size = 0;
        bool m_success = false;
        ProtFlags m_old_flags = ProtFlags::INVALID;
    };

    std::size_t page_size();

    void* protect_alloc(std::size_t size, ProtFlags flags);
    bool protect_free(Pointer address, std::size_t size);

    ProtFlags protect_query(Pointer address);
    bool protect_modify(Pointer address, std::size_t size, ProtFlags flags, ProtFlags* old_flags);

#if defined(__unix__)
    struct RegionInfo {
        std::uintptr_t start = {};
        std::uintptr_t end = {};
        std::size_t offset = {};
        int prot = {};
        int flags = {};
        const char* path_name = nullptr;
    };

    bool iter_proc_maps(bool (*callback)(RegionInfo*, void*), void* data);
#endif

    inline std::size_t page_size()
    {
#if defined(_WIN32)
        SYSTEM_INFO si = {};
        GetSystemInfo(&si);
        return static_cast<std::size_t>(si.dwPageSize);
#elif defined(__unix__)
        return static_cast<std::size_t>(sysconf(_SC_PAGESIZE));
#endif
    }

    inline void* protect_alloc(std::size_t size, ProtFlags flags)
    {
#if defined(_WIN32)
        return VirtualAlloc(nullptr, size, MEM_RESERVE | MEM_COMMIT, from_prot_flags(flags));
#elif defined(__unix__)
        void* result = mmap(nullptr, size, from_prot_flags(flags), MAP_ANONYMOUS | MAP_PRIVATE, -1, 0);
        return result == MAP_FAILED ? nullptr : result;
#endif
    }

    inline bool protect_free(Pointer address, std::size_t size)
    {
#if defined(_WIN32)
        static_cast<void>(size);
        return static_cast<bool>(VirtualFree(address, 0, MEM_RELEASE));
#elif defined(__unix__)
        return munmap(address, size) == 0;
#endif
    }

#if defined(__unix__)
    namespace internal {
        struct ProtQuery {
            std::uintptr_t address = {};
            ProtFlags result = ProtFlags::INVALID;
        };

        inline bool prot_query_callback(RegionInfo* region, void* data)
        {
            ProtQuery* query = static_cast<ProtQuery*>(data);

            if ((query->address >= region->start) && (query->address < region->end)) {
                query->result = to_prot_flags(region->prot);
                return true;
            }

            return false;
        }
    }
#endif

    inline ProtFlags protect_query(Pointer address)
    {
#if defined(_WIN32)
        MEMORY_BASIC_INFORMATION mbi = {};

        if (VirtualQuery(address, &mbi, sizeof(MEMORY_BASIC_INFORMATION))) {
            return to_prot_flags(mbi.Protect);
        }

        return ProtFlags::INVALID;
#elif defined(__unix__)
        internal::ProtQuery query = {};
        query.address = address.as<std::uintptr_t>();

        if (iter_proc_maps(&internal::prot_query_callback, &query)) {
            return query.result;
        }

        return ProtFlags::INVALID;
#endif
    }

    inline bool protect_modify(Pointer address, std::size_t size, ProtFlags flags, ProtFlags* old_flags)
    {
        if (flags == ProtFlags::INVALID) {
            return false;
        }

#if defined(_WIN32)
        native_prot old_protect = 0;
        const bool success = VirtualProtect(address, size, from_prot_flags(flags), &old_protect);

        if (old_flags) {
            *old_flags = success ? to_prot_flags(old_protect) : ProtFlags::INVALID;
        }

        return success;
#elif defined(__unix__)
        if (old_flags) {
            *old_flags = protect_query(address);
        }

        return mprotect(address, size, from_prot_flags(flags)) == 0;
#endif
    }

#if defined(__unix__)
    inline bool iter_proc_maps(bool (*callback)(RegionInfo*, void*), void* data)
    {
        std::unique_ptr<FILE, decltype(&fclose)> maps { std::fopen("/proc/self/maps", "r"), &fclose };

        bool result = false;

        if (maps) {
            char buffer[256];

            RegionInfo region;

            char perms[5];
            char pathname[256];

            while (std::fgets(buffer, sizeof(buffer), maps.get())) {
                int count = std::sscanf(
                    buffer,
                    "%" SCNxPTR "-%" SCNxPTR " %4s %zx %*x:%*x %*u %255s",
                    &region.start,
                    &region.end,
                    perms,
                    &region.offset,
                    pathname
                );

                if (count < 4) {
                    continue;
                }

                region.prot = PROT_NONE;
                region.flags = 0;

                if (perms[0] == 'r') {
                    region.prot |= PROT_READ;
                }

                if (perms[1] == 'w') {
                    region.prot |= PROT_WRITE;
                }

                if (perms[2] == 'x') {
                    region.prot |= PROT_EXEC;
                }

                if (perms[3] == 's') {
                    region.flags |= MAP_SHARED;
                } else if (perms[3] == 'p') {
                    region.flags |= MAP_PRIVATE;
                }

                if (count > 4) {
                    region.path_name = pathname;
                } else {
                    region.flags |= MAP_ANONYMOUS;
                    region.path_name = nullptr;
                }

                result = callback(&region, data);

                if (result) {
                    break;
                }
            }
        }

        return result;
    }
#endif

    YUKI_FORCE_INLINE ScopedProtect::ScopedProtect(Pointer address, std::size_t size, ProtFlags flags)
        : m_address(address)
        , m_size(size)
        , m_success(protect_modify(address, size, flags, &m_old_flags))
    {
    }

    YUKI_FORCE_INLINE ScopedProtect::~ScopedProtect()
    {
        if (m_success) {
            protect_modify(m_address, m_size, m_old_flags, nullptr);
        }
    }

    YUKI_FORCE_INLINE ScopedProtect::ScopedProtect(ScopedProtect&& other)
        : m_address(std::exchange(other.m_address, nullptr))
        , m_size(std::exchange(other.m_size, 0))
        , m_success(std::exchange(other.m_success, false))
        , m_old_flags(std::exchange(other.m_old_flags, ProtFlags::INVALID))
    {
    }

    YUKI_FORCE_INLINE ScopedProtect::operator bool() const
    {
        return m_success;
    }
}
