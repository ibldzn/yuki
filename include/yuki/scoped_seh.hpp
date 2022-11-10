#pragma once

#if !defined(_WIN32) || !defined(_WIN64)
#  error "Windows Only"
#endif

#include "defines.hpp"
#include <stdexcept>
#include <utility>

#pragma push_macro("WIN32_LEAN_AND_MEAN")
#if !defined(WIN32_LEAN_AND_MEAN)
#  define WIN32_LEAN_AND_MEAN
#endif
#include <eh.h>
#include <windows.h>
#pragma pop_macro("WIN32_LEAN_AND_MEAN")

namespace yuki {
    struct ScopedSEH {
        ScopedSEH();
        ~ScopedSEH();

        ScopedSEH(const ScopedSEH&) = delete;
        ScopedSEH(ScopedSEH&&) = delete;

        template <typename Fn, typename... Args>
        auto execute(Fn&& fn, Args&&... args) -> decltype(fn(std::forward<Args>(args)...));

    private:
        _se_translator_function m_old_handler = nullptr;
    };

    namespace internal {
        inline constexpr const char* translate_exception_code(std::uint32_t code)
        {
#define YUKI_EC_CASE_TO_STR(ec) \
  case ec:                      \
    return #ec

            switch (code) {
                YUKI_EC_CASE_TO_STR(STATUS_GUARD_PAGE_VIOLATION);
                YUKI_EC_CASE_TO_STR(STATUS_DATATYPE_MISALIGNMENT);
                YUKI_EC_CASE_TO_STR(STATUS_BREAKPOINT);
                YUKI_EC_CASE_TO_STR(STATUS_SINGLE_STEP);
                YUKI_EC_CASE_TO_STR(STATUS_LONGJUMP);
                YUKI_EC_CASE_TO_STR(STATUS_UNWIND_CONSOLIDATE);
                YUKI_EC_CASE_TO_STR(DBG_EXCEPTION_NOT_HANDLED);
                YUKI_EC_CASE_TO_STR(STATUS_ACCESS_VIOLATION);
                YUKI_EC_CASE_TO_STR(STATUS_IN_PAGE_ERROR);
                YUKI_EC_CASE_TO_STR(STATUS_INVALID_HANDLE);
                YUKI_EC_CASE_TO_STR(STATUS_INVALID_PARAMETER);
                YUKI_EC_CASE_TO_STR(STATUS_NO_MEMORY);
                YUKI_EC_CASE_TO_STR(STATUS_ILLEGAL_INSTRUCTION);
                YUKI_EC_CASE_TO_STR(STATUS_NONCONTINUABLE_EXCEPTION);
                YUKI_EC_CASE_TO_STR(STATUS_INVALID_DISPOSITION);
                YUKI_EC_CASE_TO_STR(STATUS_ARRAY_BOUNDS_EXCEEDED);
                YUKI_EC_CASE_TO_STR(STATUS_FLOAT_DENORMAL_OPERAND);
                YUKI_EC_CASE_TO_STR(STATUS_FLOAT_DIVIDE_BY_ZERO);
                YUKI_EC_CASE_TO_STR(STATUS_FLOAT_INEXACT_RESULT);
                YUKI_EC_CASE_TO_STR(STATUS_FLOAT_INVALID_OPERATION);
                YUKI_EC_CASE_TO_STR(STATUS_FLOAT_OVERFLOW);
                YUKI_EC_CASE_TO_STR(STATUS_FLOAT_STACK_CHECK);
                YUKI_EC_CASE_TO_STR(STATUS_FLOAT_UNDERFLOW);
                YUKI_EC_CASE_TO_STR(STATUS_INTEGER_DIVIDE_BY_ZERO);
                YUKI_EC_CASE_TO_STR(STATUS_INTEGER_OVERFLOW);
                YUKI_EC_CASE_TO_STR(STATUS_PRIVILEGED_INSTRUCTION);
                YUKI_EC_CASE_TO_STR(STATUS_STACK_OVERFLOW);
                YUKI_EC_CASE_TO_STR(STATUS_DLL_NOT_FOUND);
                YUKI_EC_CASE_TO_STR(STATUS_ORDINAL_NOT_FOUND);
                YUKI_EC_CASE_TO_STR(STATUS_ENTRYPOINT_NOT_FOUND);
                YUKI_EC_CASE_TO_STR(STATUS_CONTROL_C_EXIT);
                YUKI_EC_CASE_TO_STR(STATUS_DLL_INIT_FAILED);
                YUKI_EC_CASE_TO_STR(STATUS_FLOAT_MULTIPLE_FAULTS);
                YUKI_EC_CASE_TO_STR(STATUS_FLOAT_MULTIPLE_TRAPS);
                YUKI_EC_CASE_TO_STR(STATUS_REG_NAT_CONSUMPTION);
                YUKI_EC_CASE_TO_STR(STATUS_HEAP_CORRUPTION);
                YUKI_EC_CASE_TO_STR(STATUS_STACK_BUFFER_OVERRUN);
                YUKI_EC_CASE_TO_STR(STATUS_INVALID_CRUNTIME_PARAMETER);
                YUKI_EC_CASE_TO_STR(STATUS_ASSERTION_FAILURE);
                YUKI_EC_CASE_TO_STR(STATUS_ENCLAVE_VIOLATION);
            }

            return "UNKNOWN_ERROR";

#undef YUKI_EC_CASE_TO_STR
        }

        inline void translate_seh(std::uint32_t code, EXCEPTION_POINTERS* ep)
        {
            const char* code_name = translate_exception_code(code);
            char buffer[2048] {};

            std::snprintf(buffer, sizeof(buffer), // clang-format off
#if defined(YUKI_ARCH_X86_64)
                "%s (0x%08X) at 0x%016llX\n"
                "RAX = 0x%016llX RBX = 0x%016llX RCX = 0x%016llX RDX = 0x%016llX\n"
                "RSP = 0x%016llX RBP = 0x%016llX RSI = 0x%016llX RDI = 0x%016llX\n"
                "R8  = 0x%016llX R9  = 0x%016llX R10 = 0x%016llX R11 = 0x%016llX\n"
                "R12 = 0x%016llX R13 = 0x%016llX R14 = 0x%016llX R15 = 0x%016llX\n",
                code_name, code,
                reinterpret_cast<DWORD64>(ep->ExceptionRecord->ExceptionAddress),
                ep->ContextRecord->Rax, ep->ContextRecord->Rbx, ep->ContextRecord->Rcx, ep->ContextRecord->Rdx,
                ep->ContextRecord->Rsp, ep->ContextRecord->Rbp, ep->ContextRecord->Rsi, ep->ContextRecord->Rdi,
                ep->ContextRecord->R8,  ep->ContextRecord->R9,  ep->ContextRecord->R10, ep->ContextRecord->R11,
                ep->ContextRecord->R12, ep->ContextRecord->R13, ep->ContextRecord->R14, ep->ContextRecord->R15
#else /*if defined(YUKI_ARCH_X86)*/
                "%s (0x%08X) at 0x%08X\n"
                "EAX = 0x%08lX EBX = 0x%08lX ECX = 0x%08lX EDX = 0x%08lX\n"
                "ESP = 0x%08lX EBP = 0x%08lX ESI = 0x%08lX EDI = 0x%08lX\n",
                code_name, code,
                reinterpret_cast<DWORD>(ep->ExceptionRecord->ExceptionAddress),
                ep->ContextRecord->Eax, ep->ContextRecord->Ebx, ep->ContextRecord->Ecx, ep->ContextRecord->Edx,
                ep->ContextRecord->Esp, ep->ContextRecord->Ebp, ep->ContextRecord->Esi, ep->ContextRecord->Edi
#endif
            ); // clang-format on

            throw std::runtime_error(buffer);
        }
    }

#if defined(_MSC_VER)
#  pragma warning(push)
#  pragma warning(disable : 4535) // warning C4535: calling _set_se_translator() requires /EHa
#endif

    inline ScopedSEH::ScopedSEH()
        : m_old_handler(_set_se_translator(&internal::translate_seh))
    {
    }

    inline ScopedSEH::~ScopedSEH()
    {
        _set_se_translator(m_old_handler);
    }

    template <typename Fn, typename... Args>
    inline auto ScopedSEH::execute(Fn&& fn, Args&&... args) -> decltype(fn(std::forward<Args>(args)...))
    {
        return fn(std::forward<Args>(args)...);
    }

#if defined(_MSC_VER)
#  pragma warning(pop)
#endif
}