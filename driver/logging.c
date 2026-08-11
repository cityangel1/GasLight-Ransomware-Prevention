/*++

Module Name:

    logging.c

Abstract:

    See logging.h.

--*/

#include "logging.h"
#include <stdarg.h>

#define GL_LOG_PREFIX "[GasLight] "

VOID
GlLogInfo(
    _In_ PCSTR Format,
    ...
    )
{
    va_list args;
    va_start(args, Format);
    vDbgPrintExWithPrefix(GL_LOG_PREFIX, DPFLTR_IHVDRIVER_ID, DPFLTR_INFO_LEVEL, Format, args);
    va_end(args);
}

VOID
GlLogError(
    _In_ PCSTR Format,
    ...
    )
{
    va_list args;
    va_start(args, Format);
    vDbgPrintExWithPrefix(GL_LOG_PREFIX, DPFLTR_IHVDRIVER_ID, DPFLTR_ERROR_LEVEL, Format, args);
    va_end(args);
}

VOID
GlLogEnforcement(
    _In_ ULONG Pid,
    _In_ PCWSTR ProcessHint,
    _In_ PCUNICODE_STRING FileName,
    _In_ GL_POLICY Policy,
    _In_ ULONG MajorFunction
    )
{
    UNREFERENCED_PARAMETER(ProcessHint);

    //
    // %wZ formats a PUNICODE_STRING directly — standard in kernel-mode
    // DbgPrint family functions, no separate conversion buffer needed.
    //
    DbgPrintEx(
        DPFLTR_IHVDRIVER_ID,
        DPFLTR_WARNING_LEVEL,
        GL_LOG_PREFIX "ENFORCED pid=%lu policy=%d major=0x%02X file=%wZ\n",
        Pid,
        (int)Policy,
        MajorFunction,
        FileName
        );
}
