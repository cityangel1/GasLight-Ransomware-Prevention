/*++

Module Name:

    logging.h

Abstract:

    Minimal kernel debug logging. Deliberately used sparingly — only from
    enforcement paths (a write was actually blocked/redirected/denied),
    never from the per-I/O hot path itself. See the doc's "Logging"
    section: "Avoid logging every write. Instead... Only important
    events."

--*/

#pragma once

#include "structures.h"

VOID
GlLogEnforcement(
    _In_ ULONG Pid,
    _In_ PCWSTR ProcessHint,
    _In_ PCUNICODE_STRING FileName,
    _In_ GL_POLICY Policy,
    _In_ ULONG MajorFunction
    );

VOID
GlLogInfo(
    _In_ PCSTR Format,
    ...
    );

VOID
GlLogError(
    _In_ PCSTR Format,
    ...
    );
