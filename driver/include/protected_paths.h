/*++

Module Name:

    protected_paths.h

Abstract:

    Configurable list of protected folder prefixes, plus the separate
    honey-storage root. Checking these first, before any policy lookup,
    is what lets the driver ignore the vast majority of filesystem I/O on
    the machine cheaply (see the doc: "If the write isn't inside these
    folders... Ignore it. This keeps latency low.").

--*/

#pragma once

#include "structures.h"

NTSTATUS
GlProtectedPathsInitialize(
    _Out_ PGL_PROTECTED_PATHS Paths
    );

VOID
GlProtectedPathsDestroy(
    _In_ PGL_PROTECTED_PATHS Paths
    );

//
// Adds one protected folder prefix, e.g. L"\Device\HarddiskVolume3\Users".
// Note paths arriving at a minifilter are in NT device form, not drive
// letters — see the note in utils.c about resolving "C:\Users" style
// config entries to their \Device\... form at load time.
//
NTSTATUS
GlProtectedPathsAdd(
    _Inout_ PGL_PROTECTED_PATHS Paths,
    _In_ PCUNICODE_STRING Path
    );

//
// True if FileName falls under any configured protected prefix.
//
BOOLEAN
GlProtectedPathsContains(
    _In_ PGL_PROTECTED_PATHS Paths,
    _In_ PCUNICODE_STRING FileName
    );

NTSTATUS
GlHoneyRootInitialize(
    _Out_ PGL_HONEY_ROOT HoneyRoot
    );

NTSTATUS
GlHoneyRootSet(
    _Inout_ PGL_HONEY_ROOT HoneyRoot,
    _In_ PCUNICODE_STRING Path
    );

BOOLEAN
GlHoneyRootContains(
    _In_ PGL_HONEY_ROOT HoneyRoot,
    _In_ PCUNICODE_STRING FileName
    );
