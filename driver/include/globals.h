/*++

Module Name:

    globals.h

Abstract:

    The driver's entire state, in one place, per the architecture doc's
    "Driver State" section: protected folders, policy table, statistics,
    communication channel. Nothing else. A single instance of this lives
    in DriverEntry.c and is referenced via GlGetGlobalData() everywhere
    else — no additional per-file-object or per-instance context is used
    in this MVP.

--*/

#pragma once

#include "structures.h"
#include "policy.h"
#include "protected_paths.h"
#include "communication.h"

typedef struct _GL_GLOBAL_DATA {
    PFLT_FILTER          Filter;
    PFLT_PORT             DefaultPortNotUsed; // reserved; port lives inside Communication
    GL_POLICY_TABLE       PolicyTable;
    GL_PROTECTED_PATHS    ProtectedPaths;
    GL_HONEY_ROOT         HoneyRoot;
    GL_COMMUNICATION      Communication;

    // Simple running counters — the "Statistics" the doc lists as part of
    // driver state. Not persisted; reset on every load.
    volatile LONG WritesObserved;
    volatile LONG WritesEnforced;
} GL_GLOBAL_DATA, *PGL_GLOBAL_DATA;

//
// Defined once in DriverEntry.c.
//
extern GL_GLOBAL_DATA g_GlobalData;
