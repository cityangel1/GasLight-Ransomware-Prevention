/*++

Module Name:

    callbacks.h

Abstract:

    The filter's actual I/O interception points. Per the architecture
    doc's opening principle, these never compute a score or make a
    judgment call — they look up an already-made decision (the policy
    table) and enforce it. Only four operations are intercepted, matching
    the doc's Milestone 3 scope exactly: CREATE, WRITE, SET_INFORMATION
    (rename/delete/attributes), CLEANUP.

--*/

#pragma once

#include "globals.h"

FLT_PREOP_CALLBACK_STATUS
GlPreCreate(
    _Inout_ PFLT_CALLBACK_DATA Data,
    _In_ PCFLT_RELATED_OBJECTS FltObjects,
    _Flt_CompletionContext_Outptr_ PVOID *CompletionContext
    );

FLT_PREOP_CALLBACK_STATUS
GlPreWrite(
    _Inout_ PFLT_CALLBACK_DATA Data,
    _In_ PCFLT_RELATED_OBJECTS FltObjects,
    _Flt_CompletionContext_Outptr_ PVOID *CompletionContext
    );

FLT_PREOP_CALLBACK_STATUS
GlPreSetInformation(
    _Inout_ PFLT_CALLBACK_DATA Data,
    _In_ PCFLT_RELATED_OBJECTS FltObjects,
    _Flt_CompletionContext_Outptr_ PVOID *CompletionContext
    );

FLT_PREOP_CALLBACK_STATUS
GlPreCleanup(
    _Inout_ PFLT_CALLBACK_DATA Data,
    _In_ PCFLT_RELATED_OBJECTS FltObjects,
    _Flt_CompletionContext_Outptr_ PVOID *CompletionContext
    );

extern CONST FLT_OPERATION_REGISTRATION GlOperationRegistration[];
