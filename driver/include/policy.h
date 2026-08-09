/*++

Module Name:

    policy.h

Abstract:

    In-kernel PID -> Policy lookup table. O(1) average lookup via a fixed
    hash table with linear probing — no pool allocation once
    GlPolicyTableInitialize has run, which is what makes this safe to call
    from the IRP_MJ_WRITE hot path.

--*/

#pragma once

#include "structures.h"

NTSTATUS
GlPolicyTableInitialize(
    _Out_ PGL_POLICY_TABLE Table
    );

VOID
GlPolicyTableDestroy(
    _In_ PGL_POLICY_TABLE Table
    );

//
// Sets (or overwrites) the policy for a PID. Called from the
// communication layer when the behavioral engine sends a policy update.
//
NTSTATUS
GlPolicyTableSet(
    _In_ PGL_POLICY_TABLE Table,
    _In_ ULONG Pid,
    _In_ GL_POLICY Policy
    );

//
// Removes a PID from the table (e.g. once the process has exited — the
// entry would otherwise sit stale forever, and PIDs get reused).
//
VOID
GlPolicyTableRemove(
    _In_ PGL_POLICY_TABLE Table,
    _In_ ULONG Pid
    );

//
// Looks up the policy for a PID. Processes the driver has never heard
// about (the vast majority — Notepad, Word, everything benign) fall
// through to GlPolicyAllow. This is the driver's fail-open default for
// *unknown* processes; see GlCommunicationOnDisconnect in communication.c
// for the separate "the whole user-mode agent is gone" fail-open case the
// architecture doc discusses.
//
GL_POLICY
GlPolicyTableGet(
    _In_ PGL_POLICY_TABLE Table,
    _In_ ULONG Pid
    );
