/*++

Module Name:

    communication.h

Abstract:

    Kernel <-> user-mode IPC. Uses FltCreateCommunicationPort — the
    standard, purpose-built mechanism for minifilter/user-mode messaging
    (rather than a raw device + IOCTL), matching how Microsoft's own
    minifilter samples (e.g. "scanner") do it.

    Direction of travel:
      - User mode -> kernel: policy updates (GL_SET_POLICY_MESSAGE /
        GL_REMOVE_POLICY_MESSAGE), sent via FilterSendMessage from the
        Rust driver_client.
      - Kernel -> user mode: enforcement events (GL_ENFORCEMENT_EVENT),
        sent via FltSendMessage, best-effort / non-blocking for the I/O
        path — see GlCommunicationSendEnforcementEvent.

--*/

#pragma once

#include "structures.h"
#include "policy.h"

typedef struct _GL_COMMUNICATION {
    PFLT_FILTER       Filter;
    PFLT_PORT         ServerPort;
    PFLT_PORT         ClientPort;   // NULL when no user-mode agent is connected
    PGL_POLICY_TABLE  PolicyTable;  // updated directly by incoming policy messages
    KSPIN_LOCK        ClientPortLock;
} GL_COMMUNICATION, *PGL_COMMUNICATION;

NTSTATUS
GlCommunicationInitialize(
    _In_ PFLT_FILTER Filter,
    _In_ PGL_POLICY_TABLE PolicyTable,
    _Out_ PGL_COMMUNICATION Communication
    );

VOID
GlCommunicationDestroy(
    _In_ PGL_COMMUNICATION Communication
    );

//
// Best-effort: if no client is connected, or the send times out, this
// simply does nothing. Enforcement decisions must never wait on user mode
// — the policy table lookup that already happened is authoritative on
// its own; this is telemetry, not part of the enforcement path.
//
VOID
GlCommunicationSendEnforcementEvent(
    _In_ PGL_COMMUNICATION Communication,
    _In_ PGL_ENFORCEMENT_EVENT Event
    );

//
// True once fail-open logic in callbacks.c needs it: whether a user-mode
// agent is currently connected. Per the architecture doc's failure-mode
// discussion, callbacks.c defaults to fail-open (Allow) when this is
// FALSE — see the GL_FAIL_CLOSED comment in callbacks.c for how to flip
// that for an enterprise-hardened build.
//
BOOLEAN
GlCommunicationIsAgentConnected(
    _In_ PGL_COMMUNICATION Communication
    );
