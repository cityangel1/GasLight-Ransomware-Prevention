/*++

Module Name:

    structures.h

Abstract:

    Shared data structures used across the GasLight minifilter. Kept in one
    header, deliberately small — per the architecture doc, this driver
    holds almost no state: protected folders, a PID -> Policy lookup
    table, statistics, and a communication channel. Nothing else.

--*/

#pragma once

#include <fltKernel.h>

//
// A decision the behavioral engine (user mode) has made about a process.
// The driver never computes this itself — it only enforces it. See the
// architecture doc's opening point: "Keep the behavioral engine as the
// only decision-maker. The filter should be a Policy Enforcement Point."
//
typedef enum _GL_POLICY {
    GlPolicyAllow = 0,
    GlPolicyMonitor,
    GlPolicyBlock,
    GlPolicyRedirect,
    GlPolicyTerminate
} GL_POLICY;

//
// One entry in the in-kernel policy table.
//
typedef struct _GL_POLICY_ENTRY {
    ULONG     Pid;
    GL_POLICY Policy;
    BOOLEAN   InUse;    // slot currently holds a live entry
    BOOLEAN   Tombstone; // slot held an entry that was removed — keep probing through it
} GL_POLICY_ENTRY, *PGL_POLICY_ENTRY;

//
// Fixed-capacity, open-addressed hash table. No pool allocation on the
// hot path (IRP_MJ_WRITE) — the whole table is allocated once at
// DriverEntry and indexed by Pid % GL_POLICY_TABLE_SIZE with linear
// probing. 4096 concurrent tracked processes is comfortably more than a
// single endpoint will ever need to police at once.
//
#define GL_POLICY_TABLE_SIZE 4096

typedef struct _GL_POLICY_TABLE {
    GL_POLICY_ENTRY Entries[GL_POLICY_TABLE_SIZE];
    KSPIN_LOCK      Lock;
} GL_POLICY_TABLE, *PGL_POLICY_TABLE;

//
// Protected path list. Also fixed-capacity and allocated once — the
// filter only cares about I/O under these prefixes; everything else is
// ignored as early as possible to keep latency down (see the doc's
// "Protected Paths" / "Performance" sections).
//
#define GL_MAX_PROTECTED_PATHS 64
#define GL_MAX_PATH_CHARS      260

typedef struct _GL_PROTECTED_PATHS {
    UNICODE_STRING Paths[GL_MAX_PROTECTED_PATHS];
    WCHAR          Buffers[GL_MAX_PROTECTED_PATHS][GL_MAX_PATH_CHARS];
    ULONG          Count;
    KSPIN_LOCK     Lock;
} GL_PROTECTED_PATHS, *PGL_PROTECTED_PATHS;

//
// Honey (decoy) storage root. Kept structurally identical to the
// protected-path check but held separately so honeypot hits can be
// distinguished from ordinary protected-folder activity in telemetry —
// touching a honey path is a much stronger signal than touching a real
// protected folder.
//
typedef struct _GL_HONEY_ROOT {
    UNICODE_STRING Path;
    WCHAR          Buffer[GL_MAX_PATH_CHARS];
    BOOLEAN        Configured;
} GL_HONEY_ROOT, *PGL_HONEY_ROOT;

//
// Wire format for the user-mode <-> kernel-mode communication port.
// Kept as plain fixed-size structs (no pointers, no variable-length
// fields) since this crosses the user/kernel boundary via
// FltSendMessage/FltGetMessage — see communication.c.
//
typedef enum _GL_MESSAGE_TYPE {
    GlMsgSetPolicy = 1,        // user mode -> kernel: update one PID's policy
    GlMsgRemovePolicy = 2,     // user mode -> kernel: stop tracking a PID (process exited)
    GlMsgEnforcementEvent = 3  // kernel -> user mode: "I just blocked something"
} GL_MESSAGE_TYPE;

typedef struct _GL_SET_POLICY_MESSAGE {
    GL_MESSAGE_TYPE Type; // GlMsgSetPolicy
    ULONG           Pid;
    GL_POLICY       Policy;
} GL_SET_POLICY_MESSAGE, *PGL_SET_POLICY_MESSAGE;

typedef struct _GL_REMOVE_POLICY_MESSAGE {
    GL_MESSAGE_TYPE Type; // GlMsgRemovePolicy
    ULONG           Pid;
} GL_REMOVE_POLICY_MESSAGE, *PGL_REMOVE_POLICY_MESSAGE;

//
// Sent kernel -> user mode via FltSendMessage whenever the driver actually
// enforces something (blocks/redirects a write, denies a rename, etc).
// Deliberately small and infrequent — see the doc's "Logging" section:
// "Avoid logging every write. Instead: only important events."
//
typedef struct _GL_ENFORCEMENT_EVENT {
    GL_MESSAGE_TYPE Type; // GlMsgEnforcementEvent
    ULONG           Pid;
    GL_POLICY       PolicyApplied;
    ULONG           MajorFunction;      // IRP_MJ_WRITE, IRP_MJ_SET_INFORMATION, ...
    BOOLEAN         WasHoneyPath;
    WCHAR           FileName[GL_MAX_PATH_CHARS];
} GL_ENFORCEMENT_EVENT, *PGL_ENFORCEMENT_EVENT;

#define GL_POOL_TAG 'thGL' // "GLht" reversed for little-endian tag display — "GasLight"
