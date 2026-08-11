/*++

Module Name:

    policy.c

Abstract:

    See policy.h. Implementation notes:

    - Fixed-size table, allocated once in GlPolicyTableInitialize. No pool
      allocation ever happens on the lookup/set/remove paths — required,
      since GlPolicyTableGet is called from IRP_MJ_WRITE, which the
      architecture doc explicitly says must stay to "Lookup -> Decision ->
      Return" with nothing heavier.

    - Open addressing with linear probing, and tombstones on delete so a
      later lookup that has to probe *past* a deleted slot still finds
      what it's looking for. Without tombstones, deleting an entry that
      sits between a colliding entry's ideal slot and its actual slot
      would silently break that entry's lookups.

    - Protected by a single KSPIN_LOCK. A spin lock (rather than a fast
      mutex or ERESOURCE) is used deliberately: preoperation callbacks in
      a minifilter can in principle run at any IRQL up to DISPATCH_LEVEL
      depending on the operation and underlying stack, and a spin lock is
      the one synchronization primitive that's always valid regardless of
      caller IRQL. The table is small and critical sections are short
      (bounded-length linear probes), so contention cost is acceptable.

--*/

#include "policy.h"

NTSTATUS
GlPolicyTableInitialize(
    _Out_ PGL_POLICY_TABLE Table
    )
{
    RtlZeroMemory(Table, sizeof(GL_POLICY_TABLE));
    KeInitializeSpinLock(&Table->Lock);
    return STATUS_SUCCESS;
}

VOID
GlPolicyTableDestroy(
    _In_ PGL_POLICY_TABLE Table
    )
{
    //
    // Nothing to free — the table is a fixed embedded array, not
    // separately pool-allocated. Zeroing it is defensive hygiene only.
    //
    RtlZeroMemory(Table, sizeof(GL_POLICY_TABLE));
}

static
ULONG
GlpHashPid(
    _In_ ULONG Pid
    )
{
    return Pid % GL_POLICY_TABLE_SIZE;
}

NTSTATUS
GlPolicyTableSet(
    _In_ PGL_POLICY_TABLE Table,
    _In_ ULONG Pid,
    _In_ GL_POLICY Policy
    )
{
    KIRQL oldIrql;
    ULONG index;
    ULONG probes;
    NTSTATUS status = STATUS_INSUFFICIENT_RESOURCES;

    KeAcquireSpinLock(&Table->Lock, &oldIrql);

    index = GlpHashPid(Pid);

    for (probes = 0; probes < GL_POLICY_TABLE_SIZE; probes++) {

        PGL_POLICY_ENTRY entry = &Table->Entries[index];

        if (entry->InUse && entry->Pid == Pid) {
            //
            // Existing entry for this PID — overwrite the policy. This is
            // the common case once the behavioral engine has already
            // classified a process and later escalates (e.g.
            // Monitor -> Block).
            //
            entry->Policy = Policy;
            status = STATUS_SUCCESS;
            break;
        }

        if (!entry->InUse) {
            //
            // First free slot found on this probe sequence (whether
            // truly empty or a tombstone) — claim it.
            //
            entry->Pid = Pid;
            entry->Policy = Policy;
            entry->InUse = TRUE;
            entry->Tombstone = FALSE;
            status = STATUS_SUCCESS;
            break;
        }

        index = (index + 1) % GL_POLICY_TABLE_SIZE;
    }

    KeReleaseSpinLock(&Table->Lock, oldIrql);

    return status;
}

VOID
GlPolicyTableRemove(
    _In_ PGL_POLICY_TABLE Table,
    _In_ ULONG Pid
    )
{
    KIRQL oldIrql;
    ULONG index;
    ULONG probes;

    KeAcquireSpinLock(&Table->Lock, &oldIrql);

    index = GlpHashPid(Pid);

    for (probes = 0; probes < GL_POLICY_TABLE_SIZE; probes++) {

        PGL_POLICY_ENTRY entry = &Table->Entries[index];

        //
        // An empty, never-used slot means the PID was never in the
        // table — the probe chain can't continue past it, so stop.
        //
        if (!entry->InUse && !entry->Tombstone) {
            break;
        }

        if (entry->InUse && entry->Pid == Pid) {
            entry->InUse = FALSE;
            entry->Tombstone = TRUE;
            entry->Pid = 0;
            break;
        }

        index = (index + 1) % GL_POLICY_TABLE_SIZE;
    }

    KeReleaseSpinLock(&Table->Lock, oldIrql);
}

GL_POLICY
GlPolicyTableGet(
    _In_ PGL_POLICY_TABLE Table,
    _In_ ULONG Pid
    )
{
    KIRQL oldIrql;
    ULONG index;
    ULONG probes;
    GL_POLICY result = GlPolicyAllow; // fail-open default for unknown PIDs

    KeAcquireSpinLock(&Table->Lock, &oldIrql);

    index = GlpHashPid(Pid);

    for (probes = 0; probes < GL_POLICY_TABLE_SIZE; probes++) {

        PGL_POLICY_ENTRY entry = &Table->Entries[index];

        if (!entry->InUse && !entry->Tombstone) {
            // Truly empty slot — the PID was never inserted.
            break;
        }

        if (entry->InUse && entry->Pid == Pid) {
            result = entry->Policy;
            break;
        }

        index = (index + 1) % GL_POLICY_TABLE_SIZE;
    }

    KeReleaseSpinLock(&Table->Lock, oldIrql);

    return result;
}
