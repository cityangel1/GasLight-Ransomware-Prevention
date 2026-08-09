/*++

Module Name:

    protected_paths.c

Abstract:

    See protected_paths.h.

--*/

#include "protected_paths.h"

NTSTATUS
GlProtectedPathsInitialize(
    _Out_ PGL_PROTECTED_PATHS Paths
    )
{
    RtlZeroMemory(Paths, sizeof(GL_PROTECTED_PATHS));
    KeInitializeSpinLock(&Paths->Lock);
    return STATUS_SUCCESS;
}

VOID
GlProtectedPathsDestroy(
    _In_ PGL_PROTECTED_PATHS Paths
    )
{
    RtlZeroMemory(Paths, sizeof(GL_PROTECTED_PATHS));
}

NTSTATUS
GlProtectedPathsAdd(
    _Inout_ PGL_PROTECTED_PATHS Paths,
    _In_ PCUNICODE_STRING Path
    )
{
    KIRQL oldIrql;
    NTSTATUS status = STATUS_INSUFFICIENT_RESOURCES;

    if (Path->Length == 0 || Path->Length >= (GL_MAX_PATH_CHARS - 1) * sizeof(WCHAR)) {
        return STATUS_INVALID_PARAMETER;
    }

    KeAcquireSpinLock(&Paths->Lock, &oldIrql);

    if (Paths->Count < GL_MAX_PROTECTED_PATHS) {
        ULONG slot = Paths->Count;

        RtlZeroMemory(Paths->Buffers[slot], sizeof(Paths->Buffers[slot]));
        RtlCopyMemory(Paths->Buffers[slot], Path->Buffer, Path->Length);

        Paths->Paths[slot].Buffer = Paths->Buffers[slot];
        Paths->Paths[slot].Length = Path->Length;
        Paths->Paths[slot].MaximumLength = sizeof(Paths->Buffers[slot]);

        Paths->Count++;
        status = STATUS_SUCCESS;
    }

    KeReleaseSpinLock(&Paths->Lock, oldIrql);

    return status;
}

BOOLEAN
GlProtectedPathsContains(
    _In_ PGL_PROTECTED_PATHS Paths,
    _In_ PCUNICODE_STRING FileName
    )
{
    KIRQL oldIrql;
    ULONG i;
    BOOLEAN found = FALSE;

    KeAcquireSpinLock(&Paths->Lock, &oldIrql);

    for (i = 0; i < Paths->Count; i++) {
        if (RtlPrefixUnicodeString(&Paths->Paths[i], FileName, TRUE /* CaseInSensitive */)) {
            found = TRUE;
            break;
        }
    }

    KeReleaseSpinLock(&Paths->Lock, oldIrql);

    return found;
}

NTSTATUS
GlHoneyRootInitialize(
    _Out_ PGL_HONEY_ROOT HoneyRoot
    )
{
    RtlZeroMemory(HoneyRoot, sizeof(GL_HONEY_ROOT));
    return STATUS_SUCCESS;
}

NTSTATUS
GlHoneyRootSet(
    _Inout_ PGL_HONEY_ROOT HoneyRoot,
    _In_ PCUNICODE_STRING Path
    )
{
    if (Path->Length == 0 || Path->Length >= (GL_MAX_PATH_CHARS - 1) * sizeof(WCHAR)) {
        return STATUS_INVALID_PARAMETER;
    }

    RtlZeroMemory(HoneyRoot->Buffer, sizeof(HoneyRoot->Buffer));
    RtlCopyMemory(HoneyRoot->Buffer, Path->Buffer, Path->Length);

    HoneyRoot->Path.Buffer = HoneyRoot->Buffer;
    HoneyRoot->Path.Length = Path->Length;
    HoneyRoot->Path.MaximumLength = sizeof(HoneyRoot->Buffer);
    HoneyRoot->Configured = TRUE;

    return STATUS_SUCCESS;
}

BOOLEAN
GlHoneyRootContains(
    _In_ PGL_HONEY_ROOT HoneyRoot,
    _In_ PCUNICODE_STRING FileName
    )
{
    if (!HoneyRoot->Configured) {
        return FALSE;
    }

    return RtlPrefixUnicodeString(&HoneyRoot->Path, FileName, TRUE /* CaseInSensitive */);
}
