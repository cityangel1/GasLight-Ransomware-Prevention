/*++

Module Name:

    utils.c

Abstract:

    See utils.h.

--*/

#include "utils.h"

NTSTATUS
GlUtilsDosPathToNtPath(
    _In_ PCUNICODE_STRING DosPath,
    _Out_ PUNICODE_STRING NtPath,
    _Inout_updates_bytes_(BufferSizeBytes) PWCH Buffer,
    _In_ ULONG BufferSizeBytes
    )
{
    NTSTATUS status;
    UNICODE_STRING symlinkName;
    WCHAR symlinkNameBuffer[8]; // L"\??\" + drive letter + L":" + NUL, generous
    OBJECT_ATTRIBUTES objAttrs;
    HANDLE symlinkHandle = NULL;
    UNICODE_STRING targetPath;
    USHORT remainderOffsetChars;
    USHORT remainderLengthBytes;

    PAGED_CODE();

    if (DosPath->Length < 2 * sizeof(WCHAR) || DosPath->Buffer[1] != L':') {
        //
        // Doesn't look like "C:\..." — pass it through unmodified. This
        // also lets a config file that already has an NT-form path work
        // without extra special-casing.
        //
        if (DosPath->Length >= BufferSizeBytes) {
            return STATUS_BUFFER_TOO_SMALL;
        }
        RtlZeroMemory(Buffer, BufferSizeBytes);
        RtlCopyMemory(Buffer, DosPath->Buffer, DosPath->Length);
        NtPath->Buffer = Buffer;
        NtPath->Length = DosPath->Length;
        NtPath->MaximumLength = (USHORT)BufferSizeBytes;
        return STATUS_SUCCESS;
    }

    // Build "\??\C:" for the drive letter at DosPath->Buffer[0].
    RtlZeroMemory(symlinkNameBuffer, sizeof(symlinkNameBuffer));
    symlinkName.Buffer = symlinkNameBuffer;
    symlinkName.Length = 0;
    symlinkName.MaximumLength = sizeof(symlinkNameBuffer);

    status = RtlAppendUnicodeToString(&symlinkName, L"\\??\\");
    if (!NT_SUCCESS(status)) {
        return status;
    }
    {
        UNICODE_STRING driveLetter;
        driveLetter.Length = sizeof(WCHAR);
        driveLetter.MaximumLength = sizeof(WCHAR);
        driveLetter.Buffer = &DosPath->Buffer[0];

        status = RtlAppendUnicodeStringToString(&symlinkName, &driveLetter);
        if (!NT_SUCCESS(status)) {
            return status;
        }
    }
    status = RtlAppendUnicodeToString(&symlinkName, L":");
    if (!NT_SUCCESS(status)) {
        return status;
    }

    InitializeObjectAttributes(
        &objAttrs,
        &symlinkName,
        OBJ_CASE_INSENSITIVE | OBJ_KERNEL_HANDLE,
        NULL,
        NULL
        );

    status = ZwOpenSymbolicLinkObject(&symlinkHandle, GENERIC_READ, &objAttrs);
    if (!NT_SUCCESS(status)) {
        return status;
    }

    RtlZeroMemory(Buffer, BufferSizeBytes);
    targetPath.Buffer = Buffer;
    targetPath.Length = 0;
    targetPath.MaximumLength = (USHORT)BufferSizeBytes;

    status = ZwQuerySymbolicLinkObject(symlinkHandle, &targetPath, NULL);
    ZwClose(symlinkHandle);

    if (!NT_SUCCESS(status)) {
        return status;
    }

    //
    // Append the remainder of the DOS path after "C:" (e.g. "\Users\..."),
    // if any, onto the resolved device path.
    //
    remainderOffsetChars = 2; // skip "C:"
    if (DosPath->Length > remainderOffsetChars * sizeof(WCHAR)) {

        remainderLengthBytes = (USHORT)(DosPath->Length - remainderOffsetChars * sizeof(WCHAR));

        if ((ULONG)targetPath.Length + remainderLengthBytes >= BufferSizeBytes) {
            return STATUS_BUFFER_TOO_SMALL;
        }

        RtlCopyMemory(
            (PUCHAR)Buffer + targetPath.Length,
            (PUCHAR)DosPath->Buffer + remainderOffsetChars * sizeof(WCHAR),
            remainderLengthBytes
            );

        targetPath.Length = (USHORT)(targetPath.Length + remainderLengthBytes);
    }

    NtPath->Buffer = Buffer;
    NtPath->Length = targetPath.Length;
    NtPath->MaximumLength = (USHORT)BufferSizeBytes;

    return STATUS_SUCCESS;
}
