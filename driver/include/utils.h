/*++

Module Name:

    utils.h

Abstract:

    Small helpers with no state of their own.

--*/

#pragma once

#include "structures.h"

//
// Minifilters see file names in NT device form (e.g.
// "\Device\HarddiskVolume3\Users\alice\Documents\file.txt"), never drive
// letters. Config files naturally list drive-letter paths ("C:\Users"),
// so this resolves a "C:\..." style path to its NT device form by
// querying the drive letter's symbolic link in the object manager
// namespace. Must be called at PASSIVE_LEVEL (safe from DriverEntry).
//
NTSTATUS
GlUtilsDosPathToNtPath(
    _In_ PCUNICODE_STRING DosPath,
    _Out_ PUNICODE_STRING NtPath,
    _Inout_updates_bytes_(BufferSizeBytes) PWCH Buffer,
    _In_ ULONG BufferSizeBytes
    );
