/*++

Module Name:

    DriverEntry.c

Abstract:

    Registration and lifecycle, matching the doc's "Driver Responsibilities"
    sequence exactly:

        DriverEntry() -> FltRegisterFilter() -> Register Callbacks ->
        Start Filtering

    Driver state is intentionally minimal, per "Driver State": protected
    folders, policy table, statistics, communication channel. Nothing
    else — see globals.h.

--*/

#include "globals.h"
#include "callbacks.h"
#include "logging.h"
#include "utils.h"

//
// The single instance of the driver's entire state. Declared here,
// referenced everywhere else via the `extern` in globals.h.
//
GL_GLOBAL_DATA g_GlobalData;

DRIVER_INITIALIZE DriverEntry;

NTSTATUS
DriverEntry(
    _In_ PDRIVER_OBJECT DriverObject,
    _In_ PUNICODE_STRING RegistryPath
    );

NTSTATUS
GlUnload(
    _In_ FLT_FILTER_UNLOAD_FLAGS Flags
    );

static
NTSTATUS
GlLoadConfiguration(
    _In_opt_ PUNICODE_STRING RegistryPath
    );

//
// Designated initializers are used deliberately rather than positional
// ones: FLT_REGISTRATION has gained trailing fields (transaction
// notification, extended name normalization, ...) across WDK versions,
// and naming only the fields this MVP actually uses means any such
// trailing fields this header defines simply zero-initialize to their
// correct "not used" default instead of silently misaligning.
//
CONST FLT_REGISTRATION FilterRegistration = {
    .Size = sizeof(FLT_REGISTRATION),
    .Version = FLT_REGISTRATION_VERSION,
    .Flags = 0,
    .ContextRegistration = NULL,               // no per-file/per-instance contexts in this MVP
    .OperationRegistration = GlOperationRegistration,
    .FilterUnloadCallback = GlUnload,
    .InstanceSetupCallback = NULL,              // NULL = attach to all suitable volumes
    .InstanceQueryTeardownCallback = NULL,
    .InstanceTeardownStartCallback = NULL,
    .InstanceTeardownCompleteCallback = NULL,
    .GenerateFileNameCallback = NULL,
    .NormalizeNameComponentCallback = NULL,
    .NormalizeContextCleanupCallback = NULL
};

NTSTATUS
DriverEntry(
    _In_ PDRIVER_OBJECT DriverObject,
    _In_ PUNICODE_STRING RegistryPath
    )
{
    NTSTATUS status;

    RtlZeroMemory(&g_GlobalData, sizeof(g_GlobalData));

    status = GlPolicyTableInitialize(&g_GlobalData.PolicyTable);
    if (!NT_SUCCESS(status)) {
        GlLogError("policy table init failed: 0x%08X\n", status);
        return status;
    }

    status = GlProtectedPathsInitialize(&g_GlobalData.ProtectedPaths);
    if (!NT_SUCCESS(status)) {
        GlLogError("protected paths init failed: 0x%08X\n", status);
        return status;
    }

    status = GlHoneyRootInitialize(&g_GlobalData.HoneyRoot);
    if (!NT_SUCCESS(status)) {
        GlLogError("honey root init failed: 0x%08X\n", status);
        return status;
    }

    status = GlLoadConfiguration(RegistryPath);
    if (!NT_SUCCESS(status)) {
        // Non-fatal: continue with whatever defaults were successfully
        // seeded rather than failing the whole driver load over a
        // misconfigured (or absent) protected-path entry.
        GlLogError("configuration load incomplete: 0x%08X (continuing with defaults)\n", status);
    }

    status = FltRegisterFilter(DriverObject, &FilterRegistration, &g_GlobalData.Filter);
    if (!NT_SUCCESS(status)) {
        GlLogError("FltRegisterFilter failed: 0x%08X\n", status);
        return status;
    }

    status = GlCommunicationInitialize(
        g_GlobalData.Filter,
        &g_GlobalData.PolicyTable,
        &g_GlobalData.Communication
        );
    if (!NT_SUCCESS(status)) {
        GlLogError("communication init failed: 0x%08X\n", status);
        FltUnregisterFilter(g_GlobalData.Filter);
        return status;
    }

    status = FltStartFiltering(g_GlobalData.Filter);
    if (!NT_SUCCESS(status)) {
        GlLogError("FltStartFiltering failed: 0x%08X\n", status);
        GlCommunicationDestroy(&g_GlobalData.Communication);
        FltUnregisterFilter(g_GlobalData.Filter);
        return status;
    }

    GlLogInfo("GasLight filter driver loaded, protecting %lu path(s)\n",
        g_GlobalData.ProtectedPaths.Count);

    return STATUS_SUCCESS;
}

NTSTATUS
GlUnload(
    _In_ FLT_FILTER_UNLOAD_FLAGS Flags
    )
{
    UNREFERENCED_PARAMETER(Flags);

    GlCommunicationDestroy(&g_GlobalData.Communication);
    GlProtectedPathsDestroy(&g_GlobalData.ProtectedPaths);
    GlPolicyTableDestroy(&g_GlobalData.PolicyTable);

    FltUnregisterFilter(g_GlobalData.Filter);

    GlLogInfo("GasLight filter driver unloaded (writes observed=%ld, enforced=%ld)\n",
        g_GlobalData.WritesObserved, g_GlobalData.WritesEnforced);

    return STATUS_SUCCESS;
}

static
NTSTATUS
GlLoadConfiguration(
    _In_opt_ PUNICODE_STRING RegistryPath
    )
{
    NTSTATUS status;
    UNICODE_STRING dosPath;
    UNICODE_STRING ntPath;
    WCHAR ntPathBuffer[GL_MAX_PATH_CHARS];

    //
    // MVP: hardcoded defaults, matching the doc's own example config
    // ("C:\Users", "D:\Documents", ...). A real deployment should read
    // the protected-folder list and honey-storage root from this
    // driver's registry Parameters key under `RegistryPath` instead —
    // left as a follow-up rather than guessed at here, since getting a
    // registry schema right without a machine to test it against is more
    // likely to introduce a subtle bug than to help.
    //
    UNREFERENCED_PARAMETER(RegistryPath);

    RtlInitUnicodeString(&dosPath, L"C:\\Users");
    status = GlUtilsDosPathToNtPath(&dosPath, &ntPath, ntPathBuffer, sizeof(ntPathBuffer));
    if (NT_SUCCESS(status)) {
        status = GlProtectedPathsAdd(&g_GlobalData.ProtectedPaths, &ntPath);
    }
    if (!NT_SUCCESS(status)) {
        GlLogError("could not register default protected path C:\\Users: 0x%08X\n", status);
    }

    {
        WCHAR honeyBuffer[GL_MAX_PATH_CHARS];
        UNICODE_STRING honeyNtPath;
        UNICODE_STRING honeyDosPath;
        NTSTATUS honeyStatus;

        RtlInitUnicodeString(&honeyDosPath, L"C:\\ProgramData\\GasLight\\Honey");
        honeyStatus = GlUtilsDosPathToNtPath(&honeyDosPath, &honeyNtPath, honeyBuffer, sizeof(honeyBuffer));
        if (NT_SUCCESS(honeyStatus)) {
            honeyStatus = GlHoneyRootSet(&g_GlobalData.HoneyRoot, &honeyNtPath);
        }
        if (!NT_SUCCESS(honeyStatus)) {
            GlLogError("could not register default honey root: 0x%08X\n", honeyStatus);
        }
    }

    return STATUS_SUCCESS;
}
