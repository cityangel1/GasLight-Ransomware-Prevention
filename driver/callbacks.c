/*++

Module Name:

    callbacks.c

Abstract:

    See callbacks.h. All four callbacks funnel through GlpEvaluate, which
    implements exactly the flow from the architecture doc's "Callback
    Example":

        IRP_MJ_WRITE -> PID -> Protected folder? -> YES -> Policy? ->
        BLOCK -> STATUS_ACCESS_DENIED

    CREATE is observe-only (never denies) — enforcement happens at WRITE
    and SET_INFORMATION, matching the doc's own "Write Flow" example and
    its Testing Strategy table (which only tests writes/renames/deletes
    as deniable, never opens).

--*/

#include "callbacks.h"
#include "logging.h"

static
VOID
GlpCopyFileNameForTelemetry(
    _In_ PCUNICODE_STRING Name,
    _Out_writes_z_(GL_MAX_PATH_CHARS) PWCHAR Dest
    )
{
    ULONG charsToCopy = Name->Length / sizeof(WCHAR);

    if (charsToCopy > GL_MAX_PATH_CHARS - 1) {
        charsToCopy = GL_MAX_PATH_CHARS - 1;
    }

    RtlCopyMemory(Dest, Name->Buffer, charsToCopy * sizeof(WCHAR));
    Dest[charsToCopy] = L'\0';
}

//
// Shared evaluation path for CREATE/WRITE/SET_INFORMATION.
//
// ObserveOnly = TRUE (used by PreCreate): honeypot touches are still
// reported, but the operation is never denied — opens have to succeed for
// the deception to work at all, and denying an open would tip off
// anything smart enough to check its return code before doing real
// damage on the *write*.
//
static
FLT_PREOP_CALLBACK_STATUS
GlpEvaluate(
    _Inout_ PFLT_CALLBACK_DATA Data,
    _In_ ULONG MajorFunction,
    _In_ BOOLEAN ObserveOnly
    )
{
    NTSTATUS status;
    PFLT_FILE_NAME_INFORMATION nameInfo = NULL;
    ULONG pid;
    BOOLEAN isProtected;
    BOOLEAN isHoney;
    GL_POLICY policy;
    FLT_PREOP_CALLBACK_STATUS result = FLT_PREOP_SUCCESS_NO_CALLBACK;

    if (FlagOn(Data->Iopb->IrpFlags, IRP_PAGING_IO | IRP_SYNC_PAGING_IO)) {
        //
        // Paging I/O isn't how ransomware writes files, doesn't carry a
        // meaningful name lookup in the same way, and is by far the
        // highest-volume traffic on a busy system — skip immediately.
        // See the doc's "Performance" section.
        //
        return FLT_PREOP_SUCCESS_NO_CALLBACK;
    }

    status = FltGetFileNameInformation(
        Data,
        FLT_FILE_NAME_NORMALIZED | FLT_FILE_NAME_QUERY_DEFAULT,
        &nameInfo
        );
    if (!NT_SUCCESS(status)) {
        // Couldn't resolve a name (e.g. a non-file-system-file open) —
        // nothing meaningful to police here.
        return FLT_PREOP_SUCCESS_NO_CALLBACK;
    }

    FltParseFileNameInformation(nameInfo);

    isProtected = GlProtectedPathsContains(&g_GlobalData.ProtectedPaths, &nameInfo->Name);
    isHoney = GlHoneyRootContains(&g_GlobalData.HoneyRoot, &nameInfo->Name);

    if (!isProtected && !isHoney) {
        // Outside anything GasLight cares about — ignore, fast path.
        FltReleaseFileNameInformation(nameInfo);
        return FLT_PREOP_SUCCESS_NO_CALLBACK;
    }

    pid = FltGetRequestorProcessId(Data);
    policy = GlPolicyTableGet(&g_GlobalData.PolicyTable, pid);

    if (MajorFunction == IRP_MJ_WRITE) {
        InterlockedIncrement(&g_GlobalData.WritesObserved);
    }

    if (isHoney) {
        //
        // Reported unconditionally, independent of the current policy —
        // a honeypot touch is the deception engine's actual trigger
        // signal, not just something worth mentioning if we happen to
        // also be blocking. See the doc: honeypot interaction is
        // "Very high-confidence" on its own.
        //
        GL_ENFORCEMENT_EVENT honeyEvent;
        RtlZeroMemory(&honeyEvent, sizeof(honeyEvent));
        honeyEvent.Type = GlMsgEnforcementEvent;
        honeyEvent.Pid = pid;
        honeyEvent.PolicyApplied = policy;
        honeyEvent.MajorFunction = MajorFunction;
        honeyEvent.WasHoneyPath = TRUE;
        GlpCopyFileNameForTelemetry(&nameInfo->Name, honeyEvent.FileName);

        GlCommunicationSendEnforcementEvent(&g_GlobalData.Communication, &honeyEvent);
    }

    if (!ObserveOnly &&
        (policy == GlPolicyBlock || policy == GlPolicyRedirect || policy == GlPolicyTerminate)) {

        //
        // MVP note: Redirect and Terminate both currently degrade to
        // Block at the I/O level.
        //   - True redirection means handing the write a *different*
        //     target file, which is substantially more invasive than
        //     denying it outright, and the architecture doc itself
        //     recommends implementing blocking first and only
        //     prototyping redirection for a controlled demo afterward.
        //   - Terminate is enforced by the user-mode agent actually
        //     killing the process (see driver/client.rs on the Rust
        //     side, and behavior/response.rs's Decision::Terminate
        //     handling) — the filter's job for a Terminate policy is
        //     just to stop this specific I/O in the meantime, which is
        //     exactly what Block does too.
        //

        Data->IoStatus.Status = STATUS_ACCESS_DENIED;
        Data->IoStatus.Information = 0;
        result = FLT_PREOP_COMPLETE;

        InterlockedIncrement(&g_GlobalData.WritesEnforced);

        GlLogEnforcement(pid, NULL, &nameInfo->Name, policy, MajorFunction);

        {
            GL_ENFORCEMENT_EVENT enforcementEvent;
            RtlZeroMemory(&enforcementEvent, sizeof(enforcementEvent));
            enforcementEvent.Type = GlMsgEnforcementEvent;
            enforcementEvent.Pid = pid;
            enforcementEvent.PolicyApplied = policy;
            enforcementEvent.MajorFunction = MajorFunction;
            enforcementEvent.WasHoneyPath = isHoney;
            GlpCopyFileNameForTelemetry(&nameInfo->Name, enforcementEvent.FileName);

            GlCommunicationSendEnforcementEvent(&g_GlobalData.Communication, &enforcementEvent);
        }
    }

    FltReleaseFileNameInformation(nameInfo);

    return result;
}

FLT_PREOP_CALLBACK_STATUS
GlPreCreate(
    _Inout_ PFLT_CALLBACK_DATA Data,
    _In_ PCFLT_RELATED_OBJECTS FltObjects,
    _Flt_CompletionContext_Outptr_ PVOID *CompletionContext
    )
{
    UNREFERENCED_PARAMETER(FltObjects);
    UNREFERENCED_PARAMETER(CompletionContext);

    return GlpEvaluate(Data, IRP_MJ_CREATE, TRUE /* ObserveOnly */);
}

FLT_PREOP_CALLBACK_STATUS
GlPreWrite(
    _Inout_ PFLT_CALLBACK_DATA Data,
    _In_ PCFLT_RELATED_OBJECTS FltObjects,
    _Flt_CompletionContext_Outptr_ PVOID *CompletionContext
    )
{
    UNREFERENCED_PARAMETER(FltObjects);
    UNREFERENCED_PARAMETER(CompletionContext);

    return GlpEvaluate(Data, IRP_MJ_WRITE, FALSE /* ObserveOnly */);
}

FLT_PREOP_CALLBACK_STATUS
GlPreSetInformation(
    _Inout_ PFLT_CALLBACK_DATA Data,
    _In_ PCFLT_RELATED_OBJECTS FltObjects,
    _Flt_CompletionContext_Outptr_ PVOID *CompletionContext
    )
{
    UNREFERENCED_PARAMETER(FltObjects);
    UNREFERENCED_PARAMETER(CompletionContext);

    //
    // MVP simplification: every SET_INFORMATION request against a
    // protected/honey file from a Blocked/Redirect/Terminate PID is
    // denied, regardless of FileInformationClass (rename, delete,
    // attribute change, ...). The doc's own test matrix only exercises
    // rename and delete, both of which this covers; narrowing to
    // specifically FileRenameInformation/FileDispositionInformation(Ex)
    // is a reasonable follow-up if attribute-only changes on a blocked
    // PID's protected files turn out to need to stay allowed.
    //
    return GlpEvaluate(Data, IRP_MJ_SET_INFORMATION, FALSE /* ObserveOnly */);
}

FLT_PREOP_CALLBACK_STATUS
GlPreCleanup(
    _Inout_ PFLT_CALLBACK_DATA Data,
    _In_ PCFLT_RELATED_OBJECTS FltObjects,
    _Flt_CompletionContext_Outptr_ PVOID *CompletionContext
    )
{
    UNREFERENCED_PARAMETER(Data);
    UNREFERENCED_PARAMETER(FltObjects);
    UNREFERENCED_PARAMETER(CompletionContext);

    //
    // Registered per the architecture doc's operation list, but the doc
    // doesn't specify a concrete enforcement behavior for it (unlike
    // CREATE/WRITE/SET_INFORMATION), and denying a handle cleanup isn't a
    // meaningful "policy enforcement" action the way denying a write is.
    // Left as a genuine no-op — cheapest possible path, and an honest
    // reflection of what's actually implemented rather than pretending
    // there's enforcement logic here.
    //
    return FLT_PREOP_SUCCESS_NO_CALLBACK;
}

CONST FLT_OPERATION_REGISTRATION GlOperationRegistration[] = {

    { IRP_MJ_CREATE,
      0,
      GlPreCreate,
      NULL },

    { IRP_MJ_WRITE,
      0,
      GlPreWrite,
      NULL },

    { IRP_MJ_SET_INFORMATION,
      0,
      GlPreSetInformation,
      NULL },

    { IRP_MJ_CLEANUP,
      0,
      GlPreCleanup,
      NULL },

    { IRP_MJ_OPERATION_END }
};
