/*++

Module Name:

    communication.c

Abstract:

    See communication.h. Port lifecycle and message handling follow the
    same shape as Microsoft's "scanner" minifilter sample: build a default
    security descriptor restricting the port to admin/SYSTEM, create the
    port with FltCreateCommunicationPort, and free the descriptor
    immediately afterward (the port itself, not the descriptor, is what
    persists).

--*/

#include "communication.h"
#include "logging.h"

#define GL_PORT_NAME L"\\GasLightPort"

static
NTSTATUS
GlpPortConnectNotify(
    _In_ PFLT_PORT ClientPort,
    _In_opt_ PVOID ServerPortCookie,
    _In_reads_bytes_opt_(SizeOfContext) PVOID ConnectionContext,
    _In_ ULONG SizeOfContext,
    _Outptr_result_maybenull_ PVOID *ConnectionPortCookie
    )
{
    PGL_COMMUNICATION comm = (PGL_COMMUNICATION)ServerPortCookie;
    KIRQL oldIrql;

    UNREFERENCED_PARAMETER(ConnectionContext);
    UNREFERENCED_PARAMETER(SizeOfContext);

    if (comm == NULL) {
        return STATUS_UNSUCCESSFUL;
    }

    KeAcquireSpinLock(&comm->ClientPortLock, &oldIrql);

    if (comm->ClientPort != NULL) {
        //
        // Only one user-mode agent is expected. A second connection
        // attempt while one is already active is refused rather than
        // silently replacing the first — that would let a second,
        // possibly less-trusted process start issuing policy updates.
        //
        KeReleaseSpinLock(&comm->ClientPortLock, oldIrql);
        GlLogError("connection refused — an agent is already connected\n");
        return STATUS_CONNECTION_ACTIVE;
    }

    comm->ClientPort = ClientPort;
    KeReleaseSpinLock(&comm->ClientPortLock, oldIrql);

    *ConnectionPortCookie = comm;

    GlLogInfo("endpoint agent connected\n");

    return STATUS_SUCCESS;
}

static
VOID
GlpPortDisconnectNotify(
    _In_opt_ PVOID ConnectionCookie
    )
{
    PGL_COMMUNICATION comm = (PGL_COMMUNICATION)ConnectionCookie;
    KIRQL oldIrql;

    if (comm == NULL) {
        return;
    }

    KeAcquireSpinLock(&comm->ClientPortLock, &oldIrql);
    FltCloseClientPort(comm->Filter, &comm->ClientPort);
    comm->ClientPort = NULL;
    KeReleaseSpinLock(&comm->ClientPortLock, oldIrql);

    //
    // From here on, GlPolicyTableGet keeps returning whatever policies
    // were last set — stale but not unsafe, since a process already
    // classified Block/Terminate stays blocked. New, never-seen
    // processes fall open per GlPolicyTableGet's default. See the
    // architecture doc's fail-open/fail-closed discussion, and
    // GlCommunicationIsAgentConnected for where a fail-closed build would
    // hook in instead.
    //
    GlLogInfo("endpoint agent disconnected — policy table now static until reconnect\n");
}

static
NTSTATUS
GlpPortMessageNotify(
    _In_opt_ PVOID PortCookie,
    _In_reads_bytes_opt_(InputBufferLength) PVOID InputBuffer,
    _In_ ULONG InputBufferLength,
    _Out_writes_bytes_to_opt_(OutputBufferLength, *ReturnOutputBufferLength) PVOID OutputBuffer,
    _In_ ULONG OutputBufferLength,
    _Out_ PULONG ReturnOutputBufferLength
    )
{
    PGL_COMMUNICATION comm = (PGL_COMMUNICATION)PortCookie;
    GL_MESSAGE_TYPE messageType;

    UNREFERENCED_PARAMETER(OutputBuffer);
    UNREFERENCED_PARAMETER(OutputBufferLength);

    *ReturnOutputBufferLength = 0;

    if (comm == NULL || InputBuffer == NULL || InputBufferLength < sizeof(GL_MESSAGE_TYPE)) {
        return STATUS_INVALID_PARAMETER;
    }

    messageType = *(GL_MESSAGE_TYPE *)InputBuffer;

    switch (messageType) {

        case GlMsgSetPolicy: {
            PGL_SET_POLICY_MESSAGE msg;

            if (InputBufferLength < sizeof(GL_SET_POLICY_MESSAGE)) {
                return STATUS_INVALID_PARAMETER;
            }
            msg = (PGL_SET_POLICY_MESSAGE)InputBuffer;

            (VOID)GlPolicyTableSet(comm->PolicyTable, msg->Pid, msg->Policy);
            break;
        }

        case GlMsgRemovePolicy: {
            PGL_REMOVE_POLICY_MESSAGE msg;

            if (InputBufferLength < sizeof(GL_REMOVE_POLICY_MESSAGE)) {
                return STATUS_INVALID_PARAMETER;
            }
            msg = (PGL_REMOVE_POLICY_MESSAGE)InputBuffer;

            GlPolicyTableRemove(comm->PolicyTable, msg->Pid);
            break;
        }

        default:
            //
            // Unknown message type from a (by definition, already
            // authenticated-by-port-ACL) client — log and ignore rather
            // than fail the whole port.
            //
            GlLogError("unrecognized message type %d from agent\n", (int)messageType);
            return STATUS_INVALID_PARAMETER;
    }

    return STATUS_SUCCESS;
}

NTSTATUS
GlCommunicationInitialize(
    _In_ PFLT_FILTER Filter,
    _In_ PGL_POLICY_TABLE PolicyTable,
    _Out_ PGL_COMMUNICATION Communication
    )
{
    NTSTATUS status;
    PSECURITY_DESCRIPTOR securityDescriptor = NULL;
    OBJECT_ATTRIBUTES objAttrs;
    UNICODE_STRING portName;

    RtlZeroMemory(Communication, sizeof(GL_COMMUNICATION));
    Communication->Filter = Filter;
    Communication->PolicyTable = PolicyTable;
    KeInitializeSpinLock(&Communication->ClientPortLock);

    status = FltBuildDefaultSecurityDescriptor(&securityDescriptor, FLT_PORT_ALL_ACCESS);
    if (!NT_SUCCESS(status)) {
        GlLogError("FltBuildDefaultSecurityDescriptor failed: 0x%08X\n", status);
        return status;
    }

    RtlInitUnicodeString(&portName, GL_PORT_NAME);

    InitializeObjectAttributes(
        &objAttrs,
        &portName,
        OBJ_KERNEL_HANDLE | OBJ_CASE_INSENSITIVE,
        NULL,
        securityDescriptor
        );

    status = FltCreateCommunicationPort(
        Filter,
        &Communication->ServerPort,
        &objAttrs,
        Communication,               // ServerPortCookie
        GlpPortConnectNotify,
        GlpPortDisconnectNotify,
        GlpPortMessageNotify,
        1                             // max concurrent connections
        );

    FltFreeSecurityDescriptor(securityDescriptor);

    if (!NT_SUCCESS(status)) {
        GlLogError("FltCreateCommunicationPort failed: 0x%08X\n", status);
        return status;
    }

    GlLogInfo("communication port %ws ready\n", GL_PORT_NAME);

    return STATUS_SUCCESS;
}

VOID
GlCommunicationDestroy(
    _In_ PGL_COMMUNICATION Communication
    )
{
    if (Communication->ServerPort != NULL) {
        FltCloseCommunicationPort(Communication->ServerPort);
        Communication->ServerPort = NULL;
    }
    // ClientPort, if still connected, is closed by the filter manager's
    // teardown as part of FltCloseCommunicationPort tearing down any
    // outstanding client connections; GlpPortDisconnectNotify still fires
    // for it.
}

VOID
GlCommunicationSendEnforcementEvent(
    _In_ PGL_COMMUNICATION Communication,
    _In_ PGL_ENFORCEMENT_EVENT Event
    )
{
    KIRQL oldIrql;
    PFLT_PORT clientPort;
    LARGE_INTEGER timeout;

    KeAcquireSpinLock(&Communication->ClientPortLock, &oldIrql);
    clientPort = Communication->ClientPort;
    KeReleaseSpinLock(&Communication->ClientPortLock, oldIrql);

    if (clientPort == NULL) {
        return; // no agent connected — nothing to tell
    }

    // 100ms, expressed in negative 100-ns units (relative time).
    timeout.QuadPart = -1 * 100 * 1000 * 10;

    //
    // Fire-and-forget: NULL reply buffer means FltSendMessage doesn't
    // block waiting for a response, only for the message to be
    // delivered/queued (bounded by the timeout above). If it fails —
    // agent's message queue full, race with disconnect, whatever — the
    // event is simply dropped. This must never affect the enforcement
    // decision itself, which has already been made by the time this is
    // called.
    //
    (VOID)FltSendMessage(
        Communication->Filter,
        &clientPort,
        Event,
        sizeof(GL_ENFORCEMENT_EVENT),
        NULL,
        NULL,
        &timeout
        );
}

BOOLEAN
GlCommunicationIsAgentConnected(
    _In_ PGL_COMMUNICATION Communication
    )
{
    KIRQL oldIrql;
    BOOLEAN connected;

    KeAcquireSpinLock(&Communication->ClientPortLock, &oldIrql);
    connected = (Communication->ClientPort != NULL);
    KeReleaseSpinLock(&Communication->ClientPortLock, oldIrql);

    return connected;
}
