extern "C" {
#include <ntddk.h>
#include <fwpmk.h>
#include <fwpsk.h>

    // Forward declarations for driver entry and unload.
    DRIVER_UNLOAD DriverUnload;
    DRIVER_INITIALIZE DriverEntry;
}

// Global handle to the WFP management (BFE) engine.
static HANDLE gEngineHandle = nullptr;

// WFP provider, sublayer, and callout identifiers for this driver.
static GUID gProviderKey =
{ 0x4e5f3b8a, 0x7d0d, 0x4a0b, { 0x9f, 0x31, 0x2b, 0x7e, 0x55, 0x1a, 0x9c, 0x11 } };

static GUID gSublayerKey =
{ 0x0f7cf9b0, 0x6bbd, 0x4a8e, { 0x8a, 0x3b, 0x4c, 0x41, 0xa0, 0x3f, 0x22, 0x73 } };

static GUID gCalloutKey =
{ 0x6b9f4a2d, 0x3b79, 0x4fda, { 0x87, 0x4a, 0x2e, 0x1b, 0x49, 0x3d, 0x10, 0x5c } };

// Runtime ID assigned when registering the callout with the base filtering engine.
static UINT32 gCalloutId = 0;

// Forward declarations for WFP callout callbacks.
static VOID NTAPI
NetworkMonitorStreamClassifyFn(
    const FWPS_INCOMING_VALUES0* inFixedValues,
    const FWPS_INCOMING_METADATA_VALUES0* inMetaValues,
    VOID* layerData,
    const VOID* classifyContext,
    const FWPS_FILTER0* filter,
    UINT64 flowContext,
    FWPS_CLASSIFY_OUT0* classifyOut
    );

static NTSTATUS NTAPI
NetworkMonitorStreamNotifyFn(
    FWPS_CALLOUT_NOTIFY_TYPE notifyType,
    const GUID* filterKey,
    const FWPS_FILTER0* filter
    );

static VOID NTAPI
NetworkMonitorStreamFlowDeleteFn(
    UINT16 layerId,
    UINT32 calloutId,
    UINT64 flowContext
    );

// Register provider, sublayer, and callout with BFE and the base filtering engine.
static NTSTATUS
RegisterWfpObjects()
{
    NTSTATUS status;

    FWPM_PROVIDER0 provider = { 0 };
    FWPM_SUBLAYER0 subLayer = { 0 };
    FWPM_CALLOUT0 mCallout = { 0 };
    FWPS_CALLOUT0 sCallout = { 0 };

    provider.providerKey = gProviderKey;
    provider.displayData.name = const_cast<wchar_t*>(L"NetworkMonitor Provider");

    status = FwpmProviderAdd0(gEngineHandle, &provider, nullptr);
    if (!NT_SUCCESS(status) && status != FWP_E_ALREADY_EXISTS)
    {
        DbgPrintEx(DPFLTR_DEFAULT_ID, DPFLTR_ERROR_LEVEL,
                   "[NetworkMonitor] RegisterWfpObjects: FwpmProviderAdd0 failed, status=0x%08X\n",
                   status);
        return status;
    }

    subLayer.subLayerKey = gSublayerKey;
    subLayer.displayData.name = const_cast<wchar_t*>(L"NetworkMonitor Sublayer");
    subLayer.providerKey = gProviderKey;
    subLayer.weight = 0x100;

    status = FwpmSubLayerAdd0(gEngineHandle, &subLayer, nullptr);
    if (!NT_SUCCESS(status) && status != FWP_E_ALREADY_EXISTS)
    {
        DbgPrintEx(DPFLTR_DEFAULT_ID, DPFLTR_ERROR_LEVEL,
                   "[NetworkMonitor] RegisterWfpObjects: FwpmSubLayerAdd0 failed, status=0x%08X\n",
                   status);
        return status;
    }

    sCallout.calloutKey = gCalloutKey;
    sCallout.classifyFn = NetworkMonitorStreamClassifyFn;
    sCallout.notifyFn = NetworkMonitorStreamNotifyFn;
    sCallout.flowDeleteFn = NetworkMonitorStreamFlowDeleteFn;

    status = FwpsCalloutRegister0(
        nullptr,
        &sCallout,
        &gCalloutId
    );
    if (!NT_SUCCESS(status))
    {
        DbgPrintEx(DPFLTR_DEFAULT_ID, DPFLTR_ERROR_LEVEL,
                   "[NetworkMonitor] RegisterWfpObjects: FwpsCalloutRegister0 failed, status=0x%08X\n",
                   status);
        gCalloutId = 0;
        return status;
    }

    mCallout.calloutKey = gCalloutKey;
    mCallout.displayData.name = const_cast<wchar_t*>(L"NetworkMonitor Stream Callout");
    mCallout.applicableLayer = FWPM_LAYER_STREAM_V4;
    mCallout.providerKey = &gProviderKey;

    status = FwpmCalloutAdd0(
        gEngineHandle,
        &mCallout,
        nullptr,
        nullptr
    );
    if (!NT_SUCCESS(status))
    {
        DbgPrintEx(DPFLTR_DEFAULT_ID, DPFLTR_ERROR_LEVEL,
                   "[NetworkMonitor] RegisterWfpObjects: FwpmCalloutAdd0 failed, status=0x%08X\n",
                   status);
        FwpsCalloutUnregisterById0(gCalloutId);
        gCalloutId = 0;
        return status;
    }

    DbgPrintEx(DPFLTR_DEFAULT_ID, DPFLTR_INFO_LEVEL,
               "[NetworkMonitor] RegisterWfpObjects: callout registered (id=%u)\n",
               gCalloutId);

    return STATUS_SUCCESS;
}

// Unregister callout, sublayer, and provider.
static VOID
UnregisterWfpObjects()
{
    if (gEngineHandle != nullptr)
    {
        (void)FwpmCalloutDeleteByKey0(gEngineHandle, &gCalloutKey);
        (void)FwpmSubLayerDeleteByKey0(gEngineHandle, &gSublayerKey);
        (void)FwpmProviderDeleteByKey0(gEngineHandle, &gProviderKey);
    }

    if (gCalloutId != 0)
    {
        FwpsCalloutUnregisterById0(gCalloutId);
        gCalloutId = 0;
    }
}

// Initialize connection to the BFE/WFP management API.
static NTSTATUS
BfeInitialize()
{
    NTSTATUS status;

    DbgPrintEx(DPFLTR_DEFAULT_ID, DPFLTR_INFO_LEVEL, "[NetworkMonitor] BfeInitialize: opening WFP engine\n");

    status = FwpmEngineOpen0(
        nullptr,
        RPC_C_AUTHN_WINNT,
        nullptr,
        nullptr,
        &gEngineHandle
    );
    if (!NT_SUCCESS(status))
    {
        DbgPrintEx(DPFLTR_DEFAULT_ID, DPFLTR_ERROR_LEVEL,
                   "[NetworkMonitor] BfeInitialize: FwpmEngineOpen0 failed, status=0x%08X\n",
                   status);
        gEngineHandle = nullptr;
        return status;
    }

    DbgPrintEx(DPFLTR_DEFAULT_ID, DPFLTR_INFO_LEVEL,
               "[NetworkMonitor] BfeInitialize: engine opened successfully (handle=%p)\n",
               gEngineHandle);

    status = RegisterWfpObjects();
    if (!NT_SUCCESS(status))
    {
        DbgPrintEx(DPFLTR_DEFAULT_ID, DPFLTR_ERROR_LEVEL,
                   "[NetworkMonitor] BfeInitialize: RegisterWfpObjects failed, status=0x%08X\n",
                   status);

        UnregisterWfpObjects();

        FwpmEngineClose0(gEngineHandle);
        gEngineHandle = nullptr;
        return status;
    }

    return STATUS_SUCCESS;
}

// Tear down connection to the BFE/WFP engine.
static VOID
BfeUninitialize()
{
    UnregisterWfpObjects();

    if (gEngineHandle != nullptr)
    {
        DbgPrintEx(DPFLTR_DEFAULT_ID, DPFLTR_INFO_LEVEL,
                   "[NetworkMonitor] BfeUninitialize: closing WFP engine (handle=%p)\n",
                   gEngineHandle);

        FwpmEngineClose0(gEngineHandle);
        gEngineHandle = nullptr;
    }
}

// Driver entry point: set up unload routine and initialize BFE.
NTSTATUS
DriverEntry(
    _In_ PDRIVER_OBJECT DriverObject,
    _In_ PUNICODE_STRING RegistryPath
)
{
    UNREFERENCED_PARAMETER(RegistryPath);

    NTSTATUS status;

    DbgPrintEx(DPFLTR_DEFAULT_ID, DPFLTR_INFO_LEVEL, "[NetworkMonitor] DriverEntry: loading driver\n");

    DriverObject->DriverUnload = DriverUnload;

    status = BfeInitialize();
    if (!NT_SUCCESS(status))
    {
        DbgPrintEx(DPFLTR_DEFAULT_ID, DPFLTR_ERROR_LEVEL,
                   "[NetworkMonitor] DriverEntry: BfeInitialize failed, status=0x%08X\n",
                   status);
        BfeUninitialize();
        return status;
    }

    DbgPrintEx(DPFLTR_DEFAULT_ID, DPFLTR_INFO_LEVEL,
               "[NetworkMonitor] DriverEntry: initialization successful\n");

    return STATUS_SUCCESS;
}

// Driver unload routine: clean up BFE state.
VOID
DriverUnload(
    _In_ PDRIVER_OBJECT DriverObject
)
{
    UNREFERENCED_PARAMETER(DriverObject);

    DbgPrintEx(DPFLTR_DEFAULT_ID, DPFLTR_INFO_LEVEL,
               "[NetworkMonitor] DriverUnload: unloading driver\n");

    BfeUninitialize();
}

// Stream callout classify callback for FWPM_LAYER_STREAM_V4.
static VOID NTAPI
NetworkMonitorStreamClassifyFn(
    const FWPS_INCOMING_VALUES0* inFixedValues,
    const FWPS_INCOMING_METADATA_VALUES0* inMetaValues,
    VOID* layerData,
    const VOID* classifyContext,
    const FWPS_FILTER0* filter,
    UINT64 flowContext,
    FWPS_CLASSIFY_OUT0* classifyOut
    )
{
    UNREFERENCED_PARAMETER(inFixedValues);
    UNREFERENCED_PARAMETER(inMetaValues);
    UNREFERENCED_PARAMETER(layerData);
    UNREFERENCED_PARAMETER(classifyContext);
    UNREFERENCED_PARAMETER(filter);
    UNREFERENCED_PARAMETER(flowContext);

    DbgPrintEx(DPFLTR_DEFAULT_ID, DPFLTR_INFO_LEVEL,
               "[NetworkMonitor] NetworkMonitorStreamClassifyFn: classify invoked\n");

    if (classifyOut != nullptr)
    {
        classifyOut->actionType = FWP_ACTION_PERMIT;
    }
}

// Notify callback for callout lifecycle events (filter add/delete).
static NTSTATUS NTAPI
NetworkMonitorStreamNotifyFn(
    FWPS_CALLOUT_NOTIFY_TYPE notifyType,
    const GUID* filterKey,
    const FWPS_FILTER0* filter
    )
{
    UNREFERENCED_PARAMETER(filterKey);
    UNREFERENCED_PARAMETER(filter);

    DbgPrintEx(DPFLTR_DEFAULT_ID, DPFLTR_INFO_LEVEL,
               "[NetworkMonitor] NetworkMonitorStreamNotifyFn: notifyType=%u\n",
               notifyType);

    return STATUS_SUCCESS;
}

// Flow delete callback for stream flows.
static VOID NTAPI
NetworkMonitorStreamFlowDeleteFn(
    UINT16 layerId,
    UINT32 calloutId,
    UINT64 flowContext
    )
{
    UNREFERENCED_PARAMETER(flowContext);

    DbgPrintEx(DPFLTR_DEFAULT_ID, DPFLTR_INFO_LEVEL,
               "[NetworkMonitor] NetworkMonitorStreamFlowDeleteFn: layerId=%u, calloutId=%u\n",
               layerId,
               calloutId);
}