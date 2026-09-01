namespace ApfsAccess.Ipc;

public static class ApfsMessageTypes
{
    public const string StatusChanged = "StatusChanged";
    public const string QuitRequested = "QuitRequested";
    public const string ServiceStopping = "ServiceStopping";
    public const string EjectRequested = "EjectRequested";
    public const string RefreshRequested = "RefreshRequested";
    public const string InventoryRequested = "InventoryRequested";
    public const string MountRequested = "MountRequested";
    public const string FixRequested = "FixRequested";
    public const string Inventory = "Inventory";
    public const string ControlOperationRequest = "ControlOperationRequest";
    public const string OperationResultQuery = "OperationResultQuery";
    public const string CancellationRequest = "CancellationRequest";
    public const string OperationResult = "OperationResult";
    public const string Ack = "Ack";
    public const string Ping = "Ping";
    public const string Pong = "Pong";
}
