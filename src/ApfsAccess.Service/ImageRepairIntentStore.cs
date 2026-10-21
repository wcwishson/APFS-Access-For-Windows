using System.ComponentModel;
using System.Runtime.InteropServices;
using System.Text.Json;
using ApfsAccess.Backend.Native;
using ApfsAccess.Core;
using Microsoft.Win32.SafeHandles;

namespace ApfsAccess.Service;

public sealed class ImageRepairIntentStore : IDisposable
{
    private readonly string _root;
    private readonly SafeFileHandle _lease;
    public ImageRepairIntentStore(string root)
    {
        if (!ImageRepairPersistence.LocalPath(root)) throw new IOException("Image repair requires its original durable local management root.");
        ImageRepairPersistence.RequireFixedFileSystem(root);
        NativeApfsVolumeManagement.ValidateStoreRoot(root);
        _root = root;
        _lease = CreateFile(@"\\?\" + root, 0x80, 3, IntPtr.Zero, 3, 0x02000000, IntPtr.Zero);
        if (_lease.IsInvalid) throw new Win32Exception(Marshal.GetLastWin32Error());
    }

    public IReadOnlyList<ImageRepairIntent> ReadAll() => ImageRepairPersistence.ReadAll(_root);
    public ImageRepairIntent? Find(string planId) => ReadAll().SingleOrDefault(r => r.Offer.PlanId == planId);

    public void Save(ImageRepairIntent intent)
    {
        ImageRepairPersistence.Validate(intent, _root);
        var records = ReadAll();
        var old = records.SingleOrDefault(r => r.Offer.PlanId == intent.Offer.PlanId);
        if (old is not null)
        {
            if (ImageRepairPersistence.Commitment(old) != ImageRepairPersistence.Commitment(intent) ||
                old.AcceptedOperationId is not null && (old.AcceptedOperationId != intent.AcceptedOperationId || old.AcceptedFingerprint != intent.AcceptedFingerprint) ||
                old.Pending && intent.State is "offered" or "expired" ||
                old.State is "repaired" or "expired" or "refused" && JsonSerializer.Serialize(old, ImageRepairPersistence.Json) != JsonSerializer.Serialize(intent, ImageRepairPersistence.Json))
                throw new InvalidDataException("ImageRepairOriginalLineageCannotBeReplacedOrReopened");
        }
        if (intent.Pending && records.Any(r => r.Pending && r.Offer.PlanId != intent.Offer.PlanId &&
            string.Equals(r.Offer.Scope.ImagePath, intent.Offer.Scope.ImagePath, StringComparison.OrdinalIgnoreCase)))
            throw new IOException("ImageRepairOtherAcceptedLineagePending");
        var path = ImageRepairPersistence.PathFor(_root, intent.Offer.PlanId);
        var bytes = ImageRepairPersistence.Encode(intent);
        var temp = path + "." + Guid.NewGuid().ToString("N") + ".tmp";
        using (var output = new FileStream(temp, FileMode.CreateNew, FileAccess.Write, FileShare.None, 4096, FileOptions.WriteThrough))
        { output.Write(bytes); output.Flush(true); }
        if (!MoveFileEx(@"\\?\" + temp, @"\\?\" + path, 9)) throw new Win32Exception(Marshal.GetLastWin32Error());
        _ = ImageRepairPersistence.ReadVerified(path, _root, bytes);
    }

    public void Dispose() => _lease.Dispose();
    [DllImport("kernel32.dll", EntryPoint = "CreateFileW", CharSet = CharSet.Unicode, SetLastError = true)]
    private static extern SafeFileHandle CreateFile(string name, uint access, uint share, IntPtr security, uint creation, uint flags, IntPtr template);
    [DllImport("kernel32.dll", EntryPoint = "MoveFileExW", CharSet = CharSet.Unicode, SetLastError = true)]
    [return: MarshalAs(UnmanagedType.Bool)] private static extern bool MoveFileEx(string source, string destination, uint flags);
}
