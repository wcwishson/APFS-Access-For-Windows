namespace ApfsAccess.Core;

public enum RawSnapshotHardwareQualificationScheme
{
    Unavailable = 0,
    QualifiedSerialTuple = 1,
    QualifiedDeviceVpd = 2,
}

// Operator-supplied qualification belongs in private configuration, never inferred from discovered hardware.
public sealed class RawSnapshotHardwareQualification
{
    public RawSnapshotHardwareQualificationScheme Scheme { get; set; } = RawSnapshotHardwareQualificationScheme.Unavailable;
    public uint? BusType { get; set; }
    public string? Vendor { get; set; }
    public string? Product { get; set; }
    public string? QualifiedSerial { get; set; }
    public uint? QualifiedVpdType { get; set; }
}
