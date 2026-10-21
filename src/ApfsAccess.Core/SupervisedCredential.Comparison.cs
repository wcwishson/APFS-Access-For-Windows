using System.Security.Cryptography;

namespace ApfsAccess.Cli;

public sealed partial class SupervisedCredential
{
    public unsafe bool ContentEquals(SupervisedCredential other)
    {
        ArgumentNullException.ThrowIfNull(other);
        if (memory == 0 || other.memory == 0 || length <= 8 || other.length <= 8) throw Failure("Expired");
        return CryptographicOperations.FixedTimeEquals(new ReadOnlySpan<byte>((void*)(memory + 8), length - 8),
            new ReadOnlySpan<byte>((void*)(other.memory + 8), other.length - 8));
    }
}
