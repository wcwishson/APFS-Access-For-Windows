using System.Buffers;
using System.Runtime.InteropServices;
using System.Security;
using System.Text;
namespace ApfsAccess.Cli;

public sealed partial class SupervisedCredential
{
    private static SupervisedCredential Allocate()
    {
        var value = new SupervisedCredential();
        value.memory = VirtualAlloc(0, Capacity, 0x3000, 4);
        if (value.memory == 0 || !VirtualLock(value.memory, Capacity)) { value.Dispose(); throw Failure("SecureAllocation"); }
        return value;
    }
    public static async Task<SupervisedCredential> ReceiveAsync(Stream input, CancellationToken token)
    {
        var value = Allocate();
        try
        {
            using var deadline = CancellationTokenSource.CreateLinkedTokenSource(token);
            deadline.CancelAfter(TimeSpan.FromSeconds(10));
            using var bytes = new BorrowedMemory(value.memory, Capacity);
            await input.ReadExactlyAsync(bytes.Memory[..8], deadline.Token).ConfigureAwait(false);
            var size = Marshal.ReadInt32(value.memory, 4);
            if (Marshal.ReadInt32(value.memory) != 0x31435041 || size is < 1 or > 1024) throw Failure("InvalidFrame");
            await input.ReadExactlyAsync(bytes.Memory.Slice(8, size), deadline.Token).ConfigureAwait(false);
            for (var i = 0; i < size; i++) if (Marshal.ReadByte(value.memory, 8+i) == 0) throw Failure("InvalidFrame");
            if (await input.ReadAsync(bytes.Memory.Slice(8+size, 1), deadline.Token).ConfigureAwait(false) != 0) throw Failure("InvalidFrame");
            value.length = size+8;
            return value;
        }
        catch { value.Dispose(); throw; }
    }
    public async Task SendAsync(Stream output, CancellationToken token)
    {
        try
        {
            if (memory == 0 || length <= 8) throw Failure("Expired");
            using var bytes = new BorrowedMemory(memory, length);
            await output.WriteAsync(bytes.Memory, token).ConfigureAwait(false);
            await output.FlushAsync(token).ConfigureAwait(false);
        }
        finally { Dispose(); }
    }
    public static unsafe SupervisedCredential FromSecureString(SecureString secret)
    {
        var value = Allocate();
        nint chars = 0;
        nuint characterBytes = 0;
        var charsLocked = false;
        try
        {
            using var snapshot = secret.Copy();
            snapshot.MakeReadOnly();
            var characterCount = snapshot.Length;
            if (characterCount is < 1 or > 1024) throw Failure("InvalidFrame");
            characterBytes = checked((nuint)((characterCount + 1) * sizeof(char)));
            chars = Marshal.SecureStringToGlobalAllocUnicode(snapshot);
            charsLocked = VirtualLock(chars, characterBytes);
            if (!charsLocked) throw Failure("SecureAllocation");
            var input = new ReadOnlySpan<char>((void*)chars, characterCount);
            var utf8 = new UTF8Encoding(false, true);
            var size = utf8.GetByteCount(input);
            if (size is < 1 or > 1024 || input.Contains('\0')) throw Failure("InvalidFrame");
            utf8.GetBytes(input, new Span<byte>((void*)(value.memory+8),size));
            Marshal.WriteInt32(value.memory, 0x31435041); Marshal.WriteInt32(value.memory,4,size);
            value.length = 8+size; return value;
        }
        catch { value.Dispose(); throw Failure("InvalidFrame"); }
        finally
        {
            if (chars != 0)
            {
                for (nuint i = 0; i < characterBytes; ++i) Marshal.WriteByte(chars + checked((int)i), 0);
                if (charsLocked) VirtualUnlock(chars, characterBytes);
                Marshal.FreeHGlobal(chars);
            }
        }
    }
    private sealed unsafe class BorrowedMemory(nint address, int count) : MemoryManager<byte>
    {
        public override Span<byte> GetSpan() => new((void*)address, count);
        public override MemoryHandle Pin(int elementIndex = 0) => elementIndex >= 0 && elementIndex <= count
            ? new((void*)(address+elementIndex)) : throw new ArgumentOutOfRangeException(nameof(elementIndex));
        public override void Unpin() { }
        protected override void Dispose(bool disposing) { }
    }
}
