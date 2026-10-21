using System.Buffers.Binary;
using System.Net;
using System.Reflection;
using System.Text;
using System.Text.Json;
using ApfsAccess.StandardMount;
using SMBLibrary;
using SMBLibrary.Authentication.GSSAPI;

internal static class Program
{
    private static int checks;
    private static void Check(bool pass, string name)
    { checks++; if (!pass) throw new Exception(name); }
    private static void Reject(Action action, string name)
    {
        try { action(); } catch (InvalidDataException) { Check(true, name); return; }
        throw new Exception(name);
    }
    private static byte[] Frame(ushort op, ulong id, Guid epoch, byte[] body)
    {
        var result = new byte[40 + body.Length];
        // Fixed independent protocol vector: APST, version1, length at8, ID at16, epoch at24.
        Encoding.ASCII.GetBytes("APST").CopyTo(result, 0); result[4] = 1; result[6] = (byte)op;
        BinaryPrimitives.WriteUInt32LittleEndian(result.AsSpan(8), (uint)body.Length);
        BinaryPrimitives.WriteUInt64LittleEndian(result.AsSpan(16), id);
        epoch.ToByteArray().CopyTo(result, 24); body.CopyTo(result, 40); return result;
    }
    private static byte[] Pair(long a, long b)
    { var bytes = new byte[16]; BinaryPrimitives.WriteInt64LittleEndian(bytes, a); BinaryPrimitives.WriteInt64LittleEndian(bytes.AsSpan(8), b); return bytes; }
    private static byte[] HelloBody(string source, string volume, ulong features)
    {
        using var stream = new MemoryStream(); using var w = new BinaryWriter(stream);
        foreach (var s in new[] { source, volume }) { w.Write((uint)s.Length); w.Write(Encoding.Unicode.GetBytes(s)); }
        w.Write(7ul); w.Write(features); return stream.ToArray();
    }
    private static async Task Wire()
    {
        var owner = new Guid("00112233-4455-6677-8899-aabbccddeeff"); var client = Guid.NewGuid();
        var h = new StandardNativeHandle(owner, 19);
        var call = new StandardNativeCall(3, client, new StandardRead(h, 8191, 32768));
        var encoded = StandardWireCodec.EncodeRequest(call, owner);
        Check(encoded.Length == 76 && encoded[6] == 4 && encoded[16] == 3, "read fixed header");
        Check(new Guid(encoded.AsSpan(24, 16)) == client && new Guid(encoded.AsSpan(40, 16)) == owner, "distinct client and handle owner epochs");
        Check(BinaryPrimitives.ReadUInt64LittleEndian(encoded.AsSpan(56)) == 19 && BinaryPrimitives.ReadInt64LittleEndian(encoded.AsSpan(64)) == 8191, "handle and offset");
        foreach (var path in new[] { "\\..\\x", "\\a\\\\b", "\\\\other\\x", "\\a/b", "\\a\0x", "\\\ud800", "\\a:b\\c", "\\a\\" })
            Reject(() => StandardWireCodec.EncodeRequest(new(4, client, new StandardOpen(path, 1, 7, 0, 1, 0)), owner), "path refusal");
        foreach (var path in new[] { "", "\\", "\\a\\b", "\\a:stream", "\\\ud83d\ude00" })
            Check(StandardWireCodec.EncodeRequest(new(4, client, new StandardOpen(path, 1, 7, 0, 1, 0)), owner).Length >= 64, "valid path");
        Reject(() => StandardWireCodec.EncodeRequest(call with { RequestId = 0 }, owner), "zero request");
        Reject(() => StandardWireCodec.EncodeRequest(call with { ClientEpoch = Guid.Empty }, owner), "empty client");
        Reject(() => StandardWireCodec.EncodeRequest(call with { Request = new StandardRead(h, long.MaxValue, 1) }, owner), "range overflow");
        Reject(() => StandardWireCodec.EncodeRequest(call with { Request = new StandardRead(h, 0, 65537) }, owner), "native IO cap");
        Reject(() => StandardWireCodec.EncodeRequest(call with { Request = new StandardRead(new(Guid.NewGuid(), 19), 0, 1) }, owner), "foreign handle");
        var hello = Frame(0, 0, owner, HelloBody("source", "volume", 3));
        var binding = StandardWireCodec.DecodeHello(hello, "source", "volume", 7);
        Check(binding.CheckpointXid == 7 && binding.Features == (StandardNativeFeatures)3, "Stage1 binding");
        Reject(() => StandardWireCodec.DecodeHello(hello, "other", "volume", 7), "source mismatch");
        Reject(() => StandardWireCodec.DecodeHello(hello, "source", "other", 7), "volume mismatch");
        Reject(() => StandardWireCodec.DecodeHello(hello, "source", "volume", 8), "stale checkpoint");
        Reject(() => StandardWireCodec.DecodeHello(hello, "source", "volume", 6), "unexpected advanced checkpoint");
        Check(StandardWireCodec.DecodeHello(Frame(0, 0, owner, HelloBody("source", "volume", 67)), "source", "volume", 7).Features.HasFlag(StandardNativeFeatures.CaseSensitiveNames), "case policy metadata flag");
        Reject(() => StandardWireCodec.DecodeHello(Frame(0, 0, owner, HelloBody("source", "volume", 128)), "source", "volume", 7), "unknown features");
        var badHello = Frame(0, 0, owner, HelloBody("\ud800", "volume", 3));
        // Encoding.Unicode replaces isolated surrogates; overwrite its first code unit for a real wire negative.
        badHello[44] = 0; badHello[45] = 0xd8;
        Reject(() => StandardWireCodec.DecodeHello(badHello, "x", "volume", 7), "hello surrogate");
        var body = new byte[35]; body[12] = 3; body[24] = 3; body[32] = 11;
        var reply = Frame(4, 3, owner, body);
        Check(StandardWireCodec.DecodeReply(reply, call, owner).Data.Span[0] == 11, "reply payload");
        foreach (var at in new[] { 0, 4, 12, 16, 24, 68 })
        {
            var bad = reply.ToArray(); bad[at] ^= 0x80;
            Reject(() => StandardWireCodec.DecodeReply(bad, call, owner), "reply fixed field refusal");
        }
        Reject(() => StandardWireCodec.DecodeReply(reply[..^1], call, owner), "truncated reply");
        var stop = new byte[32]; stop[0] = 9; stop[8] = 9; stop[16] = 9; stop[24] = 1;
        Check(StandardWireCodec.DecodeStop(Frame(20, 8, owner, stop), 8, owner).Clean, "terminal watermarks");
        stop[16] = 8;
        Reject(() => StandardWireCodec.DecodeStop(Frame(20, 8, owner, stop), 8, owner), "false clean debt");
        var truncated = new MemoryStream(reply[..^1]);
        try { await StandardWireCodec.ReadFrameAsync(truncated, default); throw new Exception("EOF fabricated"); }
        catch (EndOfStreamException) { Check(true, "EOF refuses"); }
    }
    private static void Controls()
    {
        var h = new StandardNativeHandle(Guid.NewGuid(), 1);
        Check(StandardControlCodec.Decode(StandardControlCodec.SetSparse, [], h, 0, null, out var r) == 0 && r is StandardSparse { Sparse: true }, "sparse default");
        Check(StandardControlCodec.Decode(StandardControlCodec.SetSparse, [2], h, 0, null, out _) == NTStatus.STATUS_INVALID_PARAMETER, "sparse boolean");
        Check(StandardControlCodec.Decode(StandardControlCodec.SetSparse, [], default, 0, null, out _) == NTStatus.STATUS_INVALID_PARAMETER, "zero destination capability");
        Check(StandardControlCodec.Decode(StandardControlCodec.ZeroData, Pair(8, 7), h, 0, null, out _) != 0, "reversed zero");
        Check(StandardControlCodec.Decode(StandardControlCodec.QueryAllocatedRanges, Pair(long.MaxValue, 2), h, 16, null, out _) != 0, "range overflow");
        Check(StandardControlCodec.Decode(StandardControlCodec.DuplicateExtents, new byte[32], h, 0, null, out _) == NTStatus.STATUS_INVALID_PARAMETER, "local clone format refused");
        var clone = new byte[40]; Pair(11, 22).CopyTo(clone, 0); BinaryPrimitives.WriteInt64LittleEndian(clone.AsSpan(32), 4096);
        Check(StandardControlCodec.Decode(StandardControlCodec.DuplicateExtents, clone, h, 0, null, out _) == NTStatus.STATUS_NOT_SUPPORTED, "missing real SMB resolver");
        Check(StandardControlCodec.Decode(StandardControlCodec.DuplicateExtents, clone, h, 0, id => id == new StandardSmbFileId(11, 22) ? new(h.OwnerEpoch, 2) : null, out r) == 0 && r is StandardCloneRange { Length: 4096 }, "remote clone source mapping");
        Check(StandardControlCodec.Decode(StandardControlCodec.DuplicateExtents, clone, h, 0, _ => new(Guid.NewGuid(), 2), out _) == NTStatus.STATUS_FILE_CLOSED, "foreign clone source");
        var range = new StandardAllocatedRanges(h, 4097, 2, 32);
        Check(StandardControlCodec.ValidRanges(Pair(4096, 4096), range), "allocation rounding intersects");
        Check(!StandardControlCodec.ValidRanges(Pair(8192, 4096), range), "unrelated allocation refuses");
        Check(!StandardControlCodec.ValidRanges(Pair(4096, 4096).Concat(Pair(4096, 4096)).ToArray(), range), "overlap refuses");
    }
    private static void SmbLockWire()
    {
        foreach (var count in new[] { 1, 2 })
        {
            // Independent MS-SMB2 vector: header64, fixed lock prefix24, elements24.
            var bytes = new byte[64 + 24 + count * 24];
            bytes[0] = 0xfe; Encoding.ASCII.GetBytes("SMB").CopyTo(bytes, 1);
            bytes[4] = 64; bytes[12] = 10; bytes[64] = 48;
            BinaryPrimitives.WriteUInt16LittleEndian(bytes.AsSpan(66), (ushort)count);
            BinaryPrimitives.WriteUInt64LittleEndian(bytes.AsSpan(72), 19);
            BinaryPrimitives.WriteUInt64LittleEndian(bytes.AsSpan(80), 19);
            for (var i = 0; i < count; ++i)
            {
                BinaryPrimitives.WriteUInt64LittleEndian(bytes.AsSpan(88 + i * 24), (ulong)(32 + i * 128));
                BinaryPrimitives.WriteUInt64LittleEndian(bytes.AsSpan(96 + i * 24), 64);
                BinaryPrimitives.WriteUInt32LittleEndian(bytes.AsSpan(104 + i * 24), 0x12);
            }
            var request = new SMBLibrary.SMB2.LockRequest(bytes, 0);
            Check(request.Length == bytes.Length && request.Locks.Count == count, "Windows lock length equals exact signed wire span");
            Check(request.GetBytes().AsSpan(64).SequenceEqual(bytes.AsSpan(64)), "lock serializer preserves exact 24-byte elements without overrun");
        }
    }
    private static SecurityContext Context(string user, string address = "127.0.0.1")
    {
        var authentication = (GSSContext)typeof(GSSContext).GetConstructors(BindingFlags.NonPublic | BindingFlags.Instance).Single().Invoke([null!, new object()]);
        return new(user, "test", new IPEndPoint(IPAddress.Parse(address), 9000), authentication, new object());
    }
    private static object Open(NativeFileStore store, SecurityContext? context = null)
    {
        Check(store.CreateFile(out var h, out _, "\\file", (AccessMask)3, 0, (ShareAccess)7, (CreateDisposition)1, 0, context ?? Context("user")) == 0, "native open"); return h;
    }
    private static async Task Store()
    {
        var fake = new Transport(); var store = new NativeFileStore(fake, "user"); var context = Context("user");
        Check(store.CreateFile(out _, out _, "\\file", 0, 0, 0, 0, 0, Context("foreign")) == NTStatus.STATUS_ACCESS_DENIED, "foreign principal");
        Check(store.CreateFile(out _, out _, "\\file", 0, 0, 0, 0, 0, Context("user", "192.0.2.1")) == NTStatus.STATUS_ACCESS_DENIED, "remote endpoint");
        var h = Open(store, context);
        Check(store.GetSecurityInformation(out var descriptor, h, (SecurityInformation)7) == 0 && descriptor.Revision == 1, "native relative security query");
        Check(store.SetSecurityInformation(h, (SecurityInformation)7, descriptor) == 0 && fake.Calls.Last().Request is StandardSetSecurity, "native security set forwarding");
        var before = fake.Calls.Count;
        Check(store.SetSecurityInformation(h, (SecurityInformation)7, new SecurityDescriptor { Revision = 2 }) == NTStatus.STATUS_INVALID_PARAMETER && before == fake.Calls.Count, "invalid security revision refuses before native call");
        Check(store.LockFile(h, 0, 10, true) == NTStatus.STATUS_NOT_SUPPORTED, "Stage1 locks off");
        Check(store.DeviceIOControl(h, StandardControlCodec.SetSparse, [], out _, 0) == NTStatus.STATUS_NOT_SUPPORTED, "Stage1 sparse off");
        Check(store.SetFileInformation(h, new FileLinkInformationType2 { FileName = "link" }) == NTStatus.STATUS_NOT_SUPPORTED, "Stage1 hardlink off");
        var payload = Enumerable.Range(0, 150000).Select(i => (byte)(i * 31)).ToArray();
        Check(store.WriteFile(out var written, h, 3, payload) == 0 && written == payload.Length, "chunked large write");
        Check(fake.Calls.Count(c => c.Request is StandardWrite) == 3 && fake.Calls.Last().Request.Operation == StandardNativeOperation.Flush, "bounded writes plus real flush");
        Check(store.ReadFile(out var read, h, 3, payload.Length) == 0 && read.SequenceEqual(payload), "chunked large read exact");
        Check(store.FlushFileBuffers(new object()) == NTStatus.STATUS_FILE_CLOSED, "opaque forged handle");
        fake.FailFlush = true;
        Check(store.FlushFileBuffers(h) == NTStatus.STATUS_ACCESS_DENIED, "native refusal preserved"); fake.FailFlush = false;
        Check(store.CloseFile(h) == 0 && store.OpenCount == 0, "real cleanup close");
        Check(fake.Calls.TakeLast(3).Select(c => c.Request.Operation).SequenceEqual(new[] { StandardNativeOperation.Cleanup, StandardNativeOperation.Close, StandardNativeOperation.Disconnect }), "close ordering");
        Check(store.ReadFile(out _, h, 0, 1) == NTStatus.STATUS_FILE_CLOSED, "closed token revoked");
        Check(fake.Calls.Select(c => c.RequestId).SequenceEqual(Enumerable.Range(1, fake.Calls.Count).Select(i => (ulong)i)), "monotonic IDs");
        var tasks = new[] { store.RetireAsync(default).AsTask(), store.RetireAsync(default).AsTask() };
        await Task.WhenAll(tasks); Check(fake.RetireCalls == 1 && tasks.All(t => t.Result.Clean), "retire serialized");

        fake = new(); store = new(fake, "user"); h = Open(store); fake.Malformed = true;
        Check(store.ReadFile(out read, h, 0, 1) != 0 && read.Length == 0 && store.HasFailed, "wrong reply owner fails sticky");
        Check(!(await store.RetireAsync(default)).Clean, "protocol failure cannot become clean");
        fake = new(); store = new(fake, "user"); h = Open(store);
        fake.Binding = fake.Binding with { VolumeIdentity = "changed" };
        Check(store.FlushFileBuffers(h) != 0 && store.HasFailed, "live selection drift refuses");
        fake = new(); store = new(fake, "user"); h = Open(store); fake.FailCleanup = true;
        Check(store.CloseFile(h) != 0 && store.HasFailed && store.OpenCount == 1, "cleanup debt retained");
        Check(!(await store.RetireAsync(default)).Clean, "cleanup failure remains dirty");
        fake = new(); store = new(fake, "user"); h = Open(store); fake.CancelCall = true;
        Check(store.FlushFileBuffers(h) == NTStatus.STATUS_IO_TIMEOUT && store.HasFailed, "timeout remains a failure");
        fake = new(); store = new(fake, "user"); h = Open(store); fake.AbsoluteSecurity = true;
        Check(store.GetSecurityInformation(out _, h, (SecurityInformation)7) != 0 && store.HasFailed, "absolute native security reply rejected");
        fake = new() { Absence = false }; store = new(fake, "user");
        Check(!(await store.RetireAsync(default)).OriginalOwnerAbsent, "live native owner reserved");
        fake.Absence = true;
        Check((await store.RetireAsync(default)).OriginalOwnerAbsent && fake.RetireCalls == 2, "absence can be reobserved");
    }
    private static async Task Lifecycle()
    {
        var transport = new Transport(); var mapper = new Mapper(); var listener = new Listener();
        var mount = new LoopbackStandardMount(transport, StandardShareOptions.Create(44331), mapper, null, (_, _, _) => listener);
        await mount.StartAsync(default); Check(mount.CachedStatus.Phase == StandardMountPhase.Serving && mapper.Lease.Connected, "explicit start");
        var result = await mount.StopAsync(default); Check(result.Clean && listener.Stopped, "supervised retirement");
        transport = new(); mapper = new(); listener = new() { RequiresSigning = false };
        mount = new(transport, StandardShareOptions.Create(44331), mapper, null, (_, _, _) => listener);
        try { await mount.StartAsync(default); throw new Exception("unsigned startup"); } catch (NotSupportedException) { Check(!listener.Started && !mapper.Reserved, "unsigned listener withheld before bind"); }
        Check((await mount.StopAsync(default)).Clean, "unstarted owner still retired");
        transport = new(); mapper = new(); mapper.Lease.ConnectFailure = true; mapper.Lease.Removable = false; listener = new();
        mount = new(transport, StandardShareOptions.Create(44331), mapper, null, (_, _, _) => listener);
        try { await mount.StartAsync(default); throw new Exception("lost mapping observation"); } catch (IOException) { }
        result = await mount.StopAsync(default);
        Check(!result.MappingAbsent && result.ListenerStopped && result.Native.OriginalOwnerAbsent && !result.Clean, "uncertain mapping cannot become absent");
        mapper.Lease.Removable = true; Check((await mount.StopAsync(default)).Clean, "reserved mapping retirement retry");
        transport = new(); mapper = new(); listener = new() { StartFailure = true };
        mount = new(transport, StandardShareOptions.Create(44331), mapper, null, (_, _, _) => listener);
        try { await mount.StartAsync(default); throw new Exception("partial bind"); } catch (IOException) { }
        Check((await mount.StopAsync(default)).Clean && listener.Stopped, "partial listener startup drained");
        transport = new(); mapper = new(); listener = new() { StopFailure = true };
        mount = new(transport, StandardShareOptions.Create(44331), mapper, null, (_, _, _) => listener);
        await mount.StartAsync(default); result = await mount.StopAsync(default);
        Check(!result.Clean && !result.ListenerStopped && result.Native.OriginalOwnerAbsent, "listener stop failure does not skip native retirement");
        listener.StopFailure = false; Check((await mount.StopAsync(default)).Clean, "listener retirement can be reobserved");
        transport = new(); mapper = new(); listener = new() { WithholdClosureProof = true };
        mount = new(transport, StandardShareOptions.Create(44331), mapper, null, (_, _, _) => listener);
        await mount.StartAsync(default); result = await mount.StopAsync(default);
        Check(listener.Stopped && !result.ListenerStopped && !result.Clean, "Stop returning cannot prove exact listener closure");
        listener.WithholdClosureProof = false;
        Check((await mount.StopAsync(default)).Clean, "exact closure observation permits retirement retry");
    }
    private static async Task MappingCreationDebt()
    {
        var options = StandardShareOptions.Create(44331);
        var calls = new List<JsonElement>();
        var mapping = new WindowsLoopbackMapping((input, _) => {
            var request = JsonSerializer.SerializeToElement(input); calls.Add(request);
            return request.GetProperty("Action").GetString() switch {
                "Map" => ValueTask.FromResult(JsonSerializer.SerializeToElement(new { state = "created", remotePath = options.RemotePath, identity = "exact-created-tuple" })),
                "Probe" => throw new IOException("Actual helper probe failed after successful creation"),
                "Remove" when request.GetProperty("Identity").GetString() == "exact-created-tuple" =>
                    ValueTask.FromResult(JsonSerializer.SerializeToElement(new { state = "absent" })),
                _ => throw new IOException("Unproved mapping removal")
            };
        });
        using var credential = new StandardSmbCredential();
        var lease = mapping.Reserve(options);
        try { await lease.ConnectAsync(credential, default); throw new Exception("probe failure lost"); }
        catch (IOException) { Check(true, "probe refusal remains a failure"); }
        Check(await lease.RemoveOwnedMappingAsync(default), "creation evidence survives later probe refusal for cleanup");
        Check(calls.Select(call => call.GetProperty("Action").GetString()).SequenceEqual(new[] { "Map", "Probe", "Remove" }), "creation observed in a separate completed command before probe");
        Check(calls.All(call => call.GetProperty("ServerAddress").GetString() == options.LoopbackAddress &&
            call.GetProperty("RemotePath").GetString() == options.RemotePath), "creation/probe/removal retain one exact loopback server identity");

        string? removeIdentity = null;
        mapping = new((input, _) => {
            var request = JsonSerializer.SerializeToElement(input);
            if (request.GetProperty("Action").GetString() == "Map") throw new IOException("Unobserved creation outcome");
            removeIdentity = request.GetProperty("Identity").GetString();
            return ValueTask.FromResult(JsonSerializer.SerializeToElement(new { state = "absent" }));
        });
        lease = mapping.Reserve(StandardShareOptions.Create(44332));
        try { await lease.ConnectAsync(credential, default); throw new Exception("creation failure lost"); }
        catch (IOException) { }
        Check(await lease.RemoveOwnedMappingAsync(default) && removeIdentity == "", "unknown creation grants no removal identity and may only observe absence");
    }
    private static void EndpointPolicy()
    {
        var first = StandardShareOptions.Create(44331) with { LoopbackAddress = "127.0.0.2" };
        Check(first.IsValid && first.RemotePath == @"\\" + first.LoopbackAddress + @"\" + first.ShareName,
            "canonical loopback address and exact UNC binding");
        foreach (var address in new[] { "192.168.1.1", "0.0.0.0", "::1", "::ffff:127.0.0.1", "127.1", "127.00.0.2", "127.0.0.2\\foreign", "localhost" })
            Check(!(first with { LoopbackAddress = address }).IsValid, "noncanonical or non-IPv4-loopback endpoint refuses");
        Check((first with { LoopbackAddress = "127.0.0.2" }).IsValid, "explicit canonical loopback endpoint remains admitted");
    }
    private static void PublicAdmission()
    {
        if (!OperatingSystem.IsWindows()) return;
        var first = StandardPublicSessionAdmission.Acquire();
        try
        {
            try { using var second = StandardPublicSessionAdmission.Acquire(); throw new Exception("second public admission succeeded"); }
            catch (StandardPublicSessionException ex) { Check(ex.Reason == StandardPublicSessionRefusal.SessionActive, "live kernel admission refuses a second public session"); }
            first.RetainUntilProcessExit();
            try { using var second = StandardPublicSessionAdmission.Acquire(); throw new Exception("retained public admission lost"); }
            catch (StandardPublicSessionException ex) { Check(ex.Reason == StandardPublicSessionRefusal.SessionActive, "uncertain retirement retains public admission"); }
        }
        finally { first.Dispose(); }
        using var retry = StandardPublicSessionAdmission.Acquire();
        Check(true, "clean admission release allows a new public session");
    }
    private static void DirectoryPolicy()
    {
        foreach (var sensitive in new[] { false, true })
        {
            var fake = new Transport();
            if (sensitive) fake.Binding = fake.Binding with { Features = fake.Binding.Features | StandardNativeFeatures.CaseSensitiveNames };
            var store = new NativeFileStore(fake, "user"); var h = Open(store);
            Check(store.QueryDirectory(out var entries, h, "*.TXT", FileInformationClass.FileNamesInformation) == 0, "complete directory decode");
            Check(entries.Count == (sensitive ? 1 : 4), "case flag controls DOS matching");
            Check(store.QueryDirectory(out entries, h, "*.*", FileInformationClass.FileNamesInformation) == 0 && entries.Count == 5, "Win32 star-dot-star includes no extension");
            Check(store.QueryDirectory(out entries, h, "a?.txt", FileInformationClass.FileNamesInformation) == 0 && entries.Count == 2, "DOS question mark contraction");
            Check(fake.Calls.Last().Request is StandardQueryDirectory { Pattern: "a?.txt" }, "validated pattern forwarded");
            Check(store.GetFileSystemInformation(out _, FileSystemInformationClass.FileFsAttributeInformation) == 0, "volume case attributes agree");
        }
        var oversized = new Transport { DirectoryNames = Enumerable.Range(0, 4097).Select(i => "n" + i).ToArray() };
        var bounded = new NativeFileStore(oversized, "user"); var handle = Open(bounded);
        Check(bounded.QueryDirectory(out var empty, handle, "absent", FileInformationClass.FileNamesInformation) != 0 && empty.Count == 0 && bounded.HasFailed, "full inventory limit applies before matching");
        var inconsistent = new Transport { WrongVolumeCase = true }; var bad = new NativeFileStore(inconsistent, "user");
        Check(bad.GetFileSystemInformation(out _, FileSystemInformationClass.FileFsAttributeInformation) != 0 && bad.HasFailed, "volume case mismatch refuses");
    }
    private static async Task StreamTransport()
    {
        var owner = Guid.NewGuid(); var client = Guid.NewGuid();
        var hello = Frame(0, 0, owner, HelloBody("source", "volume", 3));
        var reply = Frame(10, 1, owner, new byte[32]);
        var marks = new byte[32]; marks[0] = 3; marks[8] = 3; marks[16] = 3; marks[24] = 1;
        var input = new MemoryStream(); var output = new MemoryStream(hello.Concat(reply).Concat(Frame(20, 2, owner, marks)).ToArray());
        var observations = 0; var exited = false;
        var transport = await ApfsAccess.StandardMount.StreamNativeTransport.ConnectAsync(input, output, "source", "volume", 7,
            _ => { observations++; return ValueTask.FromResult(new StandardNativeOwnerExit(exited, exited, true, exited ? 0 : null)); }, default);
        Check(transport.Binding.OwnerEpoch == owner, "stream Hello bound");
        var call = new StandardNativeCall(1, Guid.Empty, new StandardQueryVolume(5));
        Check((await transport.InvokeAsync(call, default)).Status == 0, "real framed stream reply");
        var first = await transport.RetireAsync(default);
        Check(!first.OriginalOwnerAbsent && !first.Clean && first.AcceptedSequence == 3 && observations == 1, "Stop receipt cannot prove process exit");
        var wireLength = input.ToArray().Length;
        Check(wireLength == 84 && StandardWireCodec.DecodeHeader(input.ToArray().AsSpan(44, 40)).RequestId == 2, "contiguous Stop only once");
        try { await transport.InvokeAsync(new(2, client, new StandardDisconnect()), default); throw new Exception("retiring invoke"); }
        catch (IOException) { Check(input.ToArray().Length == wireLength, "retiring owner rejects new call"); }
        exited = true; Check((await transport.RetireAsync(default)).Clean && observations == 2, "parent exit/job proof completes retirement");
        Check(input.ToArray().Length == wireLength, "reobserve does not replay Stop");
        await transport.DisposeAsync();

        input = new MemoryStream(); output = new MemoryStream(hello);
        transport = await ApfsAccess.StandardMount.StreamNativeTransport.ConnectAsync(input, output, "source", "volume", 7,
            _ => ValueTask.FromResult(new StandardNativeOwnerExit(true, true, true, 0)), default);
        try { await transport.InvokeAsync(call, default); throw new Exception("truncated stream"); }
        catch (EndOfStreamException) { Check(true, "framed EOF remains error"); }
        var failed = await transport.RetireAsync(default);
        Check(!failed.Clean && failed.OriginalOwnerAbsent && failed.Status != 0 && input.ToArray().Length == 44, "poisoned framing never sends guessed Stop");
        input = new MemoryStream(); output = new MemoryStream(hello.Concat(Frame(20, 1, Guid.NewGuid(), marks)).ToArray());
        transport = await ApfsAccess.StandardMount.StreamNativeTransport.ConnectAsync(input, output, "source", "volume", 7,
            _ => ValueTask.FromResult(new StandardNativeOwnerExit(true, true, true, 0)), default);
        Check(!(await transport.RetireAsync(default)).Clean, "wrong Stop owner cannot become clean");
        input = new MemoryStream(); output = new MemoryStream(hello);
        try
        {
            await ApfsAccess.StandardMount.StreamNativeTransport.ConnectAsync(input, output, "foreign", "volume", 7,
                _ => throw new Exception("unadmitted owner cleanup belongs to launch factory"), default);
            throw new Exception("foreign Hello");
        }
        catch (InvalidDataException) { Check(input.CanWrite && output.CanRead, "failed Hello leaves launch cleanup with factory"); }
    }
    private static void TrustedCloneForwarding()
    {
        var fake = new Transport(); fake.Binding = fake.Binding with { Features = fake.Binding.Features | StandardNativeFeatures.Clone };
        var store = new NativeFileStore(fake, "user"); var context = Context("user"); var source = Open(store, context); var target = Open(store, context);
        Check(store.CloneFileRange(source, target, 4096, 8192, 16384) == 0 && fake.Calls.Last().Request is StandardCloneRange { SourceOffset: 4096, DestinationOffset: 8192, Length: 16384 }, "trusted resolved opens forward exact clone");
        var foreign = Open(store, Context("user")); var count = fake.Calls.Count;
        Check(store.CloneFileRange(foreign, target, 0, 0, 4096) == NTStatus.STATUS_FILE_CLOSED && count == fake.Calls.Count, "different admitted client refuses before native clone");
        Check(store.CloneFileRange(new object(), target, 0, 0, 4096) == NTStatus.STATUS_FILE_CLOSED && count == fake.Calls.Count, "unowned resolved object refuses");
        Check(store.CloneFileRange(source, target, long.MaxValue, 0, 4096) == NTStatus.STATUS_INVALID_PARAMETER && count == fake.Calls.Count, "resolved clone overflow refuses");
    }
    private static void AdmittedControls()
    {
        var fake = new Transport();
        fake.Binding = fake.Binding with { Features = fake.Binding.Features | StandardNativeFeatures.Sparse |
            StandardNativeFeatures.ByteRangeLocks | StandardNativeFeatures.Clone | StandardNativeFeatures.HardLink };
        var store = new NativeFileStore(fake, "user"); var context = Context("user");
        var source = Open(store, context); var target = Open(store, context);
        Check(store.DeviceIOControl(target, StandardControlCodec.SetSparse, [0], out var output, 0) == 0 &&
            output.Length == 0 && fake.Calls.Last().Request is StandardSparse { Sparse: false }, "admitted sparse clear exact");
        Check(store.DeviceIOControl(target, StandardControlCodec.ZeroData, Pair(4097, 8193), out output, 0) == 0 &&
            fake.Calls.Last().Request is StandardZeroRange { Offset: 4097, BeyondFinalZero: 8193 }, "admitted zero exact exclusive end");
        fake.Ranges = Pair(4096, 4096); fake.ControlStatus = (uint)NTStatus.STATUS_BUFFER_OVERFLOW;
        Check(store.DeviceIOControl(target, StandardControlCodec.QueryAllocatedRanges, Pair(4097, 2), out output, 16) == NTStatus.STATUS_BUFFER_OVERFLOW &&
            output.SequenceEqual(fake.Ranges) && fake.Calls.Last().Request is StandardAllocatedRanges { Offset: 4097, Length: 2, MaxOutputBytes: 16 }, "partial native ranges retain overflow status");
        fake.ControlStatus = (uint)NTStatus.STATUS_ACCESS_DENIED;
        Check(store.DeviceIOControl(target, StandardControlCodec.ZeroData, Pair(1, 2), out output, 0) == NTStatus.STATUS_ACCESS_DENIED &&
            output.Length == 0 && !store.HasFailed, "native zero denial remains denial");
        Check(store.CloneFileRange(source, target, 4096, 8192, 4096) == NTStatus.STATUS_ACCESS_DENIED &&
            fake.Calls.Last().Request is StandardCloneRange { SourceOffset: 4096, DestinationOffset: 8192, Length: 4096 }, "native clone denial remains denial");
        Check(store.LockFile(target, 7, 11, true) == NTStatus.STATUS_ACCESS_DENIED &&
            fake.Calls.Last().Request is StandardRangeLock { Offset: 7, Length: 11, Exclusive: true, Unlock: false }, "native lock denial retains exact range");
        fake.ControlStatus = 0;
        Check(store.UnlockFile(target, 7, 11) == 0 &&
            fake.Calls.Last().Request is StandardRangeLock { Offset: 7, Length: 11, Exclusive: false, Unlock: true }, "native unlock exact range");
        Check(store.SetFileInformation(target, new FileLinkInformationType2 { FileName = "\\link" }) == 0 &&
            fake.Calls.Last().Request is StandardSetFile { InformationClass: (uint)FileInformationClass.FileLinkInformation }, "admitted link uses typed information request");
        var count = fake.Calls.Count;
        Check(store.LockFile(target, 0, 0, true) == NTStatus.STATUS_INVALID_PARAMETER && count == fake.Calls.Count, "empty lock refuses before native");
        Check(store.SetFileInformation(target, new FileLinkInformationType2 { RootDirectory = 1, FileName = "link" }) == NTStatus.STATUS_INVALID_PARAMETER &&
            count == fake.Calls.Count, "foreign root link refuses before native");
        var sourceWire = StandardWireCodec.EncodeRequest(new(1, Guid.NewGuid(),
            new StandardCloneRange(new(fake.Binding.OwnerEpoch, 37), new(fake.Binding.OwnerEpoch, 41), 4096, 8192, 12288)), fake.Binding.OwnerEpoch);
        Check(sourceWire.Length == 112 && BinaryPrimitives.ReadUInt64LittleEndian(sourceWire.AsSpan(56)) == 37 &&
            BinaryPrimitives.ReadUInt64LittleEndian(sourceWire.AsSpan(80)) == 41 &&
            BinaryPrimitives.ReadInt64LittleEndian(sourceWire.AsSpan(88)) == 4096 &&
            BinaryPrimitives.ReadInt64LittleEndian(sourceWire.AsSpan(96)) == 8192 &&
            BinaryPrimitives.ReadInt64LittleEndian(sourceWire.AsSpan(104)) == 12288, "clone wire preserves both capabilities and three ranges");
        fake.Ranges = Pair(4096, 4096).Concat(Pair(4096, 4096)).ToArray();
        Check(store.DeviceIOControl(target, StandardControlCodec.QueryAllocatedRanges, Pair(4097, 2), out output, 32) != 0 &&
            output.Length == 0 && store.HasFailed, "overlapping native allocation reply poisons transport");

        fake = new(); store = new(fake, "user"); target = Open(store); count = fake.Calls.Count;
        Check(store.CloneFileRange(target, target, 0, 0, 4096) == NTStatus.STATUS_NOT_SUPPORTED &&
            store.UnlockFile(target, 0, 1) == NTStatus.STATUS_NOT_SUPPORTED &&
            store.DeviceIOControl(target, StandardControlCodec.ZeroData, Pair(0, 1), out _, 0) == NTStatus.STATUS_NOT_SUPPORTED &&
            store.DeviceIOControl(target, StandardControlCodec.QueryAllocatedRanges, Pair(0, 1), out _, 16) == NTStatus.STATUS_NOT_SUPPORTED &&
            count == fake.Calls.Count, "Stage1 controls never reach native without feature admission");
    }
    private static async Task LateCloseDuringRetirement()
    {
        using var deadline = new CancellationTokenSource(TimeSpan.FromSeconds(5));
        var fake = new Transport { RetirementStarted = new(TaskCreationOptions.RunContinuationsAsynchronously),
            RetirementCompletion = new(TaskCreationOptions.RunContinuationsAsynchronously) };
        var store = new NativeFileStore(fake, "user"); var handle = Open(store); var calls = fake.Calls.Count;
        var retiring = store.RetireAsync(deadline.Token).AsTask();
        await fake.RetirementStarted.Task.WaitAsync(deadline.Token);
        try
        {
            Check(store.CloseFile(handle) == NTStatus.STATUS_FILE_CLOSED && fake.Calls.Count == calls,
                "late SMB close cannot transmit past retirement boundary");
            Check(store.ReadFile(out _, handle, 0, 1) == NTStatus.STATUS_FILE_CLOSED && fake.Calls.Count == calls,
                "late read cannot transmit past retirement boundary");
            Check(store.OpenCount == 1 && !store.HasFailed, "late callbacks preserve unproved open and protocol state");
        }
        finally { fake.RetirementCompletion.TrySetResult(new(false, false, false, 3, 3, 3, 0)); await retiring; }
        Check(!(await retiring).Clean && store.OpenCount == 1, "unproved original absence retains open capability");
        Check(store.CloseFile(handle) == NTStatus.STATUS_FILE_CLOSED && fake.Calls.Count == calls && !store.HasFailed,
            "late close after incomplete retirement remains local refusal");
        fake.RetirementStarted = new(TaskCreationOptions.RunContinuationsAsynchronously);
        fake.RetirementCompletion = new(TaskCreationOptions.RunContinuationsAsynchronously);
        retiring = store.RetireAsync(deadline.Token).AsTask();
        await fake.RetirementStarted.Task.WaitAsync(deadline.Token);
        try { Check(store.OpenCount == 1 && store.CloseFile(handle) == NTStatus.STATUS_FILE_CLOSED,
            "retry cannot release open before original owner absence"); }
        finally { fake.RetirementCompletion.TrySetResult(new(true, true, true, 3, 3, 3, 0)); await retiring; }
        Check((await retiring).Clean && store.OpenCount == 0 && fake.Calls.Count == calls && !store.HasFailed,
            "only original owner absence clears opens without late protocol traffic");
        Check(store.CloseFile(handle) == NTStatus.STATUS_FILE_CLOSED && fake.Calls.Count == calls,
            "post-terminal close cannot change terminal request sequence");
    }
    private static async Task<int> Main()
    {
        try { await Wire(); Controls(); SmbLockWire(); await Store(); DirectoryPolicy(); TrustedCloneForwarding(); AdmittedControls(); await StreamTransport(); await Lifecycle(); await MappingCreationDebt(); EndpointPolicy(); PublicAdmission(); await LateCloseDuringRetirement(); Console.WriteLine($"PASS {checks} assertions; managed codec/mock native only; no APFS gate"); return 0; }
        catch (Exception e) { Console.Error.WriteLine(e); return 1; }
    }
    private sealed class Transport : IStandardNativeTransport
    {
        public StandardNativeBinding Binding { get; set; } = new(Guid.NewGuid(), "source", "volume", 7, StandardNativeFeatures.OrdinaryIo | StandardNativeFeatures.Security);
        internal readonly List<StandardNativeCall> Calls = [];
        internal readonly byte[] Bytes = new byte[2 << 20];
        internal bool FailFlush, FailCleanup, Malformed, CancelCall, AbsoluteSecurity, WrongVolumeCase, Absence = true;
        internal uint ControlStatus;
        internal byte[] Ranges = [];
        internal string[] DirectoryNames = ["Alpha.TXT", "noext", "beta.txt", "a.txt", "ab.txt"];
        internal int RetireCalls; private ulong next;
        internal TaskCompletionSource? RetirementStarted;
        internal TaskCompletionSource<StandardNativeRetirement>? RetirementCompletion;
        public ValueTask<StandardNativeReply> InvokeAsync(StandardNativeCall c, CancellationToken token)
        {
            Calls.Add(c); var owner = Malformed ? Guid.NewGuid() : Binding.OwnerEpoch;
            if (CancelCall) throw new OperationCanceledException();
            StandardNativeReply Reply(uint status = 0, int count = 0, ReadOnlyMemory<byte> data = default, ulong id = 0) => new(c.RequestId, owner, status, id, 1, 3, count, data);
            if (c.Request is StandardOpen) return ValueTask.FromResult(Reply(id: ++next));
            if (c.Request is StandardWrite write) { write.Bytes.CopyTo(Bytes.AsMemory((int)write.Offset)); return ValueTask.FromResult(Reply(count: write.Bytes.Length)); }
            if (c.Request is StandardRead read) return ValueTask.FromResult(Reply(count: read.Count, data: Bytes.AsMemory((int)read.Offset, read.Count)));
            if (c.Request is StandardAllocatedRanges) return ValueTask.FromResult(Reply(ControlStatus, data: Ranges));
            if (c.Request is StandardSparse or StandardZeroRange or StandardCloneRange or StandardRangeLock) return ValueTask.FromResult(Reply(ControlStatus));
            if (c.Request is StandardQuerySecurity)
            {
                var security = new byte[20]; security[0] = 1; security[3] = AbsoluteSecurity ? (byte)0 : (byte)0x80;
                return ValueTask.FromResult(Reply(data: security));
            }
            if (c.Request is StandardQueryDirectory)
            {
                var entries = DirectoryNames.Select(name => (QueryDirectoryFileInformation)new FileNamesInformation { FileName = name }).ToList();
                return ValueTask.FromResult(Reply(data: QueryDirectoryFileInformation.GetBytes(entries)));
            }
            if (c.Request is StandardQueryVolume)
            {
                var sensitive = Binding.Features.HasFlag(StandardNativeFeatures.CaseSensitiveNames) != WrongVolumeCase;
                var attributes = new FileFsAttributeInformation { FileSystemName = "APFS", MaximumComponentNameLength = 255, FileSystemAttributes = (FileSystemAttributes)(sensitive ? 1u : 0u) };
                return ValueTask.FromResult(Reply(data: attributes.GetBytes()));
            }
            if (c.Request.Operation == StandardNativeOperation.Flush && FailFlush || c.Request.Operation == StandardNativeOperation.Cleanup && FailCleanup)
                return ValueTask.FromResult(Reply((uint)NTStatus.STATUS_ACCESS_DENIED));
            return ValueTask.FromResult(Reply());
        }
        public async ValueTask<StandardNativeRetirement> RetireAsync(CancellationToken token)
        {
            RetireCalls++; RetirementStarted?.TrySetResult();
            if (RetirementCompletion is {} completion) return await completion.Task.WaitAsync(token);
            await Task.Delay(5, token); return new(Absence, Absence, true, 3, 3, 3, 0);
        }
        public ValueTask DisposeAsync() => ValueTask.CompletedTask;
    }
    private sealed class Listener : IStandardSmbListener
    {
        public bool RequiresSigning { get; set; } = true;
        public bool IsStopped => Stopped && !WithholdClosureProof;
        internal bool Started, Stopped, StartFailure, StopFailure, WithholdClosureProof;
        public void Start() { Started = true; if (StartFailure) throw new IOException("partial bind"); }
        public void Stop() { if (StopFailure) throw new IOException("socket remains reserved"); Stopped = true; }
    }
    private sealed class Mapper : IStandardMappingController
    {
        internal readonly Lease Lease = new(); internal bool Reserved;
        public IStandardMappingLease Reserve(StandardShareOptions options) { Reserved = true; Lease.RemotePath = options.RemotePath; return Lease; }
    }
    private sealed class Lease : IStandardMappingLease
    {
        public string RemotePath { get; set; } = "";
        internal bool Connected, ConnectFailure, Removable = true;
        public ValueTask ConnectAsync(StandardSmbCredential credential, CancellationToken token)
        { Connected = true; if (ConnectFailure) throw new IOException("lost mapping response"); return ValueTask.CompletedTask; }
        public ValueTask<bool> RemoveOwnedMappingAsync(CancellationToken token) => ValueTask.FromResult(Removable);
    }
}
