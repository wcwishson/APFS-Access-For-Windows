// Synthetic framing and hand-assembled LZBITMAP vectors, not Apple corpus data.
#include "apfsaccess_lzbitmap.h"

void U24(Bytes& b, std::size_t at, std::uint32_t n)
{ for (unsigned i = 0; i < 3; ++i) b.at(at + i) = static_cast<std::byte>(n >> (8 * i)); }

Bytes Stored(std::byte marker, const Bytes& data)
{
    Bytes b{marker}; b.insert(b.end(), data.begin(), data.end()); return b;
}

Bytes ZbmStream(const std::vector<Bytes>& chunks)
{
    auto b = Hex("5a424d09");
    for (const auto& c : chunks) b.insert(b.end(), c.begin(), c.end());
    const auto end = Hex("060000000000"); b.insert(b.end(), end.begin(), end.end());
    return b;
}

Bytes ZbmStoredChunk(const Bytes& plain)
{
    Bytes b(6); U24(b, 0, static_cast<std::uint32_t>(6 + plain.size()));
    U24(b, 3, static_cast<std::uint32_t>(plain.size()));
    b.insert(b.end(), plain.begin(), plain.end()); return b;
}

// Assemble a compressed chunk from literal/period/bitmap regions and low-first
// instruction nibbles. Descriptors are independently packed as 12 x 10 bits.
Bytes ZbmChunk(std::uint32_t size, const Bytes& literals, const Bytes& periods,
    const Bytes& bitmaps, const std::vector<unsigned>& nibbles,
    const std::vector<unsigned>& descriptors = {0xff, 0})
{
    Bytes b(15); U24(b, 3, size);
    b.insert(b.end(), literals.begin(), literals.end());
    U24(b, 6, static_cast<std::uint32_t>(b.size()));
    b.insert(b.end(), periods.begin(), periods.end());
    U24(b, 9, static_cast<std::uint32_t>(b.size()));
    b.insert(b.end(), bitmaps.begin(), bitmaps.end());
    U24(b, 12, static_cast<std::uint32_t>(b.size()));
    for (std::size_t i = 0; i < nibbles.size(); ++i)
        if ((i & 1) == 0) b.push_back(static_cast<std::byte>(nibbles[i]));
        else b.back() |= static_cast<std::byte>(nibbles[i] << 4);
    const auto trailer = b.size(); b.resize(trailer + 17);
    for (std::size_t i = 0; i < descriptors.size(); ++i)
        for (unsigned bit = 0; bit < 10; ++bit)
            if ((descriptors[i] >> bit) & 1)
                b.at(trailer + (i * 10 + bit) / 8) |= static_cast<std::byte>(1 << ((i * 10 + bit) % 8));
    U24(b, 0, static_cast<std::uint32_t>(b.size()));
    return b;
}

Bytes ZbmRepeatedChunk(bool seed)
{
    // One initial literal bitmap, then 4095 repeated back-reference bitmaps;
    // subsequent chunks reference previous chunk history with reset period 8.
    std::vector<unsigned> n;
    if (seed) n.push_back(3);
    n.push_back(4); n.push_back(15);
    unsigned remainder = (seed ? 4095 : 4096) - 4;
    while (remainder >= 15) { n.push_back(15); remainder -= 15; }
    n.push_back(remainder);
    return ZbmChunk(32768, seed ? Hex("4142434445464748") : Bytes{}, {}, {}, n);
}

Bytes RepeatedPlain(std::size_t size)
{
    Bytes b(size); for (std::size_t i = 0; i < size; ++i) b[i] = static_cast<std::byte>('A' + i % 8);
    return b;
}

void TestRawNine()
{
    const auto plain = Hex("00ffcc80410042");
    const auto attr = Attribute(9, plain.size(), Stored(std::byte{0xcc}, plain));
    Expect(Hex("66706d63090000000500000000000000cc68656c6c6f"), 0, kMax, kHelloPlain);
    Expect(attr, 0, kMax, plain); Expect(attr, 2, 3, Hex("cc8041"));
    Expect(attr, 6, kMax, Hex("42")); Expect(attr, 7, 3, {});
    Expect(attr, kMax, kMax, {}); Expect(attr, 0, 0, {});
    Expect(Attribute(9, 0, Hex("cc")), 0, kMax, {});
    for (unsigned m = 0; m < 256; ++m) if (m != 0xcc)
        Reject(Attribute(9, plain.size(), Stored(static_cast<std::byte>(m), plain)), Status::Unsupported);
    for (std::size_t cut = 16; cut < attr.size(); ++cut)
        Reject(Bytes(attr.begin(), attr.begin() + cut), Status::Corrupt, {}, {}, kMax, 0);
    auto extra = attr; extra.push_back(std::byte{0}); Reject(extra, Status::Corrupt);
    Reject(Attribute(9, 6, Stored(std::byte{0xcc}, plain)), Status::Corrupt);
    Reject(Attribute(9, kMax, Hex("cc")), Status::Corrupt);
    Reject(attr, Status::Corrupt, {1, {}});
    ApfsCompressionHeader h{44, 55};
    auto rc = ApfsCompression::Inspect(Attribute(9, 0, Hex("ff")), {}, h);
    Require(rc.status == Status::Unsupported && h.type == 44 && h.uncompressed_size == 55, "type9 Inspect preservation");
    rc = ApfsCompression::Inspect(attr, {}, h);
    Require(static_cast<bool>(rc) && h.type == 9 && h.uncompressed_size == plain.size(), "type9 Inspect");
    auto alias = attr;
    rc = ApfsCompression::DecodeRange(alias, {}, 2, 3, {}, alias);
    Require(static_cast<bool>(rc) && alias == Hex("cc8041"), "type9 alias success");
    for (unsigned which = 0; which < 5; ++which)
    {
        ApfsCompressionLimits l;
        if (which == 0) l.max_decmpfs_bytes = attr.size() - 1;
        if (which == 1) l.max_inline_decoded_bytes = plain.size() - 1;
        if (which == 2) l.max_file_bytes = plain.size() - 1;
        if (which == 3) l.max_output_bytes = plain.size() - 1;
        if (which == 4) l.max_decoded_bytes = plain.size() - 1;
        Reject(attr, Status::LimitExceeded, {}, l);
    }
    ApfsCompressionLimits l; l.max_decoded_bytes = 1; l.max_output_bytes = 1;
    l.max_zlib_allocation_bytes = l.max_lzfse_state_bytes = l.max_lzbitmap_state_bytes = 0;
    Expect(attr, 6, kMax, Hex("42"), {}, l);
}

void TestBitmapInline()
{
    // Fully literal vector: magic, stored 5-byte chunk, six-byte terminator.
    const auto hello = Hex("5a424d090b000005000068656c6c6f060000000000");
    const auto attr = Attribute(13, 5, hello);
    Expect(attr, 0, kMax, kHelloPlain); Expect(attr, 1, 3, Hex("656c6c"));
    Expect(attr, 5, kMax, {}); Expect(attr, kMax, kMax, {}); Expect(attr, 0, 0, {});
    Expect(Attribute(13, 0, Hex("5a424d09060000000000")), 0, kMax, {});
    Expect(Attribute(13, 0, Hex("ff")), 0, kMax, {});
    Expect(Attribute(13, 5, Hex("ff68656c6c6f")), 1, 3, Hex("656c6c"));
    const auto compressed = ZbmStream({ZbmChunk(32, Hex("4142434445464748"), {}, {}, {3,4,4,4})});
    Expect(Attribute(13, 32, compressed), 0, kMax, RepeatedPlain(32));
    // Inline 64 KiB decoded in two internal 32 KiB chunks, including history.
    const auto big = ZbmStream({ZbmRepeatedChunk(true), ZbmRepeatedChunk(false)});
    Expect(Attribute(13, 65536, big), 32764, 12, Hex("454647484142434445464748"));
    Expect(Attribute(13, 65536, big), 0, kMax, RepeatedPlain(65536));
    // Direct bitmaps, new periods of one/two bytes, overlapping distance 1,
    // fixed descriptor period changes, partial final bitmap, repetition opcode.
    Expect(Attribute(13, 24, ZbmStream({ZbmChunk(24, Hex("4142434445464748"),
        Hex("08"), Hex("00"), {3,1,4})})), 0, kMax, RepeatedPlain(24));
    Expect(Attribute(13, 24, ZbmStream({ZbmChunk(24, Hex("4142434445464748"),
        Hex("0800"), Hex("00"), {3,2,4})})), 0, kMax, RepeatedPlain(24));
    Expect(Attribute(13, 24, ZbmStream({ZbmChunk(24, Hex("4142434445464748"),
        Hex("08"), {}, {3,4,5}, {0xff,0x100,0})})), 0, kMax, RepeatedPlain(24));
    Expect(Attribute(13, 7, ZbmStream({ZbmChunk(7, Hex("41"), Hex("01"), Hex("01"), {1})})),
        0, kMax, Bytes(7, std::byte{'A'}));
    Expect(Attribute(13, 8, ZbmStream({ZbmChunk(8, Hex("4142434445464748"), {}, Hex("ff"), {0})})),
        0, kMax, RepeatedPlain(8));
    Expect(Attribute(13, 40, ZbmStream({ZbmChunk(40, Hex("4142434445464748"), {}, {}, {3,4,15,0})})),
        0, kMax, RepeatedPlain(40));
    // History from a stored internal chunk is available to a compressed one.
    Expect(Attribute(13, 16, ZbmStream({ZbmStoredChunk(RepeatedPlain(8)),
        ZbmChunk(8, {}, {}, {}, {4})})), 0, kMax, RepeatedPlain(16));
    auto half = ZbmChunk(8, RepeatedPlain(8), {}, {}, {3});
    half[half.size() - 18] |= std::byte{0xf0};
    Expect(Attribute(13, 8, ZbmStream({half})), 0, kMax, RepeatedPlain(8));

    for (const auto& stream : {hello, compressed, big})
    {
        const auto size = stream == hello ? 5 : stream == compressed ? 32 : 65536;
        for (std::size_t cut = 0; cut < stream.size(); ++cut)
            Reject(Attribute(13, size, Bytes(stream.begin(), stream.begin() + cut)), Status::Corrupt);
        for (const auto advertised : {0, size - 1, size + 1})
            Reject(Attribute(13, advertised, stream), advertised > 65536 ? Status::LimitExceeded : Status::Corrupt,
                {}, {}, kMax, 0);
        auto extra = stream; extra.push_back(std::byte{0});
        Reject(Attribute(13, size, extra), Status::Corrupt);
        extra.insert(extra.end(), stream.begin(), stream.end());
        Reject(Attribute(13, size * 2, extra), size * 2 > 65536 ? Status::LimitExceeded : Status::Corrupt);
    }
    for (const auto payload : {"", "00", "cc", "fe", "ff00", "5a424d08", "5a424d09",
        "5a424d09000000000000", "5a424d09050000000000", "5a424d0907000000000000",
        "5a424d09060000018000", "5a424d09ffffff000000"})
        Reject(Attribute(13, 0, Hex(payload)), Status::Corrupt);
    for (unsigned at : {6u,9u,12u})
        for (unsigned value : {0u,14u,0xffffffu})
        {
            auto c = ZbmChunk(32, RepeatedPlain(8), {}, {}, {3,4,4,4}); U24(c, at, value);
            Reject(Attribute(13, 32, ZbmStream({c})), Status::Corrupt);
        }
    // Missing literals / periods / bitmaps must not read the next metadata region.
    for (const auto c : {
        ZbmChunk(8, {}, {}, {}, {3}),
        ZbmChunk(8, {}, {}, Hex("ff"), {1}),
        ZbmChunk(8, RepeatedPlain(8), {}, {}, {0}),
        ZbmChunk(8, {}, {}, {}, {4}), // history underflow
        ZbmChunk(8, Hex("41"), Hex("00"), Hex("01"), {1}), // zero distance
        ZbmChunk(8, Hex("41"), Hex("0200"), Hex("01"), {2}), // distance too large
        ZbmChunk(32, RepeatedPlain(8), {}, {}, {3,4,15,15,0}), // excess repetitions
        ZbmChunk(8, RepeatedPlain(8), {}, {}, {15}), // invalid bitmap selector
        ZbmChunk(8, RepeatedPlain(8), {}, {}, {3}, {0x3ff})}) // invalid descriptor
        Reject(Attribute(13, c[3] == std::byte{32} ? 32 : 8, ZbmStream({c})), Status::Corrupt);
    auto padding = ZbmChunk(32, RepeatedPlain(8), {}, {}, {3,4,4,4});
    padding.back() = std::byte{1};
    Reject(Attribute(13, 32, ZbmStream({padding})), Status::Unsupported);
    auto alias = Attribute(13, 32, compressed);
    auto rc = ApfsCompression::DecodeRange(alias, {}, 7, 3, {}, alias);
    Require(static_cast<bool>(rc) && alias == Hex("484142"), "type13 alias success");
    alias = Attribute(13, 31, compressed); const auto before = alias;
    rc = ApfsCompression::DecodeRange(alias, {}, 0, kMax, {}, alias);
    Require(rc.status == Status::Corrupt && alias == before, "type13 alias failure");
    Reject(attr, Status::Corrupt, {1,{}});
    std::size_t calls = 0;
    Reject(attr, Status::Corrupt, {0,[&](std::uint64_t, std::span<std::byte>) { ++calls; return 0; }});
    Require(calls == 0, "inline codec never calls unexpected resource reader");
    for (unsigned which = 0; which < 7; ++which)
    {
        ApfsCompressionLimits l;
        if (which == 0) l.max_decmpfs_bytes = attr.size() - 1;
        if (which == 1) l.max_inline_decoded_bytes = 4;
        if (which == 2) l.max_file_bytes = 4;
        if (which == 3) l.max_output_bytes = 4;
        if (which == 4) l.max_decoded_bytes = 4;
        if (which == 5) l.max_lzbitmap_state_bytes = apfsaccess_lzbitmap_state_size() - 1;
        if (which == 6) l.max_lzbitmap_work_units = 132; // 2 headers * 64 + 5 raw bytes
        Reject(attr, Status::LimitExceeded, {}, l);
    }
    ApfsCompressionLimits l; l.max_lzbitmap_work_units = 133;
    l.max_lzbitmap_state_bytes = apfsaccess_lzbitmap_state_size();
    Expect(attr, 0, kMax, kHelloPlain, {}, l);
    l.max_lzbitmap_work_units = 0;
    Reject(attr, Status::LimitExceeded, {}, l, kMax, 0);
    l.max_lzbitmap_state_bytes = 0;
    Expect(Attribute(13, 5, Hex("ff68656c6c6f")), 0, kMax, kHelloPlain, {}, l);
    l = {}; l.max_file_bytes = l.max_inline_decoded_bytes = l.max_decoded_bytes = kMax;
    Reject(Attribute(13, kMax, hello), Status::LimitExceeded, {}, l, kMax, 0);
}

void TestRemainingResources()
{
    const auto bitmap = ZbmStream({ZbmRepeatedChunk(true), ZbmRepeatedChunk(false)});
    for (const auto type : {10u,14u})
    {
        const auto marker = static_cast<std::byte>(type == 10 ? 0xcc : 0xff);
        const auto block = type == 10 ? Stored(marker, RepeatedPlain(65536)) : bitmap;
        const auto tail = type == 10 ? Stored(marker, kHelloPlain) : ZbmStream({ZbmStoredChunk(kHelloPlain)});
        MemoryFork f{LzvnResource({block, tail})};
        const auto attr = Attribute(type, 65541);
        Expect(attr, 65533, 8, Hex("46474868656c6c6f"), f.Reader());
        f.requests.clear();
        Expect(attr, 65538, kMax, Hex("6c6c6f"), f.Reader());
        Require(f.requests.size() == 2 && f.requests[0].second == 12 &&
            f.requests[1] == std::pair<std::uint64_t,std::size_t>{12 + block.size(),tail.size()},
            "remaining resource range reads only table and selected block");
        f.requests.clear(); Expect(attr, kMax, kMax, {}, f.Reader());
        Require(f.requests.size() == 1, "remaining resource EOF validates table only");
        Expect(attr, 65541, 1, {}, f.Reader()); Expect(attr, 0, 0, {}, f.Reader());
        MemoryFork empty{Hex("04000000")}; Expect(Attribute(type,0),0,kMax,{},empty.Reader());
        MemoryFork literal{LzvnResource({Stored(marker,kHelloPlain)})};
        Expect(Attribute(type,5),0,kMax,kHelloPlain,literal.Reader());
        // Whole-table size validation still applies when the requested range is empty.
        for (unsigned at : {0u,4u,8u}) for (unsigned value : {0u,11u,0xffffffffu})
        {
            MemoryFork bad{f.bytes}; U32(bad.bytes,at,value);
            Reject(attr,Status::Corrupt,bad.Reader(),{},kMax,0);
        }
        MemoryFork bad{f.bytes}; bad.bytes.push_back(std::byte{0});
        Reject(attr,Status::Corrupt,bad.Reader());
        U32(bad.bytes,8,static_cast<std::uint32_t>(bad.bytes.size()));
        Reject(attr,Status::Corrupt,bad.Reader()); // in-frame trailing bytes
        bad.bytes = f.bytes; bad.bytes[12 + block.size()] = std::byte{0};
        Reject(attr,type==10 ? Status::Unsupported : Status::Corrupt,bad.Reader()); // no partial output publication
        for (bool throwing : {false,true})
        {
            f.requests.clear(); f.fail_call=3; f.throw_on_failure=throwing;
            Reject(attr,Status::ReadError,f.Reader());
        }
        f.fail_call=0;
        Reject(Attribute(type,5,Hex("00")),Status::Corrupt,literal.Reader());
        Reject(Attribute(type,5),Status::Corrupt);
        Reject(Attribute(type,6),Status::Corrupt,literal.Reader());
        for (unsigned which = 0; which < 6; ++which)
        {
            ApfsCompressionLimits l;
            if(which==0) l.max_table_bytes=11;
            if(which==1) l.max_resource_bytes=f.bytes.size()-1;
            if(which==2) l.max_resource_read_bytes=12+block.size()+tail.size()-1;
            if(which==3) l.max_decoded_bytes=65540;
            if(which==4) l.max_output_bytes=7;
            if(which==5) l.max_file_bytes=65540;
            Reject(attr,Status::LimitExceeded,f.Reader(),l,65533,8);
        }
        ApfsCompressionLimits l; l.max_resource_read_bytes=12+tail.size(); l.max_decoded_bytes=5;
        Expect(attr,65536,1,Hex("68"),f.Reader(),l);
        --l.max_resource_read_bytes; Reject(attr,Status::LimitExceeded,f.Reader(),l,65536,1);
        l={}; l.max_table_bytes=0; f.requests.clear();
        Reject(attr,Status::LimitExceeded,f.Reader(),l);
        Require(f.requests.empty(),"table cap enforced before I/O");
        Reject(Attribute(type,kMax),Status::LimitExceeded,f.Reader());
        l={}; l.max_file_bytes=kMax;
        Reject(Attribute(type,kMax),Status::LimitExceeded,f.Reader(),l,kMax,0);
        Reject(Attribute(type,1),Status::LimitExceeded,{UINT64_MAX,{}},{},kMax,0);
        // New codecs inherit strict whole-table bounds and 69632 encoded block cap.
        MemoryFork oversized{LzvnResource({Bytes(69633)})};
        Reject(Attribute(type,65536),type==14 ? Status::LimitExceeded : Status::Corrupt,oversized.Reader(),{},kMax,0);
        MemoryFork huge_stored{LzvnResource({Stored(marker,RepeatedPlain(65536))})};
        Expect(Attribute(type,65536),65533,kMax,Hex("464748"),huge_stored.Reader());
        if(type==14)
        {
            // Shared work is not reset at APFS resource boundaries.
            MemoryFork two{LzvnResource({bitmap,bitmap})};
            Bytes scratch(65536); std::uint64_t work=kMax;
            const auto rc=apfsaccess_lzbitmap_decode_exact(scratch.data(),scratch.size(),
                bitmap.data(),bitmap.size(),65536,&work);
            Require(rc==0,"direct bitmap work measurement");
            const auto per_block=kMax-work;
            l={}; l.max_lzbitmap_work_units=2*per_block;
            Expect(Attribute(14,131072),65533,6,Hex("464748414243"),two.Reader(),l);
            --l.max_lzbitmap_work_units;
            Reject(Attribute(14,131072),Status::LimitExceeded,two.Reader(),l,65533,6);
            l={}; l.max_lzbitmap_state_bytes=0;
            Reject(Attribute(14,131072),Status::LimitExceeded,two.Reader(),l,0,1);
            // Full stored ZBM stream overhead is 22 bytes for 64 KiB.
            MemoryFork rawstream{LzvnResource({ZbmStream({ZbmStoredChunk(RepeatedPlain(32768)),
                ZbmStoredChunk(RepeatedPlain(32768))})})};
            Expect(Attribute(14,65536),32764,12,Hex("454647484142434445464748"),rawstream.Reader());
        }
    }
}

// Each rejection checks the caller's bytes, allocation and capacity as well as
// the precise diagnostic, so failure after a selected earlier block is covered.
void RejectReview(const Bytes& attr, Status status, std::string_view detail,
    const ApfsCompressionResourceReader& reader = {},
    std::uint64_t offset = 0, std::uint64_t length = kMax)
{
    Bytes out = Hex("deadbeef00"); const auto before = out;
    const auto* address = out.data(); const auto capacity = out.capacity();
    const auto rc = ApfsCompression::DecodeRange(attr, reader, offset, length, {}, out);
    Require(rc.status == status, detail);
    Require(rc.detail == detail, "review rejection has precise diagnostic");
    Require(out == before && out.data() == address && out.capacity() == capacity,
        "review rejection preserves destination bytes, storage and capacity");
}

void TestReviewMarkerClassification()
{
    // Review's CD hello and 0F hello vectors, plus every excluded marker.
    for (const auto type : {9u, 10u, 13u, 14u})
    {
        const bool raw = type == 9 || type == 10;
        const bool inlined = type == 9 || type == 13;
        const auto detail = raw ? "CompressionStoredMarkerUnsupported" :
            "CompressionLzbitmapRawMarkerUnsupported";
        for (unsigned m = 0; m < 256; ++m)
        {
            if (raw ? m == 0xcc : (m == 0xff || (m & 15) != 15)) continue;
            const auto payload = Stored(static_cast<std::byte>(m), kHelloPlain);
            MemoryFork fork{LzvnResource({payload})};
            const auto attr = Attribute(type, 5, inlined ? payload : Bytes{});
            RejectReview(attr, Status::Unsupported, detail, inlined ? ApfsCompressionResourceReader{} : fork.Reader(), 0, 5);
            if (inlined)
            {
                ApfsCompressionHeader h{44, 55};
                const auto rc = ApfsCompression::Inspect(attr, {}, h);
                Require(rc.status == Status::Unsupported && std::string_view(rc.detail) == detail,
                    "unknown inline marker Inspect classification and diagnostic");
                Require(h.type == 44 && h.uncompressed_size == 55,
                    "unknown inline marker preserves header sentinel");
                RejectReview(attr, Status::Unsupported, detail, {}, 5, 0);
            }
        }
        // A recognized CC/FF with the wrong advertised size remains corrupt.
        const auto payload = Stored(std::byte(raw ? 0xcc : 0xff), kHelloPlain);
        MemoryFork fork{LzvnResource({payload})};
        Reject(Attribute(type, 6, inlined ? payload : Bytes{}), Status::Corrupt,
            inlined ? ApfsCompressionResourceReader{} : fork.Reader());
        if (inlined)
        {
            for (const auto bad : {Attribute(type, 6, payload), Attribute(type, 5)})
            {
                ApfsCompressionHeader h{44, 55};
                const auto rc = ApfsCompression::Inspect(bad, {}, h);
                Require(rc.status == Status::Corrupt && h.type == 44 && h.uncompressed_size == 55,
                    "missing or wrong-size recognized inline payload preserves header");
                Reject(bad, Status::Corrupt);
            }
        }
    }
    for (const auto payload : {"0f", "1f"})
        Reject(Attribute(13, 0, Hex(payload)), Status::Unsupported);
    // Malformed magic and truncated recognized streams are still corruption.
    for (const auto payload : {"", "5a", "5a424d08", "5a424d09", "5a424d09050000000000"})
    {
        Reject(Attribute(13, 8, Hex(payload)), Status::Corrupt);
        MemoryFork fork{LzvnResource({Hex(payload)})};
        Reject(Attribute(14, 8), Status::Corrupt, fork.Reader());
    }
}

void TestReviewRegionConsumption()
{
    // All four streams advertise exactly the eight bytes their chunk emits.
    const std::vector<Bytes> chunks = {
        ZbmChunk(8, RepeatedPlain(8), Hex("01"), {}, {3}),
        ZbmChunk(8, RepeatedPlain(8), {}, Hex("00"), {3}),
        ZbmChunk(8, RepeatedPlain(8), {}, {}, {3,0,0}),
        ZbmChunk(8, RepeatedPlain(9), {}, {}, {3})};
    Require(chunks[0] == Hex("2a000008000017000018000018000041424344454647480103ff00000000000000000000000000000000"),
        "review unused-period chunk is exactly 42 bytes with offsets 23,24,24");
    for (const auto& chunk : chunks)
    {
        const auto stream = ZbmStream({chunk});
        Bytes decoded(8); std::uint64_t work = 4096;
        const auto rc = apfsaccess_lzbitmap_decode_exact(decoded.data(), decoded.size(),
            stream.data(), stream.size(), 8, &work);
        Require(rc == ZBM_NONCANONICAL, "safely parsed unused region is noncanonical");
        Require(decoded == RepeatedPlain(8), "unused-region vector emits ABCDEFGH before refusal");
        MemoryFork fork{LzvnResource({stream})};
        for (const auto range : {std::pair<std::uint64_t,std::uint64_t>{0,8}, {8,0}})
            RejectReview(Attribute(13, 8, stream), Status::Unsupported,
                "CompressionLzbitmapStreamInvalid", {}, range.first, range.second);
        RejectReview(Attribute(14, 8), Status::Unsupported,
            "CompressionLzbitmapStreamInvalid", fork.Reader(), 0, 8);
    }
    // Same advertised EOF, but actual region underflow/history errors are corrupt.
    for (const auto chunk : {ZbmChunk(8, {}, {}, {}, {3}),
        ZbmChunk(8, {}, {}, Hex("ff"), {1}), ZbmChunk(8, RepeatedPlain(8), {}, {}, {0}),
        ZbmChunk(8, {}, {}, {}, {4})})
        Reject(Attribute(13, 8, ZbmStream({chunk})), Status::Corrupt);
}

void TestReviewEncodedCeiling()
{
    const auto stream = ZbmStream(std::vector<Bytes>(1024, ZbmStoredChunk(Bytes(64, std::byte{'A'}))));
    Require(stream.size() == 71690, "fragmented stream is exactly 71690 encoded bytes");
    Bytes plain(65536); std::uint64_t work = ApfsCompressionLimits{}.max_lzbitmap_work_units;
    const auto initial_work = work;
    const auto rc = apfsaccess_lzbitmap_decode_exact(plain.data(), plain.size(),
        stream.data(), stream.size(), plain.size(), &work);
    Require(rc == 0 && plain == Bytes(65536, std::byte{'A'}), "fragmented stream directly decodes to 65536 A bytes");
    Require(initial_work - work == 131136, "fragmented stream consumes exactly 131136 work units");
    MemoryFork fork{LzvnResource({stream})};
    Require(Bytes(fork.bytes.begin(), fork.bytes.begin() + 8) == Hex("0800000012180100") &&
        fork.bytes.size() == 71698, "fragmented resource has absolute table [8,71698]");
    for (const auto range : {std::pair<std::uint64_t,std::uint64_t>{0,1}, {0,0}, {65536,1}})
    {
        fork.requests.clear();
        RejectReview(Attribute(14, 65536), Status::LimitExceeded,
            "CompressionLzbitmapEncodedBlockLimit", fork.Reader(), range.first, range.second);
        Require(fork.requests == std::vector<std::pair<std::uint64_t,std::size_t>>{{0,8}},
            "encoded ceiling validates table and refuses before payload I/O");
    }
    // Later/unselected oversized blocks still trigger the full-table ceiling.
    MemoryFork later{LzvnResource({Stored(std::byte{0xff}, RepeatedPlain(65536)), stream})};
    RejectReview(Attribute(14, 131072), Status::LimitExceeded,
        "CompressionLzbitmapEncodedBlockLimit", later.Reader(), 0, 1);
    // Reversed and out-of-fork interior offsets are structural errors.
    for (const auto middle : {11u, static_cast<unsigned>(later.bytes.size() + 1)})
    {
        auto bad = later; U32(bad.bytes, 4, middle);
        RejectReview(Attribute(14, 131072), Status::Corrupt,
            "CompressionResourceBlockBoundsInvalid", bad.Reader(), kMax, 0);
    }
}

void TestReviewResourceHistoryReset()
{
    const auto first = ZbmStream({ZbmRepeatedChunk(true), ZbmRepeatedChunk(false)});
    const auto borrow = ZbmStream({ZbmChunk(8, {}, {}, {}, {4})});
    MemoryFork fork{LzvnResource({first, borrow})};
    const auto attr = Attribute(14, 65544);
    Expect(attr, 65528, 8, RepeatedPlain(8), fork.Reader());
    for (const auto range : {std::pair<std::uint64_t,std::uint64_t>{65536,8}, {65528,16}})
    {
        fork.requests.clear();
        RejectReview(attr, Status::Corrupt, "CompressionLzbitmapStreamInvalid",
            fork.Reader(), range.first, range.second);
        Require(fork.requests.size() == (range.first == 65536 ? 2 : 3),
            "history reset tested with second block alone and after decoding first block");
    }
}

void TestRemainingCodecReviewRegressions()
{
    auto run = [](auto test, const char* label)
    {
        const auto before = checks; const auto prior_failures = failures; test();
        std::cout << label << ": " << checks - before << " checks; "
            << failures - prior_failures << " failures\n";
    };
    run(TestReviewMarkerClassification, "R1 marker classification");
    run(TestReviewRegionConsumption, "R2 region consumption");
    run(TestReviewEncodedCeiling, "R3 encoded ceiling");
    run(TestReviewResourceHistoryReset, "Resource history reset");
}

void TestBitmapMutationBounds()
{
    const auto stream=ZbmStream({ZbmChunk(32,RepeatedPlain(8),{}, {}, {3,4,4,4})});
    std::uint64_t trials=0;
    for(std::size_t at=0;at<stream.size();++at) for(unsigned byte=0;byte<256;++byte)
    {
        auto encoded=stream; encoded[at]=static_cast<std::byte>(byte);
        Bytes guarded(64,std::byte{0xa5}); std::uint64_t work=4096;
        const auto rc=apfsaccess_lzbitmap_decode_exact(guarded.data()+16,32,
            encoded.data(),encoded.size(),32,&work);
        Require(std::all_of(guarded.begin(),guarded.begin()+16,[](auto b){return b==std::byte{0xa5};}) &&
            std::all_of(guarded.end()-16,guarded.end(),[](auto b){return b==std::byte{0xa5};}),
            "mutated bitmap preserves output canaries");
        Require(work<=4096 && (rc==0 || rc==ZBM_INVAL || rc==ZBM_RANGE || rc==ZBM_LIMIT || rc==ZBM_NONCANONICAL),
            "mutated bitmap bounded work and known status");
        auto attr=Attribute(13,32,encoded); Bytes out=Hex("deadbeef00"); const auto original=out;
        const auto* address=out.data(); const auto capacity=out.capacity();
        const auto result=ApfsCompression::DecodeRange(attr,{},3,17,{},out);
        if(!result) Require(out==original && out.data()==address && out.capacity()==capacity,
            "mutated bitmap failure preserves output allocation");
        else Require(rc==0 && out==Bytes(guarded.begin()+19,guarded.begin()+36),
            "mutated bitmap successful range agrees with full output");
        ++trials;
    }
    std::cout << "LZBITMAP single-byte mutation trials: " << trials << '\n';
}

void TestRemainingCodecs()
{
    TestRemainingCodecReviewRegressions();
    TestRawNine(); TestBitmapInline(); TestRemainingResources(); TestBitmapMutationBounds();
    // A 3 GiB raw logical file is addressed without allocating its contents.
    constexpr std::uint64_t size=3ULL<<30, count=size/65536, table_size=(count+1)*4;
    constexpr std::uint64_t fork_size=table_size+count*65537;
    std::size_t calls=0, blocks=0;
    ApfsCompressionResourceReader reader{fork_size,[&](std::uint64_t at,std::span<std::byte> dest)
    {
        ++calls;
        if(at==0 && dest.size()==table_size)
        {
            Bytes b(table_size);
            for(std::uint64_t i=0;i<=count;++i) U32(b,i*4,static_cast<std::uint32_t>(table_size+i*65537));
            std::copy(b.begin(),b.end(),dest.begin());
        }
        else if(at==table_size+(count-1)*65537 && dest.size()==65537)
        { ++blocks; std::fill(dest.begin(),dest.end(),std::byte{'A'}); dest[0]=std::byte{0xcc}; }
        else { Require(false,"large raw resource touched an unselected block"); return std::size_t{0}; }
        return dest.size();
    }};
    ApfsCompressionLimits l; l.max_output_bytes=1; l.max_decoded_bytes=65536;
    l.max_table_bytes=table_size; l.max_resource_read_bytes=table_size+65537;
    Expect(Attribute(10,size),size-1,kMax,Hex("41"),reader,l);
    Require(calls==2 && blocks==1,"3 GiB raw range reads table and one block only");
    --l.max_decoded_bytes; Reject(Attribute(10,size),Status::LimitExceeded,reader,l,size-1,1);
}
