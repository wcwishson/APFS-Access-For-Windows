#include "ApfsCompression.h"
#include "LzfseDecoderBridgeTests.h"

#include <algorithm>
#include <cstddef>
#include <cstdint>
#include <iostream>
#include <limits>
#include <span>
#include <stdexcept>
#include <string_view>
#include <utility>
#include <vector>

namespace
{
using namespace apfsaccess::rw;
using Bytes = std::vector<std::byte>;
using Status = ApfsCompressionStatus;
constexpr auto kMax = (std::numeric_limits<std::uint64_t>::max)();
int failures = 0;

void Require(bool condition, std::string_view label)
{
    if (!condition) { ++failures; std::cerr << "[FAIL] " << label << '\n'; }
}

Bytes Hex(std::string_view hex)
{
    auto digit = [](char c) -> unsigned
    {
        if (c >= '0' && c <= '9') return static_cast<unsigned>(c - '0');
        if (c >= 'a' && c <= 'f') return static_cast<unsigned>(c - 'a' + 10);
        if (c >= 'A' && c <= 'F') return static_cast<unsigned>(c - 'A' + 10);
        throw std::runtime_error("invalid test hex");
    };
    if (hex.size() % 2 != 0) throw std::runtime_error("odd test hex");
    Bytes result;
    for (std::size_t i = 0; i < hex.size(); i += 2)
        result.push_back(static_cast<std::byte>((digit(hex[i]) << 4) | digit(hex[i + 1])));
    return result;
}

void U32(Bytes& bytes, std::size_t at, std::uint32_t value, bool big = false)
{
    for (unsigned i = 0; i < 4; ++i)
        bytes.at(at + i) = static_cast<std::byte>(value >> (8 * (big ? 3 - i : i)));
}

void U64(Bytes& bytes, std::size_t at, std::uint64_t value)
{
    U32(bytes, at, static_cast<std::uint32_t>(value));
    U32(bytes, at + 4, static_cast<std::uint32_t>(value >> 32));
}

Bytes Attribute(std::uint32_t type, std::uint64_t size, const Bytes& payload = {})
{
    // Literal disk magic from XNU, rather than a codec constant.
    auto bytes = Hex("66706d63000000000000000000000000");
    U32(bytes, 4, type);
    U64(bytes, 8, size);
    bytes.insert(bytes.end(), payload.begin(), payload.end());
    return bytes;
}

// Frozen independently compressed vectors, produced with .NET 10.0.11
// System.IO.Compression.ZLibStream (SmallestSize), not this codec or its vendored
// zlib build. No compressor is linked to this test. Includes fixed Huffman,
// stored DEFLATE, and dynamic Huffman streams with complete RFC 1950 checksums.
const Bytes kHello = Hex("78DACB48CDC9C90700062C0215");
const Bytes kHelloPlain = Hex("68656c6c6f");
const Bytes kBinary = Hex(
    "78DA010001FFFE000102030405060708090A0B0C0D0E0F101112131415161718191A1B1C1D1E1F"
    "202122232425262728292A2B2C2D2E2F303132333435363738393A3B3C3D3E3F"
    "404142434445464748494A4B4C4D4E4F505152535455565758595A5B5C5D5E5F"
    "606162636465666768696A6B6C6D6E6F707172737475767778797A7B7C7D7E7F"
    "808182838485868788898A8B8C8D8E8F909192939495969798999A9B9C9D9E9F"
    "A0A1A2A3A4A5A6A7A8A9AAABACADAEAFB0B1B2B3B4B5B6B7B8B9BABBBCBDBEBF"
    "C0C1C2C3C4C5C6C7C8C9CACBCCCDCECFD0D1D2D3D4D5D6D7D8D9DADBDCDDDEDF"
    "E0E1E2E3E4E5E6E7E8E9EAEBECEDEEEFF0F1F2F3F4F5F6F7F8F9FAFBFCFDFEFFADF67F81");
const Bytes kA64k = Hex(
    "78DAEDC181000000008020B6FDA516A90A0000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000006A1E8703D0");
const Bytes kB64k = Hex(
    "78DAEDC181000000008020B7FDA116A90A0000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000006A1EFF03DF");

Bytes BinaryPlain()
{
    Bytes result(256);
    for (unsigned i = 0; i != 256; ++i) result[i] = static_cast<std::byte>(i);
    return result;
}

struct MemoryFork
{
    Bytes bytes;
    std::vector<std::pair<std::uint64_t, std::size_t>> requests;
    std::size_t fail_call = 0; // 1-based; writes scratch then returns short.
    bool throw_on_failure = false;

    ApfsCompressionResourceReader Reader()
    {
        return {bytes.size(), [this](std::uint64_t at, std::span<std::byte> target)
        {
            requests.emplace_back(at, target.size());
            Require(at <= bytes.size() && target.size() <= bytes.size() - at,
                "callback request stays inside fork");
            if (at > bytes.size() || target.size() > bytes.size() - at) return std::size_t{0};
            std::copy_n(bytes.begin() + static_cast<std::size_t>(at), target.size(), target.begin());
            if (requests.size() == fail_call)
            {
                if (throw_on_failure) throw std::runtime_error("external reader failure");
                return target.size() - 1;
            }
            return target.size();
        }};
    }
};

Bytes Resource(const std::vector<Bytes>& blocks)
{
    // Synthetic ordinary AFSC layout: resource data at 0x100; payload count at
    // 0x104; offsets relative to that count. Framing is independent of codec API.
    const auto table_size = 4 + blocks.size() * 8;
    Bytes bytes(0x104 + table_size);
    U32(bytes, 0, 0x100, true);
    U32(bytes, 12, 50, true);
    U32(bytes, 0x104, static_cast<std::uint32_t>(blocks.size()));
    for (std::size_t i = 0; i < blocks.size(); ++i)
    {
        U32(bytes, 0x108 + i * 8, static_cast<std::uint32_t>(bytes.size() - 0x104));
        U32(bytes, 0x10c + i * 8, static_cast<std::uint32_t>(blocks[i].size()));
        bytes.insert(bytes.end(), blocks[i].begin(), blocks[i].end());
    }
    U32(bytes, 4, static_cast<std::uint32_t>(bytes.size()), true);
    U32(bytes, 8, static_cast<std::uint32_t>(bytes.size() - 0x100), true);
    U32(bytes, 0x100, static_cast<std::uint32_t>(bytes.size() - 0x104), true);
    // Resource map/trailer field values documented by afsctool's writer.
    const auto trailer = Hex(
        "000000000000000000000000000000000000000000000000"
        "001c003200000000636d70660000000a0001ffff000000000000");
    Require(trailer.size() == 50, "fixture resource trailer is 50 bytes");
    bytes.insert(bytes.end(), trailer.begin(), trailer.end());
    return bytes;
}

void Expect(const Bytes& attr, std::uint64_t offset, std::uint64_t length,
    const Bytes& expected, const ApfsCompressionResourceReader& reader = {},
    const ApfsCompressionLimits& limits = {})
{
    Bytes out = Hex("deadbeef00");
    const auto rc = ApfsCompression::DecodeRange(attr, reader, offset, length, limits, out);
    Require(static_cast<bool>(rc), rc.detail);
    Require(out == expected, "decoded bytes match independent expected data");
}

void Reject(const Bytes& attr, Status status, const ApfsCompressionResourceReader& reader = {},
    const ApfsCompressionLimits& limits = {}, std::uint64_t offset = 0, std::uint64_t length = kMax)
{
    Bytes out = Hex("deadbeef00");
    const auto before = out;
    const auto* address = out.data();
    const auto capacity = out.capacity();
    const auto rc = ApfsCompression::DecodeRange(attr, reader, offset, length, limits, out);
    Require(rc.status == status, rc.detail);
    Require(rc.detail[0] != '\0', "failure includes static diagnostic");
    Require(out == before && out.data() == address && out.capacity() == capacity,
        "failure leaves destination bytes, storage and capacity untouched");
}

void TestHeaderAndRaw()
{
    const auto data = Hex("00ff8041004243");
    const auto attr = Attribute(1, data.size(), data);
    Expect(attr, 0, kMax, data);
    Expect(attr, 1, 4, Hex("ff804100"));
    Expect(attr, 5, kMax, Hex("4243"));
    Expect(attr, data.size(), 12, {});
    Expect(attr, kMax, kMax, {});
    Expect(attr, 0, 0, {});
    Expect(Attribute(1, 0), 0, kMax, {});
    for (std::size_t i = 0; i < 16; ++i)
        Reject(Bytes(attr.begin(), attr.begin() + i), Status::Corrupt);
    auto bad = attr;
    bad[0] = std::byte{0x63};
    Reject(bad, Status::Corrupt);
    bad = attr;
    std::reverse(bad.begin(), bad.begin() + 4);
    Reject(bad, Status::Corrupt);
    Reject(Attribute(1, 8, data), Status::Corrupt);
    Reject(Attribute(1, 6, data), Status::Corrupt);
    Reject(Attribute(4, 7, data), Status::Corrupt);
    for (const auto type : {0u, 2u, 5u, 6u, 9u, 10u, 13u, 14u,
        0x80000001u, 0x80000002u, 0xffffffffu})
    {
        Reject(Attribute(type, kMax, kHello), Status::Unsupported);
        ApfsCompressionHeader header{77, 88};
        const auto rc = ApfsCompression::Inspect(Attribute(type, 5, kHello), {}, header);
        Require(rc.status == Status::Unsupported && header.type == 77 && header.uncompressed_size == 88,
            "unsupported Inspect preserves header and does not sniff payload");
    }
    ApfsCompressionHeader header{77, 88};
    auto rc = ApfsCompression::Inspect(Attribute(4, 0x100000002ULL), {}, header);
    Require(static_cast<bool>(rc) && header.type == 4 && header.uncompressed_size == 0x100000002ULL,
        "Inspect reads all 64 logical size bits little endian");
    rc = ApfsCompression::Inspect(bad, {}, header);
    Require(rc.status == Status::Corrupt && header.uncompressed_size == 0x100000002ULL,
        "corrupt Inspect preserves header");
    auto alias = attr;
    rc = ApfsCompression::DecodeRange(alias, {}, 1, 3, {}, alias);
    Require(static_cast<bool>(rc) && alias == Hex("ff8041"), "raw input may alias output");
}

void TestZlibInline()
{
    const auto attr = Attribute(3, 5, kHello);
    Expect(attr, 0, kMax, kHelloPlain);
    Expect(attr, 1, 3, Hex("656c6c"));
    Expect(attr, 4, kMax, Hex("6f"));
    Expect(attr, 5, 10, {});
    Expect(attr, kMax, kMax, {});
    Expect(attr, 0, 0, {});
    Expect(Attribute(3, 256, kBinary), 0, kMax, BinaryPlain());
    Expect(Attribute(3, 256, kBinary), 127, 4, Hex("7f808182"));
    Expect(Attribute(3, 65536, kA64k), 65530, kMax, Bytes(6, std::byte{0x41}));
    // RFC 1950 empty stream: empty final fixed-Huffman block + Adler-32("") = 1.
    Expect(Attribute(3, 0, Hex("789c030000000001")), 0, kMax, {});
    for (const auto marker : {0x0f, 0x1f, 0xff})
    {
        auto raw = Hex("0000ff80410042");
        raw[0] = static_cast<std::byte>(marker);
        Expect(Attribute(3, 6, raw), 0, kMax, Hex("00ff80410042"));
    }
    Expect(Attribute(3, 0, Hex("ff")), 0, kMax, {});
    Reject(Attribute(3, 1, Hex("ff")), Status::Corrupt);
    for (std::size_t i = 0; i < kHello.size(); ++i)
        Reject(Attribute(3, 5, Bytes(kHello.begin(), kHello.begin() + i)), Status::Corrupt);
    for (const auto size : {0ULL, 4ULL, 6ULL}) Reject(Attribute(3, size, kHello), Status::Corrupt);
    auto bad = kHello;
    bad.back() ^= std::byte{1};
    Reject(Attribute(3, 5, bad), Status::Corrupt);
    Reject(Attribute(3, 5, bad), Status::Corrupt, {}, {}, kMax, 0);
    bad = kHello;
    bad.push_back(std::byte{0});
    Reject(Attribute(3, 5, bad), Status::Corrupt);
    bad.insert(bad.end(), kHello.begin(), kHello.end());
    Reject(Attribute(3, 10, bad), Status::Corrupt);
    Reject(Attribute(3, 5, Bytes(kHello.begin() + 2, kHello.end() - 4)), Status::Corrupt);
    Reject(Attribute(3, 0, Hex("78bb00000001030000000001")), Status::Corrupt); // Dictionary required.
    Reject(Attribute(3, 5, Hex("1f8b0800000000000000")), Status::Corrupt); // No gzip inference.
    Reject(Attribute(3, 5, Hex("6276783200000000000000")), Status::Corrupt); // No LZFSE inference.
    Reject(Attribute(3, 1, kA64k), Status::Corrupt); // Bomb: 65536 output with advertised size 1.
    auto alias = attr;
    auto rc = ApfsCompression::DecodeRange(alias, {}, 1, 3, {}, alias);
    Require(static_cast<bool>(rc) && alias == Hex("656c6c"), "compressed input may alias output");
    alias = Attribute(3, 4, kHello);
    const auto before = alias;
    rc = ApfsCompression::DecodeRange(alias, {}, 0, kMax, {}, alias);
    Require(rc.status == Status::Corrupt && alias == before, "alias failure preserves complete attribute");
}

void TestLzvnInlineKnownBytes()
{
    // Hand-assembled fixed bytes from Apple's documented opcode layouts in
    // lzfse e634ca58b4821d9f3d560cdc6df5dec02ffc93fd src/lzvn_decode_base.c.
    // Expected content is literal and independent of decoder/encoder execution.
    // e5 = five literals; 06 + seven zeroes = canonical eight-byte EOS.
    const auto hello = Hex("e568656c6c6f0600000000000000");
    const auto attr = Attribute(7, 5, hello);
    Expect(Hex("66706d63070000000500000000000000e568656c6c6f0600000000000000"),
        0, kMax, Hex("68656c6c6f")); // Literal complete decmpfs attribute.
    Expect(attr, 0, kMax, Hex("68656c6c6f"));
    Expect(attr, 1, 3, Hex("656c6c"));
    Expect(attr, 4, kMax, Hex("6f"));
    Expect(attr, 5, kMax, {});
    Expect(attr, kMax, kMax, {});
    Expect(attr, 0, 0, {});
    // Small distance, overlapping match: literal abc, M=6, D=3.
    Expect(Attribute(7, 9, Hex("e361626318030600000000000000")), 0, kMax,
        Hex("616263616263616263"));
    // Seed D=3 with M=3, then match-only M=3 reuses the established distance.
    Expect(Attribute(7, 9, Hex("e36162630003f30600000000000000")), 2, 6,
        Hex("636162636162"));
    // Large distance: 07 0800 encodes M=3, D=8 (little endian).
    Expect(Attribute(7, 11, Hex("e861626364656667680708000600000000000000")), 0, kMax,
        Hex("6162636465666768616263"));
    // Medium distance: a0 1c00 encodes M=3, D=7.
    Expect(Attribute(7, 11, Hex("e86162636465666768a01c000600000000000000")), 0, kMax,
        Hex("6162636465666768626364"));
    // Literal+match with previous distance: L=1 ('X'), M=3, D=3.
    Expect(Attribute(7, 10, Hex("e3616263000346580600000000000000")), 0, kMax,
        Hex("61626361626358626358"));
    // Large literal, including zero/high-bit values and embedded 0x06 data.
    Expect(Attribute(7, 16, Hex("e00000010203040506070809aabbccddeeff0600000000000000")),
        0, kMax, Hex("00010203040506070809aabbccddeeff"));
    // D=1 overlapping run: literal A, M=3, then large match M=16.
    Expect(Attribute(7, 20, Hex("400141f0000600000000000000")), 0, kMax,
        Hex("4141414141414141414141414141414141414141"));
    // NOP then EOS is empty compressed data; bare 06 is empty raw data.
    Expect(Attribute(7, 0, Hex("0e0600000000000000")), 0, kMax, {});
    Expect(Attribute(7, 0, Hex("06")), 0, kMax, {});
    Expect(Attribute(7, 5, Hex("0668656c6c6f")), 0, kMax, kHelloPlain);
    Expect(Attribute(7, 5, Hex("0668656c6c6f")), 1, 3, Hex("656c6c"));
    Expect(Attribute(7, 7, Hex("0600000000000000")), 0, kMax, Bytes(7));
    auto alias = attr;
    const auto rc = ApfsCompression::DecodeRange(alias, {}, 1, 3, {}, alias);
    Require(static_cast<bool>(rc) && alias == Hex("656c6c"), "LZVN input may alias output");
    ApfsCompressionHeader header{99, 101};
    const auto inspected = ApfsCompression::Inspect(attr, {}, header);
    Require(static_cast<bool>(inspected) && header.type == 7 && header.uncompressed_size == 5,
        "Inspect admits bounded type 7 compressed framing");
}

void TestLzvnInlineRefusals()
{
    const auto hello = Hex("e568656c6c6f0600000000000000");
    const auto attr = Attribute(7, 5, hello);
    for (std::size_t cut = 0; cut < hello.size(); ++cut)
        Reject(Attribute(7, 5, Bytes(hello.begin(), hello.begin() + cut)), Status::Corrupt);
    for (const auto size : {0ULL, 1ULL, 4ULL, 6ULL})
        Reject(Attribute(7, size, hello), Status::Corrupt);
    // Exact decoded size alone is insufficient: EOS is absent or partial.
    Reject(Attribute(7, 5, Hex("e568656c6c6f0e")), Status::Corrupt);
    Reject(Attribute(7, 5, Hex("e568656c6c6f06")), Status::Corrupt, {}, {}, kMax, 0);
    auto trailing = hello;
    trailing.push_back(std::byte{0});
    Reject(Attribute(7, 5, trailing), Status::Corrupt);
    trailing = hello;
    trailing.insert(trailing.end(), hello.begin(), hello.end());
    Reject(Attribute(7, 10, trailing), Status::Corrupt);
    // Apple decoder ignores EOS's seven operand bytes; this slice admits only
    // the canonical zero operands written by Apple's encoder.
    for (std::size_t i = hello.size() - 7; i < hello.size(); ++i)
    {
        auto noncanonical = hello;
        noncanonical[i] = std::byte{1};
        Reject(Attribute(7, 5, noncanonical), Status::Unsupported);
    }
    for (const auto bad : {
        "1e0600000000000000",                 // Undefined opcode.
        "00000600000000000000",               // D=0.
        "00010600000000000000",               // D=1 before any output.
        "e14100020600000000000000",           // D=2 with only one byte history.
        "e14107ffff0600000000000000",         // D=65535 beyond history.
        "f10600000000000000",                 // Match-only with no previous D.
        "f0000600000000000000",               // Large match with no previous D.
        "e141f10600000000000000",             // Literals do not establish D.
        "46410600000000000000",               // Previous-distance opcode before D.
        "e361626300030003f0060600000000000000" // Overlong output via repeated match.
        })
        Reject(Attribute(7, 5, Hex(bad)), Status::Corrupt);
    // Exact-size regressions for upstream's match-only D=0 gap: these would
    // otherwise reach EOS with the advertised size and fabricated scratch data.
    Reject(Attribute(7, 1, Hex("f10600000000000000")), Status::Corrupt);
    Reject(Attribute(7, 16, Hex("f0000600000000000000")), Status::Corrupt);
    Reject(Attribute(7, 2, Hex("e141f10600000000000000")), Status::Corrupt);
    Reject(Attribute(7, 4, Hex("46410600000000000000")), Status::Corrupt);
    Reject(Attribute(7, 1, Hex("400141f0000600000000000000")), Status::Corrupt);
    // Never apply the zlib raw-marker rule to an LZVN opcode.
    for (const auto bad : {"ff68656c6c6f", "0f68656c6c6f", "1f68656c6c6f"})
        Reject(Attribute(7, 5, Hex(bad)), Status::Corrupt);
    Reject(Attribute(7, 5, kHello), Status::Corrupt); // No zlib sniffing.
    Reject(Attribute(7, 5, Hex("6276786e050000000e000000e568656c6c6f0600000000000000")),
        Status::Corrupt); // No bvxn container inference.
    for (const auto raw : {"06", "0668656c6c6f", "0600000000000000"})
    {
        const auto invalid_size = Hex(raw).size(); // One more than the raw payload.
        Reject(Attribute(7, invalid_size, Hex(raw)), Status::Corrupt);
        Reject(Attribute(7, invalid_size, Hex(raw)), Status::Corrupt, {}, {}, kMax, 0);
        ApfsCompressionHeader header{99, 101};
        const auto rc = ApfsCompression::Inspect(Attribute(7, invalid_size, Hex(raw)), {}, header);
        Require(rc.status == Status::Corrupt && header.type == 99 && header.uncompressed_size == 101,
            "invalid type 7 raw framing preserves Inspect header");
    }
    auto alias = Attribute(7, 4, hello);
    const auto before = alias;
    const auto* address = alias.data();
    const auto capacity = alias.capacity();
    const auto rc = ApfsCompression::DecodeRange(alias, {}, 0, kMax, {}, alias);
    Require(rc.status == Status::Corrupt && alias == before && alias.data() == address &&
        alias.capacity() == capacity, "LZVN alias failure preserves bytes and storage");
    std::size_t calls = 0;
    ApfsCompressionResourceReader reader{0, [&calls](std::uint64_t, std::span<std::byte>) -> std::size_t
        { ++calls; throw std::runtime_error("inline must not read resource fork"); }};
    Reject(attr, Status::Corrupt, reader);
    Reject(attr, Status::Corrupt, reader, {}, kMax, 0);
    Reject(attr, Status::Corrupt, ApfsCompressionResourceReader{1, {}});
    Require(calls == 0, "type 7 rejects resource-reader misuse without I/O");
}

void TestLzvnInlineLimits()
{
    const auto attr = Attribute(7, 5, Hex("e568656c6c6f0600000000000000"));
    ApfsCompressionLimits limits;
    limits.max_output_bytes = 4;
    Reject(attr, Status::LimitExceeded, {}, limits);
    Expect(attr, 4, kMax, Hex("6f"), {}, limits);
    limits = {};
    limits.max_decmpfs_bytes = attr.size() - 1;
    Reject(attr, Status::LimitExceeded, {}, limits);
    limits = {};
    limits.max_file_bytes = 4;
    Reject(attr, Status::LimitExceeded, {}, limits);
    limits = {};
    limits.max_inline_decoded_bytes = 4;
    Reject(attr, Status::LimitExceeded, {}, limits);
    limits = {};
    limits.max_decoded_bytes = 4;
    Reject(attr, Status::LimitExceeded, {}, limits, 1, 1);
    Reject(attr, Status::LimitExceeded, {}, limits, kMax, 0);
    limits.max_decoded_bytes = 5;
    limits.max_inline_decoded_bytes = 5;
    limits.max_decmpfs_bytes = attr.size();
    limits.max_output_bytes = 5;
    limits.max_zlib_allocation_bytes = 0; // LZVN has no zlib allocation dependency.
    limits.max_resource_read_bytes = 0;
    Expect(attr, 0, kMax, Hex("68656c6c6f"), {}, limits);
    limits = {};
    limits.max_file_bytes = kMax;
    limits.max_inline_decoded_bytes = kMax;
    limits.max_decoded_bytes = kMax;
    Reject(Attribute(7, kMax, Hex("0e0600000000000000")), Status::LimitExceeded,
        {}, limits, kMax, 0); // Guard-size arithmetic is checked even for empty reads.
}

Bytes LzvnResource(const std::vector<Bytes>& blocks)
{
    Bytes bytes((blocks.size() + 1) * 4);
    U32(bytes, 0, static_cast<std::uint32_t>(bytes.size()));
    for (std::size_t i = 0; i < blocks.size(); ++i)
    {
        bytes.insert(bytes.end(), blocks[i].begin(), blocks[i].end());
        U32(bytes, (i + 1) * 4, static_cast<std::uint32_t>(bytes.size()));
    }
    return bytes;
}

void TestLzvnResourceRangesAndRefusals()
{
    const auto hello = Hex("e568656c6c6f0600000000000000");
    Bytes raw(65537, std::byte{0x41});
    raw[0] = std::byte{6};
    MemoryFork fork{LzvnResource({raw, hello})};
    const auto original = fork.bytes;
    const auto attr = Attribute(8, 65541);
    Expect(attr, 65533, 8, Hex("41414168656c6c6f"), fork.Reader());
    fork.requests.clear();
    Expect(attr, 65538, kMax, Hex("6c6c6f"), fork.Reader());
    Require(fork.requests.size() == 2 && fork.requests[0] == std::pair<std::uint64_t, std::size_t>{0, 12} &&
        fork.requests[1] == std::pair<std::uint64_t, std::size_t>{65549, hello.size()},
        "type8 selected range reads only the table and selected compressed block");
    fork.requests.clear();
    Expect(attr, kMax, 0, {}, fork.Reader());
    Require(fork.requests.size() == 1, "type8 empty range still validates entire table");
    MemoryFork empty{Hex("04000000")};
    Expect(Attribute(8, 0), 0, kMax, {}, empty.Reader());
    // Independent literal table vector for one five-byte raw block.
    MemoryFork raw_hello{Hex("080000000e0000000668656c6c6f")};
    Expect(Attribute(8, 5), 0, kMax, kHelloPlain, raw_hello.Reader());
    MemoryFork compressed_hello{Hex("0800000016000000e568656c6c6f0600000000000000")};
    Expect(Attribute(8, 5), 0, kMax, kHelloPlain, compressed_hello.Reader());
    for (const auto bad : {"", "040000", "00000000", "0800000008000000",
        "070000000e0000000668656c6c6f", "080000000d0000000668656c6c6f",
        "080000000f0000000668656c6c6f", "080000000e0000000768656c6c6f"})
    {
        MemoryFork broken{Hex(bad)};
        Reject(Attribute(8, 5), Status::Corrupt, broken.Reader());
    }
    for (const auto value : {0u, 12u, 11u, 65550u, 0xffffffffu})
    {
        fork.bytes = original;
        U32(fork.bytes, 4, value);
        Reject(attr, Status::Corrupt, fork.Reader(), {}, kMax, 0);
    }
    fork.bytes = original;
    fork.bytes.resize(fork.bytes.size() - 7); // Truncated EOS in the second block.
    U32(fork.bytes, 8, static_cast<std::uint32_t>(fork.bytes.size()));
    Reject(attr, Status::Corrupt, fork.Reader()); // Must not publish the valid first block.
    fork.bytes = original;
    fork.bytes[12] = std::byte{0xff}; // Wrong LZVN raw escape, not zlib raw.
    Reject(attr, Status::Corrupt, fork.Reader());
    fork.bytes = original;
    Reject(Attribute(8, 65542), Status::Corrupt, fork.Reader());
    Reject(Attribute(8, 5, Hex("00")), Status::Corrupt, fork.Reader());
    for (const bool throwing : {false, true})
    {
        fork.bytes = original;
        fork.requests.clear();
        fork.fail_call = 3;
        fork.throw_on_failure = throwing;
        Reject(attr, Status::ReadError, fork.Reader());
    }
    fork.fail_call = 0;
    auto limits = ApfsCompressionLimits{};
    limits.max_table_bytes = 11;
    Reject(attr, Status::LimitExceeded, fork.Reader(), limits);
    limits = {};
    limits.max_resource_read_bytes = 12 + hello.size() - 1;
    Reject(attr, Status::LimitExceeded, fork.Reader(), limits, 65536, 1);
    limits.max_resource_read_bytes++;
    limits.max_decoded_bytes = 5;
    Expect(attr, 65536, 1, Hex("68"), fork.Reader(), limits);
    limits.max_decoded_bytes = 4;
    Reject(attr, Status::LimitExceeded, fork.Reader(), limits, 65536, 1);
    limits = {};
    limits.max_output_bytes = 7;
    Reject(attr, Status::LimitExceeded, fork.Reader(), limits, 65533, 8);
    limits = {};
    limits.max_resource_bytes = original.size() - 1;
    Reject(attr, Status::LimitExceeded, fork.Reader(), limits);
}

void TestLzvnLargeLogicalRange()
{
    // Literal A plus M=3,D=1; then 241 matches of271 and one match of221.
    auto full_block = Hex("400141");
    for (unsigned i = 0; i < 241; ++i) { full_block.push_back(std::byte{0xf0}); full_block.push_back(std::byte{0xff}); }
    const auto ending = Hex("f0cd0600000000000000");
    full_block.insert(full_block.end(), ending.begin(), ending.end());
    Expect(Attribute(7, 65536, full_block), 65530, kMax, Bytes(6, std::byte{0x41}));
    constexpr std::uint64_t full_blocks = (3ULL << 30) / 65536;
    constexpr std::uint64_t logical_size = (3ULL << 30) + 5;
    const auto final_block = Hex("e568656c6c6f0600000000000000");
    Bytes table(static_cast<std::size_t>((full_blocks + 2) * 4));
    for (std::uint64_t i = 0; i <= full_blocks; ++i)
        U32(table, static_cast<std::size_t>(i * 4), static_cast<std::uint32_t>(table.size() + i * full_block.size()));
    const auto final_offset = table.size() + full_blocks * full_block.size();
    const auto resource_size = final_offset + final_block.size();
    U32(table, table.size() - 4, static_cast<std::uint32_t>(resource_size));
    std::size_t calls = 0;
    ApfsCompressionResourceReader reader{resource_size, [&](std::uint64_t at, std::span<std::byte> out) {
        ++calls;
        const auto* source = at == 0 && out.size() == table.size() ? &table :
            at == final_offset && out.size() == final_block.size() ? &final_block : nullptr;
        if (!source) { Require(false, "large type8 reads no unrequested block"); return std::size_t{0}; }
        std::copy(source->begin(), source->end(), out.begin());
        return out.size();
    }};
    ApfsCompressionLimits limits;
    limits.max_output_bytes = 1;
    limits.max_decoded_bytes = 5;
    limits.max_resource_read_bytes = table.size() + final_block.size();
    Expect(Attribute(8, logical_size), logical_size - 1, kMax, Hex("6f"), reader, limits);
    Require(calls == 2, "3GiB type8 range decodes only the final five bytes");
    U32(table, 4, 0); // An unselected block cannot hide invalid table ordering.
    Reject(Attribute(8, logical_size), Status::Corrupt, reader, limits, logical_size - 1, 1);
    const auto previous_calls = calls;
    Reject(Attribute(8, logical_size), Status::LimitExceeded,
        ApfsCompressionResourceReader{1ULL << 32, reader.read});
    Require(calls == previous_calls, "type8 32-bit offset limit refuses before I/O");
}

void TestLimits()
{
    const auto attr = Attribute(3, 5, kHello);
    ApfsCompressionLimits limits;
    limits.max_output_bytes = 4;
    Reject(attr, Status::LimitExceeded, {}, limits);
    Expect(attr, 4, kMax, Hex("6f"), {}, limits); // Limit is on clipped output.
    limits = {};
    limits.max_decmpfs_bytes = attr.size() - 1;
    Reject(attr, Status::LimitExceeded, {}, limits);
    limits = {};
    limits.max_file_bytes = 4;
    Reject(attr, Status::LimitExceeded, {}, limits);
    limits = {};
    limits.max_inline_decoded_bytes = 4;
    Reject(attr, Status::LimitExceeded, {}, limits);
    limits = {};
    limits.max_decoded_bytes = 4;
    Reject(attr, Status::LimitExceeded, {}, limits, 1, 1); // Full inline stream counts.
    Expect(Attribute(1, 5, kHelloPlain), 1, 1, Hex("65"), {}, limits);
    Reject(Attribute(1, 5, kHelloPlain), Status::LimitExceeded, {}, limits);
    limits = {};
    limits.max_zlib_allocation_bytes = 0;
    Reject(attr, Status::LimitExceeded, {}, limits);
    Reject(Attribute(3, kMax, kHello), Status::LimitExceeded);
    Reject(Attribute(4, kMax), Status::LimitExceeded);
    ApfsCompressionHeader header{99, 101};
    const auto rc = ApfsCompression::Inspect(Attribute(3, kMax, kHello), {}, header);
    Require(rc.status == Status::LimitExceeded && header.type == 99 && header.uncompressed_size == 101,
        "limit failure preserves Inspect header");
}

void TestResourceRanges()
{
    // A literal, independently laid-out one-block fork, without the Resource()
    // fixture builder: BE data offset 16/map offset 45/data size 29/map size 50;
    // BE payload size 25, LE count 1, LE relative offset 12/encoded size 13.
    MemoryFork golden{Hex(
        "000000100000002d0000001d00000032"
        "00000019010000000c0000000d000000"
        "78dacb48cdc9c90700062c0215"
        "000000000000000000000000000000000000000000000000"
        "001c003200000000636d70660000000a0001ffff000000000000")};
    Expect(Attribute(4, 5), 0, kMax, kHelloPlain, golden.Reader());
    Expect(Attribute(4, 5), 1, 3, Hex("656c6c"), golden.Reader());
    MemoryFork fork{Resource({kA64k, kB64k, kBinary})};
    const auto attr = Attribute(4, 131328);
    const auto reader = fork.Reader();
    Expect(attr, 65534, 4, Hex("41414242"), reader);
    Require(fork.requests.size() == 5, "cross-block read fetches header, prefix, table and two blocks");
    if (fork.requests.size() == 5)
    {
        Require(fork.requests[3].second == kA64k.size() && fork.requests[4].second == kB64k.size(),
            "cross-block read fetches exact compressed block sizes");
    }
    fork.requests.clear();
    Expect(attr, 131199, 4, Hex("7f808182"), reader);
    Require(fork.requests.size() == 4 && fork.requests.back().second == kBinary.size(),
        "tail-only read fetches exactly one compressed block");
    Expect(attr, 131326, kMax, Hex("feff"), reader);
    fork.requests.clear();
    Expect(attr, 131328, 5, {}, reader);
    Require(fork.requests.size() == 3, "EOF validates table without reading payload blocks");
    Expect(attr, kMax, kMax, {}, reader);
    Expect(attr, 0, 0, {}, reader);
    Bytes all(65536, std::byte{0x41});
    all.insert(all.end(), 65536, std::byte{0x42});
    const auto binary = BinaryPlain();
    all.insert(all.end(), binary.begin(), binary.end());
    Expect(attr, 0, kMax, all, reader);
    // Same-sized compressed blocks can be physically out of logical order.
    auto unordered = Resource({kA64k, kB64k});
    U32(unordered, 0x108, static_cast<std::uint32_t>(20 + kA64k.size()));
    U32(unordered, 0x110, 20);
    MemoryFork reordered{unordered};
    Expect(Attribute(4, 131072), 65534, 4, Hex("42424141"), reordered.Reader());
    auto raw = Bytes(65537, std::byte{0x80});
    raw[0] = std::byte{0xff};
    MemoryFork raw_fork{Resource({raw, Hex("0f00ff00")})};
    Expect(Attribute(4, 65539), 65535, kMax, Hex("8000ff00"), raw_fork.Reader());
    MemoryFork empty{Resource({})};
    Expect(Attribute(4, 0), 0, kMax, {}, empty.Reader());
    MemoryFork wrong_tail{Resource({kA64k, kHello})};
    Reject(Attribute(4, 65542), Status::Corrupt, wrong_tail.Reader(), {}, 65536, 1);
}

void TestResourceCorruptionAndFailures()
{
    const auto attr = Attribute(4, 65541);
    const auto good = Resource({kA64k, kHello});
    auto corrupt = [&](std::size_t at, std::uint32_t value, bool big = false)
    {
        MemoryFork fork{good};
        U32(fork.bytes, at, value, big);
        Reject(attr, Status::Corrupt, fork.Reader());
    };
    corrupt(0, 0, true); // Data aliases header.
    corrupt(0, 0xfffffff0u, true);
    corrupt(4, 0x100, true); // Map overlaps data.
    corrupt(4, 0xfffffff0u, true);
    corrupt(8, 0xffffffffu, true); // Section length overflow/out of fork.
    corrupt(8, 4, true);
    corrupt(12, 0, true);
    corrupt(12, 0xffffffffu, true);
    corrupt(0x100, 0xffffffffu, true); // Payload length inconsistent.
    corrupt(0x104, 1); // Logical size requires two blocks.
    corrupt(0x104, 0xffffffffu);
    corrupt(0x108, 19); // Block aliases table.
    corrupt(0x108, 0xfffffff0u); // End must not wrap a 32-bit offset.
    corrupt(0x10c, 0);
    corrupt(0x10c, 65538);
    corrupt(0x110, 20); // Second block overlaps first (outside requested range too).
    corrupt(0x114, 0xffffffffu);
    MemoryFork overlap{good};
    U32(overlap.bytes, 0x110, 20);
    Reject(attr, Status::Corrupt, overlap.Reader(), {}, 0, 1);
    Reject(attr, Status::Corrupt, overlap.Reader(), {}, kMax, 0);
    for (const auto cut : {std::size_t{0}, std::size_t{15}, std::size_t{260}, good.size() - 1})
    {
        MemoryFork truncated{Bytes(good.begin(), good.begin() + cut)};
        Reject(attr, Status::Corrupt, truncated.Reader());
    }
    MemoryFork bad_stream{Resource({kA64k, Hex("78da00")})};
    Reject(attr, Status::Corrupt, bad_stream.Reader());
    MemoryFork bomb{Resource({kA64k})};
    Reject(Attribute(4, 1), Status::Corrupt, bomb.Reader());
    Reject(attr, Status::ReadError, ApfsCompressionResourceReader{good.size(), {}});
    for (std::size_t call = 1; call <= 5; ++call)
    {
        MemoryFork failure{good};
        failure.fail_call = call;
        Reject(attr, Status::ReadError, failure.Reader());
    }
    MemoryFork exception{good};
    exception.fail_call = 5; // First block already decoded into private staging.
    exception.throw_on_failure = true;
    Reject(attr, Status::ReadError, exception.Reader());
    ApfsCompressionResourceReader overreport{good.size(), [](std::uint64_t, std::span<std::byte> dst)
        { return dst.size() + 1; }};
    Reject(attr, Status::ReadError, overreport);
    MemoryFork bounded{good};
    ApfsCompressionLimits limits;
    limits.max_resource_bytes = good.size() - 1;
    Reject(attr, Status::LimitExceeded, bounded.Reader(), limits);
    Require(bounded.requests.empty(), "resource size limit precedes external I/O");
    limits = {};
    limits.max_table_bytes = 19;
    Reject(attr, Status::LimitExceeded, bounded.Reader(), limits);
    limits = {};
    limits.max_resource_read_bytes = 16 + 8 + 16 + kA64k.size();
    Reject(attr, Status::LimitExceeded, bounded.Reader(), limits); // Failure after first output block.
    limits = {};
    limits.max_decoded_bytes = 65535;
    Reject(attr, Status::LimitExceeded, bounded.Reader(), limits, 0, 1);
    limits = {};
    limits.max_decoded_bytes = 5;
    Expect(attr, 65536, 1, Hex("68"), bounded.Reader(), limits);
}

void TestLargeLogicalFileRange()
{
    // 3 GiB logical file, only about 4 MiB compressed. Do not materialize either
    // fork or plaintext: callback synthesizes a real table and serves one frozen
    // compressed block. Tight read/work budgets detect whole-file decompression.
    constexpr std::uint32_t count = 49152;
    constexpr std::uint64_t size = static_cast<std::uint64_t>(count) * 65536;
    const auto table_bytes = static_cast<std::uint64_t>(count) * 8;
    const auto payload_size = 4 + table_bytes + count * kA64k.size();
    const auto map_offset = 0x104 + payload_size;
    std::size_t block_reads = 0;
    std::size_t total_reads = 0;
    ApfsCompressionResourceReader reader{map_offset + 50,
        [&](std::uint64_t at, std::span<std::byte> dst) -> std::size_t
        {
            ++total_reads;
            Bytes bytes;
            if (at == 0 && dst.size() == 16)
            {
                bytes.resize(16);
                U32(bytes, 0, 0x100, true);
                U32(bytes, 4, static_cast<std::uint32_t>(map_offset), true);
                U32(bytes, 8, static_cast<std::uint32_t>(payload_size + 4), true);
                U32(bytes, 12, 50, true);
            }
            else if (at == 0x100 && dst.size() == 8)
            {
                bytes.resize(8);
                U32(bytes, 0, static_cast<std::uint32_t>(payload_size), true);
                U32(bytes, 4, count);
            }
            else if (at == 0x108 && dst.size() == table_bytes)
            {
                bytes.resize(static_cast<std::size_t>(table_bytes));
                for (std::uint32_t i = 0; i < count; ++i)
                {
                    U32(bytes, i * 8, static_cast<std::uint32_t>(4 + table_bytes + i * kA64k.size()));
                    U32(bytes, i * 8 + 4, static_cast<std::uint32_t>(kA64k.size()));
                }
            }
            else if (at == 0x104 + 4 + table_bytes + (count - 1) * kA64k.size() && dst.size() == kA64k.size())
            { ++block_reads; bytes = kA64k; }
            else { Require(false, "large-file read touched an unselected block"); return 0; }
            std::copy(bytes.begin(), bytes.end(), dst.begin());
            return dst.size();
        }};
    ApfsCompressionLimits limits;
    limits.max_output_bytes = 1;
    limits.max_decoded_bytes = 65536;
    limits.max_resource_read_bytes = 16 + 8 + table_bytes + kA64k.size();
    Expect(Attribute(4, size), size - 1, kMax, Hex("41"), reader, limits);
    Require(total_reads == 4 && block_reads == 1, "3 GiB range decodes only its final 64 KiB block");
}
#include "LzfseRangeTests.h"
} // namespace

int main()
{
    failures += RunLzfseDecoderBridgeTests();
    TestLzfseRanges();
    TestHeaderAndRaw();
    TestZlibInline();
    TestLzvnInlineKnownBytes();
    TestLzvnInlineRefusals();
    TestLzvnInlineLimits();
    TestLzvnResourceRangesAndRefusals();
    TestLzvnLargeLogicalRange();
    TestLimits();
    TestResourceRanges();
    TestResourceCorruptionAndFailures();
    TestLargeLogicalFileRange();
    if (failures != 0) { std::cerr << failures << " compression checks failed\n"; return 1; }
    std::cout << "APFS compression standalone checks passed\n";
    return 0;
}
