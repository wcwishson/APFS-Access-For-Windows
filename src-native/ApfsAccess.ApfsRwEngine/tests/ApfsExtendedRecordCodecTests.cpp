#include "ApfsExtendedRecordCodec.h"
#include "ApfsTransactionWriter.h"

#include <cstddef>
#include <array>
#include <cstdint>
#include <iostream>
#include <string>
#include <vector>

namespace
{
using apfsaccess::catalog::BtreeRecord;
using namespace apfsaccess::rw;

int g_failures = 0;

bool Require(bool condition, const std::string& message)
{
    if (!condition)
    {
        std::cerr << "[FAIL] " << message << std::endl;
        ++g_failures;
    }
    return condition;
}

std::vector<std::byte> Bytes(const std::string& text)
{
    return {
        reinterpret_cast<const std::byte*>(text.data()),
        reinterpret_cast<const std::byte*>(text.data() + text.size())};
}

bool SameExtendedFields(
    const std::vector<AppleExtendedField>& left,
    const std::vector<AppleExtendedField>& right)
{
    if (left.size() != right.size())
    {
        return false;
    }
    for (std::size_t index = 0; index < left.size(); ++index)
    {
        if (left[index].type != right[index].type ||
            left[index].flags != right[index].flags ||
            left[index].data != right[index].data)
        {
            return false;
        }
    }
    return true;
}

bool TestInodeRoundTripPreservesCompleteMetadata()
{
    AppleInodeRecord expected;
    expected.object_id = 41;
    expected.parent_id = 2;
    expected.private_id = 1041;
    expected.create_time = 101;
    expected.modification_time = 202;
    expected.change_time = 303;
    expected.access_time = 404;
    expected.internal_flags = 0x123456789abcdef0ull;
    expected.children_or_links = 3;
    expected.default_protection_class = 7;
    expected.write_generation = 19;
    expected.bsd_flags = 0x00008002u;
    expected.owner = 501;
    expected.group = 20;
    expected.mode = 0100470;
    expected.reserved_pad = 0xa55au;
    expected.uncompressed_size = 123456;
    expected.extended_fields = {
        AppleExtendedField{4, 1, Bytes("primary-name\0")},
        AppleExtendedField{8, 0, std::vector<std::byte>(40, std::byte{0x3c})},
    };

    BtreeRecord encoded;
    std::string error;
    bool ok = Require(
        EncodeAppleInodeRecord(expected, encoded, error),
        "encode complete inode: " + error);
    AppleInodeRecord actual;
    ok &= Require(
        ApfsExtendedRecordCodec::DecodeInode(encoded, actual, error),
        "decode complete inode: " + error);
    ok &= Require(actual.object_id == expected.object_id, "inode object id");
    ok &= Require(actual.parent_id == expected.parent_id, "inode parent id");
    ok &= Require(actual.private_id == expected.private_id, "inode private id");
    ok &= Require(actual.create_time == expected.create_time, "inode create time");
    ok &= Require(actual.modification_time == expected.modification_time, "inode modification time");
    ok &= Require(actual.change_time == expected.change_time, "inode change time");
    ok &= Require(actual.access_time == expected.access_time, "inode access time");
    ok &= Require(actual.internal_flags == expected.internal_flags, "inode internal flags");
    ok &= Require(actual.children_or_links == expected.children_or_links, "inode link count");
    ok &= Require(actual.default_protection_class == expected.default_protection_class, "inode protection class");
    ok &= Require(actual.write_generation == expected.write_generation, "inode generation");
    ok &= Require(actual.bsd_flags == expected.bsd_flags, "inode BSD flags");
    ok &= Require(actual.owner == expected.owner, "inode owner");
    ok &= Require(actual.group == expected.group, "inode group");
    ok &= Require(actual.mode == expected.mode, "inode mode");
    ok &= Require(actual.reserved_pad == expected.reserved_pad, "inode reserved padding");
    ok &= Require(actual.uncompressed_size == expected.uncompressed_size, "inode uncompressed size");
    ok &= Require(SameExtendedFields(actual.extended_fields, expected.extended_fields), "inode extended fields");
    return ok;
}

bool TestInodePayloadOnlyExtendedFieldLength()
{
    BtreeRecord input;
    input.key = {std::byte{41}, {}, {}, {}, {}, {}, {}, std::byte{0x30}};
    input.value.resize(0x5c + 4 + 4 + 40);
    const auto put64 = [&](std::size_t at, std::uint64_t value) {
        for (unsigned i = 0; i < 8; ++i) input.value[at + i] = std::byte((value >> (8 * i)) & 255);
    };
    const auto put16 = [&](std::size_t at, std::uint16_t value) {
        input.value[at] = std::byte(value & 255); input.value[at + 1] = std::byte(value >> 8);
    };
    put64(0, 2); put64(8, 41); input.value[0x38] = std::byte{1};
    put16(0x50, 0100644); put64(0x54, 123);
    put16(0x5c, 1); put16(0x5e, 40);
    input.value[0x60] = std::byte{8}; put16(0x62, 40);
    put64(0x64, 123); put64(0x6c, 4096);
    std::string error;
    AppleInodeRecord decoded;
    bool ok = Require(ApfsExtendedRecordCodec::DecodeInode(input, decoded, error),
        "observed payload-only xfield length is decoded for mutation: " + error);
    AppleDataStreamRecord stream;
    ok &= Require(decoded.object_id == 41 && decoded.extended_fields.size() == 1,
        "payload-only inode identity and complete field inventory");
    if (decoded.extended_fields.size() == 1)
        ok &= Require(ApfsExtendedRecordCodec::DecodeDataStream(decoded.extended_fields[0], stream, error) &&
            stream.size == 123 && stream.allocated_size == 4096,
            "payload-only dstream preserves logical and allocated length");
    auto inclusive = input; inclusive.value[0x5e] = std::byte{44};
    BtreeRecord encoded;
    ok &= Require(EncodeAppleInodeRecord(decoded, encoded, error) &&
        encoded.key == inclusive.key && encoded.value == inclusive.value,
        "mutation encoder keeps its descriptor-inclusive bytes for replay compatibility");
    for (const auto used : {0u, 39u, 41u, 43u, 45u, 65535u}) {
        auto malformed = input;
        malformed.value[0x5e] = std::byte(used & 255);
        malformed.value[0x5f] = std::byte(used >> 8);
        ok &= Require(!ApfsExtendedRecordCodec::DecodeInode(malformed, decoded, error) &&
            decoded.object_id == 0 && decoded.extended_fields.empty(),
            "incorrect native xfield byte counts refuse without publishing decoded fields");
    }
    auto trailing = input; trailing.value.push_back(std::byte{});
    ok &= Require(!ApfsExtendedRecordCodec::DecodeInode(trailing, decoded, error),
        "native xfield data cannot hide trailing bytes");
    return ok;
}

bool TestSiblingRecordsRoundTripExactIdentity()
{
    std::string error;
    BtreeRecord encoded;
    AppleSiblingLinkRecord expected_link{41, 9001, 7, "alias.bin"};
    bool ok = Require(
        EncodeAppleSiblingLinkRecord(expected_link, encoded, error),
        "encode sibling link: " + error);
    AppleSiblingLinkRecord actual_link;
    ok &= Require(
        ApfsExtendedRecordCodec::DecodeSiblingLink(encoded, actual_link, error),
        "decode sibling link: " + error);
    ok &= Require(actual_link.inode_id == expected_link.inode_id, "sibling link inode");
    ok &= Require(actual_link.sibling_id == expected_link.sibling_id, "sibling link identity");
    ok &= Require(actual_link.parent_id == expected_link.parent_id, "sibling link parent");
    ok &= Require(actual_link.name_utf8 == expected_link.name_utf8, "sibling link name bytes");

    AppleSiblingMapRecord expected_map{9001, 41};
    ok &= Require(
        EncodeAppleSiblingMapRecord(expected_map, encoded, error),
        "encode sibling map: " + error);
    AppleSiblingMapRecord actual_map;
    ok &= Require(
        ApfsExtendedRecordCodec::DecodeSiblingMap(encoded, actual_map, error),
        "decode sibling map: " + error);
    ok &= Require(actual_map.sibling_id == expected_map.sibling_id, "sibling map identity");
    ok &= Require(actual_map.file_id == expected_map.file_id, "sibling map inode");
    return ok;
}

bool TestEmbeddedXattrRoundTripPreservesOpaqueBytes()
{
    AppleXattrRecord expected;
    expected.object_id = 41;
    expected.name_utf8 = "com.apple.system.Security";
    expected.flags = kAppleXattrDataEmbedded;
    expected.data = {
        std::byte{0x00}, std::byte{0x11}, std::byte{0x80}, std::byte{0xff}};

    BtreeRecord encoded;
    std::string error;
    bool ok = Require(
        EncodeAppleXattrRecord(expected, encoded, error),
        "encode embedded security xattr: " + error);
    AppleXattrRecord actual;
    ok &= Require(
        ApfsExtendedRecordCodec::DecodeXattr(encoded, actual, error),
        "decode embedded security xattr: " + error);
    ok &= Require(actual.object_id == expected.object_id, "xattr inode");
    ok &= Require(actual.name_utf8 == expected.name_utf8, "xattr name");
    ok &= Require(actual.flags == expected.flags, "xattr flags");
    ok &= Require(actual.data == expected.data, "xattr opaque bytes");
    return ok;
}

bool TestExternalXattrCarriesCompleteDataStream()
{
    // Independent j_xattr_val + j_xattr_dstream byte fixture (APFS Reference, pp. 82, 106).
    BtreeRecord raw;
    raw.key = {std::byte{41}, std::byte{0}, std::byte{0}, std::byte{0}, std::byte{0}, std::byte{0}, std::byte{0},
        std::byte{0x40}, std::byte{2}, std::byte{0}, std::byte{'x'}, std::byte{0}};
    raw.value = {std::byte{1}, std::byte{0}, std::byte{48}, std::byte{0}};
    const std::uint64_t fields[] = {777, 8193, 12288, 23, UINT64_MAX, 0x123456789abcdef0ull};
    for (const auto field : fields)
        for (unsigned shift = 0; shift != 64; shift += 8) raw.value.push_back(static_cast<std::byte>((field >> shift) & 0xff));
    const std::vector<std::byte> descriptor(raw.value.begin() + 4, raw.value.end());
    AppleXattrRecord decoded;
    std::string error;
    bool ok = true;
    for (const auto ignored_length : std::array<std::uint16_t,3>{0,48,65535})
    {
        raw.value[2] = static_cast<std::byte>(ignored_length & 0xff);
        raw.value[3] = static_cast<std::byte>(ignored_length >> 8);
        ok &= Require(ApfsExtendedRecordCodec::DecodeXattr(raw, decoded, error) && decoded.data == descriptor &&
            decoded.object_id == 41 && decoded.name_utf8 == "x", "external xattr retains all six fields and ignores embedded-only length");
    }
    AppleXattrRecord expected{41, "com.apple.ResourceFork", kAppleXattrDataStream, descriptor};
    BtreeRecord encoded;
    ok &= Require(EncodeAppleXattrRecord(expected, encoded, error) && encoded.value.size() == 52 &&
        ApfsExtendedRecordCodec::DecodeXattr(encoded, decoded, error) && decoded.data == descriptor,
        "external resource-fork record encodes the complete stream descriptor");
    for (const auto bad_size : {0u, 8u, 40u, 47u, 49u})
    {
        auto malformed = raw;
        malformed.value.resize(4 + bad_size, std::byte{0});
        malformed.value[2] = malformed.value[3] = std::byte{0};
        ok &= Require(!ApfsExtendedRecordCodec::DecodeXattr(malformed, decoded, error),
            "truncated, legacy identifier-only, and oversized stream descriptors fail closed");
        expected.data.resize(bad_size, std::byte{0});
        ok &= Require(!EncodeAppleXattrRecord(expected, encoded, error), "encoder refuses invalid stream descriptor length");
    }
    auto no_identity = raw;
    for (unsigned i = 4; i != 12; ++i) no_identity.value[i] = std::byte{0};
    ok &= Require(!ApfsExtendedRecordCodec::DecodeXattr(no_identity, decoded, error), "stream descriptor needs a nonzero identity");
    auto too_large = raw;
    too_large.value[11] = std::byte{0xf0};
    ok &= Require(!ApfsExtendedRecordCodec::DecodeXattr(too_large, decoded, error), "stream identity must fit a filesystem record key");
    return ok;
}

bool TestEmbeddedXattrSizeBoundary()
{
    BtreeRecord encoded;
    AppleXattrRecord decoded;
    std::string error;
    bool ok = true;
    for (const auto size : {0u, 3804u})
    {
        AppleXattrRecord value{41, "user.note", kAppleXattrDataEmbedded, std::vector<std::byte>(size, std::byte{0x8a})};
        ok &= Require(EncodeAppleXattrRecord(value, encoded, error) &&
            ApfsExtendedRecordCodec::DecodeXattr(encoded, decoded, error) && decoded.data == value.data,
            "embedded xattr accepts empty values and the complete maximum inline payload");
    }
    encoded.value.push_back(std::byte{0x8a});
    encoded.value[2] = static_cast<std::byte>(3805 & 0xff);
    encoded.value[3] = static_cast<std::byte>(3805 >> 8);
    ok &= Require(!ApfsExtendedRecordCodec::DecodeXattr(encoded, decoded, error), "oversized embedded payload requires an external stream");
    return ok;
}

bool TestSecurityRecordCodec()
{
    // Independent disk fixture: XNU kauth.h layout and kern_authorization.c endian rules.
    const unsigned char fixture[] = {
        0x01, 0x2c, 0xc1, 0x6d,
        0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07,
        0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f,
        0xf0, 0xe1, 0xd2, 0xc3, 0xb4, 0xa5, 0x96, 0x87,
        0x78, 0x69, 0x5a, 0x4b, 0x3c, 0x2d, 0x1e, 0x0f,
        0x00, 0x00, 0x00, 0x01, 0x89, 0xab, 0xcd, 0xef,
        0x10, 0x21, 0x32, 0x43, 0x54, 0x65, 0x76, 0x87,
        0x98, 0xa9, 0xba, 0xcb, 0xdc, 0xed, 0xfe, 0x0f,
        0xf1, 0x23, 0x45, 0x6f, 0x87, 0x65, 0x43, 0x21};
    std::vector<std::byte> raw;
    for (auto byte : fixture) raw.push_back(static_cast<std::byte>(byte));
    AppleSecurityRecord decoded;
    std::vector<std::byte> encoded;
    std::string error = "stale";
    bool ok = Require(ApfsExtendedRecordCodec::DecodeSecurity(raw, decoded, error) && error.empty(),
        "decode independent big-endian security fixture");
    ok &= Require(!decoded.no_acl && decoded.acl_flags == 0x89abcdef && decoded.entries.size() == 1,
        "ACL count and all private/unknown flags decode without masking");
    if (decoded.entries.size() != 1) return false;
    ok &= Require(decoded.entries[0].flags == 0xf123456f && decoded.entries[0].rights == 0x87654321,
        "unknown ACE kind, flags and rights retain nonsymmetric values");
    for (std::size_t i = 0; i < 16; ++i)
        ok &= Require(decoded.owner[i] == raw[4 + i] && decoded.group[i] == raw[20 + i] &&
            decoded.entries[0].applicable[i] == raw[44 + i], "GUIDs remain uninterpreted bytes");
    ok &= Require(ApfsExtendedRecordCodec::EncodeSecurity(decoded, encoded, error) && encoded == raw,
        "security fixture round-trips byte exactly");
    const auto one_entry = decoded;
    for (std::size_t length = 0; length < raw.size(); ++length)
        ok &= Require(!ApfsExtendedRecordCodec::DecodeSecurity(std::span(raw).first(length), decoded, error) &&
            !error.empty() && decoded.entries.empty(), "every header/ACE truncation rejected and output reset");
    for (const auto count : {0x00000081u, 0xfffffffeu, 0x01000000u})
    {
        auto bad = raw;
        for (unsigned i = 0; i < 4; ++i) bad[36 + i] = static_cast<std::byte>((count >> (24 - 8 * i)) & 0xff);
        ok &= Require(!ApfsExtendedRecordCodec::DecodeSecurity(bad, decoded, error),
            "oversized or little-endian count rejected before allocation");
    }
    auto bad_magic = raw;
    bad_magic[0] = std::byte{0x6d}; bad_magic[1] = std::byte{0xc1};
    bad_magic[2] = std::byte{0x2c}; bad_magic[3] = std::byte{0x01};
    ok &= Require(!ApfsExtendedRecordCodec::DecodeSecurity(bad_magic, decoded, error), "little-endian magic rejected");
    bad_magic[0] = std::byte{0};
    ok &= Require(!ApfsExtendedRecordCodec::DecodeSecurity(bad_magic, decoded, error), "invalid magic rejected");
    auto tail = raw;
    tail.push_back(std::byte{0});
    ok &= Require(!ApfsExtendedRecordCodec::DecodeSecurity(tail, decoded, error), "extra tail rejected");
    for (bool no_acl : {false, true})
    {
        auto header = raw;
        header.resize(44);
        for (unsigned i = 36; i < 40; ++i) header[i] = no_acl ? std::byte{0xff} : std::byte{0};
        ok &= Require(ApfsExtendedRecordCodec::DecodeSecurity(header, decoded, error) &&
            decoded.no_acl == no_acl && decoded.entries.empty(), "empty ACL and NOACL stay distinct");
        if (no_acl)
        {
            ok &= Require(decoded.acl_flags == 0 && decoded.no_acl_flags ==
                std::array<std::byte, 4>{std::byte{0x89}, std::byte{0xab}, std::byte{0xcd}, std::byte{0xef}},
                "NOACL flags retained as opaque bytes without numeric interpretation");
            decoded.acl_flags = 0x12345678; // Inactive numeric field must not update NOACL bytes.
        }
        ok &= Require(ApfsExtendedRecordCodec::EncodeSecurity(decoded, encoded, error) && encoded == header,
            "empty/NOACL flags round-trip unchanged");
        header.insert(header.end(), raw.begin() + 44, raw.end());
        ok &= Require(!ApfsExtendedRecordCodec::DecodeSecurity(header, decoded, error), "zero-count/NOACL rejects actual ACE tail");
    }
    auto maximum = raw;
    maximum.resize(44);
    maximum[39] = std::byte{0x80};
    for (unsigned i = 0; i < 128; ++i) maximum.insert(maximum.end(), raw.begin() + 44, raw.end());
    ok &= Require(ApfsExtendedRecordCodec::DecodeSecurity(maximum, decoded, error) && decoded.entries.size() == 128 &&
        ApfsExtendedRecordCodec::EncodeSecurity(decoded, encoded, error) && encoded == maximum, "128 ACE boundary round-trips");
    decoded.entries.resize(129);
    ok &= Require(!ApfsExtendedRecordCodec::EncodeSecurity(decoded, encoded, error) && encoded.empty() && !error.empty(),
        "encoder rejects 129 entries and clears output");
    decoded = one_entry;
    decoded.no_acl = true;
    ok &= Require(!ApfsExtendedRecordCodec::EncodeSecurity(decoded, encoded, error) && encoded.empty(), "encoder rejects NOACL with ACE");
    return ok;
}

bool TestSecurityPrincipalVectors()
{
    using Codec = ApfsExtendedRecordCodec;
    // External compatibility GUID vectors, not produced by the encoder under test.
    const unsigned char user[] = {0xff, 0xff, 0xee, 0xee, 0xdd, 0xdd, 0xcc, 0xcc,
        0xbb, 0xbb, 0xaa, 0xaa, 0x12, 0x34, 0x56, 0x78};
    const unsigned char group[] = {0xab, 0xcd, 0xef, 0xab, 0xcd, 0xef, 0xab, 0xcd,
        0xef, 0xab, 0xcd, 0xef, 0, 0, 0, 20};
    std::array<std::byte, 16> guid{};
    std::string error;
    bool ok = true;
    for (bool is_user : {false, true})
    {
        for (unsigned i = 0; i < 16; ++i) guid[i] = static_cast<std::byte>((is_user ? user : group)[i]);
        AppleSecurityPrincipal principal;
        std::array<std::byte, 16> encoded{};
        ok &= Require(Codec::DecodeSecurityPrincipal(guid, principal, error) &&
            principal.kind == (is_user ? ApplePrincipalKind::Uid : ApplePrincipalKind::Gid) &&
            principal.id == (is_user ? 0x12345678u : 20u) &&
            Codec::EncodeSecurityPrincipal(principal, encoded, error) && encoded == guid,
            "external numeric GUID vector has exact identity and big-endian suffix");
    }
    for (unsigned i = 0; i < 16; ++i) guid[i] = static_cast<std::byte>(group[i]);
    const ApplePrincipalKind kinds[] = {ApplePrincipalKind::Owner, ApplePrincipalKind::Group,
        ApplePrincipalKind::Everybody, ApplePrincipalKind::Nobody};
    const std::uint32_t codes[] = {0x0a, 0x10, 0x0c, 0xfffffffe};
    for (unsigned n = 0; n < 4; ++n)
    {
        for (unsigned i = 0; i < 4; ++i) guid[12 + i] = static_cast<std::byte>((codes[n] >> (24 - 8 * i)) & 0xff);
        AppleSecurityPrincipal principal;
        auto encoded = guid;
        ok &= Require(Codec::DecodeSecurityPrincipal(guid, principal, error) &&
            principal.kind == kinds[n] && principal.id == 0 &&
            Codec::EncodeSecurityPrincipal(principal, encoded, error) && encoded == guid,
            "reserved group suffix decodes as symbolic principal and round-trips");
        ok &= Require(!Codec::EncodeSecurityPrincipal({ApplePrincipalKind::Gid, codes[n]}, encoded, error) &&
            encoded == guid && !error.empty(), "numeric GID cannot alias symbolic principal");
    }
    const auto unchanged_guid = guid;
    for (auto kind : {ApplePrincipalKind::Uid, ApplePrincipalKind::Gid})
    {
        for (auto id : {0u, 501u, 0xffffff9au})
        {
            AppleSecurityPrincipal decoded;
            ok &= Require(Codec::EncodeSecurityPrincipal({kind, id}, guid, error) &&
                Codec::DecodeSecurityPrincipal(guid, decoded, error) && decoded.kind == kind && decoded.id == id,
                "root, ordinary and high numeric identities round-trip");
        }
        for (auto id : {UINT32_MAX, UINT32_MAX - 100})
        {
            auto encoded = unchanged_guid;
            ok &= Require(!Codec::EncodeSecurityPrincipal({kind, id}, encoded, error) && encoded == unchanged_guid,
                "numeric sentinel encoding is atomic");
            for (unsigned i = 0; i < 12; ++i)
                encoded[i] = static_cast<std::byte>((kind == ApplePrincipalKind::Uid ? user : group)[i]);
            for (unsigned i = 0; i < 4; ++i) encoded[12 + i] = static_cast<std::byte>((id >> (24 - 8 * i)) & 0xff);
            AppleSecurityPrincipal decoded{ApplePrincipalKind::Uid, 42};
            ok &= Require(!Codec::DecodeSecurityPrincipal(encoded, decoded, error) &&
                decoded.kind == ApplePrincipalKind::Uid && decoded.id == 42, "numeric sentinel decoding is atomic");
        }
    }
    for (auto principal : {AppleSecurityPrincipal{static_cast<ApplePrincipalKind>(99), 0},
             AppleSecurityPrincipal{ApplePrincipalKind::Owner, 10}})
    {
        guid = unchanged_guid;
        ok &= Require(!Codec::EncodeSecurityPrincipal(principal, guid, error) && guid == unchanged_guid,
            "unknown kind and noncanonical symbolic identity rejected");
    }
    for (unsigned i = 0; i < 12; ++i)
    {
        auto unknown = unchanged_guid;
        unknown[i] ^= std::byte{1};
        AppleSecurityPrincipal decoded{ApplePrincipalKind::Uid, 42};
        ok &= Require(!Codec::DecodeSecurityPrincipal(unknown, decoded, error) &&
            decoded.kind == ApplePrincipalKind::Uid && decoded.id == 42, "all prefix bytes checked without output mutation");
    }
    return ok;
}

bool TestSecurityAceProjection()
{
    using Codec = ApfsExtendedRecordCodec;
    std::string error;
    AppleSecurityAce ace;
    bool ok = Require(Codec::EncodeSecurityPrincipal({ApplePrincipalKind::Gid, 20}, ace.applicable, error), "seed GID 20 ACE");
    // kauth.h right order: read, write, execute, delete, append, delete child,
    // attributes, extended attributes, security, ownership, synchronize.
    const std::uint32_t apple_rights[] = {2, 4, 8, 16, 32, 64, 128, 256, 512, 1024, 2048, 4096, 8192, 0x100000};
    const std::uint32_t windows_rights[] = {1, 2, 0x20, 0x10000, 4, 0x40, 0x80, 0x100, 8, 16, 0x20000, 0x40000, 0x80000, 0x100000};
    const std::uint32_t apple_flags[] = {0x10, 0x20, 0x40, 0x80, 0x100};
    const std::uint8_t windows_flags[] = {0x10, 1, 2, 4, 8};
    for (std::uint32_t kind : {1u, 2u})
    {
        for (unsigned flags = 0; flags < 32; ++flags)
        {
            ace.flags = kind;
            std::uint8_t expected_flags = 0;
            for (unsigned bit = 0; bit < 5; ++bit)
                if ((flags & (1u << bit)) != 0) { ace.flags |= apple_flags[bit]; expected_flags |= windows_flags[bit]; }
            for (unsigned right = 0; right < 16; ++right)
            {
                ace.rights = right < 14 ? apple_rights[right] : (right == 14 ? 0u : 0x103ffeu);
                const auto expected_mask = right < 14 ? windows_rights[right] : (right == 14 ? 0u : 0x1f01ffu);
                ProjectedSecurityAce projected;
                AppleSecurityAce restored;
                error = "stale";
                ok &= Require(Codec::ProjectSecurityAce(ace, projected, error) && error.empty() &&
                    projected.kind == (kind == 1 ? ProjectedAceKind::Allow : ProjectedAceKind::Deny) &&
                    projected.principal.kind == ApplePrincipalKind::Gid && projected.principal.id == 20 &&
                    projected.ace_flags == expected_flags && projected.access_mask == expected_mask &&
                    Codec::UnprojectSecurityAce(projected, restored, error) && restored.applicable == ace.applicable &&
                    restored.flags == ace.flags && restored.rights == ace.rights,
                    "exact right mapping and every inheritance combination round-trip for allow/deny");
            }
        }
    }
    ace.flags = 1;
    ace.rights = 2;
    const auto original = ace;
    const auto rejects_native = [&](const AppleSecurityAce& bad) {
        ProjectedSecurityAce output{{ApplePrincipalKind::Uid, 42}, ProjectedAceKind::Deny, 0x12345678, 0xa5};
        return !Codec::ProjectSecurityAce(bad, output, error) && !error.empty() &&
            output.principal.kind == ApplePrincipalKind::Uid && output.principal.id == 42 &&
            output.kind == ProjectedAceKind::Deny && output.access_mask == 0x12345678 && output.ace_flags == 0xa5;
    };
    for (unsigned kind = 0; kind < 16; ++kind)
        if (kind != 1 && kind != 2) { auto bad = original; bad.flags = kind; ok &= Require(rejects_native(bad), "unsupported native ACE kinds atomic"); }
    for (unsigned bit = 0; bit < 32; ++bit)
    {
        auto bad = original;
        if (bit >= 9) { bad.flags |= 1u << bit; ok &= Require(rejects_native(bad), "unknown native flags atomic"); }
        bad = original;
        if (((1u << bit) & 0x103ffeu) == 0)
        { bad.rights |= 1u << bit; ok &= Require(rejects_native(bad), "unknown native rights including generic bits atomic"); }
    }
    auto bad_identity = original;
    bad_identity.applicable = {};
    ok &= Require(rejects_native(bad_identity), "unresolved native principal atomic");
    const auto rejects_projected = [&](const ProjectedSecurityAce& bad) {
        auto output = original;
        return !Codec::UnprojectSecurityAce(bad, output, error) && !error.empty() &&
            output.applicable == original.applicable && output.flags == original.flags && output.rights == original.rights;
    };
    ProjectedSecurityAce projected{{ApplePrincipalKind::Gid, 20}, ProjectedAceKind::Allow, 1, 0};
    for (unsigned bit = 0; bit < 32; ++bit)
        if (((1u << bit) & 0x1f01ffu) == 0)
        { auto bad = projected; bad.access_mask |= 1u << bit; ok &= Require(rejects_projected(bad), "unknown Windows rights including generic bits atomic"); }
    for (unsigned bit = 5; bit < 8; ++bit)
    { auto bad = projected; bad.ace_flags = static_cast<std::uint8_t>(1u << bit); ok &= Require(rejects_projected(bad), "unknown Windows flags atomic"); }
    auto bad = projected;
    bad.kind = static_cast<ProjectedAceKind>(99);
    ok &= Require(rejects_projected(bad), "unknown projected kind atomic");
    bad = projected;
    bad.principal = {ApplePrincipalKind::Gid, 10};
    ok &= Require(rejects_projected(bad), "ambiguous projected principal leaves original ACE intact");
    return ok;
}

bool TestRawXattrNames()
{
    bool ok = true;
    for (const auto& name : std::vector<std::string>{".", "/", "raw/name:with\\bytes",
             std::string(821, 'x'), "raw.\xE6\xB5\x8B\xE8\xAF\x95"}) {
        AppleXattrRecord input{21,name,kAppleXattrDataEmbedded,Bytes("opaque value")};
        BtreeRecord row;std::string error;AppleXattrRecord output;
        ok &= Require(EncodeAppleXattrRecord(input,row,error) &&
            ApfsExtendedRecordCodec::DecodeXattr(row,output,error) && output.name_utf8==name && output.data==input.data,
            "raw attribute bytes survive without filename projection");
    }
    for (const auto& name : std::vector<std::string>{std::string("\xC0\xAF",2),
             std::string("\xED\xA0\x80",3),std::string("\xF4\x90\x80\x80",4),std::string("\xE6\xB5",2)}) {
        AppleXattrRecord input{21,name,kAppleXattrDataEmbedded,{}};
        BtreeRecord row;std::string error;AppleXattrRecord output;
        ok &= Require(EncodeAppleXattrRecord(input,row,error) &&
            !ApfsExtendedRecordCodec::DecodeXattr(row,output,error) && output.name_utf8.empty() && output.data.empty(),
            "invalid attribute UTF8 refuses with empty result");
    }
    return ok;
}
bool TestMalformedRecordsFailClosed()
{
    std::string error;
    BtreeRecord encoded;
    AppleSiblingLinkRecord sibling{41, 9001, 7, "alias.bin"};
    bool ok = Require(EncodeAppleSiblingLinkRecord(sibling, encoded, error), "seed sibling link");
    encoded.key.push_back(std::byte{0});
    AppleSiblingLinkRecord decoded_link;
    ok &= Require(
        !ApfsExtendedRecordCodec::DecodeSiblingLink(encoded, decoded_link, error),
        "sibling key trailing bytes rejected");

    ok &= Require(EncodeAppleSiblingLinkRecord(sibling, encoded, error), "reseed sibling link");
    encoded.value.back() = std::byte{'x'};
    ok &= Require(
        !ApfsExtendedRecordCodec::DecodeSiblingLink(encoded, decoded_link, error),
        "sibling missing terminator rejected");

    AppleXattrRecord xattr{41, "com.apple.fs.symlink", kAppleXattrDataEmbedded, Bytes("../target")};
    ok &= Require(EncodeAppleXattrRecord(xattr, encoded, error), "seed symlink xattr");
    encoded.value.push_back(std::byte{0});
    AppleXattrRecord decoded_xattr;
    ok &= Require(
        !ApfsExtendedRecordCodec::DecodeXattr(encoded, decoded_xattr, error),
        "xattr trailing bytes rejected");
    return ok;
}
} // namespace

int main()
{
    bool ok = true;
    ok &= TestInodeRoundTripPreservesCompleteMetadata();
    ok &= TestInodePayloadOnlyExtendedFieldLength();
    ok &= TestSiblingRecordsRoundTripExactIdentity();
    ok &= TestEmbeddedXattrRoundTripPreservesOpaqueBytes();
    ok &= TestExternalXattrCarriesCompleteDataStream();
    ok &= TestEmbeddedXattrSizeBoundary();
    ok &= TestMalformedRecordsFailClosed();
    ok &= TestRawXattrNames();
    ok &= TestSecurityRecordCodec();
    ok &= TestSecurityPrincipalVectors();
    ok &= TestSecurityAceProjection();
    if (ok && g_failures == 0)
    {
        std::cout << "APFS EXTENDED RECORD CODEC PASS" << std::endl;
        return 0;
    }
    std::cerr << "APFS EXTENDED RECORD CODEC FAIL: " << g_failures << " check(s)" << std::endl;
    return 1;
}
