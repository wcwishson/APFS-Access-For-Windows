#include "ApfsExtendedRecordCodec.h"

#include "ApfsFormat.h"
#include "ApfsNameCodec.h"
#include "utf8proc.h"

#include <algorithm>
#include <iterator>
#include <limits>
#include <span>
#include <unordered_set>

namespace apfsaccess::rw
{
namespace
{
constexpr std::uint64_t kFsObjectIdMask = 0x0fffffffffffffffull;
constexpr std::uint64_t kFsRecordTypeShift = 60;
constexpr std::uint32_t kSecurityMagic = 0x012cc16d;
constexpr std::uint32_t kSecurityNoAcl = 0xffffffff;
constexpr std::size_t kSecurityMaxEntries = 128;
constexpr std::size_t kSecurityHeaderBytes = 44;
constexpr std::size_t kSecurityAceBytes = 24;

// XNU kern_credential.c compatibility GUIDs and kauth_wellknown_guid codes.
constexpr unsigned char kUserPrefix[] = {0xff, 0xff, 0xee, 0xee, 0xdd, 0xdd, 0xcc, 0xcc, 0xbb, 0xbb, 0xaa, 0xaa};
constexpr unsigned char kGroupPrefix[] = {0xab, 0xcd, 0xef, 0xab, 0xcd, 0xef, 0xab, 0xcd, 0xef, 0xab, 0xcd, 0xef};

// Owned decoded metadata is wiped on failure and after move-publication. This
// covers live bytes; allocator/library scratch and caller-owned outputs remain
// outside this codec's lifetime. No secret-key storage is introduced here.
template<class T> void WipeDecodedSequence(T& bytes) noexcept
{
    volatile typename T::value_type* data = bytes.data();
    for (std::size_t i = 0; i < bytes.size(); ++i) data[i] = {};
    bytes.clear();
}
void WipeDecoded(AppleInodeRecord& inode) noexcept
{ for (auto& field : inode.extended_fields) WipeDecodedSequence(field.data); }
void WipeDecoded(AppleSiblingLinkRecord& link) noexcept { WipeDecodedSequence(link.name_utf8); }
void WipeDecoded(AppleXattrRecord& xattr) noexcept
{ WipeDecodedSequence(xattr.name_utf8); WipeDecodedSequence(xattr.data); }
void WipeDecoded(ApfsName& name) noexcept
{ WipeDecodedSequence(name.original_utf8); WipeDecodedSequence(name.windows_display); WipeDecodedSequence(name.lookup_key); }
template<class T> struct DecodedCleanup
{
    T& value;
    ~DecodedCleanup() { WipeDecoded(value); }
};

bool UnsupportedNumericIdentity(std::uint32_t id)
{
    // -1 is the POSIX unchanged-ID sentinel; kauth.h reserves -101 as *_NONE.
    return id == UINT32_MAX || id == UINT32_MAX - 100;
}

struct AceBitMapping { std::uint32_t apple; std::uint32_t windows; };
constexpr AceBitMapping kAceRights[] = {
    {1u << 1, 0x000001}, {1u << 2, 0x000002}, {1u << 3, 0x000020},
    {1u << 4, 0x010000}, {1u << 5, 0x000004}, {1u << 6, 0x000040},
    {1u << 7, 0x000080}, {1u << 8, 0x000100}, {1u << 9, 0x000008},
    {1u << 10, 0x000010}, {1u << 11, 0x020000}, {1u << 12, 0x040000},
    {1u << 13, 0x080000}, {1u << 20, 0x100000}};
constexpr AceBitMapping kAceFlags[] = {
    {1u << 4, 0x10}, {1u << 5, 0x01}, {1u << 6, 0x02},
    {1u << 7, 0x04}, {1u << 8, 0x08}};

bool MapAceBits(std::uint32_t input, std::span<const AceBitMapping> mapping,
    bool to_windows, std::uint32_t& output)
{
    output = 0;
    for (const auto& bit : mapping)
    {
        const auto source = to_windows ? bit.apple : bit.windows;
        if ((input & source) != 0)
        {
            output |= to_windows ? bit.windows : bit.apple;
            input &= ~source;
        }
    }
    return input == 0;
}

// Callers validate the complete bounded record before accessing fixed-width fields.
std::uint32_t ReadSecurityU32(std::span<const std::byte> bytes, std::size_t offset)
{
    std::uint32_t value = 0;
    for (unsigned i = 0; i < 4; ++i)
        value = (value << 8) | std::to_integer<std::uint32_t>(bytes[offset + i]);
    return value;
}

void WriteSecurityU32(std::vector<std::byte>& bytes, std::size_t offset, std::uint32_t value)
{
    for (unsigned i = 0; i < 4; ++i)
        bytes[offset + i] = static_cast<std::byte>((value >> (24 - 8 * i)) & 0xff);
}

bool Fail(std::string& out_error, std::string error)
{
    out_error = std::move(error);
    return false;
}

bool ParseExactKey(
    const catalog::BtreeRecord& record,
    std::uint64_t expected_type,
    std::size_t expected_size,
    std::uint64_t& out_object_id,
    std::string& out_error)
{
    if (record.key.size() != expected_size)
    {
        return Fail(out_error, "AppleRecordKeySizeInvalid");
    }
    const auto key = catalog::ReadU64LE(record.key, 0);
    if (!key.has_value() || (key.value() >> kFsRecordTypeShift) != expected_type)
    {
        return Fail(out_error, "AppleRecordTypeInvalid");
    }
    out_object_id = key.value() & kFsObjectIdMask;
    if (out_object_id == 0)
    {
        return Fail(out_error, "AppleRecordObjectIdInvalid");
    }
    return true;
}

std::size_t AlignEight(std::size_t size)
{
    return (size + 7u) & ~std::size_t{7u};
}

bool DecodeExtendedFields(
    const std::vector<std::byte>& value,
    std::size_t offset,
    std::vector<AppleExtendedField>& out_fields,
    std::string& out_error, bool observational = false)
{
    out_fields.clear();
    if (offset == value.size())
    {
        return true;
    }
    if (offset > value.size() || value.size() - offset < 4)
    {
        return Fail(out_error, "AppleExtendedFieldHeaderInvalid");
    }
    const auto count_value = catalog::ReadU16LE(value, offset);
    const auto used_value = catalog::ReadU16LE(value, offset + 2);
    if (!count_value.has_value() || !used_value.has_value())
    {
        return Fail(out_error, "AppleExtendedFieldHeaderInvalid");
    }
    const auto count = static_cast<std::size_t>(count_value.value());
    const auto used = static_cast<std::size_t>(used_value.value());
    if (count == 0)
    {
        return used == 0 && offset + 4 == value.size()
            ? true
            : Fail(out_error, "AppleExtendedFieldEmptyInvalid");
    }
    if (count > 1024 || count > std::numeric_limits<std::size_t>::max() / 4)
    {
        return Fail(out_error, "AppleExtendedFieldCountInvalid");
    }
    const auto descriptor_bytes = count * 4;
    const auto remaining = value.size() - offset - 4;
    const bool legacy = used >= descriptor_bytes && used == remaining;
    // Older native records also count only padded values. Both encodings
    // must consume the same complete descriptor/value area.
    const bool native = descriptor_bytes <= remaining && used == remaining - descriptor_bytes;
    if (!legacy && !native)
    {
        return Fail(out_error, "AppleExtendedFieldSizeInvalid");
    }

    const auto descriptors = offset + 4;
    auto data_cursor = descriptors + descriptor_bytes;
    const auto data_end = value.size();
    std::unordered_set<std::uint8_t> types;
    out_fields.reserve(count);
    for (std::size_t index = 0; index < count; ++index)
    {
        const auto descriptor = descriptors + index * 4;
        const auto type = std::to_integer<std::uint8_t>(value[descriptor]);
        const auto flags = std::to_integer<std::uint8_t>(value[descriptor + 1]);
        const auto size_value = catalog::ReadU16LE(value, descriptor + 2);
        if (type == 0 || !types.insert(type).second || !size_value.has_value())
        {
            return Fail(out_error, "AppleExtendedFieldDescriptorInvalid");
        }
        const auto field_size = static_cast<std::size_t>(size_value.value());
        const auto padded_size = AlignEight(field_size);
        if (padded_size < field_size || padded_size > data_end - data_cursor)
        {
            return Fail(out_error, "AppleExtendedFieldDataInvalid");
        }
        AppleExtendedField field;
        field.type = type;
        field.flags = flags;
        field.data.assign(
            value.begin() + static_cast<std::ptrdiff_t>(data_cursor),
            value.begin() + static_cast<std::ptrdiff_t>(data_cursor + field_size));
        if (observational && !std::all_of(value.begin() + static_cast<std::ptrdiff_t>(data_cursor + field_size),
                value.begin() + static_cast<std::ptrdiff_t>(data_cursor + padded_size),
                [](std::byte byte) { return byte == std::byte{}; }))
            return Fail(out_error, "AppleExtendedFieldPaddingInvalid");
        out_fields.push_back(std::move(field));
        data_cursor += padded_size;
    }
    return data_cursor == data_end
        ? true
        : Fail(out_error, "AppleExtendedFieldTrailingData");
}

bool DecodeTerminatedXattrName(
    const std::vector<std::byte>& bytes, std::size_t offset,
    std::size_t encoded_length, std::string& out_name, std::string& out_error)
{
    out_name.clear();
    if (encoded_length <= 1 || encoded_length > 822 || offset > bytes.size() ||
        encoded_length != bytes.size() - offset || bytes.back() != std::byte{})
        return Fail(out_error, "AppleXattrNameLengthInvalid");
    const auto end = bytes.size() - 1;
    for (auto at = offset; at < end;) {
        utf8proc_int32_t codepoint = 0;
        const auto consumed = utf8proc_iterate(reinterpret_cast<const utf8proc_uint8_t*>(bytes.data() + at),
            static_cast<utf8proc_ssize_t>(end - at), &codepoint);
        if (consumed <= 0 || codepoint == 0) return Fail(out_error, "AppleXattrNameUtf8Invalid");
        at += static_cast<std::size_t>(consumed);
    }
    out_name.assign(reinterpret_cast<const char*>(bytes.data() + offset), encoded_length - 1);
    return true;
}

bool DecodeTerminatedName(
    const std::vector<std::byte>& bytes,
    std::size_t offset,
    std::size_t encoded_length,
    std::string& out_name,
    std::string& out_error)
{
    out_name.clear();
    if (encoded_length <= 1 || offset > bytes.size() ||
        encoded_length != bytes.size() - offset ||
        bytes.back() != std::byte{0})
    {
        return Fail(out_error, "AppleRecordNameLengthInvalid");
    }
    out_name.assign(
        reinterpret_cast<const char*>(bytes.data() + offset),
        encoded_length - 1);
    auto decoded = ApfsNameCodec::Decode(
        std::span(bytes.data() + offset, encoded_length - 1),
        ApfsNamePolicy{});
    if (!decoded.ok())
    {
        WipeDecodedSequence(out_name);
        return Fail(out_error, "AppleRecordNameUtf8Invalid");
    }
    DecodedCleanup cleanup{*decoded.value};
    return true;
}
} // namespace

bool ApfsExtendedRecordCodec::DecodeSecurityPrincipal(
    const std::array<std::byte, 16>& guid, AppleSecurityPrincipal& out_principal,
    std::string& out_error)
{
    out_error.clear();
    const auto matches = [&](const auto& prefix) {
        return std::equal(std::begin(prefix), std::end(prefix), guid.begin(),
            [](unsigned char a, std::byte b) { return a == std::to_integer<unsigned char>(b); });
    };
    AppleSecurityPrincipal decoded;
    const auto id = ReadSecurityU32(guid, 12);
    if (matches(kGroupPrefix))
    {
        switch (id)
        {
        case 0x0c: decoded.kind = ApplePrincipalKind::Everybody; break;
        case 0xfffffffe: decoded.kind = ApplePrincipalKind::Nobody; break;
        case 0x0a: decoded.kind = ApplePrincipalKind::Owner; break;
        case 0x10: decoded.kind = ApplePrincipalKind::Group; break;
        default: decoded = {ApplePrincipalKind::Gid, id}; break;
        }
    }
    else if (matches(kUserPrefix)) decoded = {ApplePrincipalKind::Uid, id};
    else return Fail(out_error, "AppleSecurityPrincipalUnsupported");
    if ((decoded.kind == ApplePrincipalKind::Uid || decoded.kind == ApplePrincipalKind::Gid) &&
        UnsupportedNumericIdentity(id))
        return Fail(out_error, "AppleSecurityPrincipalUnsupported");
    out_principal = decoded;
    return true;
}

bool ApfsExtendedRecordCodec::EncodeSecurityPrincipal(
    const AppleSecurityPrincipal& principal, std::array<std::byte, 16>& out_guid,
    std::string& out_error)
{
    out_error.clear();
    auto id = principal.id;
    const bool numeric = principal.kind == ApplePrincipalKind::Uid || principal.kind == ApplePrincipalKind::Gid;
    if ((numeric && UnsupportedNumericIdentity(id)) || (!numeric && id != 0))
        return Fail(out_error, "AppleSecurityPrincipalUnsupported");
    switch (principal.kind)
    {
    case ApplePrincipalKind::Uid: break;
    case ApplePrincipalKind::Gid:
        if (id == 0x0a || id == 0x0c || id == 0x10 || id == 0xfffffffe)
            return Fail(out_error, "AppleSecurityPrincipalUnsupported");
        break;
    case ApplePrincipalKind::Owner: id = 0x0a; break;
    case ApplePrincipalKind::Group: id = 0x10; break;
    case ApplePrincipalKind::Everybody: id = 0x0c; break;
    case ApplePrincipalKind::Nobody: id = 0xfffffffe; break;
    default: return Fail(out_error, "AppleSecurityPrincipalUnsupported");
    }
    std::array<std::byte, 16> encoded{};
    const auto* prefix = principal.kind == ApplePrincipalKind::Uid ? kUserPrefix : kGroupPrefix;
    for (unsigned i = 0; i < 12; ++i) encoded[i] = static_cast<std::byte>(prefix[i]);
    for (unsigned i = 0; i < 4; ++i) encoded[12 + i] = static_cast<std::byte>((id >> (24 - 8 * i)) & 0xff);
    out_guid = encoded;
    return true;
}

bool ApfsExtendedRecordCodec::ProjectSecurityAce(
    const AppleSecurityAce& ace, ProjectedSecurityAce& out_ace, std::string& out_error)
{
    out_error.clear();
    ProjectedSecurityAce projected;
    const auto kind = ace.flags & 0xf;
    if (kind != 1 && kind != 2) return Fail(out_error, "AppleSecurityAceKindUnsupported");
    projected.kind = kind == 1 ? ProjectedAceKind::Allow : ProjectedAceKind::Deny;
    std::uint32_t flags = 0;
    if (!MapAceBits(ace.flags & ~0xfu, kAceFlags, true, flags))
        return Fail(out_error, "AppleSecurityAceFlagsUnsupported");
    projected.ace_flags = static_cast<std::uint8_t>(flags);
    if (!MapAceBits(ace.rights, kAceRights, true, projected.access_mask))
        return Fail(out_error, "AppleSecurityAceRightsUnsupported");
    if (!DecodeSecurityPrincipal(ace.applicable, projected.principal, out_error)) return false;
    out_ace = projected;
    return true;
}

bool ApfsExtendedRecordCodec::UnprojectSecurityAce(
    const ProjectedSecurityAce& ace, AppleSecurityAce& out_ace, std::string& out_error)
{
    out_error.clear();
    AppleSecurityAce native;
    if (ace.kind != ProjectedAceKind::Allow && ace.kind != ProjectedAceKind::Deny)
        return Fail(out_error, "AppleSecurityAceKindUnsupported");
    if (!MapAceBits(ace.ace_flags, kAceFlags, false, native.flags))
        return Fail(out_error, "AppleSecurityAceFlagsUnsupported");
    native.flags |= ace.kind == ProjectedAceKind::Allow ? 1u : 2u;
    if (!MapAceBits(ace.access_mask, kAceRights, false, native.rights))
        return Fail(out_error, "AppleSecurityAceRightsUnsupported");
    if (!EncodeSecurityPrincipal(ace.principal, native.applicable, out_error)) return false;
    out_ace = native;
    return true;
}

bool ApfsExtendedRecordCodec::DecodeSecurity(
    std::span<const std::byte> bytes, AppleSecurityRecord& out_security,
    std::string& out_error)
{
    out_security = {};
    out_error.clear();
    if (bytes.size() < kSecurityHeaderBytes)
        return Fail(out_error, "AppleSecuritySizeInvalid");
    if (ReadSecurityU32(bytes, 0) != kSecurityMagic)
        return Fail(out_error, "AppleSecurityMagicInvalid");
    const auto count = ReadSecurityU32(bytes, 36);
    const bool no_acl = count == kSecurityNoAcl;
    if (!no_acl && count > kSecurityMaxEntries)
        return Fail(out_error, "AppleSecurityCountInvalid");
    const auto entries = no_acl ? 0u : count;
    if (bytes.size() != kSecurityHeaderBytes + kSecurityAceBytes * entries)
        return Fail(out_error, "AppleSecuritySizeInvalid");

    AppleSecurityRecord decoded;
    std::copy_n(bytes.begin() + 4, 16, decoded.owner.begin());
    std::copy_n(bytes.begin() + 20, 16, decoded.group.begin());
    decoded.no_acl = no_acl;
    if (no_acl)
        std::copy_n(bytes.begin() + 40, 4, decoded.no_acl_flags.begin());
    else
        decoded.acl_flags = ReadSecurityU32(bytes, 40);
    decoded.entries.resize(entries);
    for (std::size_t i = 0; i < entries; ++i)
    {
        const auto offset = kSecurityHeaderBytes + i * kSecurityAceBytes;
        auto& ace = decoded.entries[i];
        std::copy_n(bytes.begin() + offset, 16, ace.applicable.begin());
        ace.flags = ReadSecurityU32(bytes, offset + 16);
        ace.rights = ReadSecurityU32(bytes, offset + 20);
    }
    out_security = std::move(decoded);
    return true;
}

bool ApfsExtendedRecordCodec::EncodeSecurity(
    const AppleSecurityRecord& security, std::vector<std::byte>& out_bytes,
    std::string& out_error)
{
    out_bytes.clear();
    out_error.clear();
    if (security.entries.size() > kSecurityMaxEntries ||
        (security.no_acl && !security.entries.empty()))
        return Fail(out_error, "AppleSecurityCountInvalid");
    out_bytes.resize(kSecurityHeaderBytes + kSecurityAceBytes * security.entries.size());
    WriteSecurityU32(out_bytes, 0, kSecurityMagic);
    std::copy(security.owner.begin(), security.owner.end(), out_bytes.begin() + 4);
    std::copy(security.group.begin(), security.group.end(), out_bytes.begin() + 20);
    WriteSecurityU32(out_bytes, 36, security.no_acl ? kSecurityNoAcl :
        static_cast<std::uint32_t>(security.entries.size()));
    if (security.no_acl)
        std::copy(security.no_acl_flags.begin(), security.no_acl_flags.end(), out_bytes.begin() + 40);
    else
        WriteSecurityU32(out_bytes, 40, security.acl_flags);
    for (std::size_t i = 0; i < security.entries.size(); ++i)
    {
        const auto offset = kSecurityHeaderBytes + i * kSecurityAceBytes;
        const auto& ace = security.entries[i];
        std::copy(ace.applicable.begin(), ace.applicable.end(), out_bytes.begin() + offset);
        WriteSecurityU32(out_bytes, offset + 16, ace.flags);
        WriteSecurityU32(out_bytes, offset + 20, ace.rights);
    }
    return true;
}

bool ApfsExtendedRecordCodec::DecodeDataStream(const AppleExtendedField& field,
    AppleDataStreamRecord& out_stream, std::string& out_error)
{
    out_stream = {};
    out_error.clear();
    if (field.type != 8 || field.data.size() != 40)
        return Fail(out_error, "AppleDataStreamInvalid");
    out_stream = {catalog::ReadU64LE(field.data, 0).value(),
        catalog::ReadU64LE(field.data, 8).value(), catalog::ReadU64LE(field.data, 16).value(),
        catalog::ReadU64LE(field.data, 24).value(), catalog::ReadU64LE(field.data, 32).value()};
    return true;
}

static bool DecodeInodeWithAdmission(
    const catalog::BtreeRecord& record,
    AppleInodeRecord& out_inode,
    std::string& out_error, bool observational)
{
    out_inode = {};
    out_error.clear();
    std::uint64_t object_id = 0;
    if (!ParseExactKey(record, 3, 8, object_id, out_error) ||
        record.value.size() < 0x5c)
    {
        return out_error.empty()
            ? Fail(out_error, "AppleInodeRecordSizeInvalid")
            : false;
    }

    AppleInodeRecord decoded;
    DecodedCleanup cleanup{decoded};
    decoded.object_id = object_id;
    decoded.parent_id = catalog::ReadU64LE(record.value, 0x00).value_or(0);
    decoded.private_id = catalog::ReadU64LE(record.value, 0x08).value_or(0);
    decoded.create_time = catalog::ReadU64LE(record.value, 0x10).value_or(0);
    decoded.modification_time = catalog::ReadU64LE(record.value, 0x18).value_or(0);
    decoded.change_time = catalog::ReadU64LE(record.value, 0x20).value_or(0);
    decoded.access_time = catalog::ReadU64LE(record.value, 0x28).value_or(0);
    decoded.internal_flags = catalog::ReadU64LE(record.value, 0x30).value_or(0);
    const auto links = catalog::ReadU32LE(record.value, 0x38).value_or(
        std::numeric_limits<std::uint32_t>::max());
    decoded.default_protection_class = catalog::ReadU32LE(record.value, 0x3c).value_or(0);
    decoded.write_generation = catalog::ReadU32LE(record.value, 0x40).value_or(0);
    decoded.bsd_flags = catalog::ReadU32LE(record.value, 0x44).value_or(0);
    decoded.owner = catalog::ReadU32LE(record.value, 0x48).value_or(0);
    decoded.group = catalog::ReadU32LE(record.value, 0x4c).value_or(0);
    decoded.mode = catalog::ReadU16LE(record.value, 0x50).value_or(0);
    decoded.reserved_pad = catalog::ReadU16LE(record.value, 0x52).value_or(0);
    decoded.uncompressed_size = catalog::ReadU64LE(record.value, 0x54).value_or(0);
    if (decoded.parent_id == 0 || decoded.private_id == 0 ||
        links > static_cast<std::uint32_t>(std::numeric_limits<std::int32_t>::max()))
    {
        return Fail(out_error, "AppleInodeRecordIdentityInvalid");
    }
    decoded.children_or_links = static_cast<std::int32_t>(links);
    if (!DecodeExtendedFields(
            record.value, 0x5c, decoded.extended_fields, out_error, observational))
    {
        return false;
    }
    out_inode = std::move(decoded);
    return true;
}

bool ApfsExtendedRecordCodec::DecodeInode(const catalog::BtreeRecord& record,
    AppleInodeRecord& out_inode, std::string& out_error)
{
    return DecodeInodeWithAdmission(record, out_inode, out_error, false);
}

bool ApfsExtendedRecordCodec::DecodeInodeReadOnly(const catalog::BtreeRecord& record,
    AppleInodeRecord& out_inode, std::string& out_error)
{
    return DecodeInodeWithAdmission(record, out_inode, out_error, true);
}

bool ApfsExtendedRecordCodec::DecodeDirectory(
    const catalog::BtreeRecord& record, const ApfsNamePolicy& policy,
    AppleDirectoryRecord& out_directory, std::string& out_error)
{
    out_directory = {}; out_error.clear();
    struct Publication
    {
        AppleDirectoryRecord& value;
        bool complete = false;
        ~Publication()
        {
            if (complete) return;
            WipeDecodedSequence(value.name_utf8);
            for (auto& field : value.extended_fields) WipeDecodedSequence(field.data);
            value = {};
        }
    } publication{out_directory};
    const auto header = catalog::ReadU64LE(record.key, 0);
    const auto offset = policy.UsesHashedDirectoryKeys() ? 12u : 10u;
    const auto packed = policy.UsesHashedDirectoryKeys()
        ? catalog::ReadU32LE(record.key, 8).value_or(0)
        : catalog::ReadU16LE(record.key, 8).value_or(0);
    const auto length = policy.UsesHashedDirectoryKeys() ? packed & 0x3ffu : packed;
    if (!header || (*header >> 60) != 9 || !(*header & kFsObjectIdMask) ||
        record.value.size() < 18 || record.key.size() < offset || length < 2 ||
        length != record.key.size() - offset || record.key.back() != std::byte{})
        return Fail(out_error, "AppleDirectoryEnvelopeInvalid");
    auto name = ApfsNameCodec::Decode(std::span(record.key).subspan(offset, length - 1), policy);
    if (!name.ok()) return Fail(out_error, "AppleDirectoryNameHashInvalid");
    DecodedCleanup cleanup{*name.value};
    if (policy.UsesHashedDirectoryKeys() && !ApfsNameCodec::MatchesHashedDirectoryKey(*name.value, packed))
        return Fail(out_error, "AppleDirectoryNameHashInvalid");
    // Decode under a guard, returning an empty output on any failure.
    out_directory.parent_id = *header & kFsObjectIdMask;
    out_directory.file_id = catalog::ReadU64LE(record.value, 0).value();
    out_directory.date_added = catalog::ReadU64LE(record.value, 8).value();
    out_directory.flags = catalog::ReadU16LE(record.value, 16).value();
    out_directory.name_utf8 = std::move(name.value->original_utf8);
    out_directory.hashed_name = policy.UsesHashedDirectoryKeys();
    out_directory.name_hash = packed >> 10;
    if (!out_directory.file_id || out_directory.file_id > kFsObjectIdMask)
        return Fail(out_error, "AppleDirectoryTargetInvalid");
    publication.complete = DecodeExtendedFields(record.value, 18, out_directory.extended_fields, out_error);
    return publication.complete;
}

bool ApfsExtendedRecordCodec::DecodeSiblingLink(
    const catalog::BtreeRecord& record,
    AppleSiblingLinkRecord& out_link,
    std::string& out_error)
{
    out_link = {};
    out_error.clear();
    std::uint64_t inode_id = 0;
    if (!ParseExactKey(record, 5, 16, inode_id, out_error) ||
        record.value.size() < 11)
    {
        return out_error.empty()
            ? Fail(out_error, "AppleSiblingLinkSizeInvalid")
            : false;
    }
    AppleSiblingLinkRecord decoded;
    DecodedCleanup cleanup{decoded};
    decoded.inode_id = inode_id;
    decoded.sibling_id = catalog::ReadU64LE(record.key, 8).value_or(0);
    decoded.parent_id = catalog::ReadU64LE(record.value, 0).value_or(0);
    const auto name_length = catalog::ReadU16LE(record.value, 8).value_or(0);
    if (decoded.sibling_id == 0 || decoded.parent_id == 0 ||
        !DecodeTerminatedName(
            record.value, 10, name_length, decoded.name_utf8, out_error))
    {
        return out_error.empty()
            ? Fail(out_error, "AppleSiblingLinkIdentityInvalid")
            : false;
    }
    out_link = std::move(decoded);
    return true;
}

bool ApfsExtendedRecordCodec::DecodeSiblingMap(
    const catalog::BtreeRecord& record,
    AppleSiblingMapRecord& out_map,
    std::string& out_error)
{
    out_map = {};
    out_error.clear();
    std::uint64_t sibling_id = 0;
    if (!ParseExactKey(record, 12, 8, sibling_id, out_error) ||
        record.value.size() != 8)
    {
        return out_error.empty()
            ? Fail(out_error, "AppleSiblingMapSizeInvalid")
            : false;
    }
    const auto file_id = catalog::ReadU64LE(record.value, 0).value_or(0);
    if (file_id == 0)
    {
        return Fail(out_error, "AppleSiblingMapIdentityInvalid");
    }
    out_map = AppleSiblingMapRecord{sibling_id, file_id};
    return true;
}

bool ApfsExtendedRecordCodec::DecodeXattr(
    const catalog::BtreeRecord& record,
    AppleXattrRecord& out_xattr,
    std::string& out_error)
{
    out_xattr = {};
    out_error.clear();
    if (record.key.size() < 11 || record.value.size() < 4)
    {
        return Fail(out_error, "AppleXattrRecordSizeInvalid");
    }
    std::uint64_t object_id = 0;
    const auto key = catalog::ReadU64LE(record.key, 0);
    if (!key.has_value() || (key.value() >> kFsRecordTypeShift) != 4 ||
        (object_id = key.value() & kFsObjectIdMask) == 0)
    {
        return Fail(out_error, "AppleXattrRecordKeyInvalid");
    }
    const auto name_length = catalog::ReadU16LE(record.key, 8).value_or(0);
    AppleXattrRecord decoded;
    DecodedCleanup cleanup{decoded};
    decoded.object_id = object_id;
    if (!DecodeTerminatedXattrName(
            record.key, 10, name_length, decoded.name_utf8, out_error))
    {
        return false;
    }
    decoded.flags = catalog::ReadU16LE(record.value, 0).value_or(0);
    const auto embedded_length = catalog::ReadU16LE(record.value, 2).value_or(0);
    const auto storage_flags = decoded.flags &
        (kAppleXattrDataStream | kAppleXattrDataEmbedded);
    if (storage_flags == kAppleXattrDataEmbedded)
    {
        if (embedded_length != record.value.size() - 4 || embedded_length > 3804)
        {
            return Fail(out_error, "AppleXattrEmbeddedSizeInvalid");
        }
        decoded.data.assign(record.value.begin() + 4, record.value.end());
    }
    else if (storage_flags == kAppleXattrDataStream)
    {
        // External xdata is j_xattr_dstream: an ID followed by five uint64 fields.
        // xdata_len is only meaningful for embedded attributes.
        if (record.value.size() != 4 + kAppleXattrDataStreamBytes)
        {
            return Fail(out_error, "AppleXattrStreamSizeInvalid");
        }
        const auto stream_id = catalog::ReadU64LE(record.value, 4).value_or(0);
        if (stream_id == 0 || stream_id > kFsObjectIdMask)
            return Fail(out_error, "AppleXattrStreamIdentityInvalid");
        decoded.data.assign(record.value.begin() + 4, record.value.end());
    }
    else
    {
        return Fail(out_error, "AppleXattrStorageFlagsInvalid");
    }
    out_xattr = std::move(decoded);
    return true;
}

} // namespace apfsaccess::rw
