#include "ApfsEncryptedReadSession.h"
#include "ApfsExtendedRecordCodec.h"
#include "ApfsKeybagUnlockVectors.h"
#include "TestFixtureBuilder.h"
#include <algorithm>
#include <functional>
#include <iostream>
#include <stdexcept>

using namespace apfsaccess::catalog;
using namespace apfsaccess::testfixture;
namespace rw = apfsaccess::rw;
namespace fixture = apfsaccess::keybag_fixture;
namespace
{
unsigned cases = 0, checks = 0;
void Check(bool value, const char* reason) { ++checks; if (!value) throw std::runtime_error(reason); }
KeybagUuid Uuid(std::string_view value)
{
    KeybagUuid result{}; const auto bytes = HexToBytes(std::string(value));
    std::copy(bytes.begin(), bytes.end(), result.begin()); return result;
}
PasswordUnlockRequest Selection()
{
    PasswordUnlockRequest result; result.checkpoint_xid = 8; result.volume_oid = 101;
    result.container_uuid = Uuid(fixture::ContainerUuid); result.volume_uuid = Uuid(fixture::VolumeUuid);
    result.user_uuid = Uuid(fixture::UserUuid); result.container_bag = {901, 7}; result.volume_bag = {902, 7};
    result.length = KeybagLength::IncludesHeader; return result;
}
std::vector<BtreeRecord> Namespace(unsigned fault)
{
    std::vector<BtreeRecord> records; std::string detail;
    const auto add = [&](auto encode, const auto& value) {
        BtreeRecord record; Check(encode(value, record, detail), "canonical record fixture"); records.push_back(std::move(record));
    };
    rw::AppleInodeRecord root; root.object_id = 2; root.private_id = 2; root.parent_id = 1;
    root.mode = 0040755; root.children_or_links = 2; add(rw::EncodeAppleInodeRecord, root);
    rw::AppleInodeRecord file; file.object_id = 100; file.private_id = 100; file.parent_id = 2;
    file.mode = 0100644; file.children_or_links = fault == 1 ? 1 : 2;
    rw::AppleExtendedField stream; stream.type = 8; stream.flags = 0x20; stream.data.resize(40);
    PutU64LE(stream.data, 0, 700); PutU64LE(stream.data, 8, 4096); PutU64LE(stream.data, 16, 500);
    file.extended_fields.push_back(std::move(stream)); add(rw::EncodeAppleInodeRecord, file);
    for (unsigned index = 0; index < 2; ++index)
    {
        const auto sibling = 700 + index; const std::string name = index ? "two" : "one";
        rw::AppleDirectoryRecord entry; entry.parent_id = 2; entry.file_id = fault == 2 && index ? 999 : 100;
        entry.name_utf8 = name; entry.flags = 8;
        rw::AppleExtendedField link; link.type = 1; link.data.resize(8); PutU64LE(link.data, 0, sibling);
        entry.extended_fields.push_back(std::move(link));
        add([](const auto& value, auto& out, auto& error) {
            return rw::EncodeAppleDirectoryRecord(value, {}, out, error);
        }, entry);
        if (fault != 3 || index == 0)
            add(rw::EncodeAppleSiblingLinkRecord, rw::AppleSiblingLinkRecord{100, sibling, 2, name});
        add(rw::EncodeAppleSiblingMapRecord, rw::AppleSiblingMapRecord{sibling, 100});
    }
    add(rw::EncodeAppleFileExtentRecord, rw::AppleFileExtentRecord{100, 0, 4096, 100, 500, 4096});
    add(rw::EncodeAppleDataStreamIdRecord, rw::AppleDataStreamIdRecord{100, 1});
    add(rw::EncodeAppleXattrRecord, rw::AppleXattrRecord{fault == 4 ? 999ULL : 100ULL,
        "user.note", rw::kAppleXattrDataEmbedded, {std::byte{9}}});
    if (fault == 5) { BtreeRecord record; record.key.resize(8); record.value.resize(32); PutU64LE(record.key, 0, (10ULL << 60) | 100); records.push_back(std::move(record)); }
    if (fault == 6)
        records.erase(std::remove_if(records.begin(), records.end(), [](const auto& record) {
            const auto header = ReadU64LE(record.key, 0).value();
            return (header >> 60 != 3 && header >> 60 != 8 && header >> 60 != 6) || header == ((3ULL << 60) | 2);
        }), records.end());
    Check(rw::SortAppleBtreeRecords(records, rw::AppleBtreeKeyOrder::FileSystemCaseSensitive, detail), "fixture sort");
    return records;
}
struct Source final : ImmutableEncryptedReadSource
{
    std::vector<std::byte> image;
    std::uint64_t revision = 1;
    mutable std::function<void(std::uint64_t)> on_read;
    std::shared_ptr<ApfsReadBudget> budget = std::make_shared<ApfsReadBudget>(100000, 256ULL << 20, 1000000, 256ULL << 20);
    explicit Source(unsigned fault = 0)
    {
        BuilderStore spec; spec.authoritative_checkpoint = true; spec.block_count = 128;
        spec.uuid_hex = std::string(fixture::ContainerUuid); spec.volumes[0].uuid_hex = std::string(fixture::VolumeUuid);
        spec.volumes[0].fs_flags = kFsFlagOneKey; image = BuildStoreImage(spec);
        const auto put = [&](std::uint64_t block, const auto& bytes) { std::copy(bytes.begin(), bytes.end(), image.begin() + block * 4096); };
        const auto mutate = [&](std::uint64_t block, const auto& change) {
            std::vector<std::byte> bytes(image.begin() + block * 4096, image.begin() + (block + 1) * 4096);
            change(bytes); (void)FletcherForBlock(bytes, 4096); put(block, bytes);
        };
        const auto descriptor = ReadU64LE(image, 0x70).value();
        for (const auto block : {0ULL, descriptor + 1})
            mutate(block, [](auto& bytes) {
                PutU32LE(bytes, 24, kObjectEphemeral | kNxSuperblockObjectType);
                PutU64LE(bytes, 0x510, 60); PutU64LE(bytes, 0x518, 1);
            });
        put(60, HexToBytes(std::string(fixture::ContainerCipher))); put(61, HexToBytes(std::string(fixture::VolumeCipher)));
        const auto old_map = ReadU64LE(image, 4 * 4096 + 0x80).value();
        const auto old_tree = ReadU64LE(image, old_map * 4096 + 48).value();
        const auto snapshot_oid = ReadU64LE(image, 4 * 4096 + 0x98).value();
        put(old_tree, BuildBtreeNode({OmapRecordSpec{8293, 80, 4, 7}, OmapRecordSpec{snapshot_oid, old_map + 4, 0, 7}},
            7, 4096, 0, old_tree, 0x40000002, 11));
        std::vector<std::byte> apsb(image.begin() + 4 * 4096, image.begin() + 5 * 4096); put(90, apsb);
        mutate(90, [](auto& bytes) { PutU64LE(bytes, 16, 8); PutU64LE(bytes, 0x80, 92); });
        put(92, BuildOmap(93, 8, 4096, 92, 0x4000000B, 0x40000002));
        put(93, BuildBtreeNode({OmapRecordSpec{8293, 81, 4, 8}, OmapRecordSpec{snapshot_oid, old_map + 4, 0, 7}},
            8, 4096, 0, 93, 0x40000002, 11));
        put(94, BuildOmap(95, 8, 4096, 94, 0x4000000B, 0x40000002, 1));
        put(95, BuildBtreeNode({OmapRecordSpec{101, 90, 0, 8}}, 8, 4096, 0, 95, 0x40000002, 11));
        std::vector<std::byte> map(image.begin() + descriptor * 4096, image.begin() + (descriptor + 1) * 4096); put(descriptor + 2, map);
        const auto data_base = ReadU64LE(image, 0x78).value();
        for (unsigned index = 0; index < 3; ++index)
        {
            std::vector<std::byte> object(image.begin() + (data_base + index) * 4096, image.begin() + (data_base + index + 1) * 4096);
            put(data_base + 3 + index, object);
            mutate(data_base + 3 + index, [](auto& bytes) { PutU64LE(bytes, 16, 8); });
        }
        mutate(descriptor + 2, [&](auto& bytes) {
            PutU64LE(bytes, 8, descriptor + 2); PutU64LE(bytes, 16, 8);
            for (unsigned index = 0; index < 3; ++index) PutU64LE(bytes, 0x48 + index * 0x28, data_base + 3 + index);
        });
        std::vector<std::byte> nx(image.begin() + (descriptor + 1) * 4096, image.begin() + (descriptor + 2) * 4096); put(descriptor + 3, nx);
        mutate(descriptor + 3, [](auto& bytes) {
            PutU64LE(bytes, 16, 8); PutU64LE(bytes, 0xA0, 94); PutU64LE(bytes, 0x60, 9);
            PutU32LE(bytes, 0x80, 4); PutU32LE(bytes, 0x88, 2);
            PutU32LE(bytes, 0x84, 6); PutU32LE(bytes, 0x90, 3);
        });
        for (unsigned current = 0; current < 2; ++current)
        {
            const auto records = Namespace(current ? 0 : fault);
            std::vector<std::vector<std::byte>> keys, values;
            for (const auto& record : records) { keys.push_back(record.key); values.push_back(record.value); }
            auto bytes = BuildRawLeafNode(keys, values, current ? 8 : 7, 4096, 0, 8293, 0x10000002, 14);
            const auto block = current ? 81ULL : 80ULL;
            const auto key = HexToBytes(std::string(fixture::ExpectedVek));
            for (std::size_t at = 0; at < bytes.size(); at += 512)
            {
                std::array<std::byte, 16> tweak{}; const auto unit = block * 8 + at / 512;
                for (unsigned n = 0; n < 8; ++n) tweak[n] = std::byte(unit >> (8 * n));
                auto encrypted = apfsaccess::crypto::XtsTransform(key, tweak, std::span(bytes).subspan(at, 512), apfsaccess::crypto::XtsDirection::Encrypt);
                Check(static_cast<bool>(encrypted), "canonical encrypted fixture");
                std::copy(encrypted.bytes.Bytes().begin(), encrypted.bytes.Bytes().end(), bytes.begin() + at);
            }
            put(block, bytes);
        }
    }
    std::uint64_t SizeBytes() const override { return image.size(); }
    std::uint64_t Revision() const override { return revision; }
    std::string SourceIdentity() const override { return "retained-namespace-canonical-test"; }
    std::shared_ptr<ApfsReadBudget> ReadBudget() const override { return budget; }
    bool Read(std::uint64_t at, std::size_t size, std::vector<std::byte>& out) const override
    {
        out.clear(); if (!budget->Read(size) || at > image.size() || size > image.size() - at) return false;
        if (on_read) on_read(at); out.assign(image.begin() + at, image.begin() + at + size); return true;
    }
};
std::unique_ptr<ApfsEncryptedReadSession> Open(const std::shared_ptr<Source>& source, std::uint64_t xid = 8)
{
    std::string detail;
    auto checkpoint = LoadContainerCheckpointView(*source, 0, source->SizeBytes(), detail, xid);
    if (!checkpoint) throw std::runtime_error("fixture checkpoint:" + detail);
    UnlockError inspected;
    const auto bags = InspectPasswordKeybagMetadata(*source, 101, KeybagLength::IncludesHeader, inspected);
    if (!bags) throw std::runtime_error("fixture keybag metadata:" + std::to_string(static_cast<unsigned>(inspected)));
    Check(bags->selection.checkpoint_xid == xid, "fixture exact latest checkpoint");
    PasswordUnlockBudget attempts; EncryptedReadError error; UnlockError unlock;
    auto selection = Selection(); selection.checkpoint_xid = xid;
    auto session = ApfsEncryptedReadSession::Unlock(source, source->SourceIdentity(), source->Revision(), selection,
        HexToBytes(std::string(fixture::Password)), attempts, error, unlock);
    if (!session) throw std::runtime_error("canonical current unlock " + std::to_string(static_cast<unsigned>(error)) +
        ":" + std::to_string(static_cast<unsigned>(unlock)));
    Check(session != nullptr, "canonical current unlock"); return session;
}
#ifndef APFS_RETAINED_NAMESPACE_FIXTURES_ONLY
void Run()
{
    for (unsigned fault = 0; fault <= 6; ++fault)
    {
        auto source = std::make_shared<Source>(fault); auto session = Open(source); std::string error;
        auto context = session->CreateRetainedVerificationContext(7, error); Check(context != nullptr, error.c_str());
        EncryptedNamespaceInfo current; Check(session->GetNamespaceInfo(current) == EncryptedReadError::None, "current complete despite historical fault");
        EncryptedNamespaceInfo result; result.inode_count = 999;
        const auto status = session->ValidateRetainedNamespace(*context, result, error);
        const auto expected = fault == 0 ? EncryptedReadError::None : fault == 5 ? EncryptedReadError::UnsupportedEncryptionLayout :
            fault == 6 ? EncryptedReadError::NamespaceUnavailable : EncryptedReadError::MetadataIntegrityFailure;
        Check(status == expected, ("historical typed namespace status " + std::to_string(fault) + ":" + error).c_str());
        Check(result.inode_count == (fault ? 0 : 2) && result.entry_count == (fault ? 0 : 2), "atomic exact historical counts");
        EncryptedNamespaceInfo after; Check(session->GetNamespaceInfo(after) == EncryptedReadError::None && after.inode_count == current.inode_count &&
            after.entry_count == current.entry_count, "historical projection preserves current namespace");
        if (!fault) Check(session->ValidateRetainedNamespace(*context, result, error) == EncryptedReadError::None, "warm historical projection");
        ++cases;
    }
    for (unsigned fault = 0; fault < 6; ++fault)
    {
        auto source = std::make_shared<Source>(); auto session = Open(source); std::string error;
        auto context = session->CreateRetainedVerificationContext(7, error); Check(context != nullptr, "control context");
        EncryptedNamespaceInfo result; result.inode_count = 999; EncryptedReadError status;
        if (fault == 0) { auto other = Open(source); status = other->ValidateRetainedNamespace(*context, result, error); }
        else if (fault == 1) { EncryptedReadError e; auto current = session->CreateMetadataReadContext(e); status = session->ValidateRetainedNamespace(*current, result, error); }
        else
        {
            if (fault == 2) session->Close();
            if (fault == 3) source->on_read = [&](auto at) { if (at == 80 * 4096) session->Cancel(); };
            if (fault == 4) ++source->revision;
            if (fault == 5) source->budget->LimitRemainingTo(1, 4096, 100, 4096);
            status = session->ValidateRetainedNamespace(*context, result, error);
        }
        const EncryptedReadError expected[] = {EncryptedReadError::SourceIdentityMismatch, EncryptedReadError::InvalidArgument,
            EncryptedReadError::Closed, EncryptedReadError::Cancelled, EncryptedReadError::SourceIdentityMismatch, EncryptedReadError::ResourceLimit};
        Check(status == expected[fault] && result.inode_count == 0 && result.entry_count == 0,
            ("bound refusal has no namespace counts " + std::to_string(fault) + ":" + std::to_string(static_cast<unsigned>(status)) + ":" + error).c_str());
        ++cases;
    }
}
}
int main() try { Run(); std::cout << "PASS " << cases << " cases / " << checks << " checks\n"; return 0; }
catch (const std::exception& e) { std::cerr << "FAIL " << e.what() << " after " << checks << " checks\n"; return 1; }
#else
}
#endif
