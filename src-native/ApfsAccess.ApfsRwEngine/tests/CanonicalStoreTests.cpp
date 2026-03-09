#include "ApfsObjectMapStore.h"
#include "ApfsSpacemanStore.h"
#include "ApfsVolumeTreeStore.h"
#include "BtreeMutationCodec.h"

#include <array>
#include <cstddef>
#include <cstdint>
#include <iostream>
#include <string>
#include <vector>

namespace
{
constexpr std::size_t kCheckpointHeaderBytes = 32;
constexpr std::size_t kCheckpointChecksumOffset = 28;
constexpr std::uint32_t kCheckpointChecksumSeed = 2166136261u;
constexpr std::uint32_t kCheckpointChecksumPrime = 16777619u;

void WriteLe32(std::vector<std::byte>& buffer, std::size_t offset, std::uint32_t value)
{
    if (offset + sizeof(std::uint32_t) > buffer.size())
    {
        return;
    }

    buffer[offset + 0] = static_cast<std::byte>(value & 0xffu);
    buffer[offset + 1] = static_cast<std::byte>((value >> 8) & 0xffu);
    buffer[offset + 2] = static_cast<std::byte>((value >> 16) & 0xffu);
    buffer[offset + 3] = static_cast<std::byte>((value >> 24) & 0xffu);
}

void WriteLe64(std::vector<std::byte>& buffer, std::size_t offset, std::uint64_t value)
{
    if (offset + sizeof(std::uint64_t) > buffer.size())
    {
        return;
    }

    for (int i = 0; i < 8; ++i)
    {
        buffer[offset + static_cast<std::size_t>(i)] =
            static_cast<std::byte>((value >> (i * 8)) & 0xffu);
    }
}

std::uint32_t UpdateFnv1a(std::uint32_t hash, const std::byte* bytes, std::size_t length)
{
    for (std::size_t index = 0; index < length; ++index)
    {
        hash ^= static_cast<std::uint32_t>(std::to_integer<unsigned char>(bytes[index]));
        hash *= kCheckpointChecksumPrime;
    }
    return hash;
}

std::uint32_t ComputeCheckpointChecksum(const std::vector<std::byte>& block, std::size_t payload_bytes)
{
    if (block.size() < kCheckpointHeaderBytes || payload_bytes > (block.size() - kCheckpointHeaderBytes))
    {
        return 0;
    }

    auto hash = UpdateFnv1a(kCheckpointChecksumSeed, block.data(), kCheckpointChecksumOffset);
    if (payload_bytes > 0)
    {
        hash = UpdateFnv1a(hash, block.data() + kCheckpointHeaderBytes, payload_bytes);
    }
    return hash;
}

std::vector<std::byte> BuildObjectMapCheckpointV3Block(
    const std::vector<apfsaccess::rw::ApfsObjectMapEntry>& entries,
    std::uint64_t xid)
{
    constexpr std::array<char, 12> kMagic =
    {
        'A', 'P', 'F', 'S', 'R', 'W', 'O', 'M', 'A', 'P', '3', '\0'
    };

    constexpr std::size_t kRecordBytes = 32;
    const auto payload_bytes = entries.size() * kRecordBytes;
    std::vector<std::byte> block(kCheckpointHeaderBytes + payload_bytes, std::byte{0});

    for (std::size_t index = 0; index < kMagic.size(); ++index)
    {
        block[index] = static_cast<std::byte>(kMagic[index]);
    }
    WriteLe64(block, 12, xid);
    WriteLe32(block, 20, static_cast<std::uint32_t>(entries.size()));
    WriteLe32(block, 24, static_cast<std::uint32_t>(payload_bytes));

    std::size_t cursor = kCheckpointHeaderBytes;
    for (const auto& entry : entries)
    {
        WriteLe64(block, cursor + 0, entry.object_id);
        WriteLe64(block, cursor + 8, entry.physical_address);
        WriteLe64(block, cursor + 16, entry.logical_size);
        WriteLe64(block, cursor + 24, entry.xid);
        cursor += kRecordBytes;
    }

    WriteLe32(block, kCheckpointChecksumOffset, ComputeCheckpointChecksum(block, payload_bytes));
    return block;
}

std::vector<std::byte> BuildSpacemanCheckpointV3Block(
    const std::vector<apfsaccess::rw::ApfsExtent>& allocations,
    const std::vector<apfsaccess::rw::ApfsExtent>& free_extents,
    std::uint64_t xid)
{
    constexpr std::array<char, 12> kMagic =
    {
        'A', 'P', 'F', 'S', 'R', 'W', 'S', 'P', 'M', '3', '\0', '\0'
    };

    constexpr std::size_t kRecordBytes = 16;
    const auto total_records = allocations.size() + free_extents.size();
    const auto payload_bytes = total_records * kRecordBytes;
    std::vector<std::byte> block(kCheckpointHeaderBytes + payload_bytes, std::byte{0});

    for (std::size_t index = 0; index < kMagic.size(); ++index)
    {
        block[index] = static_cast<std::byte>(kMagic[index]);
    }
    WriteLe64(block, 12, xid);
    WriteLe32(block, 20, static_cast<std::uint32_t>(allocations.size()));
    WriteLe32(block, 24, static_cast<std::uint32_t>(free_extents.size()));

    std::size_t cursor = kCheckpointHeaderBytes;
    for (const auto& extent : allocations)
    {
        WriteLe64(block, cursor + 0, extent.physical_address);
        WriteLe64(block, cursor + 8, extent.bytes);
        cursor += kRecordBytes;
    }
    for (const auto& extent : free_extents)
    {
        WriteLe64(block, cursor + 0, extent.physical_address);
        WriteLe64(block, cursor + 8, extent.bytes);
        cursor += kRecordBytes;
    }

    WriteLe32(block, kCheckpointChecksumOffset, ComputeCheckpointChecksum(block, payload_bytes));
    return block;
}

bool Require(bool condition, const std::string& message)
{
    if (!condition)
    {
        std::cerr << "[FAIL] " << message << std::endl;
        return false;
    }
    return true;
}

bool TestObjectMapCheckpointParserRoundTrip()
{
    apfsaccess::rw::ApfsObjectMapStore store;
    std::vector<apfsaccess::rw::ApfsObjectMapEntry> entries =
    {
        { 101, 4096, 4096, 11 },
        { 102, 8192, 8192, 11 },
    };

    auto block = BuildObjectMapCheckpointV3Block(entries, 11);
    std::vector<apfsaccess::rw::ApfsObjectMapEntry> parsed;
    std::uint64_t xid = 0;
    return Require(store.TryParseCheckpointV3(block, parsed, xid), "ObjectMap parser should accept valid block") &&
           Require(xid == 11, "ObjectMap parser should preserve checkpoint xid") &&
           Require(parsed.size() == entries.size(), "ObjectMap parser should preserve entry count");
}

bool TestObjectMapCheckpointParserRejectsChecksumMismatch()
{
    apfsaccess::rw::ApfsObjectMapStore store;
    std::vector<apfsaccess::rw::ApfsObjectMapEntry> entries =
    {
        { 201, 12288, 4096, 21 },
    };
    auto block = BuildObjectMapCheckpointV3Block(entries, 21);
    if (block.size() > kCheckpointHeaderBytes)
    {
        block[kCheckpointHeaderBytes] ^= std::byte{0x7f};
    }

    std::vector<apfsaccess::rw::ApfsObjectMapEntry> parsed;
    std::uint64_t xid = 0;
    return Require(!store.TryParseCheckpointV3(block, parsed, xid), "ObjectMap parser should reject checksum mismatch");
}

bool TestObjectMapValidatorRejectsAliasedPhysicalAddress()
{
    apfsaccess::rw::ApfsObjectMapStore store;
    std::vector<apfsaccess::rw::ApfsObjectMapEntry> entries =
    {
        { 301, 16384, 4096, 31 },
        { 302, 16384, 4096, 31 },
    };

    return Require(!store.ValidateEntries(entries), "ObjectMap validator should reject aliased physical extents");
}

bool TestSpacemanValidatorRejectsOverlap()
{
    apfsaccess::rw::ApfsSpacemanStore store;
    std::vector<apfsaccess::rw::ApfsExtent> allocations =
    {
        { 4096, 4096 },
        { 6144, 4096 },
    };

    return Require(
        !store.ValidateState(allocations, {}),
        "Spaceman validator should reject overlapping allocations");
}

bool TestSpacemanValidatorRejectsAllocationFreeOverlap()
{
    apfsaccess::rw::ApfsSpacemanStore store;
    std::vector<apfsaccess::rw::ApfsExtent> allocations =
    {
        { 16384, 4096 },
    };
    std::vector<apfsaccess::rw::ApfsExtent> free_extents =
    {
        { 18432, 4096 },
    };

    return Require(
        !store.ValidateState(allocations, free_extents),
        "Spaceman validator should reject allocation/free overlap");
}

bool TestSpacemanCheckpointParserRoundTrip()
{
    apfsaccess::rw::ApfsSpacemanStore store;
    std::vector<apfsaccess::rw::ApfsExtent> allocations =
    {
        { 24576, 4096 },
        { 28672, 4096 },
    };
    std::vector<apfsaccess::rw::ApfsExtent> free_extents =
    {
        { 32768, 4096 },
    };

    auto block = BuildSpacemanCheckpointV3Block(allocations, free_extents, 55);
    std::vector<apfsaccess::rw::ApfsExtent> parsed_allocations;
    std::vector<apfsaccess::rw::ApfsExtent> parsed_free_extents;
    std::uint64_t xid = 0;

    return Require(
               store.TryParseCheckpointV3(block, parsed_allocations, parsed_free_extents, xid),
               "Spaceman parser should accept valid block") &&
           Require(xid == 55, "Spaceman parser should preserve checkpoint xid") &&
           Require(parsed_allocations.size() == allocations.size(), "Spaceman parser should preserve allocation count") &&
           Require(parsed_free_extents.size() == free_extents.size(), "Spaceman parser should preserve free-extent count");
}

bool TestSpacemanCheckpointParserRejectsChecksumMismatch()
{
    apfsaccess::rw::ApfsSpacemanStore store;
    std::vector<apfsaccess::rw::ApfsExtent> allocations =
    {
        { 36864, 4096 },
    };
    auto block = BuildSpacemanCheckpointV3Block(allocations, {}, 77);
    if (block.size() > kCheckpointHeaderBytes)
    {
        block[kCheckpointHeaderBytes] ^= std::byte{0x55};
    }

    std::vector<apfsaccess::rw::ApfsExtent> parsed_allocations;
    std::vector<apfsaccess::rw::ApfsExtent> parsed_free_extents;
    std::uint64_t xid = 0;
    return Require(
        !store.TryParseCheckpointV3(block, parsed_allocations, parsed_free_extents, xid),
        "Spaceman parser should reject checksum mismatch");
}

bool TestVolumeTreeProjectionRoundTrip()
{
    apfsaccess::rw::ApfsVolumeTreeStore store;

    std::vector<apfsaccess::rw::BtreeRecord> records;
    records.push_back(apfsaccess::rw::BtreeMutationCodec::EncodeInodeRecord(
        /*object_id=*/10,
        /*parent_object_id=*/1,
        L"docs",
        /*is_directory=*/true,
        /*logical_size=*/0,
        /*data_physical_address=*/0,
        /*timestamp_utc=*/0,
        /*xid=*/91));
    records.push_back(apfsaccess::rw::BtreeMutationCodec::EncodeInodeRecord(
        /*object_id=*/11,
        /*parent_object_id=*/10,
        L"note.txt",
        /*is_directory=*/false,
        /*logical_size=*/1024,
        /*data_physical_address=*/4096,
        /*timestamp_utc=*/0,
        /*xid=*/91));
    records.push_back(apfsaccess::rw::BtreeMutationCodec::EncodeDirectoryRecord(
        /*parent_object_id=*/1,
        L"docs",
        /*child_object_id=*/10,
        /*xid=*/91));
    records.push_back(apfsaccess::rw::BtreeMutationCodec::EncodeDirectoryRecord(
        /*parent_object_id=*/10,
        L"note.txt",
        /*child_object_id=*/11,
        /*xid=*/91));
    records.push_back(apfsaccess::rw::BtreeMutationCodec::EncodeExtentRecord(
        /*object_id=*/11,
        /*logical_offset=*/0,
        /*physical_address=*/4096,
        /*extent_bytes=*/1024,
        /*xid=*/91));

    apfsaccess::rw::ApfsVolumeTreeProjection projection{};
    std::wstring error;
    return Require(
               store.TryProjectFromBtreeRecords(records, projection, error),
               "VolumeTree projection should accept coherent inode/directory/extent records") &&
           Require(error.empty(), "VolumeTree projection should not emit an error on coherent records") &&
           Require(projection.inode_record_count == 2, "VolumeTree projection should report inode count") &&
           Require(projection.directory_entry_record_count == 2, "VolumeTree projection should report directory-entry count") &&
           Require(projection.extent_record_count == 1, "VolumeTree projection should report extent count");
}

bool TestVolumeTreeProjectionRejectsDirectoryChildMismatch()
{
    apfsaccess::rw::ApfsVolumeTreeStore store;

    std::vector<apfsaccess::rw::BtreeRecord> records;
    records.push_back(apfsaccess::rw::BtreeMutationCodec::EncodeInodeRecord(
        /*object_id=*/20,
        /*parent_object_id=*/1,
        L"data.bin",
        /*is_directory=*/false,
        /*logical_size=*/2048,
        /*data_physical_address=*/8192,
        /*timestamp_utc=*/0,
        /*xid=*/101));
    records.push_back(apfsaccess::rw::BtreeMutationCodec::EncodeDirectoryRecord(
        /*parent_object_id=*/1,
        L"mismatch.bin",
        /*child_object_id=*/20,
        /*xid=*/101));
    records.push_back(apfsaccess::rw::BtreeMutationCodec::EncodeExtentRecord(
        /*object_id=*/20,
        /*logical_offset=*/0,
        /*physical_address=*/8192,
        /*extent_bytes=*/2048,
        /*xid=*/101));

    apfsaccess::rw::ApfsVolumeTreeProjection projection{};
    std::wstring error;
    const auto ok = store.TryProjectFromBtreeRecords(records, projection, error);
    return Require(!ok, "VolumeTree projection should reject directory/child inode mismatch") &&
           Require(error == L"BtreeDirectoryChildMismatch", "VolumeTree mismatch should report BtreeDirectoryChildMismatch");
}

bool TestVolumeTreeProjectionRejectsExtentInodeMismatch()
{
    apfsaccess::rw::ApfsVolumeTreeStore store;

    std::vector<apfsaccess::rw::BtreeRecord> records;
    records.push_back(apfsaccess::rw::BtreeMutationCodec::EncodeInodeRecord(
        /*object_id=*/30,
        /*parent_object_id=*/1,
        L"payload.bin",
        /*is_directory=*/false,
        /*logical_size=*/1024,
        /*data_physical_address=*/12288,
        /*timestamp_utc=*/0,
        /*xid=*/111));
    records.push_back(apfsaccess::rw::BtreeMutationCodec::EncodeDirectoryRecord(
        /*parent_object_id=*/1,
        L"payload.bin",
        /*child_object_id=*/30,
        /*xid=*/111));
    records.push_back(apfsaccess::rw::BtreeMutationCodec::EncodeExtentRecord(
        /*object_id=*/30,
        /*logical_offset=*/0,
        /*physical_address=*/16384,
        /*extent_bytes=*/1024,
        /*xid=*/111));

    apfsaccess::rw::ApfsVolumeTreeProjection projection{};
    std::wstring error;
    const auto ok = store.TryProjectFromBtreeRecords(records, projection, error);
    return Require(!ok, "VolumeTree projection should reject extent/inode physical mismatch") &&
           Require(error == L"BtreeExtentInodeMismatch", "VolumeTree extent mismatch should report BtreeExtentInodeMismatch");
}

} // namespace

int main()
{
    bool ok = true;
    ok &= TestObjectMapCheckpointParserRoundTrip();
    ok &= TestObjectMapCheckpointParserRejectsChecksumMismatch();
    ok &= TestObjectMapValidatorRejectsAliasedPhysicalAddress();
    ok &= TestSpacemanValidatorRejectsOverlap();
    ok &= TestSpacemanValidatorRejectsAllocationFreeOverlap();
    ok &= TestSpacemanCheckpointParserRoundTrip();
    ok &= TestSpacemanCheckpointParserRejectsChecksumMismatch();
    ok &= TestVolumeTreeProjectionRoundTrip();
    ok &= TestVolumeTreeProjectionRejectsDirectoryChildMismatch();
    ok &= TestVolumeTreeProjectionRejectsExtentInodeMismatch();

    if (!ok)
    {
        return 1;
    }

    std::cout << "[PASS] CanonicalStoreTests" << std::endl;
    return 0;
}
