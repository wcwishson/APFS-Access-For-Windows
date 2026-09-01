#include "CheckpointDelta.h"

#include <algorithm>
#include <cstdint>
#include <iostream>
#include <string>
#include <unordered_map>
#include <vector>

namespace
{
bool Require(bool condition, const std::string& message)
{
    if (!condition)
    {
        std::cerr << "[FAIL] " << message << std::endl;
        return false;
    }
    return true;
}

apfsaccess::rw::CheckpointDelta BuildSampleDelta(std::uint64_t base_xid, std::uint64_t target_xid)
{
    apfsaccess::rw::CheckpointDelta delta;
    delta.volume_identity = "volume-A";
    delta.base_xid = base_xid;
    delta.target_xid = target_xid;
    delta.object_map_updates.push_back({ 42, 0x10000, 4096, target_xid, false });
    delta.object_map_updates.push_back({ 43, 0, 0, target_xid, true });
    delta.spaceman_allocations.push_back({ 0x10000, 4096 });
    delta.spaceman_deallocations.push_back({ 0x20000, 4096 });
    delta.inode_updates.push_back(
        {
            42,
            2,
            L"sample.bin",
            L"\\sample.bin",
            false,
            4096,
            0x10000,
            target_xid,
            123456789,
            false,
        });
    delta.directory_link_updates.push_back({ 2, L"sample.bin", 42, target_xid, false });
    delta.btree_records.push_back(
        apfsaccess::rw::BtreeMutationCodec::EncodeExtentRecord(
            42,
            0,
            0x10000,
            4096,
            target_xid));
    return delta;
}

bool TestRoundTrip()
{
    const auto delta = BuildSampleDelta(10, 11);
    const auto bytes = apfsaccess::rw::CheckpointDeltaCodec::Encode(delta);
    const auto parsed = apfsaccess::rw::CheckpointDeltaCodec::Decode(bytes, "volume-A");

    bool ok = true;
    ok &= Require(parsed.status == apfsaccess::rw::CheckpointDeltaParseStatus::Ok, "RoundTrip: parse should succeed");
    ok &= Require(parsed.delta.has_value(), "RoundTrip: parse should return delta");
    if (!parsed.delta.has_value())
    {
        return false;
    }

    ok &= Require(parsed.delta->base_xid == 10, "RoundTrip: base xid should match");
    ok &= Require(parsed.delta->target_xid == 11, "RoundTrip: target xid should match");
    ok &= Require(parsed.delta->object_map_updates.size() == 2, "RoundTrip: object map updates should match");
    ok &= Require(parsed.delta->spaceman_allocations.size() == 1, "RoundTrip: allocation count should match");
    ok &= Require(parsed.delta->spaceman_deallocations.size() == 1, "RoundTrip: deallocation count should match");
    ok &= Require(parsed.delta->inode_updates.size() == 1, "RoundTrip: inode count should match");
    ok &= Require(parsed.delta->inode_updates.front().full_path == L"\\sample.bin", "RoundTrip: inode path should match");
    ok &= Require(parsed.delta->directory_link_updates.size() == 1, "RoundTrip: directory link count should match");
    ok &= Require(parsed.delta->btree_records.size() == 1, "RoundTrip: btree record count should match");
    return ok;
}

bool TestRoundTripLongUtf16Paths()
{
    auto delta = BuildSampleDelta(10, 11);
    delta.inode_updates.front().name = L"long-name.bin";
    delta.inode_updates.front().full_path = L"\\";
    for (int index = 0; index < 80; ++index)
    {
        delta.inode_updates.front().full_path += L"segment";
        delta.inode_updates.front().full_path += std::to_wstring(index);
        delta.inode_updates.front().full_path += L"\\";
    }
    delta.inode_updates.front().full_path += delta.inode_updates.front().name;
    delta.directory_link_updates.front().entry_name = delta.inode_updates.front().name;

    const auto bytes = apfsaccess::rw::CheckpointDeltaCodec::Encode(delta);
    const auto parsed = apfsaccess::rw::CheckpointDeltaCodec::Decode(bytes, "volume-A");

    bool ok = true;
    ok &= Require(!bytes.empty(), "RoundTripLongUtf16: encoded delta should not be empty");
    ok &= Require(parsed.status == apfsaccess::rw::CheckpointDeltaParseStatus::Ok, "RoundTripLongUtf16: parse should succeed");
    ok &= Require(parsed.delta.has_value(), "RoundTripLongUtf16: parse should return delta");
    if (!parsed.delta.has_value())
    {
        return false;
    }

    ok &= Require(
        parsed.delta->inode_updates.front().full_path == delta.inode_updates.front().full_path,
        "RoundTripLongUtf16: full path should round-trip without temporary string buffers");
    ok &= Require(
        parsed.delta->directory_link_updates.front().entry_name == L"long-name.bin",
        "RoundTripLongUtf16: directory link name should round-trip");
    return ok;
}

bool TestRejectsWrongVolume()
{
    const auto delta = BuildSampleDelta(10, 11);
    const auto bytes = apfsaccess::rw::CheckpointDeltaCodec::Encode(delta);
    const auto parsed = apfsaccess::rw::CheckpointDeltaCodec::Decode(bytes, "volume-B");
    return Require(
        parsed.status == apfsaccess::rw::CheckpointDeltaParseStatus::WrongVolume,
        "WrongVolume: parse should reject mismatched volume identity");
}

bool TestRejectsChecksumDamage()
{
    const auto delta = BuildSampleDelta(10, 11);
    auto bytes = apfsaccess::rw::CheckpointDeltaCodec::Encode(delta);
    if (bytes.size() > 48)
    {
        bytes[48] = static_cast<std::byte>(std::to_integer<unsigned char>(bytes[48]) ^ 0x40u);
    }
    const auto parsed = apfsaccess::rw::CheckpointDeltaCodec::Decode(bytes, "volume-A");
    return Require(
        parsed.status == apfsaccess::rw::CheckpointDeltaParseStatus::InvalidChecksum,
        "ChecksumDamage: parse should reject corrupted bytes");
}

bool TestRejectsInvalidXid()
{
    const auto delta = BuildSampleDelta(10, 12);
    const auto bytes = apfsaccess::rw::CheckpointDeltaCodec::Encode(delta);
    const auto parsed = apfsaccess::rw::CheckpointDeltaCodec::Decode(bytes, "volume-A");
    return Require(
        parsed.status == apfsaccess::rw::CheckpointDeltaParseStatus::InvalidXid,
        "InvalidXid: parse should reject non-contiguous xid");
}

bool TestRejectsTruncatedTail()
{
    const auto delta = BuildSampleDelta(10, 11);
    auto bytes = apfsaccess::rw::CheckpointDeltaCodec::Encode(delta);
    bytes.resize(bytes.size() - 7);
    const auto parsed = apfsaccess::rw::CheckpointDeltaCodec::Decode(bytes, "volume-A");
    return Require(
        parsed.status == apfsaccess::rw::CheckpointDeltaParseStatus::InvalidChecksum,
        "TruncatedTail: parse should reject torn tail before trusting records");
}

bool TestCompactChain()
{
    auto first = BuildSampleDelta(10, 11);
    auto second = BuildSampleDelta(11, 12);
    second.object_map_updates.front().physical_address = 0x18000;
    second.inode_updates.front().data_physical_address = 0x18000;
    second.directory_link_updates.front().entry_name = L"renamed.bin";

    const std::vector<apfsaccess::rw::CheckpointDelta> chain{ first, second };
    const auto compacted = apfsaccess::rw::CheckpointDeltaCodec::CompactChain(chain, "volume-A", 10);
    bool ok = true;
    ok &= Require(compacted.status == apfsaccess::rw::CheckpointDeltaParseStatus::Ok, "CompactChain: compact should succeed");
    ok &= Require(compacted.target_xid == 12, "CompactChain: target xid should advance to chain tail");
    ok &= Require(compacted.compacted.base_xid == 10, "CompactChain: base xid should remain original");
    ok &= Require(compacted.compacted.target_xid == 12, "CompactChain: compacted target xid should match tail");
    ok &= Require(compacted.compacted.object_map_updates.size() == 2, "CompactChain: object-map updates should collapse by object id");
    ok &= Require(compacted.compacted.inode_updates.size() == 1, "CompactChain: inode updates should collapse by object id");
    if (!compacted.compacted.inode_updates.empty())
    {
        ok &= Require(
            compacted.compacted.inode_updates.front().data_physical_address == 0x18000,
            "CompactChain: latest inode update should win");
    }
    ok &= Require(
        compacted.compacted.directory_link_updates.size() == 2,
        "CompactChain: distinct directory names should both remain for loader reconciliation");
    return ok;
}

bool TestCompactRejectsGap()
{
    const std::vector<apfsaccess::rw::CheckpointDelta> chain
    {
        BuildSampleDelta(10, 11),
        BuildSampleDelta(12, 13),
    };
    const auto compacted = apfsaccess::rw::CheckpointDeltaCodec::CompactChain(chain, "volume-A", 10);
    return Require(
        compacted.status == apfsaccess::rw::CheckpointDeltaParseStatus::InvalidXid,
        "CompactGap: compact should reject non-contiguous chain");
}

apfsaccess::rw::CheckpointDeltaState BuildBaseState()
{
    apfsaccess::rw::CheckpointDeltaState state;
    state.volume_identity = "volume-A";
    state.checkpoint_xid = 10;
    state.object_map.emplace(41, apfsaccess::rw::CheckpointDeltaObjectMapUpdate{ 41, 0x08000, 4096, 10, false });
    state.object_map.emplace(43, apfsaccess::rw::CheckpointDeltaObjectMapUpdate{ 43, 0x20000, 4096, 10, false });
    state.spaceman_allocations.push_back({ 0x08000, 4096 });
    state.spaceman_allocations.push_back({ 0x20000, 4096 });
    state.inodes.emplace(
        43,
        apfsaccess::rw::CheckpointDeltaInodeUpdate
        {
            43,
            2,
            L"old.bin",
            L"\\old.bin",
            false,
            4096,
            0x20000,
            10,
            99,
            false,
        });
    state.directory_links.emplace(
        L"2:old.bin",
        apfsaccess::rw::CheckpointDeltaDirectoryLinkUpdate{ 2, L"old.bin", 43, 10, false });
    const auto record = apfsaccess::rw::BtreeMutationCodec::EncodeExtentRecord(43, 0, 0x20000, 4096, 10);
    state.btree_records.emplace(
        std::string(
            1,
            static_cast<char>(record.kind)) +
            std::string(reinterpret_cast<const char*>(record.key.data()), record.key.size()),
        record);
    return state;
}

bool TestApplyDeltaUpdatesAndTombstones()
{
    auto state = BuildBaseState();
    auto delta = BuildSampleDelta(10, 11);

    const auto status = apfsaccess::rw::CheckpointDeltaCodec::ApplyDelta(state, delta);
    bool ok = true;
    ok &= Require(status == apfsaccess::rw::CheckpointDeltaParseStatus::Ok, "ApplyDelta: apply should succeed");
    ok &= Require(state.checkpoint_xid == 11, "ApplyDelta: checkpoint xid should advance");
    ok &= Require(state.object_map.contains(42), "ApplyDelta: live object-map update should be present");
    ok &= Require(!state.object_map.contains(43), "ApplyDelta: object-map tombstone should remove base object");
    ok &= Require(state.inodes.contains(42), "ApplyDelta: live inode update should be present");
    ok &= Require(state.directory_links.contains(L"2:sample.bin"), "ApplyDelta: live directory link should be present");
    ok &= Require(state.spaceman_allocations.size() == 2, "ApplyDelta: allocation/deallocation should update free-space view");
    ok &= Require(
        std::none_of(
            state.spaceman_allocations.begin(),
            state.spaceman_allocations.end(),
            [](const auto& extent)
            {
                return extent.physical_address == 0x20000 && extent.bytes == 4096;
            }),
        "ApplyDelta: deallocation should remove matching base extent");
    return ok;
}

bool TestApplyDeltaRejectsWithoutPartialMutation()
{
    auto state = BuildBaseState();
    auto delta = BuildSampleDelta(10, 11);
    delta.spaceman_deallocations.push_back({ 0xDEAD0000, 4096 });

    const auto before = state;
    const auto status = apfsaccess::rw::CheckpointDeltaCodec::ApplyDelta(state, delta);
    bool ok = true;
    ok &= Require(
        status == apfsaccess::rw::CheckpointDeltaParseStatus::InvalidRecord,
        "ApplyDeltaPartial: missing deallocation source should fail");
    ok &= Require(state.checkpoint_xid == before.checkpoint_xid, "ApplyDeltaPartial: xid should not change on failure");
    ok &= Require(state.object_map.size() == before.object_map.size(), "ApplyDeltaPartial: object map should not change on failure");
    ok &= Require(state.spaceman_allocations.size() == before.spaceman_allocations.size(), "ApplyDeltaPartial: allocations should not change on failure");
    ok &= Require(state.inodes.size() == before.inodes.size(), "ApplyDeltaPartial: inodes should not change on failure");
    return ok;
}

bool TestApplyChainRejectsGapWithoutPartialMutation()
{
    auto state = BuildBaseState();
    const auto before = state;
    const std::vector<apfsaccess::rw::CheckpointDelta> chain
    {
        BuildSampleDelta(10, 11),
        BuildSampleDelta(12, 13),
    };

    const auto status = apfsaccess::rw::CheckpointDeltaCodec::ApplyChain(state, chain);
    bool ok = true;
    ok &= Require(
        status == apfsaccess::rw::CheckpointDeltaParseStatus::InvalidXid,
        "ApplyChainGap: chain gap should fail");
    ok &= Require(state.checkpoint_xid == before.checkpoint_xid, "ApplyChainGap: xid should not change on failure");
    ok &= Require(!state.object_map.contains(42), "ApplyChainGap: earlier valid delta should not partially apply");
    return ok;
}

bool TestDecodeChainFullOnly()
{
    const auto bytes = apfsaccess::rw::CheckpointDeltaCodec::EncodeChain({}, "volume-A", 10);
    const auto parsed = apfsaccess::rw::CheckpointDeltaCodec::DecodeChain(bytes, "volume-A", 10);

    bool ok = true;
    ok &= Require(!bytes.empty(), "DecodeChainFullOnly: encoded chain should not be empty");
    ok &= Require(parsed.status == apfsaccess::rw::CheckpointDeltaParseStatus::Ok, "DecodeChainFullOnly: parse should succeed");
    ok &= Require(parsed.base_xid == 10, "DecodeChainFullOnly: base xid should match");
    ok &= Require(parsed.target_xid == 10, "DecodeChainFullOnly: target xid should equal base xid");
    ok &= Require(parsed.deltas.empty(), "DecodeChainFullOnly: no deltas should be present");
    return ok;
}

bool TestDecodeChainFullPlusOneDelta()
{
    auto state = BuildBaseState();
    const std::vector<apfsaccess::rw::CheckpointDelta> chain{ BuildSampleDelta(10, 11) };
    const auto bytes = apfsaccess::rw::CheckpointDeltaCodec::EncodeChain(chain, "volume-A", 10);
    const auto parsed = apfsaccess::rw::CheckpointDeltaCodec::DecodeChain(bytes, "volume-A", 10);

    bool ok = true;
    ok &= Require(parsed.status == apfsaccess::rw::CheckpointDeltaParseStatus::Ok, "DecodeChainOne: parse should succeed");
    ok &= Require(parsed.target_xid == 11, "DecodeChainOne: target xid should advance");
    ok &= Require(parsed.deltas.size() == 1, "DecodeChainOne: one delta should be present");
    ok &= Require(
        apfsaccess::rw::CheckpointDeltaCodec::ApplyChain(state, parsed.deltas) == apfsaccess::rw::CheckpointDeltaParseStatus::Ok,
        "DecodeChainOne: decoded chain should apply");
    ok &= Require(state.checkpoint_xid == 11, "DecodeChainOne: applied state should advance");
    ok &= Require(state.object_map.contains(42), "DecodeChainOne: applied object should be present");
    return ok;
}

bool TestDecodeChainManyDeltas()
{
    auto state = BuildBaseState();
    auto first = BuildSampleDelta(10, 11);
    auto second = BuildSampleDelta(11, 12);
    second.object_map_updates.front().physical_address = 0x18000;
    second.inode_updates.front().data_physical_address = 0x18000;
    second.spaceman_allocations.front() = { 0x18000, 4096 };
    second.spaceman_deallocations.front() = { 0x10000, 4096 };

    const std::vector<apfsaccess::rw::CheckpointDelta> chain{ first, second };
    const auto bytes = apfsaccess::rw::CheckpointDeltaCodec::EncodeChain(chain, "volume-A", 10);
    const auto parsed = apfsaccess::rw::CheckpointDeltaCodec::DecodeChain(bytes, "volume-A", 10);

    bool ok = true;
    ok &= Require(parsed.status == apfsaccess::rw::CheckpointDeltaParseStatus::Ok, "DecodeChainMany: parse should succeed");
    ok &= Require(parsed.deltas.size() == 2, "DecodeChainMany: two deltas should be present");
    ok &= Require(
        apfsaccess::rw::CheckpointDeltaCodec::ApplyChain(state, parsed.deltas) == apfsaccess::rw::CheckpointDeltaParseStatus::Ok,
        "DecodeChainMany: decoded chain should apply");
    ok &= Require(state.checkpoint_xid == 12, "DecodeChainMany: applied state should advance to tail");
    ok &= Require(state.object_map.at(42).physical_address == 0x18000, "DecodeChainMany: latest object-map update should win");
    ok &= Require(state.inodes.at(42).data_physical_address == 0x18000, "DecodeChainMany: latest inode update should win");
    return ok;
}

bool TestDecodeChainRejectsCorruption()
{
    const std::vector<apfsaccess::rw::CheckpointDelta> chain{ BuildSampleDelta(10, 11) };
    auto bytes = apfsaccess::rw::CheckpointDeltaCodec::EncodeChain(chain, "volume-A", 10);
    if (bytes.size() > 64)
    {
        bytes[64] = static_cast<std::byte>(std::to_integer<unsigned char>(bytes[64]) ^ 0x20u);
    }

    const auto parsed = apfsaccess::rw::CheckpointDeltaCodec::DecodeChain(bytes, "volume-A", 10);
    return Require(
        parsed.status == apfsaccess::rw::CheckpointDeltaParseStatus::InvalidChecksum,
        "DecodeChainCorrupt: checksum damage should be rejected");
}

bool TestEncodeChainRejectsGap()
{
    const std::vector<apfsaccess::rw::CheckpointDelta> chain
    {
        BuildSampleDelta(10, 11),
        BuildSampleDelta(12, 13),
    };
    const auto bytes = apfsaccess::rw::CheckpointDeltaCodec::EncodeChain(chain, "volume-A", 10);
    return Require(bytes.empty(), "EncodeChainGap: encoder should reject missing delta");
}

bool TestDecodeChainRejectsWrongVolume()
{
    const std::vector<apfsaccess::rw::CheckpointDelta> chain{ BuildSampleDelta(10, 11) };
    const auto bytes = apfsaccess::rw::CheckpointDeltaCodec::EncodeChain(chain, "volume-A", 10);
    const auto parsed = apfsaccess::rw::CheckpointDeltaCodec::DecodeChain(bytes, "volume-B", 10);
    return Require(
        parsed.status == apfsaccess::rw::CheckpointDeltaParseStatus::WrongVolume,
        "DecodeChainWrongVolume: parser should reject wrong volume");
}

bool TestCompactChainSummaryTracksLatestState()
{
    auto first = BuildSampleDelta(10, 11);
    auto second = BuildSampleDelta(11, 12);
    second.object_map_updates.front().physical_address = 0x18000;
    second.inode_updates.front().data_physical_address = 0x18000;
    second.spaceman_allocations.front() = { 0x18000, 4096 };
    second.spaceman_deallocations.front() = { 0x10000, 4096 };

    const std::vector<apfsaccess::rw::CheckpointDelta> chain{ first, second };
    const auto compacted = apfsaccess::rw::CheckpointDeltaCodec::CompactChain(chain, "volume-A", 10);
    bool ok = true;
    ok &= Require(compacted.status == apfsaccess::rw::CheckpointDeltaParseStatus::Ok, "CompactSummary: compact should succeed");
    ok &= Require(compacted.compacted.base_xid == 10, "CompactSummary: base xid should remain original");
    ok &= Require(compacted.compacted.target_xid == 12, "CompactSummary: target xid should advance to tail");
    ok &= Require(compacted.compacted.object_map_updates.size() == 2, "CompactSummary: object-map updates should collapse by id");
    ok &= Require(compacted.compacted.inode_updates.size() == 1, "CompactSummary: inode updates should collapse by id");
    if (!compacted.compacted.object_map_updates.empty())
    {
        const auto latest = std::find_if(
            compacted.compacted.object_map_updates.begin(),
            compacted.compacted.object_map_updates.end(),
            [](const auto& update)
            {
                return update.object_id == 42;
            });
        ok &= Require(latest != compacted.compacted.object_map_updates.end(), "CompactSummary: object 42 should remain");
        if (latest != compacted.compacted.object_map_updates.end())
        {
            ok &= Require(latest->physical_address == 0x18000, "CompactSummary: latest object-map update should win");
        }
    }
    if (!compacted.compacted.inode_updates.empty())
    {
        ok &= Require(
            compacted.compacted.inode_updates.front().data_physical_address == 0x18000,
            "CompactSummary: latest inode update should win");
    }
    ok &= Require(compacted.compacted.spaceman_allocations.size() == 2, "CompactSummary: allocation history should remain ordered");
    ok &= Require(compacted.compacted.spaceman_deallocations.size() == 2, "CompactSummary: deallocation history should remain ordered");
    return ok;
}
} // namespace

int main()
{
    bool ok = true;
    ok &= TestRoundTrip();
    ok &= TestRoundTripLongUtf16Paths();
    ok &= TestRejectsWrongVolume();
    ok &= TestRejectsChecksumDamage();
    ok &= TestRejectsInvalidXid();
    ok &= TestRejectsTruncatedTail();
    ok &= TestCompactChain();
    ok &= TestCompactRejectsGap();
    ok &= TestApplyDeltaUpdatesAndTombstones();
    ok &= TestApplyDeltaRejectsWithoutPartialMutation();
    ok &= TestApplyChainRejectsGapWithoutPartialMutation();
    ok &= TestDecodeChainFullOnly();
    ok &= TestDecodeChainFullPlusOneDelta();
    ok &= TestDecodeChainManyDeltas();
    ok &= TestDecodeChainRejectsCorruption();
    ok &= TestEncodeChainRejectsGap();
    ok &= TestDecodeChainRejectsWrongVolume();
    ok &= TestCompactChainSummaryTracksLatestState();

    if (!ok)
    {
        return 1;
    }

    std::cout << "[PASS] CheckpointDeltaTests" << std::endl;
    return 0;
}
