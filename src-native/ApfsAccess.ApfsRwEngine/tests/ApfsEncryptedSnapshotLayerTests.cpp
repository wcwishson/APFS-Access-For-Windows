#include "AppleReadOnlyRecordGraph.h"
#include "ApfsExtendedRecordCodec.h"
#include <iostream>
#include <stdexcept>

using namespace apfsaccess::rw;
using namespace apfsaccess::catalog;
namespace
{
unsigned checks = 0;
void Check(bool okay, const std::string& detail) { ++checks; if (!okay) throw std::runtime_error(detail); }
void Put(std::vector<std::byte>& bytes, std::size_t offset, std::uint64_t value)
{ for (unsigned i = 0; i < 8; ++i) bytes[offset + i] = std::byte(value >> (8 * i)); }

template<class Value, class Encoder> BtreeRecord Encoded(const Value& value, Encoder encode)
{
    BtreeRecord record; std::string error;
    Check(encode(value, record, error), error); return record;
}

std::vector<BtreeRecord> Files(bool clone)
{
    std::vector<BtreeRecord> rows;
    for (const auto oid : clone ? std::vector<std::uint64_t>{23, 24} : std::vector<std::uint64_t>{23})
    {
        AppleInodeRecord inode; inode.object_id = inode.private_id = oid;
        inode.parent_id = 2; inode.mode = 0100644; inode.children_or_links = 1;
        AppleExtendedField stream; stream.type = 8; stream.data.resize(40);
        Put(stream.data, 0, 4096); Put(stream.data, 8, 4096); inode.extended_fields.push_back(std::move(stream));
        rows.push_back(Encoded(inode, EncodeAppleInodeRecord));
        AppleEncryptedFileExtentRecord extent; extent.extent = {oid, 0, 4096, 98, 98, 4096};
        rows.push_back(Encoded(extent, [](const auto& value, auto& out, auto& error) {
            return EncodeAppleEncryptedFileExtentRecord(value, AppleEncryptedExtentProfile::OneKeyGenerationZero, out, error);
        }));
    }
    return rows;
}

BtreeRecord Reference(std::uint8_t kind, std::int32_t refs, std::uint64_t owner = 23)
{ return Encoded(ApplePhysicalExtentRecord{98, 1, kind, owner, refs}, EncodeApplePhysicalExtentRecord); }

bool Resolve(const std::vector<ApplePhysicalExtentRecord>& prior, const std::vector<ApplePhysicalExtentRecord>& historical,
    const std::vector<BtreeRecord>& files, const std::vector<BtreeRecord>& refs,
    std::vector<ApplePhysicalExtentRecord>& out, std::string& error)
{ return ResolveAppleEncryptedReadOnlySnapshotExtentLayer(prior, historical, files, refs, 4096, 512, out, error); }

void Cases()
{
    std::string error; std::vector<ApplePhysicalExtentRecord> first, second, current, removed;
    const auto clone = Files(true), single = Files(false);
    Check(Resolve({}, {}, clone, {Reference(kApplePhysicalExtentKindNew, 2)}, first, error), error);
    Check(first.size() == 1 && first[0].reference_count == 2 && first[0].owning_object_id == 23,
        "two clone uses are one physical interval with multiplicity two");
    Check(Resolve(first, first, single, {Reference(kApplePhysicalExtentKindUpdate, -1)}, second, error), error);
    Check(second.size() == 1 && second[0].reference_count == 1, "signed next-snapshot decrement uses prior layer");
    auto history = first; history.insert(history.end(), second.begin(), second.end());
    Check(Resolve(second, history, single, {}, current, error), error);
    Check(current.size() == 1 && current[0].reference_count == 1, "empty live layer inherits count without summing snapshot views");
    Check(Resolve(current, history, {}, {Reference(kApplePhysicalExtentKindUpdate, -1)}, removed, error) && removed.empty(),
        "last live owner removal leaves historical views protected separately");
    for (unsigned fault = 0; fault < 7; ++fault)
    {
        auto prior = first, all = first; auto files = single;
        std::vector<BtreeRecord> refs{Reference(kApplePhysicalExtentKindUpdate, -1)};
        if (fault == 0) prior.clear();
        if (fault == 1) refs = {Reference(kApplePhysicalExtentKindUpdate, -3)};
        if (fault == 2) refs = {Reference(kApplePhysicalExtentKindNew, 1)};
        if (fault == 3) refs = {Reference(kApplePhysicalExtentKindUpdate, -1, 24)};
        if (fault == 4) refs[0].value[7] |= std::byte{0xF0};
        if (fault == 5) files = clone;
        if (fault == 6) { prior.clear(); files = single; refs = {Reference(kApplePhysicalExtentKindNew, 1)}; }
        std::vector<ApplePhysicalExtentRecord> out(1);
        Check(!Resolve(prior, all, files, refs, out, error) && out.empty() && !error.empty(),
            "missing/underflow/reuse/wrong-owner/unknown-kind/multiplicity history refuses atomically: " + std::to_string(fault));
    }
    for (unsigned repeat = 0; repeat < 2; ++repeat)
    {
        std::vector<ApplePhysicalExtentRecord> out(1);
        Check(ResolveAppleSnapshotExtentLayer({}, {}, clone, {Reference(kApplePhysicalExtentKindNew, 2)},
            4096, 512, out, error) && out.size() == 1,
            "existing record-only helper still admits unchanged encoded records");
        NxSuperblock nx; ApsbVolume volume; volume.fs_flags = kFsFlagOneKey;
        Check(!CheckAppleVolumeWriteFeatures(nx, volume, error),
            "canonical mutation admission remains refused for encrypted volume");
        Check(Resolve({}, {}, clone, {Reference(kApplePhysicalExtentKindNew, 2)}, out, error) && out.size() == 1,
            "strict/read interleaving preserves independent admission");
    }
    AppleXattrRecord attribute; attribute.object_id = 23; attribute.name_utf8 = "com.apple.ResourceFork";
    attribute.flags = kAppleXattrDataStream; attribute.data.resize(kAppleXattrDataStreamBytes);
    Put(attribute.data, 0, 24); Put(attribute.data, 8, 4096); Put(attribute.data, 16, 4096);
    AppleEncryptedFileExtentRecord extent; extent.extent = {24, 0, 4096, 98, 98, 4096};
    std::vector<BtreeRecord> files{Encoded(attribute, EncodeAppleXattrRecord), Encoded(extent, [](const auto& value, auto& out, auto& detail) {
        return EncodeAppleEncryptedFileExtentRecord(value, AppleEncryptedExtentProfile::OneKeyGenerationZero, out, detail);
    })};
    std::vector<ApplePhysicalExtentRecord> out;
    Check(Resolve({}, {}, files, {Reference(kApplePhysicalExtentKindNew, 1)}, out, error), error);
    Check(out.size() == 1 && out.front().owning_object_id == 23, "external stream24 uses canonical xattr-header physical owner23");
    const auto aliases = Files(true);
    files.push_back(aliases[2]); out.resize(1);
    Check(!Resolve({}, {}, files, {Reference(kApplePhysicalExtentKindNew, 1)}, out, error) && out.empty() &&
        error == "AppleVolumeAttributeInodeAlias", "encrypted signed layer cannot bypass file/external stream alias rejection");
}
}
int main()
{
    try { Cases(); std::cout << "PASS " << checks << " checks; encrypted signed snapshot layers\n"; return 0; }
    catch (const std::exception& error) { std::cerr << "FAIL " << error.what() << '\n'; return 1; }
}
