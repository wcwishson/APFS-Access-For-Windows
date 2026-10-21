#include "VolumeGptGeometry.h"
#include <zlib.h>
#include <set>

namespace apfsaccess::rw::volume_geometry
{
namespace
{
using format_evidence::Need;
std::uint64_t N(std::span<const std::byte> b, std::size_t at)
{ const auto value = catalog::ReadU64LE(b, at); Need(value.has_value(), "VolumeGptTruncated"); return *value; }
std::uint32_t D(std::span<const std::byte> b, std::size_t at)
{ const auto value = catalog::ReadU32LE(b, at); Need(value.has_value(), "VolumeGptTruncated"); return *value; }
void Put(Bytes& b, std::size_t at, std::uint64_t value, unsigned size = 8)
{ Need(at <= b.size() && size <= b.size() - at, "VolumeGptBounds"); for (unsigned i = 0; i < size; ++i) b[at + i] = std::byte(value >> (8 * i)); }
bool Zero(std::span<const std::byte> bytes)
{ return std::all_of(bytes.begin(), bytes.end(), [](auto b) { return b == std::byte{}; }); }
std::array<std::byte, 16> Guid(std::span<const std::byte> bytes, std::size_t at)
{
    Need(at <= bytes.size() && bytes.size() - at >= 16, "VolumeGptGuidBounds");
    constexpr unsigned order[] = {3,2,1,0,5,4,7,6,8,9,10,11,12,13,14,15}; std::array<std::byte,16> out{};
    for (unsigned i = 0; i < 16; ++i) out[i] = bytes[at + order[i]]; return out;
}
struct Header { std::uint64_t first, last, array_lba; std::uint32_t count, entry_bytes; };
Header HeaderOf(const Bytes& bytes, std::uint64_t here, std::uint64_t other, const RawSnapshotBinding& binding)
{
    const auto sector = binding.media.logical_sector_bytes;
    Need(bytes.size() == sector && N(bytes,0) == 0x5452415020494645ull && D(bytes,8) == 0x10000 && D(bytes,12) == 92 &&
        D(bytes,20) == 0 && N(bytes,24) == here && N(bytes,32) == other && Guid(bytes,56) == binding.media.disk_guid,
        "VolumeGptHeaderProfileInvalid");
    auto crc = Bytes(bytes.begin(), bytes.begin() + 92); Put(crc,16,0,4);
    Need(Crc32(crc) == D(bytes,16), "VolumeGptHeaderChecksumInvalid");
    Header result{N(bytes,40),N(bytes,48),N(bytes,72),D(bytes,80),D(bytes,84)};
    Need(result.first <= result.last && result.count >= 128 && result.count <= 4096 && result.entry_bytes == 128,
        "VolumeGptArrayProfileInvalid");
    return result;
}
bool ValidHeader(const Bytes& bytes)
{
    if (bytes.size() < 92 || N(bytes,0) != 0x5452415020494645ull || D(bytes,12) < 92 || D(bytes,12) > bytes.size()) return false;
    auto crc = Bytes(bytes.begin(), bytes.begin() + D(bytes,12)); Put(crc,16,0,4); return Crc32(crc) == D(bytes,16);
}
void HeaderChecksum(Bytes& header, const Bytes& array, std::uint64_t count)
{ Put(header,88,Crc32(std::span(array).first(static_cast<std::size_t>(count))),4); Put(header,16,0,4); Put(header,16,Crc32(std::span(header).first(92)),4); }
void ExactRead(const catalog::RandomAccessSource& source, std::uint64_t offset, std::size_t size, Bytes& out)
{ Need(source.Read(offset,size,out) && out.size() == size, "VolumeGptReadFailed"); }
}
std::uint32_t Crc32(std::span<const std::byte> bytes)
{ return static_cast<std::uint32_t>(crc32_z(0, reinterpret_cast<const Bytef*>(bytes.data()), bytes.size())); }
Plan Build(Snapshot snapshot)
{
    Plan plan; plan.snapshot = std::move(snapshot); auto& s = plan.snapshot;
    std::string error; const auto& before = s.original.binding; const auto& media = before.media;
    const bool window = s.profile == Profile::ContainerWindow;
    Need((s.profile == Profile::LegacyPartition || s.profile == Profile::Partition || window) &&
        ValidateVolumePhysicalPolicy(before,s.original.instance,error) &&
        (window ? media.limit_bytes <= media.partition_length_bytes && s.target_bytes <= media.partition_length_bytes :
            media.limit_bytes == media.partition_length_bytes) &&
        s.target_bytes >= 1048576 && s.target_bytes % 4096 == 0 && s.target_bytes != media.limit_bytes &&
        s.target_bytes <= media.disk_size_bytes - media.base_offset_bytes, "VolumeGptResizeScopeInvalid");
    const auto sector = media.logical_sector_bytes; const auto disk_last = media.disk_size_bytes / sector - 1;
    const auto primary = HeaderOf(s.primary_header,1,disk_last,before), backup = HeaderOf(s.backup_header,disk_last,1,before);
    Need(primary.first == backup.first && primary.last == backup.last && primary.count == backup.count &&
        primary.entry_bytes == backup.entry_bytes && primary.first >= 2 && primary.last < disk_last,
        "VolumeGptCopiesDisagree");
    const auto array_bytes = static_cast<std::uint64_t>(primary.count) * primary.entry_bytes;
    const auto array_sectors = (array_bytes + sector - 1) / sector;
    Need(primary.array_lba >= 2 && primary.array_lba < primary.first && array_sectors <= primary.first - primary.array_lba &&
        backup.array_lba > primary.last && backup.array_lba < disk_last && array_sectors <= disk_last - backup.array_lba &&
        s.primary_array.size() == array_sectors * sector && s.backup_array.size() == array_sectors * sector &&
        std::equal(s.primary_array.begin(),s.primary_array.begin()+array_bytes,s.backup_array.begin()) &&
        Crc32(std::span(s.primary_array).first(array_bytes)) == D(s.primary_header,88) &&
        Crc32(std::span(s.backup_array).first(array_bytes)) == D(s.backup_header,88), "VolumeGptArrayInvalid");
    Need(s.mbr.size() == sector && s.mbr.size() >= 512 && s.mbr[510] == std::byte{0x55} && s.mbr[511] == std::byte{0xaa} &&
        s.mbr[446] == std::byte{} && s.mbr[450] == std::byte{0xee} && D(s.mbr,454) == 1 &&
        D(s.mbr,458) == (std::min<std::uint64_t>)(disk_last,UINT32_MAX) && Zero(std::span(s.mbr).subspan(462,48)),
        "VolumeGptProtectiveMbrRequired");
    std::set<std::array<std::byte,16>> ids; std::vector<std::pair<std::uint64_t,std::uint64_t>> ranges, originals;
    std::size_t selected = SIZE_MAX;
    constexpr std::array<std::byte,16> apfs_type{std::byte{0x7c},std::byte{0x34},std::byte{0x57},std::byte{0xef},std::byte{0},std::byte{0},std::byte{0x11},std::byte{0xaa},
        std::byte{0xaa},std::byte{0x11},std::byte{0},std::byte{0x30},std::byte{0x65},std::byte{0x43},std::byte{0xec},std::byte{0xac}};
    const auto new_last = media.base_offset_bytes / sector + s.target_bytes / sector - 1;
    Need(new_last <= primary.last, "VolumeGptTargetBeyondUsableSpace");
    for (std::size_t i = 0; i < primary.count; ++i) {
        const auto entry = std::span(s.primary_array).subspan(i*128,128); const auto type = Guid(entry,0), id = Guid(entry,16);
        if (Zero(type)) { Need(Zero(entry), "VolumeGptUnusedEntryNotEmpty"); continue; }
        const auto first = N(entry,32), last = N(entry,40);
        Need(!Zero(id) && ids.insert(id).second && first >= primary.first && first <= last && last <= primary.last,
            "VolumeGptPartitionCensusInvalid");
        originals.emplace_back(first,last);
        if (id == media.partition_guid) {
            Need(selected == SIZE_MAX && type == apfs_type && first * sector == media.base_offset_bytes &&
                (last-first+1)*sector == media.partition_length_bytes, "VolumeGptSelectedPartitionMismatch"); selected = i;
            ranges.emplace_back(first,window ? last : new_last);
        } else ranges.emplace_back(first,last);
    }
    Need(selected != SIZE_MAX, "VolumeGptSelectedPartitionMissing"); std::sort(ranges.begin(),ranges.end()); std::sort(originals.begin(),originals.end());
    for (std::size_t i = 1; i < originals.size(); ++i) Need(originals[i-1].second < originals[i].first, "VolumeGptOriginalPartitionsOverlap");
    for (std::size_t i = 1; i < ranges.size(); ++i) Need(ranges[i-1].second < ranges[i].first, "VolumeGptNeighborWouldBeOverwritten");
    plan.after = before; plan.after.media.limit_bytes = s.target_bytes;
    if (!window) plan.after.media.partition_length_bytes = s.target_bytes;
    Need(ValidateVolumePhysicalPolicy(plan.after,s.original.instance,error), "VolumeGptTargetBindingInvalid");
    if (window) return plan;
    auto primary_array = s.primary_array, backup_array = s.backup_array;
    Put(primary_array,selected*128+40,new_last); Put(backup_array,selected*128+40,new_last);
    auto primary_header = s.primary_header, backup_header = s.backup_header;
    HeaderChecksum(primary_header,primary_array,array_bytes); HeaderChecksum(backup_header,backup_array,array_bytes);
    const auto add_array = [&](const Bytes& old, const Bytes& next, std::uint64_t lba) {
        for (std::size_t at = 0; at < old.size(); at += sector) if (!std::equal(old.begin()+at,old.begin()+at+sector,next.begin()+at))
            plan.writes.push_back({lba*sector+at,Bytes(old.begin()+at,old.begin()+at+sector),Bytes(next.begin()+at,next.begin()+at+sector)});
    };
    add_array(s.backup_array,backup_array,backup.array_lba); plan.writes.push_back({disk_last*sector,s.backup_header,backup_header});
    add_array(s.primary_array,primary_array,primary.array_lba); plan.writes.push_back({sector,s.primary_header,primary_header});
    Need(plan.writes.size() == 4, "VolumeGptExpectedFourSectorWrites"); return plan;
}
Plan Capture(const catalog::RandomAccessSource& source, const volume_physical::Envelope& original, std::uint64_t target)
{
    const auto& media = original.binding.media; std::string error;
    Need(ValidateVolumePhysicalPolicy(original.binding,original.instance,error) && source.SizeBytes() == media.disk_size_bytes,
        "VolumeGptHeldDiskSizeMismatch");
    Snapshot s; s.original = original; s.target_bytes = target;
    if (media.limit_bytes < media.partition_length_bytes) s.profile = Profile::ContainerWindow;
    const auto sector = media.logical_sector_bytes; const auto last = media.disk_size_bytes/sector-1;
    ExactRead(source,0,sector,s.mbr); ExactRead(source,sector,sector,s.primary_header); ExactRead(source,last*sector,sector,s.backup_header);
    const auto a = HeaderOf(s.primary_header,1,last,original.binding), b = HeaderOf(s.backup_header,last,1,original.binding);
    const auto count = (static_cast<std::uint64_t>(a.count)*a.entry_bytes+sector-1)/sector*sector;
    Need(a.count == b.count && a.entry_bytes == b.entry_bytes && count <= (1u<<20) && a.array_lba < last && b.array_lba < last &&
        count/sector <= last-a.array_lba && count/sector <= last-b.array_lba, "VolumeGptArrayReadBounds");
    ExactRead(source,a.array_lba*sector,static_cast<std::size_t>(count),s.primary_array);
    ExactRead(source,b.array_lba*sector,static_cast<std::size_t>(count),s.backup_array); return Build(std::move(s));
}
Bytes Encode(const Plan& plan)
{
    const auto& s = plan.snapshot; Bytes out; format_evidence::Number(out,MagicOf(plan));
    if (s.profile != Profile::LegacyPartition) format_evidence::Number(out, static_cast<std::uint64_t>(s.profile));
    const auto add = [&](const Bytes& bytes) { format_evidence::Number(out,bytes.size()); out.insert(out.end(),bytes.begin(),bytes.end()); };
    add(volume_physical::Encode(s.original.binding,s.original.instance)); format_evidence::Number(out,s.target_bytes);
    for (const auto* bytes : {&s.mbr,&s.primary_header,&s.backup_header,&s.primary_array,&s.backup_array}) add(*bytes);
    Need(out.size() <= (3u<<20), "VolumeGptEvidenceQuota"); return out;
}
Plan Decode(std::span<const std::byte> bytes)
{
    Need(bytes.size() <= (3u<<20), "VolumeGptEvidenceQuota"); std::size_t at = 0;
    const auto number = [&]() { const auto n = N(bytes,at); at+=8; return n; };
    const auto read = [&]() { const auto n = number(); Need(n <= (1u<<20) && n <= bytes.size()-at, "VolumeGptEvidenceBounds");
        Bytes value(bytes.begin()+at,bytes.begin()+at+n); at+=n; return value; };
    const auto magic = number(); Need(IsMagic(magic), "VolumeGptEvidenceVersion"); Snapshot s;
    if (magic == Version2Magic) {
        const auto profile = number(); Need(profile == 1 || profile == 2, "VolumeGptEvidenceProfileInvalid");
        s.profile = static_cast<Profile>(profile);
    }
    s.original = volume_physical::Decode(read()); s.target_bytes = number();
    s.mbr=read();s.primary_header=read();s.backup_header=read();s.primary_array=read();s.backup_array=read();
    Need(at == bytes.size(), "VolumeGptEvidenceTrailingBytes"); return Build(std::move(s));
}
void Verify(const catalog::RandomAccessSource& source, const Plan& plan, unsigned state)
{
    const auto& s = plan.snapshot; const auto& media = s.original.binding.media; const auto sector=media.logical_sector_bytes;
    Need(source.SizeBytes() == media.disk_size_bytes && state <= 4, "VolumeGptVerificationScope");
    const auto check = [&](std::uint64_t offset, const Bytes& before) {
        Bytes current; ExactRead(source,offset,before.size(),current);
        for (std::size_t at=0; at<before.size(); at+=sector) {
            const auto write = std::find_if(plan.writes.begin(),plan.writes.end(),[&](const auto& w){return w.offset==offset+at;});
            const auto block=std::span(current).subspan(at,sector);
            if (write==plan.writes.end() || state==0 || state==1 || state==4)
                Need(std::equal(block.begin(),block.end(),before.begin()+at),"VolumeGptOriginalOrNeighborChanged");
            else if (state==3) Need(std::equal(block.begin(),block.end(),write->after.begin()),"VolumeGptFinalBytesChanged");
            else if (!std::equal(block.begin(),block.end(),write->before.begin()) && !std::equal(block.begin(),block.end(),write->after.begin()))
                Need(!ValidHeader(Bytes(block.begin(),block.end())),"VolumeGptForeignValidHeader");
        }
    };
    check(0,s.mbr);check(sector,s.primary_header);check((media.disk_size_bytes/sector-1)*sector,s.backup_header);
    check(N(s.primary_header,72)*sector,s.primary_array);check(N(s.backup_header,72)*sector,s.backup_array);
}
bool Follows(const Plan& completed,const Plan& next)
{
    auto expected=completed.snapshot;const auto& actual=next.snapshot;
    if(completed.after!=actual.original.binding || expected.original.instance!=actual.original.instance)return false;
    const auto sector=expected.original.binding.media.logical_sector_bytes;
    const auto patch=[&](std::uint64_t offset,Bytes& bytes){for(const auto& w:completed.writes)
        if(w.offset>=offset && w.offset-offset<=bytes.size() && w.after.size()<=bytes.size()-(w.offset-offset))
            std::copy(w.after.begin(),w.after.end(),bytes.begin()+w.offset-offset);};
    patch(sector,expected.primary_header);patch(expected.original.binding.media.disk_size_bytes-sector,expected.backup_header);
    patch(N(expected.primary_header,72)*sector,expected.primary_array);patch(N(expected.backup_header,72)*sector,expected.backup_array);
    return expected.mbr==actual.mbr && expected.primary_header==actual.primary_header && expected.backup_header==actual.backup_header &&
        expected.primary_array==actual.primary_array && expected.backup_array==actual.backup_array;
}
void Publish(const Plan& plan, const std::function<bool(std::uint64_t,std::span<const std::byte>)>& write,
    const std::function<bool()>& flush, const catalog::RandomAccessSource& readback, const AppleCheckpointStageHook& hook)
{
    const auto stage = [&](std::string_view name) { Need(!hook || hook(name),"VolumeGptInterrupted"); };
    Verify(readback,plan,2); const char* stages[]={"after-gpt-backup-array","after-gpt-backup-header","after-gpt-primary-array","after-gpt-primary-header"};
    for (std::size_t i=0;i<plan.writes.size();++i) {
        const auto& w=plan.writes[i]; Need(write(w.offset,w.after),"VolumeGptWriteFailed");stage(stages[i]);
        Need(flush(),"VolumeGptFlushFailed");Bytes bytes;ExactRead(readback,w.offset,w.after.size(),bytes);
        Need(bytes==w.after,"VolumeGptReadbackFailed");
    }
    Verify(readback,plan,3);stage("after-gpt-complete");
}
}
