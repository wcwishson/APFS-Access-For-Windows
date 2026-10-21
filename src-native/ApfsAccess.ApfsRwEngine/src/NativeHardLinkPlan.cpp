#include "NativeHardLinkPlan.h"
#include "WindowsMetadataAttribute.h"
#include <algorithm>
#include <map>
#include <set>

namespace apfsaccess::rw
{
namespace
{
constexpr std::uint64_t Mask = 0x0fffffffffffffffULL;
bool Equal(const std::vector<catalog::BtreeRecord>& a, const std::vector<catalog::BtreeRecord>& b)
{
    return a.size() == b.size() && std::equal(a.begin(), a.end(), b.begin(),
        [](const auto& x, const auto& y) { return x.key == y.key && x.value == y.value; });
}
AppleExtendedField SiblingField(std::uint64_t id)
{
    AppleExtendedField field{1, 0, std::vector<std::byte>(8)};
    for (unsigned i = 0; i < 8; ++i) field.data[i] = std::byte((id >> (i * 8)) & 255);
    return field;
}
}

bool PrepareNativeHardLinkPlan(const std::vector<catalog::BtreeRecord>& filesystem,
    const ApfsNamePolicy& policy, const NativeHardLinkRequest& request,
    NativeHardLinkPlan& plan, std::string& error)
{
    plan = {}; error.clear();
    const auto refuse = [&](const char* reason) { plan = {}; error = reason; return false; };
    if (filesystem.empty() || filesystem.size() > 16384 || request.source_inode <= 2 ||
        !request.destination_parent || request.source_inode == request.destination_parent ||
        !request.next_object_id || request.next_object_id >= Mask - 1 || !request.timestamp_ns)
        return refuse("HardLinkInvalidRequest");
    const auto target_name = ApfsNameCodec::Decode(std::span(
        reinterpret_cast<const std::byte*>(request.leaf_utf8.data()), request.leaf_utf8.size()), policy);
    if (!target_name.ok()) return refuse("HardLinkInvalidName");
    std::size_t bytes = 0, source_at = SIZE_MAX, parent_at = SIZE_MAX, old_link_at = SIZE_MAX;
    AppleInodeRecord source, parent;
    AppleDirectoryRecord old_link;
    struct Alias { std::size_t index; AppleDirectoryRecord directory; std::uint64_t sibling; };
    std::vector<Alias> aliases;
    std::map<std::uint64_t, AppleSiblingLinkRecord> siblings;
    std::map<std::uint64_t, AppleSiblingMapRecord> maps;
    std::map<std::uint64_t, AppleDirectoryRecord> sibling_directories;
    std::set<std::pair<std::uint64_t, std::vector<std::byte>>> names;
    std::set<std::string> source_attributes;
    std::uint64_t parent_children = 0;
    std::vector<catalog::BtreeRecord> before = filesystem;
    const auto order = policy.UsesHashedDirectoryKeys() ? AppleBtreeKeyOrder::FileSystemHashedDirectory : AppleBtreeKeyOrder::FileSystemCaseSensitive;
    if (!SortAppleBtreeRecords(before, order, error)) return refuse("HardLinkInvalidTree");
    for (std::size_t i = 0; i < before.size(); ++i)
    {
        const auto& record = before[i];
        if (record.key.size() > 1048576 - bytes) return refuse("HardLinkRecordLimit");
        bytes += record.key.size();
        if (record.value.size() > 1048576 - bytes) return refuse("HardLinkRecordLimit");
        bytes += record.value.size();
        const auto header = catalog::ReadU64LE(record.key, 0);
        if (!header || (*header & Mask) >= request.next_object_id) return refuse("HardLinkOidFloorUnproven");
        const auto oid = *header & Mask, type = *header >> 60;
        if (type == 3 && (oid == request.source_inode || oid == request.destination_parent))
        {
            AppleInodeRecord inode;
            if (!ApfsExtendedRecordCodec::DecodeInode(record, inode, error)) return refuse("HardLinkInvalidInode");
            if (oid == request.source_inode) {
                if (source_at != SIZE_MAX) return refuse("HardLinkDuplicateInode");
                source = std::move(inode); source_at = i;
            } else {
                if (parent_at != SIZE_MAX) return refuse("HardLinkDuplicateInode");
                parent = std::move(inode); parent_at = i;
            }
        }
        if (type == 4 && oid == request.source_inode) {
            AppleXattrRecord attribute;
            if (!ApfsExtendedRecordCodec::DecodeXattr(record, attribute, error) ||
                attribute.flags != kAppleXattrDataEmbedded ||
                !source_attributes.insert(attribute.name_utf8).second)
                return refuse("HardLinkSourceXattrInvalid");
            if (!IsOrdinaryAppleXattrName(attribute.name_utf8) ||
                attribute.name_utf8 == "com.apple.system.Security" ||
                (attribute.name_utf8.starts_with("com.apfsaccess.") &&
                    attribute.name_utf8 != "com.apfsaccess.windows.security" &&
                    attribute.name_utf8 != "com.apfsaccess.windows.attributes"))
                return refuse("HardLinkSourceXattrProfileUnsupported");
            if (attribute.name_utf8 == "com.apfsaccess.windows.security" &&
                !windows_metadata::ValidSecurityPayload(attribute.data))
                return refuse("HardLinkSourceSecurityInvalid");
            std::uint32_t attributes = 0;
            if (attribute.name_utf8 == "com.apfsaccess.windows.attributes" &&
                !windows_metadata::DecodeAttributes(attribute.data, attributes))
                return refuse("HardLinkSourceAttributesInvalid");
        }
        if (type == 5) {
            AppleSiblingLinkRecord sibling;
            if (!ApfsExtendedRecordCodec::DecodeSiblingLink(record, sibling, error) ||
                !siblings.emplace(sibling.sibling_id, sibling).second) return refuse("HardLinkSiblingInvalid");
        }
        if (type == 12) {
            AppleSiblingMapRecord map;
            if (!ApfsExtendedRecordCodec::DecodeSiblingMap(record, map, error) ||
                !maps.emplace(map.sibling_id, map).second) return refuse("HardLinkSiblingMapInvalid");
        }
        if (type != 9) continue;
        AppleDirectoryRecord directory;
        if (!ApfsExtendedRecordCodec::DecodeDirectory(record, policy, directory, error)) return refuse("HardLinkInvalidDirectory");
        const auto decoded_name = ApfsNameCodec::Decode(std::as_bytes(std::span(directory.name_utf8)), policy);
        if (!decoded_name.ok() || !names.emplace(directory.parent_id, decoded_name.value->lookup_key).second)
            return refuse("HardLinkDirectoryNameAmbiguous");
        std::uint64_t sibling = 0;
        for (const auto& field : directory.extended_fields) if (field.type == 1) {
            if (sibling || field.data.size() != 8 || !(sibling = catalog::ReadU64LE(field.data, 0).value_or(0)) ||
                !sibling_directories.emplace(sibling, directory).second) return refuse("HardLinkDirectorySiblingInvalid");
        }
        if (directory.parent_id == request.destination_parent)
        {
            ++parent_children;
            if (decoded_name.value->lookup_key == target_name.value->lookup_key)
                return refuse("HardLinkDestinationExistsOrInvalid");
        }
        if (directory.file_id == request.source_inode)
        {
            if (directory.flags != 8 || (!sibling && !directory.extended_fields.empty()) ||
                (sibling && (directory.extended_fields.size() != 1 || directory.extended_fields.front().flags)))
                return refuse("HardLinkExistingLinksUnsupported");
            aliases.push_back({i, std::move(directory), sibling});
        }
    }
    if (siblings.size() != maps.size() || siblings.size() != sibling_directories.size())
        return refuse("HardLinkSiblingCensusMismatch");
    for (const auto& [id, sibling] : siblings) {
        const auto map = maps.find(id); const auto directory = sibling_directories.find(id);
        if (map == maps.end() || directory == sibling_directories.end() || map->second.file_id != sibling.inode_id ||
            directory->second.file_id != sibling.inode_id || directory->second.parent_id != sibling.parent_id ||
            directory->second.name_utf8 != sibling.name_utf8) return refuse("HardLinkSiblingOwnershipMismatch");
    }
    const auto owned_siblings = std::count_if(siblings.begin(), siblings.end(), [&](const auto& entry) {
        return entry.second.inode_id == request.source_inode;
    });
    const bool linked = owned_siblings != 0;
    if (aliases.empty() || aliases.size() > 16384 ||
        (linked ? static_cast<std::size_t>(owned_siblings) != aliases.size() : aliases.size() != 1))
        return refuse("HardLinkSourceCensusMismatch");
    const auto primary = std::min_element(aliases.begin(), aliases.end(), [](const auto& a, const auto& b) {
        return a.sibling < b.sibling;
    });
    old_link_at = primary->index; old_link = primary->directory;
    if (source_at == SIZE_MAX || parent_at == SIZE_MAX ||
        (source.mode & 0170000) != 0100000 || source.children_or_links <= 0 ||
        static_cast<std::size_t>(source.children_or_links) != aliases.size() || source.children_or_links == INT32_MAX ||
        (source.bsd_flags & kAppleBsdCompressedFlag) || source.parent_id != old_link.parent_id ||
        (parent.mode & 0170000) != 0040000 || parent.children_or_links < 0 ||
        static_cast<std::uint64_t>(parent.children_or_links) != parent_children || parent.children_or_links == INT32_MAX)
        return refuse("HardLinkProfileUnsupported");
    for (const auto& field : parent.extended_fields)
        if (field.type != 4) return refuse("HardLinkParentFieldsUnsupported");
    unsigned primary_fields = 0;
    for (const auto& field : source.extended_fields)
    {
        if (field.type != 4 && field.type != 8) return refuse("HardLinkSourceFieldsUnsupported");
        if (field.type == 4)
        {
            if (++primary_fields != 1) return refuse("HardLinkPrimaryNameMismatch");
            std::vector<std::byte> expected;
            for (const auto ch : old_link.name_utf8) expected.push_back(std::byte(static_cast<unsigned char>(ch)));
            expected.push_back(std::byte{0});
            if (field.data != expected) return refuse("HardLinkPrimaryNameMismatch");
        }
    }
    if (std::none_of(source.extended_fields.begin(), source.extended_fields.end(), [](const auto& f) { return f.type == 4; }))
    {
        AppleExtendedField name{4, 0, {}};
        for (const auto ch : old_link.name_utf8) name.data.push_back(std::byte(static_cast<unsigned char>(ch)));
        name.data.push_back(std::byte{0}); source.extended_fields.push_back(std::move(name));
    }
    auto after = before;
    ++source.children_or_links; source.change_time = request.timestamp_ns;
    ++parent.children_or_links; parent.change_time = parent.modification_time = request.timestamp_ns;
    if (!EncodeAppleInodeRecord(source, after[source_at], error) || !EncodeAppleInodeRecord(parent, after[parent_at], error))
        return refuse("HardLinkInodeEncodingFailed");
    if (!linked) {
        old_link.extended_fields.push_back(SiblingField(request.next_object_id));
        if (!EncodeAppleDirectoryRecord(old_link, policy, after[old_link_at], error)) return refuse("HardLinkOldDirectoryEncodingFailed");
    }
    AppleDirectoryRecord added;
    added.parent_id = request.destination_parent; added.file_id = request.source_inode;
    added.name_utf8 = request.leaf_utf8; added.flags = 8; added.date_added = request.timestamp_ns;
    const auto added_sibling = request.next_object_id + (linked ? 0 : 1);
    added.extended_fields.push_back(SiblingField(added_sibling));
    catalog::BtreeRecord encoded;
    if (!EncodeAppleDirectoryRecord(added, policy, encoded, error)) return refuse("HardLinkDirectoryEncodingFailed");
    after.push_back(std::move(encoded));
    const auto additions = linked ? std::vector<AppleDirectoryRecord>{added} : std::vector<AppleDirectoryRecord>{old_link, added};
    for (const auto& item : additions)
    {
        const auto sibling = item.parent_id == old_link.parent_id && item.name_utf8 == old_link.name_utf8 ? request.next_object_id : added_sibling;
        if (!EncodeAppleSiblingLinkRecord({request.source_inode, sibling, item.parent_id, item.name_utf8}, encoded, error))
            return refuse("HardLinkSiblingEncodingFailed");
        after.push_back(std::move(encoded));
        if (!EncodeAppleSiblingMapRecord({sibling, request.source_inode}, encoded, error)) return refuse("HardLinkMapEncodingFailed");
        after.push_back(std::move(encoded));
    }
    if (!SortAppleBtreeRecords(after, order, error)) return refuse("HardLinkResultTreeInvalid");
    plan.source_inode = request.source_inode; plan.next_object_id = added_sibling + 1;
    plan.primary_parent = old_link.parent_id; plan.primary_name = old_link.name_utf8;
    plan.source_links = static_cast<std::uint32_t>(aliases.size());
    plan.before = std::move(before); plan.after = std::move(after);
    return true;
}

NativeHardLinkPlanState ClassifyNativeHardLinkPlan(const std::vector<catalog::BtreeRecord>& filesystem,
    const NativeHardLinkPlan& accepted_plan)
{
    if (!accepted_plan.source_inode || accepted_plan.before.empty() || accepted_plan.after.empty()) return NativeHardLinkPlanState::Refused;
    if (Equal(filesystem, accepted_plan.before)) return NativeHardLinkPlanState::Preimage;
    if (Equal(filesystem, accepted_plan.after)) return NativeHardLinkPlanState::Published;
    return NativeHardLinkPlanState::Refused;
}
}
