#include "ApfsFirmlinkRouter.h"

#include <functional>
#include <iostream>
#include <stdexcept>

using namespace apfsaccess;
using namespace apfsaccess::rw;
namespace
{
std::size_t assertions = 0;
void Check(bool condition, const char* expression, int line)
{
    ++assertions;
    if (!condition) throw std::runtime_error(std::string(expression) + " at line " + std::to_string(line));
}
#define CHECK(x) Check((x), #x, __LINE__)

// Pure typed algorithm examples. These are NOT APFS images or serialized
// firmlink fixtures, and do not establish any production decoder support.
struct Example
{
    catalog::ApfsContainerDescriptor container;
    NativeApfsVolumeProjection system, data;
    std::vector<VerifiedFirmlinkRecord> records;
    std::shared_ptr<const ApfsFirmlinkRouter> router;
    std::string error;
    Example()
    {
        container.container_uuid_hex = std::string(32, 'a');
        container.member_store_ids = {"apfs-store:raw"};
        container.checkpoint_xid = 90;
        for (unsigned i = 0; i < 2; ++i)
        {
            catalog::ApfsVolumeDescriptor v;
            v.object_id = 10 + i;
            v.volume_uuid_hex = std::string(32, static_cast<char>('b' + i));
            v.group_uuid_hex = std::string(32, 'd');
            v.role_raw = static_cast<std::uint16_t>(i == 0 ? 0x1 : 0x40);
            v.group_association_status = "valid-system-data";
            v.superblock_xid = 87 + i; // per-volume superblock need not equal checkpoint
            v.superblock_block = 100 + i;
            v.name_utf8 = "Same display name"; // names are not identity
            container.volumes.push_back(v);
        }
        catalog::ApfsVolumeGroupDescriptor group;
        group.container_uuid_hex = container.container_uuid_hex;
        group.group_uuid_hex = std::string(32, 'd');
        group.association_status = "valid-system-data";
        group.system_volume_id = "apfs-vol:" + container.container_uuid_hex + ":10";
        group.data_volume_id = "apfs-vol:" + container.container_uuid_hex + ":11";
        group.member_volume_ids = {group.system_volume_id, group.data_volume_id};
        container.groups.push_back(group);
        for (auto* p : {&system, &data})
        {
            const unsigned i = p == &system ? 0 : 1;
            p->volume_object_id = container.volumes[i].object_id;
            p->volume_superblock_block = container.volumes[i].superblock_block;
            p->checkpoint_xid = 90;
            p->root_directory_inode = 2;
            Add(*p, 2, 2, "");
            Add(*p, 3, 2, "Users");
            Add(*p, 4, 3, "Child");
            Add(*p, 5, 2, "Other");
        }
        records.push_back({Id(system, 3), Id(data, 3)});
    }
    static void Add(NativeApfsVolumeProjection& p, std::uint64_t oid, std::uint64_t parent,
        const std::string& name)
    {
        MetadataStore::InodeRecord inode;
        inode.object_id = oid;
        inode.parent_object_id = parent;
        inode.name_utf8 = name;
        inode.is_directory = true;
        inode.node_type = MetadataStore::NodeType::Directory;
        inode.mode = 0040755;
        inode.xid = p.volume_object_id == 10 ? 85 : 86;
        if (!name.empty())
        {
            const auto decoded = ApfsNameCodec::Decode(std::as_bytes(std::span(name)), p.name_policy);
            CHECK(decoded.ok());
            inode.name = decoded.value->windows_display;
            MetadataStore::DirectoryLink link;
            link.child_object_id = oid;
            link.parent_object_id = parent;
            link.entry_name_utf8 = name;
            link.entry_name = inode.name;
            link.xid = 89;
            p.directory_links.push_back(link);
        }
        p.inodes.push_back(inode);
    }
    FirmlinkObjectIdentity Id(const NativeApfsVolumeProjection& p, std::uint64_t oid) const
    {
        const auto& v = container.volumes[p.volume_object_id == 10 ? 0 : 1];
        for (const auto& inode : p.inodes)
            if (inode.object_id == oid)
                return {{container.container_uuid_hex, v.volume_uuid_hex, v.name_utf8,
                    v.object_id, v.incompatible_features}, oid, p.checkpoint_xid, inode.xid};
        throw std::runtime_error("missing test object");
    }
    bool Build()
    {
        return ApfsFirmlinkRouter::TryBuild(container, std::string(32, 'd'), system, data, records, router, error);
    }
    FirmlinkObjectIdentity Route(const FirmlinkObjectIdentity& id, FirmlinkTraversal direction)
    {
        FirmlinkObjectIdentity result;
        CHECK(router->TryRoute(id, FirmlinkViewPolicy::ReadOnlyUnifiedGroup, direction, FirmlinkAccess::Read, result, error));
        return result;
    }
};

void DecoderRefusesEveryPayload()
{
    AppleXattrRecord attr;
    attr.object_id = 3;
    attr.name_utf8 = kFirmlinkEaName;
    const std::vector<std::vector<std::byte>> opaque = {
        {}, {std::byte{0}}, {std::byte{3}, std::byte{0}, std::byte{0}, std::byte{0},
            std::byte{0}, std::byte{0}, std::byte{0}, std::byte{0}},
        {std::byte{'/'}, std::byte{'U'}, std::byte{'s'}, std::byte{'r'}},
        {std::byte{0xff}, std::byte{0xfe}}
    };
    for (const auto& bytes : opaque)
        for (std::uint16_t flags : std::array<std::uint16_t, 5>{0, 1, 2, 3, 65535})
        {
            attr.data = bytes;
            attr.flags = flags;
            CHECK(InspectFirmlinkAttribute(attr) == FirmlinkDecodeStatus::UnsupportedSerialization);
            CHECK(attr.data == bytes && attr.flags == flags);
        }
    for (const std::string name : {"com.apple.fs.symlink", "com.apple.fs.Firmlink", "com.apple.fs.firmlink.extra"})
    {
        attr.name_utf8 = name;
        CHECK(InspectFirmlinkAttribute(attr) == FirmlinkDecodeStatus::NotFirmlink);
    }
    attr.name_utf8 = std::string(kFirmlinkEaName) + '\0';
    CHECK(InspectFirmlinkAttribute(attr) == FirmlinkDecodeStatus::NotFirmlink);
}

void TraversalPreservesBackingIdentity()
{
    Example e;
    CHECK(e.Build());
    const auto target = e.Route(e.Id(e.system, 3), FirmlinkTraversal::Forward);
    CHECK(target.volume.object_id == 11 && target.object_id == 3);
    CHECK(target.volume.volume_uuid_hex == std::string(32, 'c'));
    CHECK(target.inode_xid == 86 && target.checkpoint_xid == 90);
    const auto parent = e.Route(target, FirmlinkTraversal::Parent);
    CHECK(parent.volume.object_id == 10 && parent.object_id == 2 && parent.inode_xid == 85);
    const auto child_parent = e.Route(e.Id(e.data, 4), FirmlinkTraversal::Parent);
    CHECK(child_parent.volume.object_id == 11 && child_parent.object_id == 3);
    const auto other = e.Route(e.Id(e.system, 5), FirmlinkTraversal::Forward);
    CHECK(other.volume.object_id == 10 && other.object_id == 5);
    const auto root = e.Route(e.Id(e.system, 2), FirmlinkTraversal::Parent);
    CHECK(root.volume.object_id == 10 && root.object_id == 2);
    auto alias = e.Id(e.system, 3);
    CHECK(e.router->TryRoute(alias, FirmlinkViewPolicy::ReadOnlyUnifiedGroup, FirmlinkTraversal::Forward,
        FirmlinkAccess::Read, alias, e.error));
    CHECK(alias.volume.object_id == 11);
}

void PolicyAndIndependentMount()
{
    Example e;
    CHECK(e.Build());
    for (const auto direction : {FirmlinkTraversal::Forward, FirmlinkTraversal::Parent})
        for (const auto& input : {e.Id(e.system, 3), e.Id(e.data, 3), e.Id(e.system, 5)})
        {
            FirmlinkObjectIdentity out = input;
            CHECK(!e.router->TryRoute(input, FirmlinkViewPolicy::ReadOnlyUnifiedGroup, direction,
                FirmlinkAccess::Mutation, out, e.error));
            CHECK(e.error == "FirmlinkUnifiedViewReadOnly" && out.object_id == 0);
            for (const auto access : {FirmlinkAccess::Read, FirmlinkAccess::Mutation})
            {
                CHECK(e.router->TryRoute(input, FirmlinkViewPolicy::IndependentVolume, direction, access, out, e.error));
                CHECK(out.volume.object_id == input.volume.object_id && out.object_id == input.object_id && out.inode_xid == input.inode_xid);
            }
        }
    auto external = e.Id(e.data, 3);
    external.volume.container_uuid_hex = std::string(32, 'e');
    external.volume.object_id = 900;
    FirmlinkObjectIdentity out;
    CHECK(e.router->TryRoute(external, FirmlinkViewPolicy::IndependentVolume, FirmlinkTraversal::Forward,
        FirmlinkAccess::Mutation, out, e.error));
    CHECK(out.volume.container_uuid_hex == external.volume.container_uuid_hex && out.volume.object_id == 900);
    CHECK(!e.router->TryRoute(external, static_cast<FirmlinkViewPolicy>(99), FirmlinkTraversal::Forward,
        FirmlinkAccess::Read, out, e.error));
    CHECK(out.object_id == 0);
}

void InvalidGroupsAndProjectionBindings()
{
    const std::vector<std::function<void(Example&)>> changes = {
        [](Example& e) { e.container.groups.clear(); },
        [](Example& e) { e.container.volumes.pop_back(); },
        [](Example& e) { e.container.groups[0].association_status = "incomplete"; },
        [](Example& e) { e.container.groups[0].container_uuid_hex = std::string(32, 'e'); },
        [](Example& e) { e.container.groups[0].member_volume_ids.pop_back(); },
        [](Example& e) { e.container.groups[0].member_volume_ids.push_back(e.container.groups[0].data_volume_id); },
        [](Example& e) { e.container.volumes[1].role_raw = 0; },
        [](Example& e) { e.container.volumes[1].role_raw = 1; },
        [](Example& e) { e.container.volumes[1].volume_uuid_hex = std::string(32, 'b'); },
        [](Example& e) { e.container.volumes[1].volume_uuid_hex.clear(); },
        [](Example& e) { e.container.volumes[1].group_metadata_valid = false; },
        [](Example& e) { e.container.volumes[1].group_uuid_hex = std::string(32, 'e'); },
        [](Example& e) { e.container.volumes[1].locked = true; },
        [](Example& e) { e.container.fusion = true; },
        [](Example& e) { e.container.groups.push_back(e.container.groups[0]); },
        [](Example& e) { e.data.checkpoint_xid--; },
        [](Example& e) { e.data.volume_superblock_block++; },
        [](Example& e) { e.data.volume_object_id = 10; },
        [](Example& e) { e.data.incompatible_features = 1; },
        [](Example& e) { e.data.name_policy.case_mode = ApfsCaseMode::Insensitive; }
    };
    for (const auto& change : changes)
    {
        Example e;
        CHECK(e.Build()); // failure must discard an earlier successful output
        change(e);
        CHECK(!e.Build());
        CHECK(!e.router && !e.error.empty());
    }
}

void RejectStaleOrForeignIdentities()
{
    const std::vector<std::function<void(FirmlinkObjectIdentity&)>> changes = {
        [](auto& id) { id.volume.container_uuid_hex = std::string(32, 'e'); },
        [](auto& id) { id.volume.volume_uuid_hex = std::string(32, 'e'); },
        [](auto& id) { id.volume.object_id = 12; },
        [](auto& id) { id.object_id = 900; },
        [](auto& id) { id.checkpoint_xid++; },
        [](auto& id) { id.inode_xid++; }
    };
    for (const auto& change : changes)
    {
        Example e;
        CHECK(e.Build());
        auto input = e.Id(e.system, 3);
        change(input);
        FirmlinkObjectIdentity out = input;
        CHECK(!e.router->TryRoute(input, FirmlinkViewPolicy::ReadOnlyUnifiedGroup, FirmlinkTraversal::Forward,
            FirmlinkAccess::Read, out, e.error));
        CHECK(out.object_id == 0 && e.error == "FirmlinkIdentityNotInPinnedView");
        change(e.records[0].target);
        CHECK(!e.Build() && !e.router);
    }
}

void RejectNonDirectoriesAndAmbiguousPairs()
{
    const std::vector<std::function<void(Example&)>> changes = {
        [](Example& e) { e.records.push_back(e.records[0]); },
        [](Example& e) { e.records.push_back({e.Id(e.system, 5), e.Id(e.data, 3)}); },
        [](Example& e) { e.records.push_back({e.Id(e.system, 3), e.Id(e.data, 5)}); },
        // A reversed edge which could form a forward cycle is rejected by role before publication.
        [](Example& e) { e.records.push_back({e.Id(e.data, 3), e.Id(e.system, 3)}); },
        [](Example& e) { e.records[0].target = e.Id(e.system, 5); },
        [](Example& e) { e.records[0].source = e.Id(e.system, 2); },
        [](Example& e) { e.records[0].target = e.Id(e.data, 2); },
        [](Example& e) { e.data.inodes[1].is_directory = false; e.data.inodes[1].node_type = MetadataStore::NodeType::SymbolicLink; },
        [](Example& e) { e.data.inodes[1].node_type = MetadataStore::NodeType::RegularFile; },
        [](Example& e) { e.data.inodes[1].mode = 0120777; },
        [](Example& e) { e.data.inodes[1].symlink_target_utf8 = "/Users"; },
        [](Example& e) { e.data.inodes[1].xid = 91; },
        [](Example& e) { e.data.inodes.push_back(e.data.inodes[1]); },
        [](Example& e) { e.data.directory_links.push_back(e.data.directory_links[0]); },
        [](Example& e) { e.data.directory_links[0].parent_object_id = 900; },
        [](Example& e) { e.data.directory_links.erase(e.data.directory_links.begin()); },
        [](Example& e) { e.data.directory_links[0].xid = 91; },
        [](Example& e) { e.data.directory_links[0].entry_name_utf8 = std::string(1, static_cast<char>(0xff)); }
    };
    for (const auto& change : changes)
    {
        Example e;
        change(e);
        CHECK(!e.Build());
        CHECK(!e.router && !e.error.empty());
    }
}

void ParentCycleAndDepthBound()
{
    Example self;
    self.data.inodes[1].parent_object_id = 3;
    self.data.directory_links[0].parent_object_id = 3;
    CHECK(!self.Build() && self.error == "FirmlinkParentCycle");
    Example cycle;
    cycle.data.inodes[1].parent_object_id = 4;
    cycle.data.directory_links[0].parent_object_id = 4;
    CHECK(!cycle.Build() && cycle.error == "FirmlinkParentCycle");
    Example depth;
    // Root plus 255 descendants reaches the root on the final allowed step.
    std::uint64_t parent = 5;
    for (std::uint64_t i = 0; i < 254; ++i)
    {
        Example::Add(depth.data, 100 + i, parent, "d" + std::to_string(i));
        parent = 100 + i;
    }
    CHECK(depth.Build());
    Example::Add(depth.data, 999, parent, "too-deep");
    CHECK(!depth.Build() && depth.error == "FirmlinkParentLimit");
}

void ImmutableAndNativeNames()
{
    Example e;
    Example::Add(e.system, 6, 2, "A:B");
    Example::Add(e.data, 6, 2, "\xe4\xb8\xad\xe6\x96\x87");
    e.records.push_back({e.Id(e.system, 6), e.Id(e.data, 6)});
    CHECK(e.Build());
    const auto source = e.Id(e.system, 6);
    e.system.inodes.clear();
    e.data.inodes.clear();
    e.records.clear();
    e.container = {};
    const auto target = e.Route(source, FirmlinkTraversal::Forward);
    CHECK(target.volume.object_id == 11 && target.object_id == 6);
    CHECK(target.volume.volume_uuid_hex == std::string(32, 'c'));
}

void NestedCrossingsRefused()
{
    Example source;
    source.records.push_back({source.Id(source.system, 4), source.Id(source.data, 5)});
    CHECK(!source.Build() && source.error == "FirmlinkNestedCrossingUnsupported");
    Example target;
    target.records.push_back({target.Id(target.system, 5), target.Id(target.data, 4)});
    CHECK(!target.Build() && target.error == "FirmlinkNestedCrossingUnsupported");
}

void NativeCaseAndNormalization()
{
    Example sensitive;
    Example::Add(sensitive.data, 6, 2, "users");
    CHECK(sensitive.Build());
    sensitive.container.volumes[1].incompatible_features = 1;
    sensitive.data.incompatible_features = 1;
    sensitive.data.name_policy = ApfsNamePolicy::FromIncompatibleFeatures(1);
    CHECK(!sensitive.Build() && sensitive.error == "FirmlinkDirectoryNameInvalid");
    Example normalized;
    normalized.container.volumes[1].incompatible_features = 8;
    normalized.data.incompatible_features = 8;
    normalized.data.name_policy = ApfsNamePolicy::FromIncompatibleFeatures(8);
    Example::Add(normalized.data, 6, 2, "\xc3\xa9");
    Example::Add(normalized.data, 7, 2, "e\xcc\x81");
    CHECK(!normalized.Build() && normalized.error == "FirmlinkDirectoryNameInvalid");
}

void OrdinaryFilesAndBounds()
{
    Example e;
    e.records.clear();
    Example::Add(e.data, 6, 2, "ordinary-symlink");
    e.data.inodes.back().is_directory = false;
    e.data.inodes.back().node_type = MetadataStore::NodeType::SymbolicLink;
    e.data.inodes.back().mode = 0120777;
    e.data.inodes.back().symlink_target_utf8 = "/Users";
    CHECK(e.Build()); // unrelated symlinks are not reinterpreted
    const auto source = e.Route(e.Id(e.system, 3), FirmlinkTraversal::Forward);
    CHECK(source.volume.object_id == 10 && source.object_id == 3);
    FirmlinkObjectIdentity out;
    CHECK(!e.router->TryRoute(e.Id(e.data, 6), FirmlinkViewPolicy::ReadOnlyUnifiedGroup,
        FirmlinkTraversal::Forward, FirmlinkAccess::Read, out, e.error));
    CHECK(out.object_id == 0);
    e.records.resize(ApfsFirmlinkRouter::kMaxRecords + 1);
    CHECK(!e.Build() && e.error == "FirmlinkTableLimit");
}
} // namespace

int main()
{
    const std::vector<std::pair<const char*, std::function<void()>>> tests = {
        {"opaque marker refusal", DecoderRefusesEveryPayload},
        {"forward and parent identity", TraversalPreservesBackingIdentity},
        {"read-only and independent policies", PolicyAndIndependentMount},
        {"complete group and projection binding", InvalidGroupsAndProjectionBindings},
        {"stale and foreign identities", RejectStaleOrForeignIdentities},
        {"directory and one-to-one validation", RejectNonDirectoriesAndAmbiguousPairs},
        {"parent cycles and exact depth boundary", ParentCycleAndDepthBound},
        {"immutable ownership and native names", ImmutableAndNativeNames},
        {"nested crossings refused", NestedCrossingsRefused},
        {"native case and normalization collisions", NativeCaseAndNormalization},
        {"ordinary symlinks and table bounds", OrdinaryFilesAndBounds}
    };
    for (const auto& [name, test] : tests)
    {
        try { test(); std::cout << "PASS " << name << '\n'; }
        catch (const std::exception& ex) { std::cerr << "FAIL " << name << ": " << ex.what() << '\n'; return 1; }
    }
    std::cout << tests.size() << " tests, " << assertions << " assertions\n";
    return 0;
}
