#include "ApfsFusionReadSession.h"
#include "ApfsExtendedRecordCodec.h"
#include <algorithm>
#include <stdexcept>
namespace apfsaccess::rw {
bool ApfsFusionReadSession::ValidatePlanningRecords(const catalog::ApfsFusionStore& store,
    const catalog::NxSuperblock& container, const catalog::ApsbVolume& volume,
    const std::vector<catalog::BtreeRecord>& records, std::string& error)
{
    const auto& bound = store.Checkpoint().superblock;
    if (container.uuid_hex != bound.uuid_hex || container.fusion_uuid != bound.fusion_uuid ||
        container.block_size != bound.block_size || container.block_count != bound.block_count ||
        !store.CheckAvailable(error)) { error = "FusionPlanningNamespaceBindingMismatch"; return false; }
    NativeApfsVolumeProjection projection;
    if (!NativeApfsReader::ProjectFusionReadOnlyRecords(records,container,volume,
            store.SizeBytes()/container.block_size,store.ReadBudget(),projection,error)) return false;
    const auto validate = [&](const auto& extents) {
        for (const auto& extent : extents) {
            if (!extent.physical_address) continue;
            catalog::FusionRoute route;
            if (!store.MapPhysical(extent.physical_address/container.block_size,
                    extent.physical_address%container.block_size,extent.bytes,route,error)) return false;
        }
        return true;
    };
    for (const auto& [id,extents] : projection.read_extents_by_inode) if (!validate(extents)) return false;
    for (const auto& [id,extents] : projection.attribute_stream_extents) if (!validate(*extents)) return false;
    return store.CheckAvailable(error);
}
using namespace catalog;
struct ApfsFusionReadSession::Operation {
    const ApfsFusionReadSession& session;
    ApfsReadBudget budget{100000,256*1024*1024,1000000,256*1024*1024};
    bool owns;
    explicit Operation(const ApfsFusionReadSession& s) : session(s), owns(s.runtime_enabled_ && !s.operation_budget_) {
        if(owns) s.operation_budget_=&budget;
    }
    ~Operation() { if(owns) session.operation_budget_=nullptr; }
};
bool ApfsFusionReadSession::EnableRuntimeReads(std::string& error) {
    if(!CheckAvailable(error) || !source_->RuntimeCapable()) return false;
    runtime_enabled_=true; return true;
}
bool ApfsFusionReadSession::Charge(std::uint64_t records,std::uint64_t bytes,std::string& error) const {
    auto* budget=operation_budget_ ? operation_budget_ : source_->ReadBudget().get();
    if(budget->Materialize(records,bytes)) return true;
    if(!CheckAvailable(error)) return false;
    return Fail(FusionReadStatus::ResourceLimit,budget->Failure(),error);
}
bool ApfsFusionReadSession::ReadBytes(std::uint64_t offset,std::size_t size,std::vector<std::byte>& out,std::string& error) const {
    bool ok;
    if(operation_budget_) {
        if(!operation_budget_->Read(size)) return Fail(FusionReadStatus::ResourceLimit,operation_budget_->Failure(),error);
        const ApfsFusionStore::RuntimeRead reservation(*source_,offset,size);
        ok=source_->ReadRuntime(reservation,out);
    } else ok=source_->Read(offset,size,out);
    if(!ok) return Fail(FusionReadStatus::Unavailable,source_->LastError().c_str(),error);
    return true;
}
bool ApfsFusionReadSession::GetNamespaceInfo(FusionNamespaceInfo& out,std::string& error) const {
    Operation operation(*this); out={};
    if(!CheckAvailable(error) || !Charge(1,sizeof(out),error)) return false;
    FusionNamespaceInfo staged{view_.root_directory_inode,view_.incompatible_features,view_.name_policy};
    if(!CheckAvailable(error)) return false;
    out=staged; return true;
}
bool ApfsFusionReadSession::GetMetadata(std::uint64_t oid,FusionNodeInfo& out,std::string& error) const {
    Operation operation(*this); out={};
    if(!CheckAvailable(error) || !Charge(1,sizeof(out),error)) return false;
    for(const auto& n:view_.inodes) if(n.object_id==oid) {
        FusionNodeInfo staged{n.object_id,n.parent_object_id,n.logical_size,n.allocation_size.value_or(0),
            n.create_time_utc,n.modification_time_utc,n.change_time_utc,n.access_time_utc,
            n.owner,n.group,n.is_directory ? n.directory_entry_count : n.link_count,n.mode};
        if(oid==view_.root_directory_inode) staged.parent_id=oid;
        if(!CheckAvailable(error)) return false;
        out=staged;return true;
    }
    return Fail(FusionReadStatus::NotFound,"FusionInodeMissing",error);
}
bool ApfsFusionReadSession::ListXattrs(std::uint64_t oid,std::vector<FusionXattrInfo>& out,std::string& error) const try {
    Operation operation(*this); out.clear(); FusionNodeInfo node;
    if(!GetMetadata(oid,node,error)) return false;
    std::vector<FusionXattrInfo> staged;
    const auto found=view_.extended_attributes_by_inode.find(oid);
    if(found!=view_.extended_attributes_by_inode.end()) for(const auto& [name,attr]:found->second) {
        if(!Charge(1,sizeof(FusionXattrInfo)+name.size(),error)) return false;
        staged.push_back({name,(attr.flags & kAppleXattrDataStream) ? ReadU64LE(attr.data,8).value() : attr.data.size()});
    }
    if(!CheckAvailable(error)) return false;
    out=std::move(staged);return true;
} catch(const std::bad_alloc&) {out.clear();return AllocationFailed(error);}
  catch(const std::length_error&) {out.clear();return AllocationFailed(error);}
bool ApfsFusionReadSession::Fail(FusionReadStatus status, const char* reason, std::string& error) const
{ status_ = status; error = reason; return false; }
bool ApfsFusionReadSession::CheckAvailable(std::string& error) const
{
    if (!source_->CheckAvailable(error)) { status_ = FusionReadStatus::Unavailable; return false; }
    status_ = FusionReadStatus::Ok; return true;
}
void ApfsFusionReadSession::Cancel() const { source_->Cancel(); status_ = FusionReadStatus::Unavailable; }
std::unique_ptr<ApfsFusionReadSession> ApfsFusionReadSession::Open(
    std::unique_ptr<ApfsFusionStore> source, const FusionVolumeSelection& selected,
    FusionReadStatus& status, std::string& error, unsigned* unavailable_members)
{
    if (unavailable_members) *unavailable_members = 0;
    status = FusionReadStatus::Unavailable; error.clear();
    if (!source || !source->CheckAvailable(error)) { if (unavailable_members && source) *unavailable_members = source->UnavailableMembers(); if (error.empty()) error = "FusionSourceRequired"; return {}; }
    auto budget = source->ReadBudget();
    try {
        const auto& nx = source->Checkpoint().superblock;
        if (selected.container_uuid_hex != nx.uuid_hex || selected.checkpoint_xid != nx.xid ||
            !selected.volume_oid || selected.volume_uuid_hex.empty() ||
            selected.member_store_ids[0] != source->Members()[0].stable_store_id ||
            selected.member_store_ids[1] != source->Members()[1].stable_store_id)
        { status = FusionReadStatus::SelectionMismatch; error = "FusionSelectionIdentityMismatch"; return {}; }
        auto result = std::unique_ptr<ApfsFusionReadSession>(new ApfsFusionReadSession);
        result->source_ = std::move(source);
        // Destroy this guard before result so failed catalog/session admission
        // retains the exact missing-member diagnostic while its source is alive.
        struct AdmissionDiagnostic {
            const ApfsFusionStore* source;
            unsigned* output;
            ~AdmissionDiagnostic() { if (output) *output = source->UnavailableMembers(); }
        } diagnostic{result->source_.get(), unavailable_members};
        const auto failed = [&](FusionReadStatus fallback) {
            std::string availability_error;
            if (!result->source_->CheckAvailable(availability_error))
            { status = FusionReadStatus::Unavailable; error = std::move(availability_error); }
            else status = fallback;
        };
        if (!ApfsContainerCatalog::TryLoadFusion(*result->source_, "fusion", "held-fusion-images", result->catalog_, error))
        { failed(FusionReadStatus::MetadataInvalid); return {}; }
        const auto* readonly = result->catalog_.TryGetReadOnlyVolumeView();
        if (!readonly) { status = FusionReadStatus::Unavailable; error = "FusionCatalogUnavailable"; return {}; }
        const auto found = std::find_if(readonly->volumes.begin(), readonly->volumes.end(),
            [&](const auto& v) { return v.superblock.object_id == selected.volume_oid && v.superblock.uuid_hex == selected.volume_uuid_hex; });
        if (found == readonly->volumes.end())
        { status = FusionReadStatus::SelectionMismatch; error = "FusionSelectedVolumeMissing"; return {}; }
        const auto& volume = *found;
        if (volume.superblock.fs_flags != kFsFlagUnencrypted)
        { status = FusionReadStatus::EncryptionUnsupported; error = "FusionEncryptionUnsupported"; return {}; }
        if ((volume.superblock.features & ~kVolumeKnownOptionalFeaturesMask) || volume.superblock.readonly_features || (volume.superblock.incompatible_features & ~kVolumeSupportedIncompatibleFeaturesMask))
        { status = FusionReadStatus::FeaturesUnsupported; error = "FusionVolumeFeaturesUnsupported"; return {}; }
        if (volume.superblock.fext_tree_oid || volume.superblock.fext_tree_type)
        { status = FusionReadStatus::FileExtentTreeUnsupported; error = "FusionSeparateFileExtentTreeUnsupported"; return {}; }
        std::vector<catalog::BtreeRecord> records;
        if (!ReadAppleVolumeFileSystemRecords(*result->source_, readonly->container, volume, records, error))
        { failed(FusionReadStatus::MetadataInvalid); return {}; }
        for (const auto& record : records)
            if (!budget->Materialize(1, sizeof(record) + record.key.size() + record.value.size()))
            { status = FusionReadStatus::Unavailable; error = budget->Failure(); return {}; }
        auto ordered = records;
        if (!SortAppleBtreeRecords(ordered, ApfsNamePolicy::FromIncompatibleFeatures(volume.superblock.incompatible_features).UsesHashedDirectoryKeys()
            ? AppleBtreeKeyOrder::FileSystemHashedDirectory : AppleBtreeKeyOrder::FileSystemCaseSensitive, error))
        { failed(FusionReadStatus::MetadataInvalid); return {}; }
        for (std::size_t i = 0; i < records.size(); ++i)
            if (records[i].key != ordered[i].key)
            { status = FusionReadStatus::MetadataInvalid; error = "FusionFilesystemKeyOrderInvalid"; return {}; }
        if (!NativeApfsReader::ProjectFusionReadOnlyRecords(records, nx, volume.superblock,
            result->source_->SizeBytes() / nx.block_size, budget, result->view_, error))
        { failed(error.find("Unsupported") != std::string::npos ? FusionReadStatus::FilesystemUnsupported : FusionReadStatus::MetadataInvalid); return {}; }
        // The projector uses a routed span only for arithmetic. Validate every
        // nonzero complete extent against its real member, including xattrs.
        const auto validate = [&](const auto& extents) {
            for (const auto& extent : extents) {
                if (!extent.physical_address) continue; // shared projector proved explicit sparse coverage
                FusionRoute route;
                if (!result->source_->MapPhysical(extent.physical_address / nx.block_size,
                    extent.physical_address % nx.block_size, extent.bytes, route, error)) return false;
            }
            return true;
        };
        for (const auto& [id, extents] : result->view_.read_extents_by_inode)
            if (!validate(extents)) { failed(FusionReadStatus::MetadataInvalid); return {}; }
        for (const auto& [id, extents] : result->view_.attribute_stream_extents)
            if (!validate(*extents)) { failed(FusionReadStatus::MetadataInvalid); return {}; }
        if (!result->CheckAvailable(error)) { status = FusionReadStatus::Unavailable; return {}; }
        result->view_.incompatible_features=volume.superblock.incompatible_features;
        status = FusionReadStatus::Ok; return result;
    } catch (const std::bad_alloc&) { (void)budget->Refuse("ApfsReadBudgetAllocationFailed"); }
      catch (const std::length_error&) { (void)budget->Refuse("ApfsReadBudgetAllocationFailed"); }
    status = FusionReadStatus::Unavailable; error = budget->Failure(); return {};
}
bool ApfsFusionReadSession::AllocationFailed(std::string& error) const
{
    if(runtime_enabled_) return Fail(FusionReadStatus::ResourceLimit,"ApfsReadBudgetAllocationFailed",error);
    (void)source_->ReadBudget()->Refuse("ApfsReadBudgetAllocationFailed");
    (void)CheckAvailable(error); return false;
}
bool ApfsFusionReadSession::GetCatalog(ApfsContainerCatalog& out, std::string& error) const try
{
    Operation operation(*this);
    out = {};
    if (!CheckAvailable(error)) return false;
    const auto* view = catalog_.TryGetReadOnlyVolumeView();
    if (!view || !Charge(1,
        sizeof(ApfsContainerCatalog) + view->container.superblock_bytes.size() +
        view->container.mappings.size() * sizeof(CheckpointMapping) +
        view->container.checkpoint_map_blocks.size() * sizeof(std::uint64_t) +
        view->volumes.size() * (sizeof(AppleVolumeCheckpointView) + 8192) + 8192, error))
        return false;
    out = catalog_;
    if (!CheckAvailable(error)) { out = {}; return false; }
    return true;
}
catch (const std::bad_alloc&) { out = {}; return AllocationFailed(error); }
catch (const std::length_error&) { out = {}; return AllocationFailed(error); }

bool ApfsFusionReadSession::Enumerate(std::uint64_t oid,
    std::vector<MetadataStore::DirectoryLink>& out, std::string& error) const try
{
    Operation operation(*this);
    out.clear(); if (!CheckAvailable(error)) return false;
    if (oid == 3) return Fail(FusionReadStatus::NotFound, "FusionPrivateDirectoryHidden", error);
    const auto inode = std::find_if(view_.inodes.begin(), view_.inodes.end(), [&](const auto& i) {return i.object_id == oid && i.is_directory;});
    if (inode == view_.inodes.end()) return Fail(FusionReadStatus::NotFound, "FusionDirectoryMissing", error);
    std::vector<MetadataStore::DirectoryLink> staged;
    for (const auto& link : view_.directory_links) if (link.parent_object_id == oid) {
        if (!Charge(1, sizeof(link) + 4 * link.entry_name.size() + link.entry_name_utf8.size(), error))
            return false;
        staged.push_back(link);
    }
    if (!CheckAvailable(error)) return false;
    out = std::move(staged); return true;
}
catch (const std::bad_alloc&) { out.clear(); return AllocationFailed(error); }
catch (const std::length_error&) { out.clear(); return AllocationFailed(error); }

bool ApfsFusionReadSession::Lookup(std::uint64_t oid,std::wstring_view name,
    std::uint64_t& out_oid,std::string& error) const {
    out_oid=0;MetadataStore::DirectoryLink entry;
    if(!LookupEntry(oid,name,entry,error))return false;
    out_oid=entry.child_object_id;return true;
}
bool ApfsFusionReadSession::PrivateFiles(std::map<std::uint64_t, std::string>& out, std::string& error) const
{
    Operation operation(*this); out.clear();
    if (!CheckAvailable(error)) return false;
    std::map<std::uint64_t, std::string> files;
    for (const auto& node : view_.inodes) if (node.internal_flags & 1) {
        if (node.parent_object_id != 3 || !Charge(1, sizeof(node.object_id) + node.name_utf8.size(), error) ||
            !files.emplace(node.object_id, node.name_utf8).second) return false;
    }
    if (!CheckAvailable(error)) return false;
    out = std::move(files); return true;
}
bool ApfsFusionReadSession::LookupEntry(std::uint64_t oid, std::wstring_view name,
    MetadataStore::DirectoryLink& out, std::string& error) const try
{
    Operation operation(*this);
    out = {}; if (!CheckAvailable(error)) return false;
    auto key = ApfsNameCodec::CanonicalWindowsComponentKey(name, view_.name_policy);
    if (!key.ok()) return Fail(FusionReadStatus::NotFound, "FusionNameInvalid", error);
    std::vector<MetadataStore::DirectoryLink> links;
    if (!Enumerate(oid, links, error)) return false;
    for (const auto& link : links) {
        auto candidate = ApfsNameCodec::CanonicalWindowsComponentKey(link.entry_name, view_.name_policy);
        if (candidate.ok() && *candidate.value == *key.value) {
            if (!CheckAvailable(error)) return false;
            out = link; return true;
        }
    }
    return Fail(FusionReadStatus::NotFound, "FusionNameMissing", error);
}
catch (const std::bad_alloc&) { out = {}; return AllocationFailed(error); }
catch (const std::length_error&) { out = {}; return AllocationFailed(error); }

bool ApfsFusionReadSession::ReadRange(const std::vector<MetadataStore::FileExtent>& extents,
    std::uint64_t logical_size, std::uint64_t offset, std::size_t count,
    std::vector<std::byte>& out, std::string& error) const try
{
    Operation operation(*this);
    out.clear(); if (!CheckAvailable(error)) return false;
    if (count > 16 * 1024 * 1024) return Fail(FusionReadStatus::RangeLimit, "FusionReadRangeLimit", error);
    if (offset >= logical_size || !count) return CheckAvailable(error);
    count = static_cast<std::size_t>((std::min)(static_cast<std::uint64_t>(count), logical_size - offset));
    if (!Charge(1, count, error)) return false;
    std::vector<std::byte> staged(count); // only explicit, validated hole records produce zeros
    std::uint64_t cursor = offset; std::size_t entries = 0;
    for (const auto& extent : extents) {
        if (cursor >= offset + count) break;
        if (extent.logical_offset + extent.bytes <= cursor) continue;
        if (++entries > 4096) return Fail(FusionReadStatus::RangeLimit, "FusionReadExtentLimit", error);
        if (extent.logical_offset > cursor) return Fail(FusionReadStatus::MetadataInvalid, "FusionReadCoverageMissing", error);
        const auto within = cursor - extent.logical_offset;
        const auto size = static_cast<std::size_t>((std::min)(extent.bytes - within, offset + count - cursor));
        if (extent.physical_address) {
            std::vector<std::byte> bytes;
            if (!ReadBytes(extent.physical_address + within, size, bytes, error)) return false;
            std::copy(bytes.begin(), bytes.end(), staged.begin() + static_cast<std::ptrdiff_t>(cursor - offset));
        }
        cursor += size;
    }
    if (cursor != offset + count) return Fail(FusionReadStatus::MetadataInvalid, "FusionReadCoverageMissing", error);
    if (!CheckAvailable(error)) return false;
    out = std::move(staged); return true;
}
catch (const std::bad_alloc&) { out.clear(); return AllocationFailed(error); }
catch (const std::length_error&) { out.clear(); return AllocationFailed(error); }

bool ApfsFusionReadSession::ReadFile(std::uint64_t oid, std::uint64_t offset, std::size_t count,
    std::vector<std::byte>& out, std::string& error) const try
{
    Operation operation(*this);
    out.clear(); if (!CheckAvailable(error)) return false;
    const auto inode = std::find_if(view_.inodes.begin(), view_.inodes.end(), [&](const auto& i) {return i.object_id == oid;});
    if (inode == view_.inodes.end()) return Fail(FusionReadStatus::NotFound, "FusionInodeMissing", error);
    if (inode->node_type != MetadataStore::NodeType::RegularFile) return Fail(FusionReadStatus::NotRegularFile, "FusionNotRegularFile", error);
    const auto found = view_.read_extents_by_inode.find(oid);
    static const std::vector<MetadataStore::FileExtent> empty;
    return ReadRange(found == view_.read_extents_by_inode.end() ? empty : found->second, inode->logical_size, offset, count, out, error);
}
catch (const std::bad_alloc&) { out.clear(); return AllocationFailed(error); }
catch (const std::length_error&) { out.clear(); return AllocationFailed(error); }

bool ApfsFusionReadSession::ReadXattr(std::uint64_t oid, const std::string& name,
    std::uint64_t offset, std::size_t count, std::vector<std::byte>& out, std::string& error) const try
{
    Operation operation(*this);
    out.clear(); if (!CheckAvailable(error)) return false;
    const auto attrs = view_.extended_attributes_by_inode.find(oid);
    if (attrs == view_.extended_attributes_by_inode.end() || !attrs->second.contains(name))
        return Fail(FusionReadStatus::NotFound, "FusionXattrMissing", error);
    const auto& attr = attrs->second.at(name);
    if (count > 16 * 1024 * 1024) return Fail(FusionReadStatus::RangeLimit, "FusionReadRangeLimit", error);
    if (attr.flags & kAppleXattrDataStream) {
        const auto id = ReadU64LE(attr.data, 0).value();
        return ReadRange(*view_.attribute_stream_extents.at(id), ReadU64LE(attr.data, 8).value(), offset, count, out, error);
    }
    if (offset >= attr.data.size() || !count) return CheckAvailable(error);
    count = (std::min)(count, attr.data.size() - static_cast<std::size_t>(offset));
    if (!Charge(1, count, error)) return false;
    std::vector<std::byte> staged(attr.data.begin() + offset, attr.data.begin() + offset + count);
    if (!CheckAvailable(error)) return false;
    out = std::move(staged); return true;
}
catch (const std::bad_alloc&) { out.clear(); return AllocationFailed(error); }
catch (const std::length_error&) { out.clear(); return AllocationFailed(error); }

}
