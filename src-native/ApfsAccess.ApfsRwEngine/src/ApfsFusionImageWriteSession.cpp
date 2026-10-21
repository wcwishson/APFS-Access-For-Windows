#include "ApfsFusionImageWriteSession.h"
#include "ApfsFusionSpaceman.h"
#include <algorithm>
#include <bcrypt.h>
#include <limits>

namespace apfsaccess::rw
{
namespace
{
bool Fail(std::string& error, const char* reason) { error = reason; return false; }
bool OrdinaryPath(const std::wstring& path)
{
    if (path.size() < 4 || !((path[0] >= L'A' && path[0] <= L'Z') ||
        (path[0] >= L'a' && path[0] <= L'z')) || path[1] != L':' || path[2] != L'\\' ||
        path.find_first_of(L":/*?\"<>|", 3) != path.npos ||
        std::any_of(path.begin(), path.end(), [](wchar_t c) { return c < 32; })) return false;
    for (std::size_t begin = 3; begin < path.size();)
    {
        auto end = path.find(L'\\', begin); if (end == path.npos) end = path.size();
        const auto part = path.substr(begin, end - begin);
        if (part.empty() || part == L"." || part == L".." || part.back() == L'.' || part.back() == L' ') return false;
        auto stem = part.substr(0, part.find(L'.'));
        std::transform(stem.begin(), stem.end(), stem.begin(), [](wchar_t c) -> wchar_t {
            return c >= L'a' && c <= L'z' ? static_cast<wchar_t>(c - 32) : c; });
        if (stem == L"CON" || stem == L"PRN" || stem == L"AUX" || stem == L"NUL" ||
            stem == L"CONIN$" || stem == L"CONOUT$" ||
            (stem.size() == 4 && (stem.starts_with(L"COM") || stem.starts_with(L"LPT")))) return false;
        begin = end + 1;
    }
    return path.back() != L'\\';
}
void Number(std::vector<std::byte>& bytes, std::uint64_t value)
{ for (unsigned i = 0; i < 8; ++i) bytes.push_back(std::byte((value >> (8 * i)) & 255)); }
void Text(std::vector<std::byte>& bytes, std::string_view value)
{
    Number(bytes, value.size());
    for (unsigned char c : value) bytes.push_back(std::byte(c));
}
bool Hash(std::span<const std::byte> bytes, std::array<std::byte, 32>& out)
{
    return bytes.size() <= (std::numeric_limits<ULONG>::max)() && BCryptHash(BCRYPT_SHA256_ALG_HANDLE, nullptr, 0,
        reinterpret_cast<PUCHAR>(const_cast<std::byte*>(bytes.data())), static_cast<ULONG>(bytes.size()),
        reinterpret_cast<PUCHAR>(out.data()), static_cast<ULONG>(out.size())) >= 0;
}
}
struct ApfsFusionImageWriteSession::DirectoryLeases
{
    std::vector<HANDLE> handles;
    ~DirectoryLeases() { for (auto h : handles) CloseHandle(h); }
    bool Pin(const std::wstring& path, std::string& error)
    {
        if (!OrdinaryPath(path)) return Fail(error, "FusionImageOrdinaryLocalPathRequired");
        const auto type = GetDriveTypeW(path.substr(0, 3).c_str());
        if (type != DRIVE_FIXED && type != DRIVE_REMOVABLE && type != DRIVE_RAMDISK)
            return Fail(error, "FusionImageLocalDriveRequired");
        for (std::size_t end = 2; end != path.npos; end = path.find(L'\\', end + 1))
        {
            const auto prefix = path.substr(0, end == 2 ? 3 : end);
            const auto h = CreateFileW(prefix.c_str(), FILE_READ_ATTRIBUTES, FILE_SHARE_READ,
                nullptr, OPEN_EXISTING, FILE_FLAG_BACKUP_SEMANTICS | FILE_FLAG_OPEN_REPARSE_POINT, nullptr);
            if (h == INVALID_HANDLE_VALUE) return Fail(error, "FusionImageDirectoryLeaseUnavailable");
            handles.push_back(h);
            FILE_ATTRIBUTE_TAG_INFO info{};
            if (!GetFileInformationByHandleEx(h, FileAttributeTagInfo, &info, sizeof(info)) ||
                !(info.FileAttributes & FILE_ATTRIBUTE_DIRECTORY) || (info.FileAttributes & FILE_ATTRIBUTE_REPARSE_POINT))
                return Fail(error, "FusionImageDirectoryReparseOrInvalid");
        }
        return true;
    }
};

std::unique_ptr<ApfsFusionImageWriteSession> ApfsFusionImageWriteSession::Open(
    const catalog::FusionBindRequest& request, const FusionVolumeSelection& selected,
    std::string& error, unsigned* unavailable_members)
{ return OpenInternal(request, selected, error, unavailable_members, nullptr); }
std::unique_ptr<ApfsFusionImageWriteSession> ApfsFusionImageWriteSession::OpenInternal(
    const catalog::FusionBindRequest& request, const FusionVolumeSelection& selected,
    std::string& error, unsigned* unavailable_members,
    const std::map<std::uint64_t,std::vector<std::byte>>* preimage) try
{
    error.clear(); if (unavailable_members) *unavailable_members = 0;
    if (request.members.size() != 2 || request.members[0].role == request.members[1].role)
        return (Fail(error, "FusionImageCompleteTwoMemberSetRequired"), nullptr);
    auto result = std::unique_ptr<ApfsFusionImageWriteSession>(new ApfsFusionImageWriteSession);
    result->directories_ = std::make_unique<DirectoryLeases>();
    result->external_cancellation_ = request.cancellation;
    if (request.cancellation && request.cancellation->load())
        return (Fail(error, "FusionImageCancelled"), nullptr);
    // Validate all path spellings before attempting any member open.
    for (const auto& m : request.members)
        if ((m.role != catalog::FusionMemberRole::Main && m.role != catalog::FusionMemberRole::Tier2) ||
            !OrdinaryPath(m.path)) return (Fail(error, "FusionImageOrdinaryLocalPathRequired"), nullptr);
    for (const auto& m : request.members)
        if (!result->directories_->Pin(m.path, error)) return {};
    for (const auto& m : request.members)
    {
        const auto role = m.role == catalog::FusionMemberRole::Main ? 0u : 1u;
        auto& device = result->devices_[role];
        device = BlockDevice::OpenExclusiveManagementImage(m.path, 0, error);
        catalog::FusionImageIdentity actual;
        if (!device || !device->QueryHeldImageIdentity(actual) || actual != m.exact_identity)
        {
            if (unavailable_members) *unavailable_members = 1u << role;
            if (error.empty()) error = "FusionImageExactIdentityMismatch";
            return {};
        }
    }
    auto binding = request;
    // Keep the externally revocable token in the store as well. Owner Cancel
    // independently prevents subsequent operations through the gate.
    if (!binding.cancellation) binding.cancellation = result->cancellation_;
    auto store = catalog::ApfsFusionStore::BindHeldImages(binding, result->devices_, result->cancellation_, error, unavailable_members, preimage);
    if (!store) return {};
    result->writer_ = catalog::ApfsFusionWriteSession::Bind(*store, result->devices_[0], result->devices_[1], error, unavailable_members);
    if (!result->writer_) return {};
    catalog::FusionSpacemanOwnership geometry;
    if (!catalog::LoadFusionSpacemanOwnership(*store, geometry, error)) return {};
    if (!Identify(request,selected,geometry.block_size,result->source_binding_,result->journal_identity_,error)) return {};
    result->request_=request;result->selection_=selected;
    result->volume_oid_ = selected.volume_oid;
    result->status_.checkpoint_xid = store->Checkpoint().superblock.xid;
    result->status_.tier_ahead = store->TierAheadSkewTolerated();
    result->store_ = store.get();
    FusionReadStatus read_status;
    result->reader_ = ApfsFusionReadSession::Open(std::move(store), selected, read_status, error, unavailable_members);
    if (!result->reader_) { result->store_ = nullptr; return {}; }
    if (!result->reader_->EnableRuntimeReads(error)) return {};
    result->status_.closed = false;
    if (!result->Available(error)) return {};
    return result;
}
catch (const std::bad_alloc&) { error = "FusionImageAllocationLimit"; return {}; }
catch (const std::length_error&) { error = "FusionImageAllocationLimit"; return {}; }

bool ApfsFusionImageWriteSession::Identify(const catalog::FusionBindRequest& request,
    const FusionVolumeSelection& selected,std::uint32_t block_size,std::array<std::byte,32>& source,
    std::wstring& jid,std::string& error)
{
    if(request.members.size()!=2)return Fail(error,"FusionImageCompleteTwoMemberSetRequired");
    std::vector<std::byte> identity;
    Text(identity, "apfs-fusion-image-v1");
    Text(identity, request.container_uuid_hex); Text(identity, request.fusion_uuid_hex);
    Number(identity, static_cast<unsigned>(request.convention)); Number(identity, block_size);
    for (const auto role : {catalog::FusionMemberRole::Main, catalog::FusionMemberRole::Tier2})
    {
        const auto found=std::find_if(request.members.begin(),request.members.end(),[&](const auto& m){return m.role==role;});
        if(found==request.members.end())return Fail(error,"FusionImageCompleteTwoMemberSetRequired");
        const auto& m = *found; const auto& file = m.exact_identity;
        Number(identity, static_cast<unsigned>(role)); Text(identity, m.stable_store_id);
        Number(identity, file.volume_serial); identity.insert(identity.end(), file.file_id.begin(), file.file_id.end());
        Number(identity, file.creation_time); Number(identity, file.size_bytes);
        Number(identity, m.store_offset); Number(identity, m.store_size);
    }
    if (!Hash(identity, source)) return Fail(error, "FusionImageBindingHashFailed");
    const auto journal = "apfs-fusion-image-v1:" + catalog::BytesToHexLower(source.data(), source.size()) +
        ":" + std::to_string(selected.volume_oid) + ":" + selected.volume_uuid_hex;
    jid.assign(journal.begin(), journal.end());return true;
}

bool ApfsFusionImageWriteSession::RefreshHeld(std::uint64_t xid,std::string& error,
    const std::map<std::uint64_t,std::vector<std::byte>>* preimage)
{
    if(!Available(error))return false;
    auto request=request_;auto selected=selection_;request.checkpoint_xid=selected.checkpoint_xid=xid;
    for(auto& m:request.members)if(!devices_[m.role==catalog::FusionMemberRole::Main?0:1]->QueryHeldImageIdentity(m.exact_identity))return Fail(error,"FusionRefreshIdentity");
    auto store=catalog::ApfsFusionStore::BindHeldImages(request,devices_,cancellation_,error,nullptr,preimage);
    if(!store)return false;
    auto writer=catalog::ApfsFusionWriteSession::Bind(*store,devices_[0],devices_[1],error);
    if(!writer)return false;
    auto* bound=store.get();FusionReadStatus status;
    auto reader=ApfsFusionReadSession::Open(std::move(store),selected,status,error);
    if(!reader||!reader->EnableRuntimeReads(error))return false;
    writer_=std::move(writer);reader_=std::move(reader);store_=bound;request_=std::move(request);selection_=std::move(selected);
    status_.checkpoint_xid=xid;status_.tier_ahead=false;return Available(error);
}

ApfsFusionImageWriteSession::~ApfsFusionImageWriteSession() { Close(); }
bool ApfsFusionImageWriteSession::Available(std::string& error)
{
    error.clear();
    if (status_.closed || !store_ || !reader_ || !writer_) return Fail(error, "FusionImageClosed");
    if (cancellation_->load() || (external_cancellation_ && external_cancellation_->load()))
    {
        cancellation_->store(true); status_.cancelled = true; store_->Cancel();
        return Fail(error, "FusionImageCancelled");
    }
    if (!writer_->CheckAvailable(error))
    {
        status_.unavailable_members |= store_->UnavailableMembers();
        return false;
    }
    return true;
}
bool ApfsFusionImageWriteSession::CheckAvailable(std::string& error)
{ std::lock_guard lock(gate_); return Available(error); }
bool ApfsFusionImageWriteSession::ReadFile(std::uint64_t inode, std::uint64_t offset, std::size_t count,
    std::vector<std::byte>& out, std::string& error)
{
    std::lock_guard lock(gate_); out.clear();
    if (!Available(error) || !reader_->ReadFile(inode, offset, count, out, error) || !Available(error))
    { out.clear(); return false; }
    return true;
}
bool ApfsFusionImageWriteSession::InspectAcceptedOverwrite(TransactionManager& transactions,
    std::uint64_t sequence, FusionAcceptedOverwriteInspection& out, std::string& error) try
{
    std::lock_guard lock(gate_); out = {};
    if (!Available(error)) return false;
    if (!sequence || !transactions.JournalMatchesVolumeIdentity(journal_identity_) ||
        !transactions.RecoveryStateValid()) return Fail(error, "FusionImageOriginalJournalMismatch");
    std::vector<TransactionManager::AcceptedTransaction> accepted;
    if (!transactions.LoadAcceptedTransactionsSinceCleanup(accepted, &error)) return false;
    if (accepted.empty() || accepted.front().accepted_sequence != sequence)
        return Fail(error, "FusionImageEarliestOriginalBoundaryRequired");
    const auto& original = accepted.front();
    if (original.preimage_checkpoint_xid != status_.checkpoint_xid || original.mutations.size() != 1)
        return Fail(error, "FusionImageExactSingleOverwritePreimageRequired");
    const auto& m = original.mutations.front();
    if (m.operation != WriteAheadLog::OperationKind::Write || m.state != WriteAheadLog::RecordState::Prepared ||
        m.transaction_id != original.transaction_id || !m.sequence || m.sequence >= sequence ||
        m.object_id < 16 || m.parent_object_id != original.preimage_checkpoint_xid || m.flags || m.unlink_outcome ||
        !m.secondary_path_utf8.empty() || !m.logical_length || m.logical_length > 256 * 1024 ||
        m.logical_length != m.payload_length || m.inline_payload.size() != m.payload_length ||
        m.payload_offset || m.payload_spool_id != m.sequence || !WriteAheadLog::InlinePayloadIsConsistent(m))
        return Fail(error, "FusionImageOriginalInlineOverwriteRequired");
    FusionNodeInfo node;
    if (!reader_->GetMetadata(m.object_id, node, error)) return false;
    if ((node.mode & 0170000) != 0100000 || m.logical_offset > node.size || m.logical_length > node.size - m.logical_offset)
        return Fail(error, "FusionImageExistingFileRangeRequired");
    // Resolve the original bytes through the admitted canonical reader before
    // exposing the record for planning. No APFS-durable watermark is advanced.
    std::vector<std::byte> before;
    if (!reader_->ReadFile(m.object_id, m.logical_offset, static_cast<std::size_t>(m.logical_length), before, error) ||
        before.size() != m.logical_length || !Available(error)) return false;
    out = {sequence, original.transaction_id, original.preimage_checkpoint_xid,
        m.object_id, m.logical_offset, m.inline_payload};
    return true;
}
catch (const std::bad_alloc&) { out = {}; return Fail(error, "FusionImageAllocationLimit"); }
catch (const std::length_error&) { out = {}; return Fail(error, "FusionImageAllocationLimit"); }

bool ApfsFusionImageWriteSession::CheckAllocatorAdmission(std::string& error)
{
    std::lock_guard lock(gate_);
    if (!Available(error)) return false;
    catalog::AppleSpacemanView ownership;
    return catalog::LoadFusionSpacemanAllocationView(*store_, ownership, error) && Available(error);
}
bool ApfsFusionImageWriteSession::PlanVolumeTransaction(const AppleVolumeTransactionRequest& request,
    FusionVolumeTransactionPlan& out, std::string& error)
{
    std::lock_guard lock(gate_); out = {};
    if (!Available(error)) return false;
    if (request.volume_object_id != volume_oid_) return Fail(error,"FusionImageVolumeSelectionMismatch");
    if (!PlanFusionVolumeTransaction(*store_,request,out,error) || !Available(error))
    { out = {}; return false; }
    return true;
}
void ApfsFusionImageWriteSession::Cancel() noexcept { cancellation_->store(true); }
void ApfsFusionImageWriteSession::Close() noexcept
{
    Cancel(); std::lock_guard lock(gate_);
    writer_.reset(); reader_.reset(); store_ = nullptr;
    devices_ = {}; directories_.reset(); status_.closed = true;
}
FusionImageWriteStatus ApfsFusionImageWriteSession::Status() const
{
    std::lock_guard lock(gate_); auto status = status_;
    status.cancelled = cancellation_->load() || (external_cancellation_ && external_cancellation_->load());
    return status;
}
}
