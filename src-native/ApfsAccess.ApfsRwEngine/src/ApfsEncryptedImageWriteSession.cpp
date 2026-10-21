#include "ApfsEncryptedImageWriteSession.h"
#include "ApfsFormat.h"
#include "ApfsSoftwareKeybagMaintenance.h"
#include "ApfsSoftwareKeybagPublication.h"
#include "InodeMetadataPatch.h"
#include "ApfsExtendedRecordCodec.h"
#include "EncryptedImagePlainWriterDependencies.inc"
#ifndef NOMINMAX
#define NOMINMAX
#endif
#include <windows.h>
#include <bcrypt.h>
#include <algorithm>
#include <mutex>
#include <stdexcept>
#include <utility>
#undef CreateFile
#undef CreateDirectory

namespace apfsaccess::catalog
{
namespace
{
using Phase = EncryptedImageWritePhase;
using Error = EncryptedReadError;
struct Handle
{
    HANDLE value = INVALID_HANDLE_VALUE;
    explicit Handle(HANDLE h) : value(h) {}
    Handle(Handle&& other) noexcept : value(std::exchange(other.value, INVALID_HANDLE_VALUE)) {}
    ~Handle() { if (value != INVALID_HANDLE_VALUE) CloseHandle(value); }
};
bool OrdinaryPath(const std::wstring& path)
{
    if (path.size() < 4 || !((path[0] >= L'A' && path[0] <= L'Z') || (path[0] >= L'a' && path[0] <= L'z')) ||
        path[1] != L':' || path[2] != L'\\' ||
        path.find_first_of(L":*?\"<>|/", 3) != path.npos ||
        std::any_of(path.begin(), path.end(), [](wchar_t c) { return c < 32; })) return false;
    for (std::size_t begin = 3; begin < path.size();)
    {
        auto end = path.find(L'\\', begin);
        if (end == path.npos) end = path.size();
        auto part = path.substr(begin, end - begin);
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
std::array<std::byte, 32> Hash(std::string_view text)
{
    std::array<std::byte, 32> out{};
    if (BCryptHash(BCRYPT_SHA256_ALG_HANDLE, nullptr, 0,
        reinterpret_cast<PUCHAR>(const_cast<char*>(text.data())), static_cast<ULONG>(text.size()),
        reinterpret_cast<PUCHAR>(out.data()), static_cast<ULONG>(out.size())) < 0)
        throw std::runtime_error("ImageBindingHashFailed");
    return out;
}
struct AcceptedWipe
{
    std::vector<rw::TransactionManager::AcceptedTransaction>& rows;
    ~AcceptedWipe()
    {
        for (auto& row : rows) for (auto& record : row.mutations)
            SecureZeroMemory(record.inline_payload.data(), record.inline_payload.size());
    }
};
bool ReconstructAccepted(const rw::TransactionManager::AcceptedTransaction& accepted,
    std::span<const std::byte> supplied, std::uint64_t next_inode,
    EncryptedMutationRequest& request, std::string& error)
{
    const auto fail = [&](const char* reason) { error = reason; return false; };
    if (accepted.mutations.size() != 1 || !accepted.transaction_id || !accepted.preimage_checkpoint_xid)
        return fail("ImageWriterSingleTypedOriginalRequired");
    const auto& m = accepted.mutations.front();
    const bool replacement = m.operation == rw::WriteAheadLog::OperationKind::Rename && m.flags == 0x4;
    if (m.state != rw::WriteAheadLog::RecordState::Prepared || m.transaction_id != accepted.transaction_id ||
        !m.sequence || m.sequence >= accepted.accepted_sequence ||
        (m.object_id < 16 && !(m.object_id == 2 &&
            (m.operation == rw::WriteAheadLog::OperationKind::SetInodeMetadata ||
             m.operation == rw::WriteAheadLog::OperationKind::SetExtendedAttribute ||
             m.operation == rw::WriteAheadLog::OperationKind::RemoveExtendedAttribute))) ||
        (m.flags && !replacement) || m.unlink_outcome ||
        m.path_utf8.starts_with("\\$apfs-keybag-rewrap-"))
        return fail("ImageWriterTypedOriginalUnsupported");
    request = {}; request.inode = m.object_id;
    const auto name = [](const std::string& value) {
        return !value.empty() && value.size() <= 255 && value != "." && value != ".." &&
            value.find('\0') == value.npos && value.find('/') == value.npos;
    };
    const auto empty = [&] {
        return supplied.empty() && !m.payload_length && !m.payload_offset && !m.payload_spool_id &&
            m.inline_payload.empty() && m.payload_sha256 == std::array<std::uint8_t, 32>{};
    };
    const auto payload = [&] {
        if (m.payload_length > 64 * 4096 || m.logical_length != m.payload_length ||
            m.payload_length > UINT64_MAX - m.payload_offset)
            return fail("ImageWriterRecoveryPayloadCapacityOrRange");
        auto bytes = supplied;
        if (!m.inline_payload.empty() || !m.payload_length) {
            if (m.payload_offset || (m.payload_spool_id && m.payload_spool_id != m.sequence) || m.inline_payload.size() != m.payload_length ||
                (!supplied.empty() && !std::equal(supplied.begin(), supplied.end(), m.inline_payload.begin(), m.inline_payload.end())))
                return fail("ImageWriterRecoveryInlinePayloadMismatch");
            bytes = m.inline_payload;
        } else if (!m.payload_spool_id || supplied.size() != m.payload_length)
            return fail("ImageWriterExactRecoverySpoolPayloadRequired");
        std::array<std::uint8_t, 32> digest{};
        if (BCryptHash(BCRYPT_SHA256_ALG_HANDLE, nullptr, 0,
            reinterpret_cast<PUCHAR>(const_cast<std::byte*>(bytes.data())), static_cast<ULONG>(bytes.size()),
            digest.data(), static_cast<ULONG>(digest.size())) < 0 || digest != m.payload_sha256)
            return fail("ImageWriterRecoveryPayloadDigestMismatch");
        request.data = bytes; return true;
    };
    using Op = rw::WriteAheadLog::OperationKind;
    switch (m.operation) {
    case Op::Write:
        if (!m.logical_length || !m.secondary_path_utf8.empty() ||
            (m.parent_object_id != accepted.preimage_checkpoint_xid &&
                (m.parent_object_id || m.inline_payload.empty())))
            return fail("ImageWriterRecoveryWriteIntentInvalid");
        request.kind = EncryptedMutationKind::Write; request.offset = m.logical_offset;
        return payload();
    case Op::CreateFile:
        if (m.object_id != next_inode || m.parent_object_id < 2 || m.logical_offset > 0777 ||
            !name(m.path_utf8) || !m.secondary_path_utf8.empty())
            return fail("ImageWriterRecoveryCreateIntentInvalid");
        request.kind = EncryptedMutationKind::Create; request.inode = 0;
        request.parent = m.parent_object_id; request.name = m.path_utf8;
        request.permissions = static_cast<std::uint16_t>(m.logical_offset);
        return payload();
    case Op::CreateDirectory:
        if (m.object_id != next_inode || m.parent_object_id < 2 || m.logical_offset > 0777 ||
            m.logical_length || !name(m.path_utf8) || !m.secondary_path_utf8.empty() || !empty())
            return fail("ImageWriterRecoveryDirectoryIntentInvalid");
        request.kind = EncryptedMutationKind::MakeDirectory; request.inode = 0;
        request.parent = m.parent_object_id; request.name = m.path_utf8;
        request.permissions = static_cast<std::uint16_t>(m.logical_offset);
        return true;
    case Op::SetInodeMetadata:
    {
        rw::InodeMetadataPatch patch;
        std::array<std::uint8_t, 32> digest{};
        if (m.parent_object_id != accepted.preimage_checkpoint_xid || m.logical_offset || m.logical_length || m.payload_spool_id || m.payload_offset ||
            !m.secondary_path_utf8.empty() || m.payload_length != m.inline_payload.size() ||
            !rw::DecodeInodeMetadataPatch(m.inline_payload, patch) ||
            (!supplied.empty() && !std::equal(supplied.begin(), supplied.end(), m.inline_payload.begin(), m.inline_payload.end())) ||
            BCryptHash(BCRYPT_SHA256_ALG_HANDLE, nullptr, 0,
                reinterpret_cast<PUCHAR>(const_cast<std::byte*>(m.inline_payload.data())), static_cast<ULONG>(m.inline_payload.size()),
                digest.data(), static_cast<ULONG>(digest.size())) < 0 || digest != m.payload_sha256)
            return fail("ImageWriterRecoveryMetadataIntentInvalid");
        request.kind = EncryptedMutationKind::SetInodeMetadata; request.data = m.inline_payload;
        return true;
    }
    case Op::SetExtendedAttribute:
    case Op::RemoveExtendedAttribute:
    {
        if (m.parent_object_id != accepted.preimage_checkpoint_xid || m.path_utf8 != "encrypted-data" ||
            !rw::WriteAheadLog::ExtendedAttributeMutationIsConsistent(m) || m.payload_length > 3804 ||
            (!supplied.empty() && !std::equal(supplied.begin(), supplied.end(), m.inline_payload.begin(), m.inline_payload.end())))
            return fail("ImageWriterRecoveryAttributeIntentInvalid");
        request.kind = m.operation == Op::SetExtendedAttribute ? EncryptedMutationKind::SetExtendedAttribute :
            EncryptedMutationKind::RemoveExtendedAttribute;
        request.name = m.secondary_path_utf8; request.data = m.inline_payload;
        return true;
    }
    case Op::SetFileSize:
        if (m.parent_object_id || m.logical_offset || !m.secondary_path_utf8.empty() || !empty())
            return fail("ImageWriterRecoveryResizeIntentInvalid");
        request.kind = EncryptedMutationKind::Resize; request.size = m.logical_length;
        return true;
    case Op::Rename:
        if (m.parent_object_id < 2 || m.logical_offset < 2 || m.logical_length || !empty() ||
            !name(m.path_utf8) || !name(m.secondary_path_utf8))
            return fail("ImageWriterRecoveryRenameIntentInvalid");
        request.kind = replacement ? EncryptedMutationKind::ReplaceRename : EncryptedMutationKind::Rename;
        request.parent = m.parent_object_id;
        request.destination_parent = m.logical_offset; request.name = m.path_utf8; request.destination_name = m.secondary_path_utf8;
        return true;
    case Op::Delete:
        if (m.parent_object_id < 2 || m.logical_offset || m.logical_length || !empty() ||
            !name(m.path_utf8) || !m.secondary_path_utf8.empty())
            return fail("ImageWriterRecoveryUnlinkIntentInvalid");
        request.kind = EncryptedMutationKind::Unlink; request.parent = m.parent_object_id; request.name = m.path_utf8;
        return true;
    default: return fail("ImageWriterTypedOriginalUnsupported");
    }
}
struct ImageIo
{
    std::vector<Handle> directories;
    HANDLE file = INVALID_HANDLE_VALUE;
    BY_HANDLE_FILE_INFORMATION identity{};
    std::uint64_t offset = 0, bytes = 0;
    mutable std::mutex mutex;
    ~ImageIo() { if (file != INVALID_HANDLE_VALUE) CloseHandle(file); }
    bool Valid() const
    {
        BY_HANDLE_FILE_INFORMATION now{};
        return file != INVALID_HANDLE_VALUE && GetFileInformationByHandle(file, &now) &&
            now.dwVolumeSerialNumber == identity.dwVolumeSerialNumber &&
            now.nFileIndexHigh == identity.nFileIndexHigh && now.nFileIndexLow == identity.nFileIndexLow &&
            now.nFileSizeHigh == identity.nFileSizeHigh && now.nFileSizeLow == identity.nFileSizeLow;
    }
    bool Read(std::uint64_t at, std::size_t size, std::vector<std::byte>& out) const
    {
        std::lock_guard lock(mutex);
        out.clear();
        if (!Valid() || at > bytes || size > bytes - at || size > MAXDWORD || offset + at > INT64_MAX) return false;
        LARGE_INTEGER position{}; position.QuadPart = static_cast<LONGLONG>(offset + at);
        if (!SetFilePointerEx(file, position, nullptr, FILE_BEGIN)) return false;
        out.resize(size); DWORD got = 0;
        if (!::ReadFile(file, out.data(), static_cast<DWORD>(size), &got, nullptr) || got != size)
        { out.clear(); return false; }
        return true;
    }
    bool Write(std::uint64_t at, std::span<const std::byte> data)
    {
        std::lock_guard lock(mutex);
        if (!Valid() || at > bytes || data.size() > bytes - at || data.size() > MAXDWORD || offset + at > INT64_MAX) return false;
        LARGE_INTEGER position{}; position.QuadPart = static_cast<LONGLONG>(offset + at); DWORD put = 0;
        return SetFilePointerEx(file, position, nullptr, FILE_BEGIN) &&
            ::WriteFile(file, data.data(), static_cast<DWORD>(data.size()), &put, nullptr) && put == data.size();
    }
};
// Sources never escape this translation unit. Revocation follows draining every
// session that could call one, before mutation of any byte in the held image.
struct ImageView final : ImmutableEncryptedReadSource
{
    std::shared_ptr<ImageIo> io;
    std::string identity;
    std::uint64_t revision = 0;
    std::atomic<bool> active{true};
    std::shared_ptr<const std::atomic<bool>> cancellation;
    std::shared_ptr<ApfsReadBudget> budget = std::make_shared<ApfsReadBudget>(100000, 256ULL << 20, 1000000, 256ULL << 20);
    std::string SourceIdentity() const override { return identity; }
    std::uint64_t Revision() const override { return revision; }
    std::uint64_t SizeBytes() const override { return io->bytes; }
    std::shared_ptr<ApfsReadBudget> ReadBudget() const override { return budget; }
    std::optional<EncryptedRuntimeReadLimits> RuntimeReadLimits() const override { return EncryptedRuntimeReadLimits{}; }
    bool Read(std::uint64_t at, std::size_t size, std::vector<std::byte>& out) const override
    {
        out.clear();
        if (!active.load() || cancellation->load() || !budget->Read(size) || !io->Read(at, size, out) ||
            !active.load() || cancellation->load()) { out.clear(); return false; }
        return true;
    }
    bool ReadRuntime(const RuntimeRead& request, std::vector<std::byte>& out) const override
    {
        out.clear();
        if (!request.IsFor(*this) || !active.load() || cancellation->load() ||
            !io->Read(request.Offset(), request.Size(), out) || !active.load() || cancellation->load())
        { out.clear(); return false; }
        return true;
    }
};
}

struct ApfsEncryptedImageWriteSession::ReadInode::State
{
    std::weak_ptr<const std::uint8_t> owner;
    std::uint64_t inode = 0, checkpoint = 0;
};
ApfsEncryptedImageWriteSession::ReadInode::ReadInode(std::shared_ptr<State> state) : state_(std::move(state)) {}
ApfsEncryptedImageWriteSession::ReadInode::~ReadInode() = default;
std::uint64_t ApfsEncryptedImageWriteSession::ReadInode::Inode() const noexcept { return state_->inode; }

struct ApfsEncryptedImageWriteSession::Impl
{
    Image image;
    std::shared_ptr<ImageIo> io;
    std::string identity, uuid, volume_uuid;
    std::array<std::byte, 32> binding{};
    std::mutex gate;
    mutable std::mutex status_gate;
    EncryptedImageWriteStatus status;
    PasswordUnlockResult key;
    PasswordUnlockRequest admitted;
    const std::shared_ptr<std::atomic<bool>> cancelled = std::make_shared<std::atomic<bool>>(false);
    std::shared_ptr<ImageView> current_source;
    std::shared_ptr<ApfsEncryptedReadSession> current;
    struct View { std::weak_ptr<ApfsEncryptedReadSession> session; std::shared_ptr<ImageView> source; };
    std::vector<View> views;
    std::shared_ptr<const std::uint8_t> inode_epoch = std::make_shared<const std::uint8_t>(std::uint8_t{0});
    std::vector<std::weak_ptr<ReadInode::State>> read_inodes;
    void PruneInodes() { std::erase_if(read_inodes, [](const auto& inode) { return inode.expired(); }); }
    bool HasInode(std::uint64_t id)
    {
        PruneInodes();
        return std::any_of(read_inodes.begin(), read_inodes.end(), [&](const auto& row) {
            auto value = row.lock(); return value && !value->checkpoint && value->inode == id;
        });
    }
    std::vector<std::uint64_t> ReadPins(const EncryptedMutationRequest* request = nullptr)
    {
        PruneInodes(); std::vector<std::uint64_t> pins;
        for (const auto& row : read_inodes) if (auto value = row.lock(); value && value->checkpoint)
            pins.push_back(value->checkpoint);
        if (request) {
            auto removed = request->kind == EncryptedMutationKind::Unlink ? request->inode : 0;
            if (request->kind == EncryptedMutationKind::ReplaceRename && current && !read_inodes.empty()) {
                EncryptedDirectoryEntry target;
                const auto found = current->Lookup(request->destination_parent, request->destination_name, target);
                if (found == Error::None) removed = target.inode_id;
                else if (found != Error::FileNotFound)
                    throw std::runtime_error("ImageWriterReadInodeLookupFailed:" + std::to_string(static_cast<int>(found)));
            }
            if (removed && HasInode(removed)) pins.push_back(Snapshot().checkpoint_xid);
        }
        std::sort(pins.begin(), pins.end()); pins.erase(std::unique(pins.begin(), pins.end()), pins.end());
        return pins;
    }
    void ArmInodes(const EncryptedCowOverwrite& prepared)
    {
        const auto removed = prepared.IntentKind() == EncryptedMutationKind::Unlink
            ? prepared.RequestedInode() : prepared.ReplacedInode();
        if (!removed) return;
        for (const auto& row : read_inodes) if (auto value = row.lock(); value && !value->checkpoint && value->inode == removed)
            value->checkpoint = prepared.SourceCheckpointXid();
    }
    bool writing = false;
    EncryptedImageWriteStatus Snapshot() const noexcept
    { std::lock_guard lock(status_gate); return status; }
    void PhaseTo(Phase phase, bool recovery = false) noexcept
    {
        std::lock_guard lock(status_gate);
        status.phase = phase; status.key_present = static_cast<bool>(key); status.recovery_required = recovery;
    }
    std::shared_ptr<ImageView> NewSource()
    {
        auto view = std::make_shared<ImageView>(); view->io = io; view->identity = identity;
        view->cancellation = cancelled;
        if (BCryptGenRandom(nullptr, reinterpret_cast<PUCHAR>(&view->revision), sizeof(view->revision),
            BCRYPT_USE_SYSTEM_PREFERRED_RNG) < 0 || !view->revision) throw std::runtime_error("ImageRevisionFailed");
        return view;
    }
    void Revoke() noexcept
    {
        for (auto& view : views) if (auto session = view.session.lock()) session->Cancel();
        if (current) current->Cancel();
        for (auto& view : views)
        {
            if (auto session = view.session.lock()) session->Close();
            view.source->active.store(false);
        }
        views.clear();
        if (current) current->Close();
        if (current_source) current_source->active.store(false);
        current.reset(); current_source.reset();
    }
    bool Refresh(std::string& error)
    {
        auto source = NewSource(); Error read_error{};
        auto reader = ApfsEncryptedReadSession::OpenImageWriterView(source, key, admitted, read_error, cancelled);
        if (!reader) { error = "ImageWriterRebindFailed:" + std::to_string(static_cast<int>(read_error)); return false; }
        auto context = reader->CreateMetadataReadContext(read_error);
        auto canonical = context ? LoadAppleCheckpointView(*source, 0, io->bytes, error, *context) : std::nullopt;
        if (!canonical) { reader->Close(); return false; }
        const auto& nx = canonical->container.superblock;
        if (nx.uuid_hex != uuid || nx.block_size != 4096 || nx.block_count * nx.block_size != io->bytes)
        { error = "ImageWriterGeometryChanged"; reader->Close(); return false; }
        const auto selected = std::find_if(canonical->volumes.begin(), canonical->volumes.end(),
            [&](const auto& volume) { return volume.superblock.object_id == image.volume_oid; });
        if (selected == canonical->volumes.end() || selected->superblock.uuid_hex != volume_uuid)
        { error = "ImageWriterVolumeIdentityChanged"; reader->Close(); return false; }
        const auto next_inode = selected->superblock.next_object_id;
        std::uint64_t free = 0;
        for (const auto& device : canonical->spaceman.devices)
        {
            if (device.free_count > UINT64_MAX / nx.block_size || free > UINT64_MAX - device.free_count * nx.block_size)
            { error = "ImageWriterFreeSpaceOverflow"; return false; }
            free += device.free_count * nx.block_size;
        }
        current_source = std::move(source); current = std::move(reader);
        std::lock_guard lock(status_gate);
        status.checkpoint_xid = nx.xid; status.free_bytes = free; status.container_bytes = io->bytes;
        status.next_inode_id = next_inode;
        status.free_space_valid = true;
        return true;
    }
    struct Target final : rw::EncryptedPublicationTarget
    {
        Impl& owner;
        explicit Target(Impl& value) : owner(value) {}
        std::array<std::byte, 32> SourceBinding() const noexcept override { return owner.binding; }
        bool ReadBlock(std::uint64_t block, std::uint32_t size, std::vector<std::byte>& out) override
        { return size == 4096 && block <= UINT64_MAX / size && owner.io->Read(block * size, size, out); }
        bool WriteBlock(std::uint64_t block, std::span<const std::byte> bytes) override
        {
            return !owner.cancelled->load() && owner.writing && !owner.current && owner.views.empty() && bytes.size() == 4096 &&
                block <= UINT64_MAX / 4096 && owner.io->Write(block * 4096, bytes);
        }
        bool Flush() override
        { std::lock_guard lock(owner.io->mutex); return !owner.cancelled->load() && owner.writing && owner.io->Valid() && FlushFileBuffers(owner.io->file); }
    };
    bool Publish(rw::TransactionManager& tx, rw::EncryptedPublicationJournal& journal,
        std::uint64_t sequence, std::string& error, const rw::AppleCheckpointStageHook& hook)
    {
        if (cancelled->load())
        { error = "ImageWriterCancelled"; PhaseTo(Phase::RecoveryRequired, true); return false; }
        // Original accepted/cleanup debt belongs to the runtime. A healthy
        // in-flight publication is distinct from an owner recovery attempt.
        PhaseTo(Phase::Publishing, Snapshot().recovery_required || !key);
        Revoke(); writing = true;
        struct Stop { bool& value; ~Stop() { value = false; } } stop{writing};
        Target target(*this);
        const auto guarded_hook = [&](std::string_view stage) {
            return !cancelled->load() && (!hook || hook(stage)) && !cancelled->load();
        };
        if (!journal.PublishOrRecover(tx, sequence, target, error, guarded_hook) ||
            tx.Watermarks().apfs_durable_sequence < sequence)
        {
            if (cancelled->load()) error = "ImageWriterCancelled";
            PhaseTo(Phase::RecoveryRequired, true); return false;
        }
        writing = false;
        if (key)
        {
            if (!Refresh(error)) { PhaseTo(Phase::RecoveryRequired, true); return false; }
        }
        else
        {
            auto source = NewSource();
            auto checkpoint = LoadContainerCheckpointView(*source, 0, io->bytes, error);
            if (!checkpoint || checkpoint->superblock.uuid_hex != uuid)
            { PhaseTo(Phase::RecoveryRequired, true); return false; }
            std::lock_guard lock(status_gate);
            status.checkpoint_xid = checkpoint->superblock.xid;
            status.free_bytes = 0; status.free_space_valid = false;
            status.next_inode_id = 0;
        }
        { std::lock_guard lock(status_gate); ++status.commits; }
        PhaseTo(key ? Phase::Ready : Phase::Locked);
        return true;
    }
};

ApfsEncryptedImageWriteSession::ApfsEncryptedImageWriteSession(std::unique_ptr<Impl> impl) : impl_(std::move(impl)) {}
ApfsEncryptedImageWriteSession::~ApfsEncryptedImageWriteSession() { Close(); }
std::unique_ptr<ApfsEncryptedImageWriteSession> ApfsEncryptedImageWriteSession::Open(const Image& image, std::string& error)
{
    error.clear();
    try
    {
        if (!OrdinaryPath(image.path) || !image.bytes || !image.volume_oid ||
            image.offset > INT64_MAX || image.bytes > INT64_MAX - image.offset)
        { error = "ImageWriterDRegularPathAndGeometryRequired"; return {}; }
        if (GetDriveTypeW(image.path.substr(0, 3).c_str()) != DRIVE_FIXED)
        { error = "ImageWriterLocalFixedImageRequired"; return {}; }
        auto impl = std::make_unique<Impl>(); impl->image = image; impl->io = std::make_shared<ImageIo>();
        auto& io = *impl->io;
        for (std::size_t end = 2; end != std::wstring::npos; end = image.path.find(L'\\', end + 1))
        {
            const auto prefix = image.path.substr(0, end == 2 ? 3 : end);
            Handle directory(CreateFileW(prefix.c_str(), FILE_READ_ATTRIBUTES, FILE_SHARE_READ, nullptr,
                OPEN_EXISTING, FILE_FLAG_BACKUP_SEMANTICS | FILE_FLAG_OPEN_REPARSE_POINT, nullptr));
            if (directory.value == INVALID_HANDLE_VALUE)
            { error = "ImageWriterRegularAncestorsRequired:stage=AncestorOpen:win32=" + std::to_string(GetLastError()); return {}; }
            FILE_ATTRIBUTE_TAG_INFO info{};
            if (!GetFileInformationByHandleEx(directory.value, FileAttributeTagInfo, &info, sizeof(info)))
            { error = "ImageWriterRegularAncestorsRequired:stage=AncestorAttributes:win32=" + std::to_string(GetLastError()); return {}; }
            if (!(info.FileAttributes & FILE_ATTRIBUTE_DIRECTORY) || (info.FileAttributes & FILE_ATTRIBUTE_REPARSE_POINT))
            { error = "ImageWriterRegularAncestorsRequired:stage=AncestorProperties:attributes=" + std::to_string(info.FileAttributes); return {}; }
            io.directories.push_back(std::move(directory));
        }
        for (DWORD attempt = 1; ; ++attempt)
        {
            io.file = CreateFileW(image.path.c_str(), GENERIC_READ | GENERIC_WRITE, 0, nullptr,
                OPEN_EXISTING, FILE_FLAG_OPEN_REPARSE_POINT | FILE_FLAG_RANDOM_ACCESS, nullptr);
            if (io.file != INVALID_HANDLE_VALUE) break;
            const auto os_error = GetLastError();
            if (attempt == 4 || (os_error != ERROR_SHARING_VIOLATION && os_error != ERROR_LOCK_VIOLATION))
            {
                error = "ImageWriterExclusiveSingleLinkRegularFileRequired:stage=FileOpen:win32=" +
                    std::to_string(os_error) + ":attempts=" + std::to_string(attempt);
                return {};
            }
            Sleep(25UL << (attempt - 1));
        }
        SetLastError(ERROR_SUCCESS);
        const auto file_type = GetFileType(io.file);
        if (file_type == FILE_TYPE_UNKNOWN)
        { error = "ImageWriterExclusiveSingleLinkRegularFileRequired:stage=FileType:win32=" + std::to_string(GetLastError()); return {}; }
        if (file_type != FILE_TYPE_DISK)
        { error = "ImageWriterExclusiveSingleLinkRegularFileRequired:stage=FileTypeProperties:type=" + std::to_string(file_type); return {}; }
        if (!GetFileInformationByHandle(io.file, &io.identity))
        { error = "ImageWriterExclusiveSingleLinkRegularFileRequired:stage=FileIdentity:win32=" + std::to_string(GetLastError()); return {}; }
        FILE_STANDARD_INFO standard{};
        if (!GetFileInformationByHandleEx(io.file, FileStandardInfo, &standard, sizeof(standard)))
        { error = "ImageWriterExclusiveSingleLinkRegularFileRequired:stage=FileStandardInfo:win32=" + std::to_string(GetLastError()); return {}; }
        if ((io.identity.dwFileAttributes & (FILE_ATTRIBUTE_DIRECTORY | FILE_ATTRIBUTE_REPARSE_POINT | FILE_ATTRIBUTE_DEVICE)) ||
            standard.Directory || standard.DeletePending || standard.NumberOfLinks != 1)
        {
            error = "ImageWriterExclusiveSingleLinkRegularFileRequired:stage=FileProperties:attributes=" +
                std::to_string(io.identity.dwFileAttributes) + ":directory=" + std::to_string(standard.Directory) +
                ":deletePending=" + std::to_string(standard.DeletePending) + ":links=" + std::to_string(standard.NumberOfLinks);
            return {};
        }
        const auto length = (std::uint64_t(io.identity.nFileSizeHigh) << 32) | io.identity.nFileSizeLow;
        if (image.offset > length || image.bytes > length - image.offset)
        { error = "ImageWriterGeometryOutsideFile"; return {}; }
        io.offset = image.offset; io.bytes = image.bytes;
        impl->identity = "image-writer-v1:" + std::to_string(io.identity.dwVolumeSerialNumber) + ":" +
            std::to_string((std::uint64_t(io.identity.nFileIndexHigh) << 32) | io.identity.nFileIndexLow) + ":" +
            std::to_string(length) + ":" + std::to_string(image.offset) + ":" + std::to_string(image.bytes);
        auto source = impl->NewSource();
        auto checkpoint = LoadContainerCheckpointView(*source, 0, io.bytes, error);
        if (!checkpoint || checkpoint->superblock.block_size != 4096 ||
            checkpoint->superblock.block_count * 4096 != io.bytes) return {};
        impl->uuid = checkpoint->superblock.uuid_hex;
        auto volumes = LoadAppleReadOnlyVolumeView(*source, *checkpoint, error);
        if (!volumes) return {};
        const auto selected = std::find_if(volumes->volumes.begin(), volumes->volumes.end(),
            [&](const auto& volume) { return volume.superblock.object_id == image.volume_oid; });
        if (selected == volumes->volumes.end() || selected->superblock.uuid_hex.empty())
        { error = "ImageWriterVolumeSelectionRequired"; return {}; }
        impl->volume_uuid = selected->superblock.uuid_hex;
        impl->binding = Hash("apfs-image-writer-binding-v2:" + impl->identity + ":" + impl->uuid + ":" +
            std::to_string(image.volume_oid) + ":" + impl->volume_uuid);
        impl->status.container_bytes = io.bytes; impl->status.checkpoint_xid = checkpoint->superblock.xid;
        return std::unique_ptr<ApfsEncryptedImageWriteSession>(new ApfsEncryptedImageWriteSession(std::move(impl)));
    }
    catch (const std::exception& ex) { error = ex.what(); return {}; }
}
bool ApfsEncryptedImageWriteSession::Unlock(const crypto::SecureBytes& password, PasswordUnlockBudget& attempts, std::string& error)
{
    std::lock_guard lock(impl_->gate); error.clear();
    const auto status = impl_->Snapshot();
    if (impl_->cancelled->load()) { error = "ImageWriterCancelled"; return false; }
    if (status.phase != Phase::Locked || status.recovery_required || !password.IsLocked())
    { error = "ImageWriterNotUnlockable"; return false; }
    try
    {
        auto source = impl_->NewSource(); UnlockError unlock_error{};
        auto metadata = InspectPasswordKeybagMetadata(*source, impl_->image.volume_oid, impl_->image.keybag_length, unlock_error);
        if (!metadata || metadata->users.size() != 1) { error = "ImageWriterExactSingleUserRequired"; return false; }
        auto selection = metadata->selection; selection.user_uuid = metadata->users.front(); Error read_error{};
        if (BytesToHexLower(selection.volume_uuid.data(), selection.volume_uuid.size()) != impl_->volume_uuid ||
            BytesToHexLower(selection.container_uuid.data(), selection.container_uuid.size()) != impl_->uuid)
        { error = "ImageWriterUnlockSelectionChanged"; return false; }
        auto reader = ApfsEncryptedReadSession::Unlock(source, impl_->identity, source->revision,
            selection, password.Bytes(), attempts, read_error, unlock_error, impl_->cancelled);
        if (!reader) { error = "ImageWriterUnlockFailed:" + std::to_string(static_cast<int>(unlock_error)); return false; }
        impl_->key = reader->CopyKeyForImageWriter(read_error);
        reader->Close(); source->active.store(false);
        if (!impl_->key) { error = "ImageWriterLockedKeyCopyFailed"; return false; }
        impl_->admitted = selection;
        if (!impl_->Refresh(error)) { impl_->key.xts_key.Clear(); return false; }
        impl_->PhaseTo(Phase::Ready); return true;
    }
    catch (const std::exception& ex) { impl_->key.xts_key.Clear(); error = ex.what(); return false; }
}
std::shared_ptr<ApfsEncryptedReadSession> ApfsEncryptedImageWriteSession::OpenReadView(Error& error)
{
    std::lock_guard lock(impl_->gate); error = Error::Closed;
    if (impl_->cancelled->load()) { error = Error::Cancelled; return {}; }
    if (impl_->Snapshot().phase != Phase::Ready || !impl_->key) return {};
    std::erase_if(impl_->views, [](const auto& view) { return view.session.expired(); });
    if (impl_->views.size() >= 4) { error = Error::ResourceLimit; return {}; }
    try
    {
        auto source = impl_->NewSource();
        auto reader = ApfsEncryptedReadSession::OpenImageWriterView(source, impl_->key, impl_->admitted, error, impl_->cancelled);
        if (!reader) return {};
        std::shared_ptr<ApfsEncryptedReadSession> session(std::move(reader));
        impl_->views.push_back({session, std::move(source)}); return session;
    }
    catch (...) { error = Error::ResourceLimit; return {}; }
}
std::shared_ptr<ApfsEncryptedImageWriteSession::ReadInode> ApfsEncryptedImageWriteSession::RetainReadInode(
    std::uint64_t inode, std::string& error)
{
    std::lock_guard lock(impl_->gate); error.clear();
    const auto status = impl_->Snapshot();
    if (impl_->cancelled->load() || status.phase != Phase::Ready || status.recovery_required || !impl_->key || !impl_->current)
    { error = "ImageWriterReadyReadInodeRequired"; return {}; }
    try {
        impl_->PruneInodes();
        if (impl_->read_inodes.size() >= 64) { error = "ImageWriterReadInodeCapacity"; return {}; }
        EncryptedNodeInfo node;
        if (impl_->current->GetMetadata(inode, node) != Error::None || (node.mode & 0170000) != 0100000 ||
            node.children_or_links != 1 || node.private_id != inode || (node.bsd_flags & rw::kAppleBsdCompressedFlag) ||
            node.size > UINT64_MAX - 4095 || node.allocated_size != ((node.size + 4095) / 4096) * 4096)
        { error = "ImageWriterReadInodeProfileUnsupported"; return {}; }
        if (!impl_->inode_epoch) impl_->inode_epoch = std::make_shared<const std::uint8_t>(std::uint8_t{0});
        auto state = std::make_shared<ReadInode::State>(); state->owner = impl_->inode_epoch; state->inode = inode;
        auto result = std::shared_ptr<ReadInode>(new ReadInode(state)); impl_->read_inodes.push_back(state);
        return result;
    } catch (const std::exception& ex) { error = ex.what(); return {}; }
}
std::shared_ptr<ApfsEncryptedReadSession> ApfsEncryptedImageWriteSession::OpenReadView(const ReadInode& inode, Error& error)
{
    std::lock_guard lock(impl_->gate); error = Error::Closed;
    if (impl_->cancelled->load()) { error = Error::Cancelled; return {}; }
    if (impl_->Snapshot().phase != Phase::Ready || !impl_->key || !impl_->inode_epoch ||
        inode.state_->owner.lock() != impl_->inode_epoch) return {};
    std::erase_if(impl_->views, [](const auto& view) { return view.session.expired(); });
    if (impl_->views.size() >= 4) { error = Error::ResourceLimit; return {}; }
    try {
        auto source = impl_->NewSource();
        auto reader = ApfsEncryptedReadSession::OpenImageWriterView(source, impl_->key, impl_->admitted, error,
            impl_->cancelled, inode.state_->checkpoint);
        EncryptedNodeInfo node;
        if (!reader || reader->GetMetadata(inode.Inode(), node) != Error::None) { error = Error::MetadataIntegrityFailure; return {}; }
        std::shared_ptr<ApfsEncryptedReadSession> result(std::move(reader));
        impl_->views.push_back({result, std::move(source)}); error = Error::None; return result;
    } catch (const std::exception&) { error = Error::ReadFailure; return {}; }
}
bool ApfsEncryptedImageWriteSession::CommitAcceptedOverwrite(rw::TransactionManager& tx,
    rw::EncryptedPublicationJournal& journal, std::uint64_t sequence, std::uint64_t xid,
    std::uint64_t inode, std::uint64_t offset, std::span<const std::byte> replacement,
    std::string& error, const rw::AppleCheckpointStageHook& hook)
{
    EncryptedMutationRequest request;
    request.kind = EncryptedMutationKind::Overwrite; request.inode = inode;
    request.offset = offset; request.data = replacement;
    return CommitAcceptedMutation(tx, journal, sequence, xid, request, error, {}, hook);
}
bool ApfsEncryptedImageWriteSession::CommitAcceptedMutation(rw::TransactionManager& tx,
    rw::EncryptedPublicationJournal& journal, std::uint64_t sequence, std::uint64_t xid,
    const EncryptedMutationRequest& request, std::string& error,
    std::span<const std::uint64_t> supplied_pins, const rw::AppleCheckpointStageHook& hook)
{
    std::lock_guard lock(impl_->gate); error.clear();
    const auto status = impl_->Snapshot();
    if (impl_->cancelled->load())
    { error = "ImageWriterCancelled"; impl_->PhaseTo(Phase::RecoveryRequired, true); return false; }
    if (status.phase != Phase::Ready || status.checkpoint_xid != xid || !impl_->current)
    { error = "ImageWriterReadyCurrentCheckpointRequired"; return false; }
    try
    {
        impl_->PhaseTo(Phase::Preparing);
        std::vector<std::uint64_t> required;
        if (!tx.LoadRequiredCheckpointXidsSinceCleanup(required, &error)) { impl_->PhaseTo(Phase::Ready); return false; }
        required.insert(required.end(), supplied_pins.begin(), supplied_pins.end());
        std::sort(required.begin(), required.end()); required.erase(std::unique(required.begin(), required.end()), required.end());
        const auto read_pins = impl_->ReadPins(&request);
        auto prepared = impl_->current->PrepareDeltaMutationWithReadPins(*impl_->current_source, xid, request, error, required, read_pins);
        if (!prepared) { impl_->PhaseTo(Phase::Ready); return false; }
        if (impl_->cancelled->load())
        { error = "ImageWriterCancelled"; impl_->PhaseTo(Phase::RecoveryRequired, true); return false; }
        impl_->ArmInodes(*prepared);
        if (!journal.Stage(tx, sequence, *prepared, error)) { impl_->PhaseTo(Phase::RecoveryRequired, true); return false; }
        prepared.reset();
        return impl_->Publish(tx, journal, sequence, error, hook);
    }
    catch (const std::exception& ex) { impl_->PhaseTo(Phase::RecoveryRequired, true); error = ex.what(); return false; }
}
bool ApfsEncryptedImageWriteSession::ChangePassword(rw::TransactionManager& tx,
    rw::EncryptedPublicationJournal& journal, std::uint64_t xid,
    const crypto::SecureBytes& old_password, const crypto::SecureBytes& new_password,
    PasswordUnlockBudget& budget, std::uint64_t& accepted, std::string& error,
    const rw::AppleCheckpointStageHook& hook)
{
    std::lock_guard lock(impl_->gate); error.clear(); accepted = 0;
    const auto status = impl_->Snapshot();
    if (impl_->cancelled->load()) { error = "ImageWriterCancelled"; return false; }
    if (status.phase != Phase::Ready || status.recovery_required || status.checkpoint_xid != xid ||
        !impl_->key || !impl_->current || !impl_->current_source ||
        !old_password.IsLocked() || !new_password.IsLocked() ||
        tx.ProtectedSourceBinding() != std::optional{impl_->binding})
    { error = "ImageWriterReadyMaintenanceOwnerRequired"; return false; }
    bool authorization_attempted = false;
    impl_->PruneInodes();
    if (!impl_->read_inodes.empty()) { error = "ImageWriterOpenReadInodesMaintenanceUnsupported"; return false; }
    const auto lock_for_recovery = [&] {
        impl_->Revoke(); impl_->key.xts_key.Clear(); impl_->admitted = {};
        impl_->PhaseTo(Phase::Locked, true);
        return false;
    };
    try {
        impl_->PhaseTo(Phase::Preparing);
        std::vector<std::uint64_t> required;
        if (!tx.LoadRequiredCheckpointXidsSinceCleanup(required, &error)) {
            impl_->PhaseTo(Phase::Ready); return false;
        }
        UnlockError unlock{};
        auto rewrap = SoftwareKeybagRewrap::Prepare(impl_->current_source, impl_->identity,
            impl_->current_source->Revision(), impl_->image.volume_oid, impl_->image.keybag_length,
            old_password, new_password, budget, unlock);
        if (!rewrap) {
            error = "ImageWriterMaintenancePreparationFailed:" + std::to_string(static_cast<int>(unlock));
            impl_->PhaseTo(Phase::Ready); return false;
        }
        auto prepared = rewrap->PreparePublication(old_password, new_password, budget, error, required);
        if (!prepared) { impl_->PhaseTo(Phase::Ready); return false; }
        if (rewrap->CheckpointXid() != xid || prepared->SourceIdentity() != impl_->identity ||
            prepared->Publication().expected_checkpoint_xid != xid ||
            prepared->VolumeObjectId() != impl_->image.volume_oid || prepared->VolumeUuid() != impl_->volume_uuid)
        { error = "ImageWriterMaintenanceScopeMismatch"; impl_->PhaseTo(Phase::Ready); return false; }
        if (impl_->cancelled->load()) {
            error = "ImageWriterCancelled"; return lock_for_recovery();
        }
        authorization_attempted = true;
        if (!journal.AcceptMaintenance(tx, *prepared, accepted, error)) return lock_for_recovery();
        rewrap.reset();
        impl_->Revoke(); impl_->key.xts_key.Clear(); impl_->admitted = {};
        impl_->PhaseTo(Phase::Locked, true);
        if (impl_->cancelled->load()) { error = "ImageWriterCancelled"; return false; }
        if (hook && !hook("after-encrypted-original-accept")) {
            error = "ImageWriterMaintenanceInterruptedBeforeStage"; return false;
        }
        if (!journal.StageMaintenance(tx, accepted, *prepared, error)) return false;
        prepared.reset();
        return impl_->Publish(tx, journal, accepted, error, hook);
    }
    catch (const std::exception& ex) {
        error = ex.what();
        if (authorization_attempted) return lock_for_recovery();
        impl_->PhaseTo(Phase::Ready); return false;
    }
}
bool ApfsEncryptedImageWriteSession::RecoverAcceptedMaintenance(rw::TransactionManager& tx,
    rw::EncryptedPublicationJournal& journal, std::uint64_t sequence, std::string& error,
    const rw::AppleCheckpointStageHook& hook)
{
    std::lock_guard lock(impl_->gate); error.clear();
    if (impl_->Snapshot().phase == Phase::Closed) { error = "ImageWriterClosed"; return false; }
    const auto failed = [&] {
        impl_->Revoke(); impl_->key.xts_key.Clear(); impl_->admitted = {};
        impl_->PhaseTo(Phase::Locked, true); return false;
    };
    try {
        if (impl_->cancelled->load()) { error = "ImageWriterCancelled"; return failed(); }
        if (tx.ProtectedSourceBinding() != std::optional{impl_->binding}) {
            error = "ImageWriterRecoverySourceBindingMismatch"; return failed();
        }
        if (!journal.RestageMaintenance(tx, sequence, error)) return failed();
        impl_->Revoke(); impl_->key.xts_key.Clear(); impl_->admitted = {};
        impl_->PhaseTo(Phase::Locked, true);
        if (impl_->cancelled->load()) { error = "ImageWriterCancelled"; return false; }
        return impl_->Publish(tx, journal, sequence, error, hook);
    }
    catch (const std::exception& ex) { error = ex.what(); return failed(); }
}
bool ApfsEncryptedImageWriteSession::RecoverAccepted(rw::TransactionManager& tx,
    rw::EncryptedPublicationJournal& journal, std::uint64_t sequence, std::string& error,
    const rw::AppleCheckpointStageHook& hook)
{
    std::lock_guard lock(impl_->gate); error.clear();
    if (impl_->Snapshot().phase == Phase::Closed) { error = "ImageWriterClosed"; return false; }
    try {
        impl_->PhaseTo(Phase::RecoveryRequired, true);
        return impl_->Publish(tx, journal, sequence, error, hook);
    }
    catch (const std::exception& ex) { impl_->writing = false; impl_->PhaseTo(Phase::RecoveryRequired, true); error = ex.what(); return false; }
}
std::unique_ptr<ApfsEncryptedImageWriteSession::PreparedMutation> ApfsEncryptedImageWriteSession::PrepareMutation(
    std::uint64_t xid, const EncryptedMutationRequest& request, std::string& error,
    std::span<const std::uint64_t> required)
{
    std::lock_guard lock(impl_->gate); error.clear();
    const auto status = impl_->Snapshot();
    if (impl_->cancelled->load()) { error = "ImageWriterCancelled"; return {}; }
    if (status.phase != Phase::Ready || status.checkpoint_xid != xid || !impl_->key || !impl_->current || !impl_->current_source)
    { error = "ImageWriterReadyCurrentCheckpointRequired"; return {}; }
    try {
        impl_->PhaseTo(Phase::Preparing);
        const auto read_pins = impl_->ReadPins(&request);
        auto capability = impl_->current->PrepareDeltaMutationWithReadPins(*impl_->current_source, xid, request, error, required, read_pins);
        if (!capability) { impl_->PhaseTo(Phase::Ready); return {}; }
        if (impl_->cancelled->load()) { impl_->PhaseTo(Phase::Ready); error = "ImageWriterCancelled"; return {}; }
        auto result = std::unique_ptr<PreparedMutation>(new PreparedMutation);
        result->source_ = impl_->current_source; result->prepared_ = std::move(capability);
        impl_->PhaseTo(Phase::Ready); return result;
    }
    catch (const std::exception& ex) { impl_->PhaseTo(Phase::Ready); error = ex.what(); return {}; }
}
bool ApfsEncryptedImageWriteSession::CommitAcceptedPrepared(rw::TransactionManager& tx,
    rw::EncryptedPublicationJournal& journal, std::uint64_t sequence, std::uint64_t xid,
    std::unique_ptr<PreparedMutation> prepared, std::string& error, const rw::AppleCheckpointStageHook& hook)
{
    std::lock_guard lock(impl_->gate); error.clear();
    const auto status = impl_->Snapshot();
    if (status.phase == Phase::Closed) { error = "ImageWriterClosed"; return false; }
    const auto failed = [&] {
        impl_->PhaseTo(impl_->key ? Phase::RecoveryRequired : Phase::Locked, true); return false;
    };
    try {
        if (impl_->cancelled->load()) { error = "ImageWriterCancelled"; return failed(); }
        if (status.phase != Phase::Ready || status.checkpoint_xid != xid || !impl_->current ||
            !prepared || !prepared->prepared_ || prepared->source_.lock() != impl_->current_source ||
            tx.ProtectedSourceBinding() != std::optional{impl_->binding})
        { error = "ImageWriterCurrentPreparedCapabilityRequired"; return failed(); }
        const auto& intent = prepared->Intent();
        if (intent.SourceIdentity() != impl_->identity || intent.SourceCheckpointXid() != xid ||
            intent.VolumeObjectId() != impl_->image.volume_oid || intent.VolumeUuid() != impl_->volume_uuid)
        { error = "ImageWriterPreparedScopeMismatch"; return failed(); }
        std::vector<std::uint64_t> required;
        if (!tx.LoadRequiredCheckpointXidsSinceCleanup(required, &error)) return failed();
        const auto& recovery_proved = intent.RequiredRecoveryCheckpointXids();
        if (std::any_of(required.begin(), required.end(), [&](auto pin) {
                return !std::binary_search(recovery_proved.begin(), recovery_proved.end(), pin); }))
        { error = "ImageWriterPreparedRecoveryCheckpointUnproved"; return failed(); }
        const auto read_pins = impl_->ReadPins(); required.insert(required.end(), read_pins.begin(), read_pins.end());
        auto active_read_pins = read_pins;
        const auto removed = intent.IntentKind() == EncryptedMutationKind::Unlink ? intent.RequestedInode() : intent.ReplacedInode();
        if (removed && impl_->HasInode(removed)) active_read_pins.push_back(xid);
        const auto& read_proved = intent.RequiredReadCheckpointXids();
        if (std::any_of(active_read_pins.begin(), active_read_pins.end(), [&](auto pin) {
                return !std::binary_search(read_proved.begin(), read_proved.end(), pin); }))
        { error = "ImageWriterPreparedReadCheckpointUnproved"; return failed(); }
        const auto& proved = intent.RequiredCheckpointXids();
        if (std::any_of(required.begin(), required.end(), [&](auto pin) {
                return std::find(proved.begin(), proved.end(), pin) == proved.end(); }))
        { error = "ImageWriterPreparedRequiredCheckpointUnproved"; return failed(); }
        impl_->PhaseTo(Phase::Preparing);
        if (impl_->cancelled->load()) { error = "ImageWriterCancelled"; return failed(); }
        impl_->ArmInodes(intent);
        if (!journal.Stage(tx, sequence, intent, error)) return failed();
        prepared.reset();
        return impl_->Publish(tx, journal, sequence, error, hook);
    }
    catch (const std::exception& ex) { impl_->writing = false; error = ex.what(); return failed(); }
}
bool ApfsEncryptedImageWriteSession::RecoverAcceptedMutationCore(rw::TransactionManager& tx,
    rw::EncryptedPublicationJournal& journal, std::uint64_t sequence, std::span<const std::byte> payload,
    std::string& error, std::span<const std::uint64_t> supplied_pins, const rw::AppleCheckpointStageHook& hook,
    RetainedDataRecovery history)
{
    std::lock_guard lock(impl_->gate); error.clear();
    if (impl_->Snapshot().phase == Phase::Closed) { error = "ImageWriterClosed"; return false; }
    const auto failed = [&] {
        impl_->PhaseTo(impl_->key ? Phase::RecoveryRequired : Phase::Locked, true);
        return false;
    };
    try {
        if (impl_->cancelled->load()) { error = "ImageWriterCancelled"; return failed(); }
        if (tx.ProtectedSourceBinding() != std::optional{impl_->binding})
        { error = "ImageWriterRecoverySourceBindingMismatch"; return failed(); }
        rw::EncryptedPublicationJournal::AcceptedDataRecovery disposition;
        if (!journal.InspectAcceptedDataRecovery(tx, sequence, disposition, error)) return failed();
        if (disposition == rw::EncryptedPublicationJournal::AcceptedDataRecovery::CompleteWitness) {
            impl_->PhaseTo(Phase::RecoveryRequired, true);
            return impl_->Publish(tx, journal, sequence, error, hook);
        }
        const auto status = impl_->Snapshot();
        if (!impl_->key || !impl_->key.xts_key.IsLocked() || !impl_->current || !impl_->current_source ||
            (status.phase != Phase::Ready && status.phase != Phase::RecoveryRequired))
        { error = "ImageWriterRecoveryPreimageKeyRequired"; return failed(); }
        std::vector<rw::TransactionManager::AcceptedTransaction> accepted;
        AcceptedWipe wipe{accepted};
        if (!tx.LoadAcceptedTransactionsSinceCleanup(accepted, &error)) return failed();
        if (accepted.size() != 1 || accepted.front().accepted_sequence != sequence ||
            accepted.front().preimage_checkpoint_xid != status.checkpoint_xid)
        { error = "ImageWriterRecoveryExactPreimageRequired"; return failed(); }
        EncryptedMutationRequest request;
        if (!ReconstructAccepted(accepted.front(), payload, status.next_inode_id, request, error)) return failed();
        std::vector<std::uint64_t> required;
        if (!tx.LoadRequiredCheckpointXidsSinceCleanup(required, &error)) return failed();
        required.insert(required.end(), supplied_pins.begin(), supplied_pins.end());
        std::sort(required.begin(), required.end()); required.erase(std::unique(required.begin(), required.end()), required.end());
        impl_->PhaseTo(Phase::Preparing, true);
        const auto read_pins = impl_->ReadPins(&request);
        std::unique_ptr<const SoftwareVolumeRetainedOwners> owners;
        if (history == RetainedDataRecovery::ProtectedTransitionOwners &&
            !journal.TryRestoreTransitionRetainedOwnersForEncryptedReplay(tx, *impl_->current_source, sequence, owners, error))
            return failed();
        auto prepared = owners
            ? impl_->current->PrepareDeltaMutationWithTransitionRetention(*impl_->current_source, status.checkpoint_xid,
                request, *owners, *tx.ProtectedJournalIdentity(), error, required, read_pins)
            : impl_->current->PrepareDeltaMutationWithReadPins(*impl_->current_source, status.checkpoint_xid, request, error, required, read_pins);
        if (!prepared) return failed();
        if (impl_->cancelled->load()) { error = "ImageWriterCancelled"; return failed(); }
        impl_->ArmInodes(*prepared);
        if (!journal.RestageData(tx, sequence, *prepared, error)) return failed();
        prepared.reset();
        return impl_->Publish(tx, journal, sequence, error, hook);
    }
    catch (const std::exception& ex) { impl_->writing = false; error = ex.what(); return failed(); }
}
void ApfsEncryptedImageWriteSession::Cancel() noexcept
{
    impl_->cancelled->store(true);
}
std::optional<PasswordUnlockRequest> ApfsEncryptedImageWriteSession::UnlockedSelection() const
{
    std::lock_guard lock(impl_->gate);
    const auto status = impl_->Snapshot();
    if (status.phase != Phase::Ready || status.recovery_required || !impl_->key || impl_->cancelled->load()) return {};
    return impl_->admitted;
}
void ApfsEncryptedImageWriteSession::Lock() noexcept
{
    std::lock_guard lock(impl_->gate);
    if (impl_->Snapshot().phase == Phase::Closed) return;
    impl_->Revoke(); impl_->key.xts_key.Clear(); impl_->PhaseTo(Phase::Locked, impl_->Snapshot().recovery_required);
    impl_->inode_epoch.reset(); impl_->read_inodes.clear();
}
void ApfsEncryptedImageWriteSession::Close() noexcept
{
    std::lock_guard lock(impl_->gate);
    if (impl_->Snapshot().phase == Phase::Closed) return;
    impl_->Revoke(); impl_->key.xts_key.Clear();
    impl_->inode_epoch.reset(); impl_->read_inodes.clear();
    { std::lock_guard io_lock(impl_->io->mutex); CloseHandle(impl_->io->file); impl_->io->file = INVALID_HANDLE_VALUE; }
    impl_->io->directories.clear(); impl_->PhaseTo(Phase::Closed, impl_->Snapshot().recovery_required);
}
EncryptedImageWriteStatus ApfsEncryptedImageWriteSession::CachedStatus() const noexcept { return impl_->Snapshot(); }
const std::string& ApfsEncryptedImageWriteSession::SourceIdentity() const noexcept { return impl_->identity; }
const std::string& ApfsEncryptedImageWriteSession::ContainerUuid() const noexcept { return impl_->uuid; }
std::uint64_t ApfsEncryptedImageWriteSession::VolumeObjectId() const noexcept { return impl_->image.volume_oid; }
const std::string& ApfsEncryptedImageWriteSession::VolumeUuid() const noexcept { return impl_->volume_uuid; }
const std::array<std::byte, 32>& ApfsEncryptedImageWriteSession::SourceBinding() const noexcept { return impl_->binding; }
#include "EncryptedImageJournalEndpoint.inc"
#include "EncryptedImageVolumeTransition.inc"
#include "EncryptedImageTransitionRetention.inc"
#include "EncryptedImageKeyManagement.inc"
#include "EncryptedImageKeyRotation.inc"
#include "EncryptedImagePlainWriter.inc"
}
