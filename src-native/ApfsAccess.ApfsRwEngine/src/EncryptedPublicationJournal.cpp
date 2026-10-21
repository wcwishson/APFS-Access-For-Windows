#include "EncryptedPublicationJournal.h"
#include "ProtectedJournalEpoch.h"
#include <algorithm>
#include <limits>
#include <map>
#include <set>
#include <stdexcept>
#define WIN32_LEAN_AND_MEAN
#define NOMINMAX
#include <windows.h>
#include <bcrypt.h>
#undef CreateFile
#undef CreateDirectory

namespace apfsaccess::rw
{
namespace
{
constexpr std::size_t max_bytes = 900u * 1024u;
constexpr std::size_t max_blocks = 192;
constexpr std::size_t chunk_bytes = 4096;
constexpr std::string_view witness_path = "\\encrypted-publication-chunk-v2";
constexpr std::string_view witness_end_path = "\\encrypted-publication-end-v2";
constexpr std::string_view disposition_intent_path = "\\encrypted-authorization-abort-intent-v1";
constexpr std::string_view disposition_receipt_path = "\\encrypted-authorization-abort-receipt-v1";
using Digest = std::array<std::uint8_t, 32>;
bool Fail(std::string& error, const char* message) { error = message; return false; }
bool Hash(std::span<const std::byte> data, Digest& digest)
{
    return data.size() <= ULONG_MAX && BCryptHash(BCRYPT_SHA256_ALG_HANDLE, nullptr, 0,
        reinterpret_cast<PUCHAR>(const_cast<std::byte*>(data.data())), static_cast<ULONG>(data.size()),
        digest.data(), static_cast<ULONG>(digest.size())) >= 0;
}
bool Nonzero(const std::array<std::byte, 32>& digest)
{ return std::any_of(digest.begin(), digest.end(), [](auto b) { return b != std::byte{}; }); }
struct Wipe
{
    std::vector<WriteAheadLog::Record>& records;
    ~Wipe()
    {
        for (auto& r : records) {
            SecureZeroMemory(r.inline_payload.data(), r.inline_payload.size());
            SecureZeroMemory(r.path_utf8.data(), r.path_utf8.size());
            SecureZeroMemory(r.secondary_path_utf8.data(), r.secondary_path_utf8.size());
        }
    }
};
struct AcceptedWipe
{
    std::vector<TransactionManager::AcceptedTransaction>& transactions;
    ~AcceptedWipe() { for (auto& transaction : transactions) { Wipe wipe{transaction.mutations}; } }
};
struct Encoder
{
    std::vector<std::byte> bytes;
    void Number(std::uint64_t value)
    {
        if (bytes.size() > max_bytes - 8) throw std::runtime_error("PublicationLimit");
        for (unsigned i = 0; i != 8; ++i) bytes.push_back(static_cast<std::byte>((value >> (8 * i)) & 255));
    }
    void Data(std::span<const std::byte> value)
    {
        Number(value.size());
        if (value.size() > max_bytes - bytes.size()) throw std::runtime_error("PublicationLimit");
        bytes.insert(bytes.end(), value.begin(), value.end());
    }
    void Text(std::string_view value) { Data(std::as_bytes(std::span(value))); }
};
struct Decoder
{
    std::span<const std::byte> bytes;
    std::uint64_t Number()
    {
        if (bytes.size() < 8) throw std::runtime_error("PublicationTruncated");
        std::uint64_t result = 0;
        for (unsigned i = 0; i != 8; ++i) result |= std::to_integer<std::uint64_t>(bytes[i]) << (8 * i);
        bytes = bytes.subspan(8); return result;
    }
    std::vector<std::byte> Data(std::size_t cap)
    {
        const auto size = Number();
        if (size > cap || size > bytes.size()) throw std::runtime_error("PublicationLength");
        std::vector<std::byte> result(bytes.begin(), bytes.begin() + static_cast<std::size_t>(size));
        bytes = bytes.subspan(static_cast<std::size_t>(size)); return result;
    }
    std::string Text(std::size_t cap)
    { auto value = Data(cap); return {reinterpret_cast<const char*>(value.data()), value.size()}; }
};
void EncodeWrite(Encoder& e, const AppleCheckpointPlannedWrite& w)
{ e.Number(static_cast<std::uint64_t>(w.kind)); e.Number(w.physical_block); e.Number(w.object_id); e.Data(w.bytes); }
AppleCheckpointPlannedWrite DecodeWrite(Decoder& d, std::uint32_t block_size)
{
    AppleCheckpointPlannedWrite w;
    const auto kind = d.Number();
    if (kind > static_cast<std::uint64_t>(AppleCheckpointWriteKind::CheckpointSuperblock))
        throw std::runtime_error("PublicationKind");
    w.kind = static_cast<AppleCheckpointWriteKind>(kind); w.physical_block = d.Number();
    w.object_id = d.Number(); w.bytes = d.Data(block_size);
    if (w.bytes.size() != block_size) throw std::runtime_error("PublicationBlockSize");
    return w;
}
bool IsRetainedRewrite(std::uint64_t version) noexcept { return version == 6 || version == 8; }
bool ValidRetainedRewriteModes(std::uint64_t version, std::uint64_t before, std::uint64_t after) noexcept
{
    return version == 6 ? before <= 1 && after <= 1 && before != after :
        version == 8 && before == 1 && after == 1;
}
struct Witness
{
    std::uint64_t version = 2;
    std::uint64_t accepted = 0, transaction = 0, inode = 0, offset = 0, length = 0;
    Digest replacement{};
    catalog::EncryptedMutationKind kind = catalog::EncryptedMutationKind::Overwrite;
    std::uint64_t parent = 0, destination_parent = 0, result_size = 0;
    std::uint64_t permissions = 0, effective_mode = 0, volume_object_id = 0;
    Digest name{}, destination_name{};
    std::uint64_t replaced_inode = 0, replaced_private_id = 0, replaced_size = 0, replaced_mode = 0;
    Digest replaced_name{};
    std::vector<std::uint64_t> required_checkpoints, read_checkpoints;
    std::array<std::byte, 32> original_journal{};
    std::string volume_uuid;
    std::string source;
    AppleCheckpointPublicationPlan plan;
    std::uint64_t transition_before = 0, transition_after = 0;
    Digest transition_owners_sha256{};
    std::vector<std::byte> transition_owners;
    Witness() = default;
    Witness(const Witness&) = default;
    Witness& operator=(const Witness&) = default;
    Witness(Witness&&) noexcept = default;
    Witness& operator=(Witness&&) noexcept = default;
    ~Witness()
    {
        if (!IsRetainedRewrite(version)) return;
        SecureZeroMemory(transition_owners.data(), transition_owners.size());
        for (auto& row : plan.before_superblock_writes) SecureZeroMemory(row.bytes.data(), row.bytes.size());
        for (auto& row : plan.guard_blocks) SecureZeroMemory(row.bytes.data(), row.bytes.size());
        SecureZeroMemory(plan.superblock_write.bytes.data(), plan.superblock_write.bytes.size());
    }
};
bool ValidateTransitionEnvelope(const Witness&, const EncryptedPublicationJournal::Options&, std::string&);
bool MatchTransitionOriginal(const TransactionManager::AcceptedTransaction&, const Witness&,
    const EncryptedPublicationJournal::Options&, std::string&);
Encoder EncodeHeader(const Witness& w, const EncryptedPublicationJournal::Options& options)
{
    Encoder e;
    e.Number(w.version); e.Number(w.accepted); e.Number(w.transaction); e.Number(w.inode); e.Number(w.offset);
    e.Number(w.length); e.Data(std::as_bytes(std::span(w.replacement))); e.Text(w.source);
    e.Number(static_cast<std::uint64_t>(w.kind) + 1);
    e.Number(w.parent); e.Number(w.destination_parent); e.Number(w.result_size);
    e.Number(w.permissions); e.Number(w.effective_mode); e.Number(w.volume_object_id);
    e.Text(w.volume_uuid); e.Data(std::as_bytes(std::span(w.name)));
    e.Data(std::as_bytes(std::span(w.destination_name)));
    if (w.version >= 4) e.Data(w.original_journal);
    if (IsRetainedRewrite(w.version)) {
        e.Number(w.transition_before); e.Number(w.transition_after);
        e.Data(std::as_bytes(std::span(w.transition_owners_sha256)));
    }
    if (w.version == 5 || w.version == 7) {
        e.Number(w.replaced_inode); e.Number(w.replaced_private_id); e.Number(w.replaced_size); e.Number(w.replaced_mode);
        e.Data(std::as_bytes(std::span(w.replaced_name)));
        e.Number(w.required_checkpoints.size());
        for (const auto xid : w.required_checkpoints) e.Number(xid);
        e.Number(w.read_checkpoints.size());
        for (const auto xid : w.read_checkpoints) e.Number(xid);
    }
    e.Number(options.container_bytes); e.Text(options.container_uuid);
    e.Number(w.plan.block_size); e.Number(w.plan.expected_checkpoint_xid); e.Number(w.plan.transaction_xid);
    e.Number(w.plan.next_object_id);
    return e;
}
std::vector<std::byte> Encode(const Witness& w, const EncryptedPublicationJournal::Options& options)
{
    auto e = EncodeHeader(w, options);
    e.Number(w.plan.guard_blocks.size());
    for (const auto& g : w.plan.guard_blocks) { e.Number(g.physical_block); e.Data(g.bytes); }
    e.Number(w.plan.before_superblock_writes.size());
    for (const auto& row : w.plan.before_superblock_writes) EncodeWrite(e, row);
    EncodeWrite(e, w.plan.superblock_write);
    if (IsRetainedRewrite(w.version)) e.Data(w.transition_owners);
    return std::move(e.bytes);
}
enum class OriginalJournalBinding { Selected, Historical };
Witness Decode(std::span<const std::byte> bytes, const EncryptedPublicationJournal::Options& options,
    bool maintenance_template = false, OriginalJournalBinding binding = OriginalJournalBinding::Selected)
{
    if (bytes.size() > max_bytes) throw std::runtime_error("PublicationLimit");
    Decoder d{bytes}; Witness w;
    w.version = d.Number();
    if (w.version < 1 || w.version > 8) throw std::runtime_error("PublicationVersion");
    if (maintenance_template && w.version != 4 && !IsRetainedRewrite(w.version)) throw std::runtime_error("PublicationMaintenanceVersion");
    w.accepted = d.Number(); w.transaction = d.Number(); w.inode = d.Number();
    w.offset = d.Number(); w.length = d.Number();
    const auto digest = d.Data(32);
    if (digest.size() != 32) throw std::runtime_error("PublicationDigest");
    std::transform(digest.begin(), digest.end(), w.replacement.begin(), [](auto b) { return std::to_integer<std::uint8_t>(b); });
    w.source = d.Text(4096);
    if (w.version >= 2) {
        const auto kind = d.Number();
        const auto last_kind = w.version == 7 ? catalog::EncryptedMutationKind::RemoveExtendedAttribute :
            w.version == 5 ? catalog::EncryptedMutationKind::ReplaceRename :
            catalog::EncryptedMutationKind::SetInodeMetadata;
        if (!kind || kind > static_cast<std::uint64_t>(last_kind) + 1)
            throw std::runtime_error("PublicationIntentKind");
        w.kind = static_cast<catalog::EncryptedMutationKind>(kind - 1);
        if (w.version == 7 && w.kind != catalog::EncryptedMutationKind::SetExtendedAttribute &&
            w.kind != catalog::EncryptedMutationKind::RemoveExtendedAttribute)
            throw std::runtime_error("PublicationVersionIntent");
        w.parent = d.Number(); w.destination_parent = d.Number(); w.result_size = d.Number();
        w.permissions = d.Number(); w.effective_mode = d.Number(); w.volume_object_id = d.Number();
        w.volume_uuid = d.Text(32);
        const auto name = d.Data(32), destination = d.Data(32);
        if (name.size() != 32 || destination.size() != 32 || w.permissions > 0777 ||
            w.effective_mode > UINT16_MAX || w.volume_object_id != options.volume_object_id ||
            w.volume_uuid != options.volume_uuid)
            throw std::runtime_error("PublicationIntentIdentity");
        std::transform(name.begin(), name.end(), w.name.begin(), [](auto b) { return std::to_integer<std::uint8_t>(b); });
        std::transform(destination.begin(), destination.end(), w.destination_name.begin(), [](auto b) { return std::to_integer<std::uint8_t>(b); });
    }
    if (w.version >= 4) {
        const auto original = d.Data(32);
        if (original.size() != 32)
            throw std::runtime_error("PublicationOriginalJournalIdentity");
        std::copy(original.begin(), original.end(), w.original_journal.begin());
        if (!Nonzero(w.original_journal) || (binding == OriginalJournalBinding::Selected &&
            (!Nonzero(options.maintenance_original_journal_identity) ||
             w.original_journal != options.maintenance_original_journal_identity)))
            throw std::runtime_error("PublicationOriginalJournalIdentity");
    }
    if (IsRetainedRewrite(w.version)) {
        w.transition_before = d.Number(); w.transition_after = d.Number();
        const auto owners_digest = d.Data(32);
        if (owners_digest.size() != 32 || !ValidRetainedRewriteModes(w.version, w.transition_before, w.transition_after))
            throw std::runtime_error("PublicationTransitionMode");
        std::transform(owners_digest.begin(), owners_digest.end(), w.transition_owners_sha256.begin(), [](auto b) { return std::to_integer<std::uint8_t>(b); });
    }
    if (w.version == 5 || w.version == 7) {
        w.replaced_inode = d.Number(); w.replaced_private_id = d.Number();
        w.replaced_size = d.Number(); w.replaced_mode = d.Number();
        const auto name = d.Data(32);
        if (name.size() != 32) throw std::runtime_error("PublicationReplacedIdentity");
        std::transform(name.begin(), name.end(), w.replaced_name.begin(), [](auto b) { return std::to_integer<std::uint8_t>(b); });
        const auto pins = [&](std::vector<std::uint64_t>& values) {
            const auto count = d.Number();
            if (count > max_blocks) throw std::runtime_error("PublicationPinLimit");
            for (std::uint64_t i = 0; i < count; ++i) {
                const auto xid = d.Number();
                if (!xid || (!values.empty() && xid <= values.back())) throw std::runtime_error("PublicationPinOrder");
                values.push_back(xid);
            }
        };
        pins(w.required_checkpoints); pins(w.read_checkpoints);
        if (w.replaced_inode) {
            if (w.kind != catalog::EncryptedMutationKind::ReplaceRename || w.replaced_inode < 16 ||
                w.replaced_inode == w.inode || w.replaced_private_id != w.replaced_inode ||
                (w.replaced_mode & 0170000) != 0100000 || w.replaced_mode > UINT16_MAX || w.replaced_name == Digest{})
                throw std::runtime_error("PublicationReplacedIdentity");
        } else if (w.replaced_private_id || w.replaced_size || w.replaced_mode || w.replaced_name != Digest{}) {
            throw std::runtime_error("PublicationReplacedIdentity");
        }
    }
    if (d.Number() != options.container_bytes || d.Text(32) != options.container_uuid)
        throw std::runtime_error("PublicationSourceGeometry");
    const auto block_size = d.Number();
    if (block_size != 4096) throw std::runtime_error("PublicationBlockSize");
    w.plan.block_size = static_cast<std::uint32_t>(block_size);
    w.plan.expected_checkpoint_xid = d.Number(); w.plan.transaction_xid = d.Number(); w.plan.next_object_id = d.Number();
    if ((w.version == 5 || w.version == 7) && (w.required_checkpoints.empty() || w.required_checkpoints.back() != w.plan.expected_checkpoint_xid ||
        !std::includes(w.required_checkpoints.begin(), w.required_checkpoints.end(), w.read_checkpoints.begin(), w.read_checkpoints.end())))
        throw std::runtime_error("PublicationRequiredPins");
    const auto guards = d.Number();
    if (!guards || guards > (IsRetainedRewrite(w.version) ? 384 : max_blocks)) throw std::runtime_error("PublicationGuards");
    for (std::uint64_t i = 0; i != guards; ++i) {
        AppleCheckpointGuardBlock g; g.physical_block = d.Number(); g.bytes = d.Data(w.plan.block_size);
        if (g.bytes.size() != w.plan.block_size) throw std::runtime_error("PublicationGuardSize");
        w.plan.guard_blocks.push_back(std::move(g));
    }
    const auto count = d.Number();
    if (!count || count > max_blocks) throw std::runtime_error("PublicationWrites");
    for (std::uint64_t i = 0; i != count; ++i) w.plan.before_superblock_writes.push_back(DecodeWrite(d, w.plan.block_size));
    w.plan.superblock_write = DecodeWrite(d, w.plan.block_size);
    if (IsRetainedRewrite(w.version)) {
        w.transition_owners = d.Data(max_bytes);
        Digest owners_digest{};
        if (w.transition_owners.empty() || !Hash(w.transition_owners, owners_digest) || owners_digest != w.transition_owners_sha256)
            throw std::runtime_error("PublicationTransitionOwnersDigest");
    }
    const bool boundary = maintenance_template ? !w.accepted && !w.transaction && !w.length && w.replacement == Digest{} : w.accepted && w.transaction;
    if (!d.bytes.empty() || !boundary ||
        (w.inode < 16 && !(w.inode == 2 && (w.kind == catalog::EncryptedMutationKind::SetInodeMetadata ||
            w.kind == catalog::EncryptedMutationKind::SetExtendedAttribute ||
            w.kind == catalog::EncryptedMutationKind::RemoveExtendedAttribute))) || w.source.empty() ||
        !w.plan.expected_checkpoint_xid || w.plan.expected_checkpoint_xid == UINT64_MAX ||
        w.plan.transaction_xid != w.plan.expected_checkpoint_xid + 1 ||
        w.plan.superblock_write.kind != AppleCheckpointWriteKind::CheckpointSuperblock)
        throw std::runtime_error("PublicationShape");
    std::set<std::uint64_t> locations;
    const auto in_range = [&](std::uint64_t block) { return block < options.container_bytes / block_size; };
    for (const auto& row : w.plan.before_superblock_writes)
        if (!in_range(row.physical_block) || !locations.insert(row.physical_block).second ||
            row.kind == AppleCheckpointWriteKind::CheckpointSuperblock)
            throw std::runtime_error("PublicationWriteLocations");
    if (!in_range(w.plan.superblock_write.physical_block) || !locations.insert(w.plan.superblock_write.physical_block).second)
        throw std::runtime_error("PublicationSwitchLocation");
    locations.clear();
    for (const auto& row : w.plan.guard_blocks)
        if (!in_range(row.physical_block) || !locations.insert(row.physical_block).second)
            throw std::runtime_error("PublicationGuardLocations");
    if (IsRetainedRewrite(w.version)) {
        std::string error;
        if (!ValidateTransitionEnvelope(w, options, error)) throw std::runtime_error(error);
    }
    return w;
}
std::vector<std::byte> MaintenanceTemplate(Witness w, const EncryptedPublicationJournal::Options& options)
{
    w.accepted = w.transaction = w.length = 0; w.replacement = {};
    return Encode(w, options);
}
bool MaintenanceWitness(const catalog::SoftwareKeybagPublication& prepared,
    const EncryptedPublicationJournal::Options& options, Witness& w, std::string& error)
{
    w.version = 4; w.inode = prepared.VolumeObjectId();
    w.original_journal = options.maintenance_original_journal_identity;
    w.volume_object_id = prepared.VolumeObjectId(); w.volume_uuid = prepared.VolumeUuid();
    w.source = prepared.SourceIdentity(); w.plan = prepared.Publication();
    if (!Nonzero(w.original_journal) || w.volume_object_id != options.volume_object_id || w.volume_uuid != options.volume_uuid ||
        w.source != options.preimage_source_identity || w.plan.fusion_tier2_anchor_write ||
        w.plan.published_checkpoint.superblock.uuid_hex != options.container_uuid ||
        w.plan.published_checkpoint.superblock.block_count != options.container_bytes / 4096)
        return Fail(error, "EncryptedPublicationMaintenanceScopeMismatch");
    return true;
}
bool MatchAccepted(TransactionManager& tx, const Witness& w,
    const EncryptedPublicationJournal::Options& options, std::string& error)
{
    std::vector<TransactionManager::AcceptedTransaction> accepted;
    AcceptedWipe wipe{accepted};
    if (!tx.LoadAcceptedTransactionsSinceCleanup(accepted, &error)) return false;
    const auto it = std::find_if(accepted.begin(), accepted.end(), [&](const auto& row) { return row.accepted_sequence == w.accepted; });
    // Initial image profile admits one complete original acceptance since
    // cleanup. Older uncleaned owners require a broader proved pin-set contract.
    if (accepted.size() != 1 || it == accepted.end() || it->transaction_id != w.transaction ||
        it->preimage_checkpoint_xid != w.plan.expected_checkpoint_xid ||
        (w.version != 4 && !IsRetainedRewrite(w.version) && it->mutations.size() != 1))
        return Fail(error, "EncryptedPublicationAcceptedBoundaryMismatch");
    if (IsRetainedRewrite(w.version)) {
        if (tx.ProtectedJournalIdentity() != std::optional{w.original_journal})
            return Fail(error, "EncryptedPublicationTransitionOriginalJournalMismatch");
        return MatchTransitionOriginal(*it, w, options, error);
    }
    if (w.version == 4) {
        const auto original = MaintenanceTemplate(w, options);
        Digest hash{};
        if (!(tx.ProtectedJournalIdentity() == std::optional{w.original_journal} &&
            w.inode == options.volume_object_id && !w.offset && !w.parent && !w.destination_parent &&
            w.kind == catalog::EncryptedMutationKind::Overwrite && !w.result_size && !w.permissions && !w.effective_mode &&
            w.name == Digest{} && w.destination_name == Digest{} && Hash(original, hash) &&
            w.length == original.size() && w.replacement == hash &&
            it->mutations.size() == (original.size() + chunk_bytes - 1) / chunk_bytes))
            return Fail(error, "EncryptedPublicationMaintenanceIntentMismatch");
        std::size_t offset = 0;
        for (const auto& m : it->mutations) {
            const auto bytes = std::span(original).subspan(offset, (std::min)(chunk_bytes, original.size() - offset));
            Digest digest{};
            if (m.operation != WriteAheadLog::OperationKind::Write || m.object_id != w.inode ||
                m.parent_object_id != w.plan.expected_checkpoint_xid || m.logical_offset != offset ||
                m.logical_length != bytes.size() || m.payload_length != bytes.size() || m.payload_offset ||
                m.flags || m.unlink_outcome || m.path_utf8 != "\\$apfs-keybag-rewrap-v2" ||
                !m.secondary_path_utf8.empty() || m.inline_payload.size() != bytes.size() ||
                !std::equal(m.inline_payload.begin(), m.inline_payload.end(), bytes.begin()) ||
                !Hash(bytes, digest) || digest != m.payload_sha256)
                return Fail(error, "EncryptedPublicationMaintenanceIntentMismatch");
            offset += bytes.size();
        }
        return true;
    }
    const auto& m = it->mutations.front();
    if (w.version == 5 || w.version == 7) {
        std::vector<std::uint64_t> required;
        if (tx.ProtectedJournalIdentity() != std::optional{w.original_journal} ||
            !tx.LoadRequiredCheckpointXidsSinceCleanup(required, &error) ||
            !std::all_of(required.begin(), required.end(), [&](auto xid) {
                return std::binary_search(w.required_checkpoints.begin(), w.required_checkpoints.end(), xid);
            })) return Fail(error, "EncryptedPublicationRequiredPinsMismatch");
    }
    const auto flags = w.kind == catalog::EncryptedMutationKind::ReplaceRename ? 0x4u : 0u;
    if (m.object_id != w.inode || m.flags != flags || m.unlink_outcome)
        return Fail(error, "EncryptedPublicationAcceptedIntentMismatch");
    using Kind = catalog::EncryptedMutationKind;
    using Op = WriteAheadLog::OperationKind;
    const auto fail = [&] { return Fail(error, "EncryptedPublicationAcceptedIntentMismatch"); };
    const auto name_matches = [&](const std::string& text, const Digest& expected) {
        Digest actual{};
        // Exact APFS leaf bytes were validated by the private capability. A
        // colon or backslash is data here, not Windows path/stream syntax.
        return !text.empty() && text.size() <= 255 && text != "." && text != ".." &&
            text.find('\0') == std::string::npos && text.find('/') == std::string::npos &&
            Hash(std::as_bytes(std::span(text)), actual) && actual == expected;
    };
    const auto payload = [&] {
        return m.payload_length == w.length && m.payload_sha256 == w.replacement;
    };
    const auto no_payload = [&] {
        return !m.payload_length && !m.payload_offset && !m.payload_spool_id &&
            m.inline_payload.empty() && m.payload_sha256 == Digest{};
    };
    switch (w.kind) {
    case Kind::Overwrite:
    case Kind::Write:
        return (m.operation == Op::Write && w.length &&
            (m.parent_object_id == w.plan.expected_checkpoint_xid || (!m.parent_object_id && !m.inline_payload.empty())) &&
            m.logical_offset == w.offset && m.logical_length == w.length && payload() &&
            m.secondary_path_utf8.empty()) || fail();
    case Kind::Create:
        return (m.operation == Op::CreateFile && w.parent >= 2 && !w.destination_parent &&
            w.effective_mode == (0100000 | w.permissions) &&
            m.parent_object_id == w.parent && m.logical_offset == w.permissions &&
            m.logical_length == w.length && w.result_size == w.length && payload() &&
            name_matches(m.path_utf8, w.name) && m.secondary_path_utf8.empty()) || fail();
    case Kind::MakeDirectory:
        return (m.operation == Op::CreateDirectory && w.parent >= 2 && !w.destination_parent &&
            !w.offset && !w.length && !w.result_size && w.effective_mode == (0040000 | w.permissions) &&
            m.parent_object_id == w.parent && m.logical_offset == w.permissions && !m.logical_length &&
            no_payload() && name_matches(m.path_utf8, w.name) && m.secondary_path_utf8.empty()) || fail();
    case Kind::SetInodeMetadata:
        return (m.operation == Op::SetInodeMetadata && !w.offset && !w.parent && !w.destination_parent &&
            m.parent_object_id == w.plan.expected_checkpoint_xid && !m.logical_offset && !m.logical_length && !m.payload_offset && !m.payload_spool_id &&
            m.secondary_path_utf8.empty() && payload() && WriteAheadLog::InlinePayloadIsConsistent(m) &&
            WriteAheadLog::InodeMetadataMutationIsConsistent(m)) || fail();
    case Kind::SetExtendedAttribute:
    case Kind::RemoveExtendedAttribute:
    {
        Digest name{};
        const bool set = w.kind == Kind::SetExtendedAttribute;
        return (w.version == 7 && m.operation == (set ? Op::SetExtendedAttribute : Op::RemoveExtendedAttribute) &&
            !w.offset && !w.parent && !w.destination_parent && m.parent_object_id == w.plan.expected_checkpoint_xid &&
            m.path_utf8 == "encrypted-data" && WriteAheadLog::ExtendedAttributeMutationIsConsistent(m) &&
            Hash(std::as_bytes(std::span(m.secondary_path_utf8)), name) && name == w.name &&
            (set ? payload() : (!w.length && no_payload()))) || fail();
    }
    case Kind::Resize:
        return (m.operation == Op::SetFileSize && !m.parent_object_id && !m.logical_offset &&
            m.logical_length == w.result_size && no_payload() && m.secondary_path_utf8.empty()) || fail();
    case Kind::Rename:
    case Kind::ReplaceRename:
        return (m.operation == Op::Rename && w.parent >= 2 && w.destination_parent >= 2 &&
            (w.kind != Kind::ReplaceRename || ((w.version == 5 || w.version == 7) && (w.effective_mode & 0170000) == 0100000)) &&
            m.parent_object_id == w.parent && m.logical_offset == w.destination_parent &&
            !m.logical_length && no_payload() && name_matches(m.path_utf8, w.name) &&
            name_matches(m.secondary_path_utf8, w.destination_name)) || fail();
    case Kind::Unlink:
        return (m.operation == Op::Delete && w.parent >= 2 && !w.destination_parent &&
            m.parent_object_id == w.parent && !m.logical_offset && !m.logical_length &&
            no_payload() && name_matches(m.path_utf8, w.name) && m.secondary_path_utf8.empty()) || fail();
    }
    return fail();
}
bool SupportedDataIntent(const WriteAheadLog::Record& m, std::uint64_t preimage)
{
    using Op = WriteAheadLog::OperationKind;
    if ((m.object_id < 16 && !(m.object_id == 2 && (m.operation == Op::SetInodeMetadata ||
            m.operation == Op::SetExtendedAttribute || m.operation == Op::RemoveExtendedAttribute))) ||
        (m.flags && !(m.operation == Op::Rename && m.flags == 0x4u)) || m.unlink_outcome ||
        m.path_utf8.starts_with("\\$apfs-keybag-rewrap-")) return false;
    const auto leaf = [](const std::string& name) {
        return !name.empty() && name.size() <= 255 && name != "." && name != ".." &&
            name.find('\0') == std::string::npos && name.find('/') == std::string::npos &&
            MultiByteToWideChar(CP_UTF8, MB_ERR_INVALID_CHARS, name.data(), static_cast<int>(name.size()), nullptr, 0) > 0;
    };
    const auto no_payload = [&] {
        return !m.payload_length && !m.payload_offset && !m.payload_spool_id &&
            m.inline_payload.empty() && m.payload_sha256 == Digest{};
    };
    const auto payload = [&] {
        if (m.logical_length != m.payload_length) return false;
        if (!m.payload_length) {
            Digest empty{};
            return m.inline_payload.empty() && !m.payload_offset && !m.payload_spool_id &&
                Hash({}, empty) && m.payload_sha256 == empty;
        }
        if (m.payload_sha256 == Digest{}) return false;
        if (m.inline_payload.empty()) return true;
        return !m.payload_offset && (!m.payload_spool_id || m.payload_spool_id == m.sequence) &&
            WriteAheadLog::InlinePayloadIsConsistent(m);
    };
    switch (m.operation) {
    case Op::Write:
        return m.logical_length && m.logical_offset <= UINT64_MAX - m.logical_length && payload() &&
            (m.parent_object_id == preimage || (!m.parent_object_id && !m.inline_payload.empty())) &&
            m.secondary_path_utf8.empty();
    case Op::CreateFile:
        return m.parent_object_id >= 2 && m.logical_offset <= 0777 && payload() && leaf(m.path_utf8) &&
            m.secondary_path_utf8.empty();
    case Op::CreateDirectory:
        return m.parent_object_id >= 2 && m.logical_offset <= 0777 && !m.logical_length && no_payload() &&
            leaf(m.path_utf8) && m.secondary_path_utf8.empty();
    case Op::SetInodeMetadata:
        return m.parent_object_id == preimage && !m.logical_offset && !m.logical_length && !m.payload_offset && !m.payload_spool_id &&
            m.secondary_path_utf8.empty() && WriteAheadLog::InlinePayloadIsConsistent(m) &&
            WriteAheadLog::InodeMetadataMutationIsConsistent(m);
    case Op::SetExtendedAttribute:
    case Op::RemoveExtendedAttribute:
        return m.parent_object_id == preimage && m.path_utf8 == "encrypted-data" &&
            WriteAheadLog::ExtendedAttributeMutationIsConsistent(m);
    case Op::SetFileSize:
        return !m.parent_object_id && !m.logical_offset && no_payload() && m.secondary_path_utf8.empty();
    case Op::Rename:
        return m.parent_object_id >= 2 && m.logical_offset >= 2 && !m.logical_length && no_payload() &&
            leaf(m.path_utf8) && leaf(m.secondary_path_utf8);
    case Op::Delete:
        return m.parent_object_id >= 2 && !m.logical_offset && !m.logical_length && no_payload() &&
            leaf(m.path_utf8) && m.secondary_path_utf8.empty();
    default: return false;
    }
}
bool PreparedDataWitness(const catalog::EncryptedCowOverwrite& prepared,
    const EncryptedPublicationJournal::Options& options, Witness& w, std::string& error)
{
    w.inode = prepared.RequestedInode(); w.offset = prepared.RequestedOffset();
    w.length = prepared.ReplacementLength(); w.replacement = prepared.ReplacementSha256();
    w.source = prepared.SourceIdentity(); w.plan = prepared.Publication();
    w.kind = prepared.IntentKind(); w.parent = prepared.IntentParent();
    w.destination_parent = prepared.IntentDestinationParent(); w.result_size = prepared.ResultSize();
    w.permissions = prepared.RequestedPermissions(); w.effective_mode = prepared.EffectiveMode();
    w.name = prepared.IntentNameSha256(); w.destination_name = prepared.IntentDestinationNameSha256();
    w.volume_object_id = prepared.VolumeObjectId(); w.volume_uuid = prepared.VolumeUuid();
    const bool xattr = w.kind == catalog::EncryptedMutationKind::SetExtendedAttribute ||
        w.kind == catalog::EncryptedMutationKind::RemoveExtendedAttribute;
    if (xattr || w.kind == catalog::EncryptedMutationKind::ReplaceRename || !prepared.RequiredReadCheckpointXids().empty()) {
        w.version = xattr ? 7 : 5; w.original_journal = options.maintenance_original_journal_identity;
        w.replaced_inode = prepared.ReplacedInode(); w.replaced_private_id = prepared.ReplacedPrivateId();
        w.replaced_size = prepared.ReplacedSize(); w.replaced_mode = prepared.ReplacedMode();
        w.replaced_name = prepared.ReplacedNameSha256();
        w.required_checkpoints = prepared.RequiredCheckpointXids();
        w.read_checkpoints = prepared.RequiredReadCheckpointXids();
    }
    if (prepared.SourceCheckpointXid() != w.plan.expected_checkpoint_xid ||
        prepared.PublishedCheckpointXid() != w.plan.transaction_xid ||
        w.volume_object_id != options.volume_object_id || w.volume_uuid != options.volume_uuid ||
        w.source != options.preimage_source_identity || w.plan.fusion_tier2_anchor_write ||
        w.plan.published_checkpoint.superblock.uuid_hex != options.container_uuid ||
        w.plan.published_checkpoint.superblock.block_count != options.container_bytes / 4096)
        return Fail(error, "EncryptedPublicationPreparedScopeMismatch");
    return true;
}
struct WitnessGroup
{
    std::uint64_t accepted = 0, transaction = 0, inode = 0;
    std::vector<std::byte> bytes;
    std::vector<std::byte> disposition_intent, disposition_receipt;
    WitnessGroup() = default;
    WitnessGroup(const WitnessGroup&) = default;
    WitnessGroup& operator=(const WitnessGroup&) = default;
    WitnessGroup(WitnessGroup&&) noexcept = default;
    WitnessGroup& operator=(WitnessGroup&&) noexcept = default;
    ~WitnessGroup()
    {
        if (bytes.size() >= 8 && catalog::ReadU64LE(bytes, 0) == 6) SecureZeroMemory(bytes.data(), bytes.size());
    }
};
bool ReadGroups(const std::vector<WriteAheadLog::Record>& records,
    std::vector<WitnessGroup>& groups, std::string& error, WitnessGroup* incomplete = nullptr)
{
    groups.clear();
    WitnessGroup group;
    std::uint64_t transaction = 0, inode = 0, count = 0, prior_accepted = 0;
    for (const auto& record : records) {
        if (record.operation != WriteAheadLog::OperationKind::Write || record.state != WriteAheadLog::RecordState::Prepared ||
            !record.parent_object_id || !record.object_id || !record.transaction_id ||
            record.flags || record.payload_offset || record.payload_spool_id || record.unlink_outcome ||
            !record.secondary_path_utf8.empty() || !WriteAheadLog::InlinePayloadIsConsistent(record))
            return Fail(error, "EncryptedPublicationWitnessRecordInvalid");
        if (record.path_utf8 == disposition_intent_path || record.path_utf8 == disposition_receipt_path) {
            if (count || groups.empty() || record.logical_offset || record.inline_payload.empty() ||
                record.inline_payload.size() > 512) return Fail(error, "AuthorizationDispositionEnvelopeInvalid");
            auto& prior = groups.back();
            if (record.parent_object_id != prior.accepted || record.transaction_id != prior.transaction || record.object_id != prior.inode)
                return Fail(error, "AuthorizationDispositionEnvelopeMismatch");
            if (record.path_utf8 == disposition_intent_path) {
                if (!prior.disposition_intent.empty()) return Fail(error, "AuthorizationDispositionDuplicateIntent");
                prior.disposition_intent = record.inline_payload;
            } else {
                if (prior.disposition_intent.empty() || !prior.disposition_receipt.empty())
                    return Fail(error, "AuthorizationDispositionReceiptOrder");
                prior.disposition_receipt = record.inline_payload;
            }
            continue;
        }
        if (!groups.empty() && !groups.back().disposition_intent.empty() && groups.back().disposition_receipt.empty())
            return Fail(error, "AuthorizationDispositionPending");
        if (!count) {
            if (record.parent_object_id <= prior_accepted) return Fail(error, "EncryptedPublicationWitnessOrder");
            group.accepted = record.parent_object_id; transaction = record.transaction_id; inode = record.object_id;
            group.transaction = transaction; group.inode = inode;
        }
        if (record.parent_object_id != group.accepted || record.transaction_id != transaction || record.object_id != inode)
            return Fail(error, "EncryptedPublicationWitnessGroupMismatch");
        if (record.path_utf8 == witness_path) {
            if (record.inline_payload.empty() || record.inline_payload.size() > chunk_bytes ||
                record.logical_offset != group.bytes.size() || record.inline_payload.size() > max_bytes - group.bytes.size())
                return Fail(error, "EncryptedPublicationWitnessChunkInvalid");
            group.bytes.insert(group.bytes.end(), record.inline_payload.begin(), record.inline_payload.end());
            ++count;
        } else if (record.path_utf8 == witness_end_path) {
            if (!count || record.logical_offset) return Fail(error, "EncryptedPublicationWitnessEndInvalid");
            Decoder d{record.inline_payload};
            if (d.Number() != 2 || d.Number() != group.accepted || d.Number() != transaction ||
                d.Number() != inode || d.Number() != count || d.Number() != group.bytes.size())
                return Fail(error, "EncryptedPublicationWitnessEndMismatch");
            const auto expected = d.Data(32); Digest digest{};
            if (!d.bytes.empty() || expected.size() != digest.size() || !Hash(group.bytes, digest) ||
                !std::equal(expected.begin(), expected.end(), digest.begin(), [](auto a, auto b) { return std::to_integer<std::uint8_t>(a) == b; }))
                return Fail(error, "EncryptedPublicationWitnessDigestMismatch");
            prior_accepted = group.accepted; groups.push_back(std::move(group)); group = {}; count = 0;
        } else return Fail(error, "EncryptedPublicationWitnessPathInvalid");
    }
    if (count && incomplete) { *incomplete = std::move(group); return true; }
    return !count || Fail(error, "EncryptedPublicationWitnessIncomplete");
}
std::vector<WriteAheadLog::Record> WitnessRecords(const Witness& w, std::span<const std::byte> bytes,
    const EncryptedPublicationJournal::Options& options, std::uint64_t sequence)
{
    std::vector<WriteAheadLog::Record> records;
    records.reserve((bytes.size() + chunk_bytes - 1) / chunk_bytes + 1);
    WriteAheadLog::Record record;
    record.volume_identity = options.witness.volume_identity;
    record.sequence = sequence; record.transaction_id = w.transaction;
    record.operation = WriteAheadLog::OperationKind::Write;
    record.state = WriteAheadLog::RecordState::Prepared;
    record.object_id = w.inode; record.parent_object_id = w.accepted;
    std::uint64_t count = 0;
    for (std::size_t offset = 0; offset < bytes.size(); offset += chunk_bytes) {
        const auto size = (std::min)(chunk_bytes, bytes.size() - offset);
        record.path_utf8 = witness_path; record.logical_offset = offset;
        record.inline_payload.assign(bytes.begin() + offset, bytes.begin() + offset + size);
        record.payload_length = record.logical_length = size;
        if (!Hash(record.inline_payload, record.payload_sha256)) throw std::runtime_error("PublicationHashFailed");
        records.push_back(record); ++record.sequence; ++count;
    }
    Digest digest{};
    if (!Hash(bytes, digest)) throw std::runtime_error("PublicationHashFailed");
    Encoder end; end.Number(2); end.Number(w.accepted); end.Number(w.transaction); end.Number(w.inode);
    end.Number(count); end.Number(bytes.size()); end.Data(std::as_bytes(std::span(digest)));
    record.path_utf8 = witness_end_path; record.logical_offset = 0; record.inline_payload = std::move(end.bytes);
    record.payload_length = record.logical_length = record.inline_payload.size();
    if (!Hash(record.inline_payload, record.payload_sha256)) throw std::runtime_error("PublicationHashFailed");
    records.push_back(std::move(record));
    return records;
}
struct TargetSource : catalog::RandomAccessSource
{
    EncryptedPublicationTarget& target;
    std::uint64_t size;
    std::shared_ptr<catalog::ApfsReadBudget> budget = std::make_shared<catalog::ApfsReadBudget>(
        100000, 256ull << 20, 1000000, 256ull << 20);
    TargetSource(EncryptedPublicationTarget& value, std::uint64_t length) : target(value), size(length) {}
    std::uint64_t SizeBytes() const override { return size; }
    std::shared_ptr<catalog::ApfsReadBudget> ReadBudget() const override { return budget; }
    bool Read(std::uint64_t offset, std::size_t count, std::vector<std::byte>& bytes) const override
    {
        bytes.clear();
        if (offset > size || count > size - offset || count > (64u << 20)) return false;
        for (std::size_t i = 0; i < count;) {
            std::vector<std::byte> block;
            if (!budget->Read(4096) || !target.ReadBlockRangeForVerification((offset + i) / 4096, 4096, 1, block) ||
                block.size() != 4096) { bytes.clear(); return false; }
            const auto first = static_cast<std::size_t>((offset + i) % 4096);
            const auto take = (std::min)(count - i, 4096 - first);
            bytes.insert(bytes.end(), block.begin() + first, block.begin() + first + take);
            i += take;
        }
        return true;
    }
};
bool Exact(EncryptedPublicationTarget& target, const AppleCheckpointPlannedWrite& row)
{
    std::vector<std::byte> bytes;
    return target.ReadBlockRangeForVerification(row.physical_block, 4096, 1, bytes) && bytes == row.bytes;
}
bool UnchangedGuards(EncryptedPublicationTarget& target, const AppleCheckpointPublicationPlan& plan)
{
    std::map<std::uint64_t, const std::vector<std::byte>*> writes;
    for (const auto& row : plan.before_superblock_writes) writes.emplace(row.physical_block, &row.bytes);
    writes.emplace(plan.superblock_write.physical_block, &plan.superblock_write.bytes);
    for (const auto& guard : plan.guard_blocks) {
        const auto written = writes.find(guard.physical_block);
        const auto& expected = written == writes.end() ? guard.bytes : *written->second;
        std::vector<std::byte> bytes;
        if (!target.ReadBlockRangeForVerification(guard.physical_block, 4096, 1, bytes) || bytes != expected) return false;
    }
    return true;
}
}

EncryptedPublicationJournal::EncryptedPublicationJournal(Options options)
    : options_(std::move(options)), witness_(options_.witness)
{
    const auto& protection = options_.witness.protected_persistence;
    const auto uuid = [](const std::string& value) {
        return value.size() == 32 && std::all_of(value.begin(), value.end(), [](char c) {
            return (c >= '0' && c <= '9') || (c >= 'a' && c <= 'f'); });
    };
    poisoned_ = !protection || !Nonzero(protection->source_binding) || !Nonzero(protection->journal_identity) ||
        options_.container_bytes < 4096 || options_.container_bytes % 4096 || !options_.volume_object_id ||
        options_.preimage_source_identity.empty() || options_.preimage_source_identity.size() > 4096 ||
        !uuid(options_.container_uuid) || !uuid(options_.volume_uuid);
}
EncryptedPublicationJournal::~EncryptedPublicationJournal() = default;

bool EncryptedPublicationJournal::InspectAcceptedDataRecovery(TransactionManager& tx, std::uint64_t sequence,
    AcceptedDataRecovery& state, std::string& error)
{
    state = AcceptedDataRecovery::CompleteWitness; error.clear();
    if (poisoned_ || !sequence || !tx.RecoveryStateValid() || tx.CurrentState() != TransactionManager::State::Idle ||
        tx.ProtectedSourceBinding() != std::optional{options_.witness.protected_persistence->source_binding})
        return Fail(error, "EncryptedPublicationOwnerInvalid");
    try {
        std::vector<TransactionManager::AcceptedTransaction> accepted;
        AcceptedWipe accepted_wipe{accepted};
        if (!tx.LoadAcceptedTransactionsSinceCleanup(accepted, &error) || accepted.size() != 1 ||
            accepted.front().accepted_sequence != sequence || accepted.front().mutations.size() != 1 ||
            !accepted.front().preimage_checkpoint_xid || accepted.front().preimage_checkpoint_xid == UINT64_MAX ||
            accepted.front().mutations.front().volume_identity !=
                TransactionManager::WideToUtf8(tx.ConfiguredVolumeIdentity()) ||
            !SupportedDataIntent(accepted.front().mutations.front(), accepted.front().preimage_checkpoint_xid))
            return Fail(error, "EncryptedPublicationTypedOriginalRequired");
        auto records = witness_.ReadAllWithExclusiveWriterLease({64ull << 20, 4096});
        Wipe records_wipe{records.records};
        if (records.status != WriteAheadLog::ReadStatus::Ok)
            return Fail(error, "EncryptedPublicationWitnessUnreadable");
        std::vector<std::uint64_t> spent;
        std::vector<WitnessGroup> groups;
        if (!ReadGroups(records.records, groups, error)) return false;
        if (std::any_of(groups.begin(), groups.end(), [](const auto& g) { return !g.disposition_intent.empty(); }) &&
            !ValidateUnacceptedDispositions(tx, spent, error)) return false;
        for (const auto& group : groups) {
            const auto body = Decode(group.bytes, options_, false, OriginalJournalBinding::Historical);
            if (body.accepted != group.accepted || body.transaction != group.transaction || body.inode != group.inode)
                return Fail(error, "EncryptedPublicationWitnessBoundaryMismatch");
            if (group.accepted == sequence) {
                if (&group != &groups.back() || (body.version != 2 && body.version != 5 && body.version != 7) || body.source != options_.preimage_source_identity ||
                    !MatchAccepted(tx, body, options_, error))
                    return Fail(error, "EncryptedPublicationDataWitnessMismatch");
                state = AcceptedDataRecovery::CompleteWitness;
                return true;
            }
            if (group.accepted > tx.Watermarks().cleanup_sequence && !std::binary_search(spent.begin(), spent.end(), group.accepted))
                return Fail(error, "EncryptedPublicationPriorBoundaryNotClean");
        }
        const auto watermarks = tx.Watermarks();
        if (watermarks.accepted_sequence != sequence || watermarks.apfs_durable_sequence >= sequence ||
            watermarks.cleanup_sequence >= sequence)
            return Fail(error, "EncryptedPublicationUnpublishedOriginalRequired");
        state = AcceptedDataRecovery::TypedReprepareAllowed;
        return true;
    } catch (...) { return Fail(error, "EncryptedPublicationDataRecoveryInvalid"); }
}

bool EncryptedPublicationJournal::RestageData(TransactionManager& tx, std::uint64_t sequence,
    const catalog::EncryptedCowOverwrite& prepared, std::string& error)
{
    AcceptedDataRecovery state;
    if (!InspectAcceptedDataRecovery(tx, sequence, state, error)) return false;
    if (state != AcceptedDataRecovery::TypedReprepareAllowed)
        return Fail(error, "EncryptedPublicationCompleteWitnessRequiresReplay");
    return Stage(tx, sequence, prepared, error);
}

bool EncryptedPublicationJournal::Stage(TransactionManager& tx, std::uint64_t accepted,
    const catalog::EncryptedCowOverwrite& prepared, std::string& error)
{
    error.clear();
    if (poisoned_ || !tx.RecoveryStateValid() ||
        tx.ProtectedSourceBinding() != std::optional{options_.witness.protected_persistence->source_binding})
        return Fail(error, "EncryptedPublicationOwnerInvalid");
    try {
        std::vector<TransactionManager::AcceptedTransaction> transactions;
        AcceptedWipe accepted_wipe{transactions};
        if (!tx.LoadUnappliedAcceptedTransactions(transactions, &error) || transactions.size() != 1 ||
            transactions.front().accepted_sequence != accepted)
            return Fail(error, "EncryptedPublicationPendingBoundaryMismatch");
        Witness w;
        w.accepted = accepted; w.transaction = transactions.front().transaction_id;
        if (!PreparedDataWitness(prepared, options_, w, error)) return false;
        if (!MatchAccepted(tx, w, options_, error)) return false;
        return AppendWitness(accepted, Encode(w, options_), error, false, &tx);
    } catch (...) { return Fail(error, "EncryptedPublicationWitnessInvalid"); }
}

bool EncryptedPublicationJournal::DataCapacityAvailable(TransactionManager& tx,
    const catalog::EncryptedCowOverwrite& prepared, std::string& error)
{
    error.clear();
    if (!ValidateOriginalStreamConfiguration(tx, error)) return false;
    const auto watermarks = tx.Watermarks();
    if (poisoned_ || !tx.RecoveryStateValid() || tx.CurrentState() != TransactionManager::State::Idle ||
        watermarks.accepted_sequence != watermarks.cleanup_sequence ||
        tx.ProtectedSourceBinding() != std::optional{options_.witness.protected_persistence->source_binding})
        return Fail(error, "EncryptedPublicationCapacityOwnerInvalid");
    try {
        std::vector<std::uint64_t> spent;
        auto existing = witness_.ReadAllWithExclusiveWriterLease({64ull << 20, 4096});
        Wipe wipe{existing.records};
        if (existing.status != WriteAheadLog::ReadStatus::Ok || existing.recovered_torn_tail)
            return Fail(error, "EncryptedPublicationCapacityHistoryInvalid");
        std::vector<WitnessGroup> groups;
        if (!ReadGroups(existing.records, groups, error)) return false;
        if (std::any_of(groups.begin(), groups.end(), [](const auto& g) { return !g.disposition_intent.empty(); }) &&
            !ValidateUnacceptedDispositions(tx, spent, error)) return false;
        for (const auto& group : groups) {
            const auto body = Decode(group.bytes, options_, false, OriginalJournalBinding::Historical);
            if (body.accepted != group.accepted || body.transaction != group.transaction || body.inode != group.inode ||
                (body.accepted > watermarks.cleanup_sequence && !std::binary_search(spent.begin(), spent.end(), body.accepted)))
                return Fail(error, "EncryptedPublicationCapacityHistoryUnclean");
        }
        Witness projected;
        // All numbers have fixed eight-byte encodings. These placeholders are
        // used only to measure size and are never persisted or used as authority.
        projected.accepted = projected.transaction = 1;
        if (!PreparedDataWitness(prepared, options_, projected, error)) return false;
        const auto encoded = Encode(projected, options_);
        (void)Decode(encoded, options_);
        const auto last = existing.records.empty() ? 0 : existing.records.back().sequence;
        if (last > UINT64_MAX - (max_bytes / chunk_bytes + 2))
            return Fail(error, "EncryptedPublicationCapacityExceeded");
        auto records = WitnessRecords(projected, encoded, options_, last + 1);
        Wipe projected_wipe{records};
        const auto& protection = *options_.witness.protected_persistence;
        const auto capacity = (std::min)({std::uint64_t{64} << 20, options_.witness.max_bytes, protection.read_limits.bytes,
            protection.max_allocation_bytes / 4});
        std::error_code ec;
        const bool present = std::filesystem::exists(options_.witness.path, ec);
        if (ec) return Fail(error, "EncryptedPublicationCapacityHistoryInvalid");
        WriteAheadLog::ProtectedHistoryHead head;
        if (present && !witness_.CaptureProtectedHistoryHead(head))
            return Fail(error, "EncryptedPublicationCapacityHistoryInvalid");
        auto bytes = present ? head.bytes : 4096ull;
        auto count = static_cast<std::uint64_t>(existing.records.size());
        for (const auto& record : records) {
            const auto plain = WriteAheadLog::EncodeForTest(record);
            const auto extra = plain.size() + journal::kJournalRecordHeaderBytes + crypto::kGcmTagBytes;
            if (plain.empty() || bytes > capacity || extra > capacity - bytes ||
                ++count > (std::min<std::uint64_t>)(4096, protection.read_limits.records))
                return Fail(error, "EncryptedPublicationCapacityExceeded");
            bytes += extra;
        }
        if (count > (protection.max_allocation_bytes - bytes * 4) / (2 * sizeof(WriteAheadLog::Record) + 4))
            return Fail(error, "EncryptedPublicationCapacityExceeded");
        return true;
    } catch (...) { return Fail(error, "EncryptedPublicationCapacityHistoryInvalid"); }
}

bool EncryptedPublicationJournal::BuildMaintenanceAcceptance(const catalog::SoftwareKeybagPublication& prepared,
    std::vector<std::byte>& output, std::string& error) const
{
    output.clear(); error.clear();
    if (poisoned_) return Fail(error, "EncryptedPublicationOwnerInvalid");
    try {
        Witness w;
        if (!MaintenanceWitness(prepared, options_, w, error)) return false;
        auto encoded = MaintenanceTemplate(w, options_);
        (void)Decode(encoded, options_, true);
        output = std::move(encoded); return true;
    } catch (...) { return Fail(error, "EncryptedPublicationMaintenanceIntentInvalid"); }
}

bool EncryptedPublicationJournal::StageMaintenance(TransactionManager& tx, std::uint64_t accepted,
    const catalog::SoftwareKeybagPublication& prepared, std::string& error)
{
    std::vector<std::byte> original;
    return BuildMaintenanceAcceptance(prepared, original, error) && RestageMaintenance(tx, accepted, original, error);
}

bool EncryptedPublicationJournal::BuildMaintenanceAcceptanceRecords(const catalog::SoftwareKeybagPublication& prepared,
    std::vector<TransactionManager::MutationIntent>& output, std::string& error) const
{
    output.clear();
    std::vector<std::byte> original;
    if (!BuildMaintenanceAcceptance(prepared, original, error)) return false;
    try {
        std::vector<TransactionManager::MutationIntent> records;
        records.reserve((original.size() + chunk_bytes - 1) / chunk_bytes);
        for (std::size_t offset = 0; offset < original.size(); offset += chunk_bytes) {
            const auto bytes = std::span(original).subspan(offset, (std::min)(chunk_bytes, original.size() - offset));
            TransactionManager::MutationIntent record;
            record.kind = TransactionManager::MutationKind::Write;
            record.path = MaintenanceAcceptancePath; record.object_id = prepared.VolumeObjectId();
            record.generation = prepared.Publication().expected_checkpoint_xid;
            record.offset = offset; record.length = record.payload_length = bytes.size();
            record.inline_payload.assign(bytes.begin(), bytes.end());
            if (!Hash(bytes, record.payload_checksum)) return Fail(error, "EncryptedPublicationHashFailed");
            records.push_back(std::move(record));
        }
        output = std::move(records); return true;
    } catch (...) { return Fail(error, "EncryptedPublicationMaintenanceIntentInvalid"); }
}

bool EncryptedPublicationJournal::AcceptMaintenance(TransactionManager& tx,
    const catalog::SoftwareKeybagPublication& prepared, std::uint64_t& accepted, std::string& error)
{
    accepted = 0; error.clear();
    if (poisoned_ || !tx.RecoveryStateValid() || tx.CurrentState() != TransactionManager::State::Idle ||
        !Nonzero(options_.maintenance_original_journal_identity) ||
        tx.ProtectedJournalIdentity() != std::optional{options_.maintenance_original_journal_identity} ||
        tx.ProtectedSourceBinding() != std::optional{options_.witness.protected_persistence->source_binding})
        return Fail(error, "EncryptedPublicationOwnerInvalid");
    const auto abort = [&]() { if (tx.CurrentState() == TransactionManager::State::Active) (void)tx.Abort(); };
    try {
        std::vector<TransactionManager::AcceptedTransaction> pending;
        AcceptedWipe wipe{pending};
        const auto watermarks = tx.Watermarks();
        if (watermarks.accepted_sequence != watermarks.cleanup_sequence ||
            watermarks.apfs_durable_sequence != watermarks.cleanup_sequence ||
            !tx.LoadAcceptedTransactionsSinceCleanup(pending, &error) || !pending.empty())
            return Fail(error, "EncryptedPublicationPriorBoundaryNotClean");
        std::vector<TransactionManager::MutationIntent> records;
        if (!BuildMaintenanceAcceptanceRecords(prepared, records, error)) return false;
        if (!tx.ProtectedAcceptanceCapacityAvailable(records, error)) return false;
        Witness witness;
        if (!MaintenanceWitness(prepared, options_, witness, error)) return false;
        const auto original = MaintenanceTemplate(witness, options_);
        if (records.empty() || !Hash(original, witness.replacement))
            return Fail(error, "EncryptedPublicationMaintenanceIntentInvalid");
        witness.length = original.size();
        if (!tx.Begin()) return Fail(error, "EncryptedPublicationMaintenanceBeginFailed");
        const auto first = tx.NextMutationSequence();
        if (!first || records.size() >= UINT64_MAX - first || !tx.CurrentTransactionId()) {
            abort(); return Fail(error, "EncryptedPublicationMaintenanceBoundaryOverflow");
        }
        witness.accepted = first + records.size();
        witness.transaction = tx.CurrentTransactionId();
        // This is the origin proof: only the private prepared capability can
        // create it, and it is flushed before any original acceptance exists.
        if (!AppendWitness(witness.accepted, Encode(witness, options_), error, false, &tx)) { abort(); return false; }
        if (!ConfirmMaintenanceAuthorization(Encode(witness, options_), error)) {
            poisoned_ = true; abort(); return false;
        }
        tx.NotifyStage("maintenance-after-private-authorization");
        for (const auto& record : records)
            if (!tx.RecordMutation(record) || !tx.FlushPreparedRecords()) {
                abort(); return Fail(error, "EncryptedPublicationMaintenancePreparationFailed");
            }
        if (!tx.Accept(witness.plan.expected_checkpoint_xid)) {
            abort(); return Fail(error, "EncryptedPublicationMaintenanceAcceptanceFailed");
        }
        if (tx.Watermarks().accepted_sequence != witness.accepted || !MatchAccepted(tx, witness, options_, error)) {
            poisoned_ = true;
            return Fail(error, "EncryptedPublicationMaintenanceBoundaryMismatch");
        }
        accepted = witness.accepted;
        return true;
    } catch (...) { abort(); return Fail(error, "EncryptedPublicationMaintenanceAcceptanceInvalid"); }
}

bool EncryptedPublicationJournal::RestageMaintenance(TransactionManager& tx, std::uint64_t accepted,
    std::string& error)
{
    error.clear();
    if (poisoned_ || !tx.RecoveryStateValid() ||
        tx.ProtectedSourceBinding() != std::optional{options_.witness.protected_persistence->source_binding})
        return Fail(error, "EncryptedPublicationOwnerInvalid");
    try {
        std::vector<TransactionManager::AcceptedTransaction> transactions;
        AcceptedWipe wipe{transactions};
        if (!tx.LoadAcceptedTransactionsSinceCleanup(transactions, &error) || transactions.size() != 1 ||
            transactions.front().accepted_sequence != accepted)
            return Fail(error, "EncryptedPublicationPendingBoundaryMismatch");
        std::vector<std::byte> original;
        for (const auto& record : transactions.front().mutations) {
            if (record.inline_payload.empty() || record.inline_payload.size() > chunk_bytes ||
                record.logical_offset != original.size() || record.inline_payload.size() > max_bytes - original.size())
                return Fail(error, "EncryptedPublicationMaintenanceIntentMismatch");
            original.insert(original.end(), record.inline_payload.begin(), record.inline_payload.end());
        }
        return RestageMaintenance(tx, accepted, original, error);
    } catch (...) { return Fail(error, "EncryptedPublicationMaintenanceIntentInvalid"); }
}

bool EncryptedPublicationJournal::RestageMaintenance(TransactionManager& tx, std::uint64_t accepted,
    std::span<const std::byte> original, std::string& error)
{
    error.clear();
    if (poisoned_ || !tx.RecoveryStateValid() ||
        tx.ProtectedSourceBinding() != std::optional{options_.witness.protected_persistence->source_binding})
        return Fail(error, "EncryptedPublicationOwnerInvalid");
    try {
        auto w = Decode(original, options_, true);
        if (w.version != 4) return Fail(error, "EncryptedPublicationMaintenanceIntentInvalid");
        if (w.source != options_.preimage_source_identity)
            return Fail(error, "EncryptedPublicationMaintenanceScopeMismatch");
        std::vector<TransactionManager::AcceptedTransaction> transactions;
        AcceptedWipe wipe{transactions};
        if (!tx.LoadAcceptedTransactionsSinceCleanup(transactions, &error) || transactions.size() != 1 ||
            transactions.front().accepted_sequence != accepted)
            return Fail(error, "EncryptedPublicationPendingBoundaryMismatch");
        w.accepted = accepted; w.transaction = transactions.front().transaction_id; w.length = original.size();
        if (!Hash(original, w.replacement)) return Fail(error, "EncryptedPublicationHashFailed");
        if (!MatchAccepted(tx, w, options_, error)) return false;
        const auto expected = Encode(w, options_);
        if (!ConfirmMaintenanceAuthorization(expected, error)) {
            if (!RebuildMaintenanceAuthorization(tx, expected, error) ||
                !ConfirmMaintenanceAuthorization(expected, error)) return false;
        }
        if (!witness_.FlushPendingAppends()) {
            poisoned_ = true; return Fail(error, "EncryptedPublicationWitnessEndFailed");
        }
        return true;
    } catch (...) { return Fail(error, "EncryptedPublicationMaintenanceIntentInvalid"); }
}

bool EncryptedPublicationJournal::ConfirmMaintenanceAuthorization(
    std::span<const std::byte> expected, std::string& error)
{
    try {
        const auto w = Decode(expected, options_);
        if (w.version != 4) return Fail(error, "EncryptedPublicationMaintenanceAuthorizationMissing");
        auto records = witness_.ReadAllWithExclusiveWriterLease({64ull << 20, 4096});
        Wipe records_wipe{records.records};
        if (records.status != WriteAheadLog::ReadStatus::Ok)
            return Fail(error, "EncryptedPublicationWitnessUnreadable");
        std::vector<WitnessGroup> groups;
        if (!ReadGroups(records.records, groups, error)) return false;
        for (const auto& group : groups) {
            const auto body = Decode(group.bytes, options_, false, OriginalJournalBinding::Historical);
            if (body.accepted != group.accepted || body.transaction != group.transaction || body.inode != group.inode)
                return Fail(error, "EncryptedPublicationWitnessBoundaryMismatch");
        }
        if (groups.empty() || groups.back().accepted != w.accepted || groups.back().transaction != w.transaction ||
            groups.back().inode != w.inode || groups.back().bytes.size() != expected.size() ||
            !std::equal(groups.back().bytes.begin(), groups.back().bytes.end(), expected.begin()))
            return Fail(error, "EncryptedPublicationMaintenanceAuthorizationMissing");
        return true;
    } catch (...) { return Fail(error, "EncryptedPublicationMaintenanceAuthorizationInvalid"); }
}

bool EncryptedPublicationJournal::RebuildMaintenanceAuthorization(TransactionManager& tx,
    std::span<const std::byte> expected, std::string& error)
{ return RebuildPrivateAuthorization(tx, expected, 4, error); }

bool EncryptedPublicationJournal::RebuildPrivateAuthorization(TransactionManager& tx,
    std::span<const std::byte> expected, std::uint64_t expected_version, std::string& error)
{
    try {
        const auto w = Decode(expected, options_);
        const auto header = EncodeHeader(w, options_).bytes;
        if ((expected_version != 4 && expected_version != 8) || w.version != expected_version ||
            header.size() > chunk_bytes || (w.version == 8 && !ValidateTransitionEnvelope(w, options_, error)) ||
            !MatchAccepted(tx, w, options_, error))
            return Fail(error, "EncryptedPublicationMaintenanceAuthorizationMissing");
        auto regenerated = WitnessRecords(w, expected, options_, 1);
        Wipe regenerated_wipe{regenerated};
        const auto authorize = [&](std::span<const WriteAheadLog::Record> prefix,
            WriteAheadLog::DerivedWitnessResetAuthority& authority) {
            std::vector<WriteAheadLog::Record> owned(prefix.begin(), prefix.end());
            Wipe owned_wipe{owned};
            std::vector<WitnessGroup> groups; WitnessGroup incomplete;
            if (!ReadGroups(owned, groups, error, &incomplete)) return false;
            std::vector<std::uint64_t> spent;
            if (expected_version == 8 && !ValidateUnacceptedDispositionRecords(tx, owned, spent, error, false, true)) return false;
            for (const auto& group : groups) {
                const auto body = Decode(group.bytes, options_, false, OriginalJournalBinding::Historical);
                if (body.accepted != group.accepted || body.transaction != group.transaction ||
                    body.inode != group.inode ||
                    body.accepted >= w.accepted || (body.accepted > tx.Watermarks().cleanup_sequence &&
                        std::find(spent.begin(), spent.end(), body.accepted) == spent.end()))
                    return false;
            }
            if (incomplete.accepted != w.accepted || incomplete.transaction != w.transaction ||
                incomplete.inode != w.inode || incomplete.bytes.size() < header.size() ||
                incomplete.bytes.size() > expected.size() ||
                !std::equal(incomplete.bytes.begin(), incomplete.bytes.end(), expected.begin()) ||
                !MatchAccepted(tx, w, options_, error)) return false;
            // The complete first authenticated chunk contains the private
            // whole-plan digest, original journal identity and exact scope.
            // Matching just arbitrary leading plan bytes cannot authorize a suffix.
            Encoder scope;
            scope.Text(expected_version == 8 ? "apfs-key-rotation-witness-rebuild-v8" : "apfs-maintenance-witness-rebuild-v4");
            scope.Text(options_.container_uuid);
            scope.Number(options_.container_bytes); scope.Number(options_.volume_object_id);
            scope.Text(options_.volume_uuid); scope.Text(options_.preimage_source_identity);
            scope.Data(options_.witness.protected_persistence->source_binding);
            scope.Data(options_.maintenance_original_journal_identity);
            Digest scope_digest{};
            if (!Hash(scope.bytes, scope_digest) || !Hash(expected, authority.body_sha256)) return false;
            std::transform(scope_digest.begin(), scope_digest.end(), authority.scope_binding.begin(),
                [](auto byte) { return static_cast<std::byte>(byte); });
            authority.source_binding = options_.witness.protected_persistence->source_binding;
            authority.original_journal_identity = options_.maintenance_original_journal_identity;
            authority.accepted_sequence = w.accepted; authority.transaction_id = w.transaction;
            authority.preimage_xid = w.plan.expected_checkpoint_xid; authority.inode = w.inode;
            authority.template_bytes = w.length; authority.template_sha256 = w.replacement;
            authority.body_bytes = expected.size();
            authority.authorization_bytes = regenerated.front().inline_payload.size();
            authority.authorization_sha256 = regenerated.front().payload_sha256;
            return true;
        };
        const auto barrier = [&] {
            return MatchAccepted(tx, w, options_, error) && tx.FlushAcceptedEvidenceDurability(w.accepted);
        };
        WriteAheadLog::ProtectedHistoryHead replacement;
        const auto result = expected_version == 8 ? witness_.RebuildDerivedWitnessV8(regenerated, authorize, barrier, replacement) :
            witness_.RebuildDerivedWitnessV4(regenerated, authorize, barrier, replacement);
        if (result != WriteAheadLog::CompactionResult::Succeeded) {
            if (result == WriteAheadLog::CompactionResult::BytesMayHavePersisted) poisoned_ = true;
            return Fail(error, "EncryptedPublicationMaintenanceWitnessRebuildRefused");
        }
        return true;
    } catch (...) { return Fail(error, "EncryptedPublicationMaintenanceWitnessRebuildInvalid"); }
}

bool EncryptedPublicationJournal::AppendWitness(std::uint64_t accepted, std::span<const std::byte> bytes,
    std::string& error, bool resume, TransactionManager* original)
{
    try {
        if (original && !ValidateOriginalStreamConfiguration(*original, error)) return false;
        const auto w = Decode(bytes, options_);
        if (w.accepted != accepted) return Fail(error, "EncryptedPublicationWitnessBoundaryMismatch");
        auto old = witness_.ReadAllWithExclusiveWriterLease({64ull << 20, 4096}); Wipe wipe{old.records};
        if (old.status != WriteAheadLog::ReadStatus::Ok) return Fail(error, "EncryptedPublicationWitnessUnreadable");
        std::vector<WitnessGroup> groups;
        WitnessGroup incomplete;
        if (!ReadGroups(old.records, groups, error, resume ? &incomplete : nullptr)) return false;
        if (std::any_of(groups.begin(), groups.end(), [](const auto& g) { return !g.disposition_intent.empty(); })) {
            std::vector<std::uint64_t> spent;
            if (!original || !ValidateUnacceptedDispositions(*original, spent, error))
                return Fail(error, "AuthorizationDispositionOriginalAuthorityRequired");
        }
        for (const auto& prior : groups) {
            const auto prior_body = Decode(prior.bytes, options_, false, OriginalJournalBinding::Historical);
            if (prior_body.accepted != prior.accepted || prior_body.transaction != prior.transaction ||
                prior_body.inode != prior.inode)
                return Fail(error, "EncryptedPublicationWitnessBoundaryMismatch");
            if (resume && !incomplete.accepted && &prior == &groups.back() &&
                prior.accepted == accepted && prior.bytes.size() == bytes.size() &&
                std::equal(prior.bytes.begin(), prior.bytes.end(), bytes.begin())) {
                if (witness_.FlushPendingAppends()) return true;
                poisoned_ = true; return Fail(error, "EncryptedPublicationWitnessEndFailed");
            }
            if (prior.accepted >= accepted) return Fail(error, "EncryptedPublicationWitnessAlreadyStaged");
        }
        std::size_t prefix_records = 0;
        if (incomplete.accepted) {
            if (w.version != 4 || incomplete.accepted != accepted || incomplete.transaction != w.transaction ||
                incomplete.inode != w.inode || incomplete.bytes.size() > bytes.size() ||
                !std::equal(incomplete.bytes.begin(), incomplete.bytes.end(), bytes.begin()))
                return Fail(error, "EncryptedPublicationWitnessPrefixMismatch");
            for (auto i = old.records.rbegin(); i != old.records.rend() && i->parent_object_id == accepted; ++i)
                ++prefix_records;
        }
        const auto full_records = (bytes.size() + chunk_bytes - 1) / chunk_bytes + 1;
        if (prefix_records >= full_records) return Fail(error, "EncryptedPublicationWitnessPrefixMismatch");
        const auto required_records = full_records - prefix_records;
        const auto& protection = *options_.witness.protected_persistence;
        const auto record_limit = (std::min)(std::size_t{4096}, protection.read_limits.records);
        if (old.records.size() > record_limit || required_records > record_limit - old.records.size() ||
            (!old.records.empty() && required_records >= UINT64_MAX - old.records.back().sequence))
            return Fail(error, "EncryptedPublicationWitnessRecordCapacity");
        const auto first_sequence = prefix_records ? old.records[old.records.size() - prefix_records].sequence :
            old.records.empty() ? 1 : old.records.back().sequence + 1;
        auto pending = WitnessRecords(w, bytes, options_, first_sequence);
        Wipe pending_wipe{pending};
        for (std::size_t i = 0; i < prefix_records; ++i)
            if (WriteAheadLog::EncodeForTest(old.records[old.records.size() - prefix_records + i]) !=
                WriteAheadLog::EncodeForTest(pending[i]))
                return Fail(error, "EncryptedPublicationWitnessPrefixMismatch");
        std::error_code size_error;
        auto total_bytes = std::filesystem::file_size(options_.witness.path, size_error);
        if (size_error) {
            if (size_error != std::errc::no_such_file_or_directory || !old.records.empty())
                return Fail(error, "EncryptedPublicationWitnessSizeUnavailable");
            // Conservative allowance for the authenticated initial WAL anchor.
            total_bytes = 4096;
        }
        const auto byte_limit = (std::min)({std::uint64_t{64} << 20, options_.witness.max_bytes, protection.read_limits.bytes});
        if (total_bytes > byte_limit) return Fail(error, "EncryptedPublicationWitnessByteCapacity");
        for (const auto& row : std::span(pending).subspan(prefix_records)) {
            const auto encoded = WriteAheadLog::EncodeForTest(row);
            const auto added = encoded.size() + journal::kJournalRecordHeaderBytes + crypto::kGcmTagBytes;
            if (encoded.empty() || added > byte_limit - total_bytes)
                return Fail(error, "EncryptedPublicationWitnessByteCapacity");
            total_bytes += added;
        }
        const auto total_records = old.records.size() + required_records;
        if (total_bytes > protection.max_allocation_bytes / 4 ||
            total_records > (protection.max_allocation_bytes - total_bytes * 4) / (2 * sizeof(WriteAheadLog::Record) + 4))
            return Fail(error, "EncryptedPublicationWitnessAllocationCapacity");
        // Keep locked staging bounded while a recovered 64 KiB payload is live.
        constexpr std::size_t batch_records = 4;
        for (std::size_t at = prefix_records; at < pending.size();) {
            const auto count = (std::min)(batch_records, pending.size() - at);
            std::vector<WriteAheadLog::Record> batch(pending.begin() + at, pending.begin() + at + count);
            Wipe batch_wipe{batch};
            if (witness_.AppendBatchWithResult(batch, false) != WriteAheadLog::AppendResult::Succeeded) {
                poisoned_ = true;
                return Fail(error, "EncryptedPublicationWitnessAppendFailed");
            }
            at += count;
        }
        if (!witness_.FlushPendingAppends()) {
            poisoned_ = true;
            return Fail(error, "EncryptedPublicationWitnessEndFailed");
        }
        return true;
    } catch (...) { return Fail(error, "EncryptedPublicationWitnessInvalid"); }
}

bool EncryptedPublicationJournal::PublishOrRecover(TransactionManager& tx, std::uint64_t accepted,
    EncryptedPublicationTarget& target, std::string& error, const AppleCheckpointStageHook& hook)
{
    error.clear();
    if (poisoned_ || !tx.RecoveryStateValid() ||
        tx.ProtectedSourceBinding() != std::optional{options_.witness.protected_persistence->source_binding} ||
        target.SourceBinding() != options_.witness.protected_persistence->source_binding)
        return Fail(error, "EncryptedPublicationSourceBindingMismatch");
    try {
        std::vector<std::uint64_t> spent;
        auto records = witness_.ReadAllWithExclusiveWriterLease({64ull << 20, 4096}); Wipe wipe{records.records};
        if (records.status != WriteAheadLog::ReadStatus::Ok) return Fail(error, "EncryptedPublicationWitnessUnreadable");
        std::vector<WitnessGroup> groups;
        if (!ReadGroups(records.records, groups, error)) return false;
        if (std::any_of(groups.begin(), groups.end(), [](const auto& g) { return !g.disposition_intent.empty(); }) &&
            !ValidateUnacceptedDispositions(tx, spent, error)) return false;
        const WitnessGroup* selected = nullptr;
        for (const auto& group : groups) {
            if (group.accepted == accepted) {
                if (selected) return Fail(error, "EncryptedPublicationWitnessDuplicate");
                selected = &group;
            }
        }
        if (!selected) return Fail(error, "EncryptedPublicationWitnessMissing");
        auto w = Decode(selected->bytes, options_);
        // No released owner wrote v1 witnesses. Retain them for diagnostics;
        // they lack the selected-volume and typed-namespace bindings of v2.
        if (w.version == 1 || w.version == 3) return Fail(error, "EncryptedPublicationLegacyWitnessNeedsOriginalOwner");
        if (w.accepted != accepted || w.transaction != selected->transaction || w.inode != selected->inode ||
            w.source != options_.preimage_source_identity)
            return Fail(error, "EncryptedPublicationWitnessBoundaryMismatch");
        if (!MatchAccepted(tx, w, options_, error)) return false;
        if (!tx.FlushAcceptedEvidenceDurability(accepted)) return Fail(error, "EncryptedPublicationOriginalAcceptanceFlushFailed");
        if (!witness_.FlushPendingAppends()) { poisoned_ = true; return Fail(error, "EncryptedPublicationWitnessFlushFailed"); }
        TargetSource source(target, options_.container_bytes);
        auto checkpoint = catalog::LoadContainerCheckpointView(source, 0, options_.container_bytes, error);
        if (!checkpoint) { error = "EncryptedPublicationCurrentSourceUnproven:" + error; return false; }
        if (checkpoint->superblock.uuid_hex != options_.container_uuid)
            return Fail(error, "EncryptedPublicationContainerIdentityMismatch");
        if (checkpoint->superblock.xid == w.plan.expected_checkpoint_xid) {
            // Exact destinations were admitted by the private COW owner proof.
            // They may contain a partial prior write. The execution copy checks
            // every other original guard; the full witness stays intact.
            std::set<std::uint64_t> planned;
            for (const auto& row : w.plan.before_superblock_writes) planned.insert(row.physical_block);
            planned.insert(w.plan.superblock_write.physical_block);
            auto execution = w.plan;
            std::erase_if(execution.guard_blocks, [&](const auto& row) { return planned.contains(row.physical_block); });
            for (const auto& guard : execution.guard_blocks) {
                std::vector<std::byte> current;
                if (!target.ReadBlockRangeForVerification(guard.physical_block, 4096, 1, current))
                    return Fail(error, "EncryptedPublicationGuardReadFailed");
                if (current != guard.bytes) return Fail(error, "EncryptedPublicationGuardChanged");
            }
            if (!ExecuteAppleCheckpointPublication(target, execution, error, hook)) return false;
        } else if (checkpoint->superblock.xid != w.plan.transaction_xid) {
            return Fail(error, "EncryptedPublicationCheckpointConflict");
        }
        if (!UnchangedGuards(target, w.plan) || !Exact(target, w.plan.superblock_write) ||
            !std::all_of(w.plan.before_superblock_writes.begin(), w.plan.before_superblock_writes.end(),
                [&](const auto& row) { return Exact(target, row); }))
            return Fail(error, "EncryptedPublicationPublishedBytesMismatch");
        if (!target.Flush()) return Fail(error, "EncryptedPublicationRecoveryFlushFailed");
        if (!UnchangedGuards(target, w.plan) || !Exact(target, w.plan.superblock_write) ||
            !std::all_of(w.plan.before_superblock_writes.begin(), w.plan.before_superblock_writes.end(),
                [&](const auto& row) { return Exact(target, row); }))
            return Fail(error, "EncryptedPublicationDurableBytesMismatch");
        return tx.MarkApfsDurableThrough(accepted) || Fail(error, "EncryptedPublicationWatermarkFailed");
    } catch (...) { return Fail(error, "EncryptedPublicationRecoveryInvalid"); }
}
#include "EncryptedPublicationTransition.inc"
#include "EncryptedPublicationKeyRotation.inc"
#include "EncryptedPublicationAuthorizationDisposition.inc"
#include "EncryptedPublicationJournalContinuation.inc"
#include "EncryptedPublicationKeyManagement.inc"
}
