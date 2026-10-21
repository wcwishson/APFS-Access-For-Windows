#pragma once

#include "VolumeKeeperOriginalWal.h"
#include "VolumeKeeperWal.h"
#include "VolumeMetadata.h"
#include <charconv>
#include <cwctype>
#include <iostream>
#include <map>
#include <set>

namespace apfsaccess::rw::rename_original
{
inline void Require(bool ok, const std::string& error) { if (!ok) throw std::runtime_error(error); }
inline std::string Utf8(std::wstring_view text)
{
    Require(!text.empty() && text.size() <= 65535, "Invalid bounded Unicode argument");
    const auto size = WideCharToMultiByte(CP_UTF8, WC_ERR_INVALID_CHARS, text.data(), static_cast<int>(text.size()), nullptr, 0, nullptr, nullptr);
    Require(size > 0, "Invalid Unicode argument");
    std::string out(size, '\0');
    Require(WideCharToMultiByte(CP_UTF8, WC_ERR_INVALID_CHARS, text.data(), static_cast<int>(text.size()), out.data(), size, nullptr, nullptr) == size,
        "Invalid Unicode argument");
    return out;
}
inline std::uint64_t Number(std::wstring_view text)
{
    const auto value = Utf8(text);
    std::uint64_t number = 0;
    const auto parsed = std::from_chars(value.data(), value.data() + value.size(), number);
    Require(parsed.ec == std::errc{} && parsed.ptr == value.data() + value.size() && std::to_string(number) == value,
        "Expected canonical unsigned integer");
    return number;
}
inline std::filesystem::path LocalPath(const std::wstring& value)
{
    Require(value.size() >= 4 && std::iswalpha(value[0]) && value[1] == L':' &&
        (value[2] == L'\\' || value[2] == L'/') && value.find(L':', 2) == std::wstring::npos,
        "Rename requires an exact local regular path");
    const std::filesystem::path path(value);
    Require(path.is_absolute(), "Rename requires an absolute path");
    for (const auto& part : path.relative_path())
        Require(part != L"." && part != L"..", "Rename path alias refused");
    Require(GetDriveTypeW(path.root_path().c_str()) == DRIVE_FIXED, "Rename requires a local fixed filesystem");
    for (auto parent = path; !parent.empty(); parent = parent == parent.root_path() ? std::filesystem::path{} : parent.parent_path())
    {
        const auto attributes = GetFileAttributesW(parent.c_str());
        Require(attributes != INVALID_FILE_ATTRIBUTES && !(attributes & FILE_ATTRIBUTE_REPARSE_POINT), "Rename path missing or redirected");
    }
    return path;
}
class Source final : public catalog::RandomAccessSource
{
    const BlockDevice& device_;
public:
    explicit Source(const BlockDevice& device) : device_(device) {}
    std::uint64_t SizeBytes() const override { return device_.GetGeometry().total_bytes; }
    bool Read(std::uint64_t at, std::size_t size, std::vector<std::byte>& out) const override
    { return device_.Read(at, size, out) && out.size() == size; }
};

inline int Run(int argc, wchar_t** argv)
{
    try
    {
        std::map<std::wstring, std::wstring> args;
        std::map<std::uint64_t, std::filesystem::path> paths;
        const std::set<std::wstring> names{L"--image", L"--container", L"--volume", L"--oid", L"--xid", L"--name", L"--source-identity", L"--confirm"};
        bool dry = false, commit = false, recover = false;
        for (int i = 2; i < argc; ++i)
        {
            const std::wstring key(argv[i]);
            if (key == L"--dry-run") { Require(!dry, "Duplicate dry-run"); dry = true; continue; }
            if (key == L"--commit") { Require(!commit, "Duplicate commit"); commit = true; continue; }
            if (key == L"--recover") { Require(!recover, "Duplicate recover"); recover = true; continue; }
            Require(i + 1 < argc, "Missing argument value");
            const std::wstring value(argv[++i]);
            if (key == L"--wal")
            {
                const auto split = value.find(L'=');
                Require(split != std::wstring::npos && paths.size() < 100, "WAL syntax OID=path and bounded complete census required");
                const auto oid = Number(value.substr(0, split));
                Require(oid && paths.emplace(oid, LocalPath(value.substr(split + 1))).second, "Duplicate or zero WAL OID");
            }
            else Require(names.contains(key) && args.emplace(key, value).second, "Unknown or duplicate option");
        }
        Require(dry != commit && commit == args.contains(L"--confirm"), "Choose dry-run or commit with exact confirmation");
        for (const auto* name : {L"--image", L"--container", L"--volume", L"--oid", L"--xid", L"--name", L"--source-identity"})
            Require(args.contains(name), "Missing exact target field");
        const auto image = LocalPath(args.at(L"--image"));
        const auto container = Utf8(args.at(L"--container")), uuid = Utf8(args.at(L"--volume")), label = Utf8(args.at(L"--name"));
        const auto oid = Number(args.at(L"--oid")), xid = Number(args.at(L"--xid"));
        Require(oid && xid && ValidRenameUuid(container) && ValidRenameUuid(uuid) && ValidNativeVolumeLabel(label), "Invalid exact rename target");
        std::string error, source_identity;
        auto owner = catalog::ContainerMountCoordinator::Open(Utf8(image.wstring()), 0, error, catalog::CatalogLoadPolicy::StrictApple, true, true, true);
        Require(!!owner, error);
        Require(owner->Device().IsRegularFile() && owner->Device().BaseOffsetBytes() == 0 &&
            owner->Device().GetGeometry().total_bytes <= 256ULL * 1024 * 1024 &&
            owner->Device().QueryRegularImageIdentity(source_identity) && source_identity == Utf8(args.at(L"--source-identity")),
            "VolumeRenameOriginalSourceIdentityMismatch");
        Require(owner->ContainerUuidHex() == container, "VolumeRenameOriginalContainerMismatch");
        Require(owner->CheckpointXid() == xid, "Stale preimage XID");
        Source source(owner->Device());
        const auto checkpoint = catalog::LoadAppleCheckpointView(source, 0, source.SizeBytes(), error);
        Require(!!checkpoint, error);
        Require(paths.size() == checkpoint->volumes.size() && paths.contains(oid), "Complete explicit original WAL census required");
        std::map<std::uint64_t, std::unique_ptr<volume_keeper::OriginalWal>> originals;
        std::map<std::uint64_t, std::vector<TransactionManager::AcceptedTransaction>> pending;
        std::map<std::uint64_t, TransactionManager::DurabilityWatermarks> marks;
        std::vector<catalog::VolumeCheckpointPins> census;
        std::set<std::wstring> distinct;
        for (const auto& volume : checkpoint->volumes)
        {
            const auto id = volume.superblock.object_id;
            Require(paths.contains(id), "Original sibling WAL missing");
            const auto& path = paths.at(id);
            auto normalized = path.wstring();
            for (auto& c : normalized) c = static_cast<wchar_t>(std::towlower(c));
            Require(distinct.insert(normalized).second && !std::filesystem::equivalent(image, path), "WAL alias refused");
            for (const auto& [peer, original] : originals)
            { (void)original; Require(!std::filesystem::equivalent(path, paths.at(peer)), "WAL hardlink alias refused"); }
            auto original = std::make_unique<volume_keeper::OriginalWal>(path);
            const auto identities = AcquireVolumeKeeperWalLeases(path, container, id, original->leases, "VolumeRenameOriginal");
            auto identity = identities.production;
            const auto records = WriteAheadLog::ReadAll(path, "");
            Require(records.status == WriteAheadLog::ReadStatus::Ok && !records.recovered_torn_tail, "Original WAL strict inspection failed");
            bool first = true;
            for (const auto& record : records.records)
            {
                Require(record.volume_identity == identities.canonical || record.volume_identity == identities.production, "Original WAL identity unproved");
                if (first) { identity = record.volume_identity; first = false; }
                else Require(record.volume_identity == identity, "Original WAL mixed identities");
            }
            original->identity = identity;
            Require(TransactionManager::InspectAcceptedTransactionsReadOnly(path, identity, pending[id], marks[id], error), error);
            Require((id == oid && recover) || pending[id].empty(), id == oid ? "VolumeRenameOriginalRecoveryRequired" : "Original sibling accepted debt");
            if (id != oid || !recover)
            {
                Require(VolumeKeeperWalHasCleanBoundary(records.records, marks[id].cleanup_sequence), "Original unclean WAL suffix");
                Require(marks[id].accepted_sequence == marks[id].apfs_durable_sequence && marks[id].apfs_durable_sequence == marks[id].cleanup_sequence,
                    "Original completion boundary not clean");
            }
            catalog::VolumeCheckpointPins pins;
            pins.volume_object_id = id;
            pins.unapplied_accepted_work = marks[id].accepted_sequence > marks[id].apfs_durable_sequence;
            for (const auto& transaction : pending[id]) pins.required_checkpoint_xids.push_back(transaction.preimage_checkpoint_xid);
            census.push_back(std::move(pins));
            originals.emplace(id, std::move(original));
        }
        catalog::ContainerVolumeSession session;
        session.volume_object_id = oid; session.container_uuid_hex = container;
        session.requested_write = true; session.use_canonical_transaction = true;
        session.metadata_context.allow_legacy_scaffold_for_fixtures = false;
        Require(owner->MountVolume(session, error) && owner->InitializeRequiredCheckpointCensus(census, error), error);
        const auto* store = owner->FindSessionStore(oid);
        Require(store && store->Context().volume_uuid_hex == uuid, "VolumeRenameOriginalSelectedIdentityMismatch");
        VolumeRenamePlan plan;
        std::vector<std::byte> binding;
        if (!recover)
        {
            Require(PrepareVolumeRename(*owner, oid, label, plan, error), error);
            binding = plan.request.inline_payload;
        }
        else
        {
            const auto& debt = pending.at(oid);
            Require(debt.size() == 1 && debt[0].mutations.size() == 1, "Recovery requires one actual accepted rename");
            MetadataStore::MutationRequest request;
            NativeVolumeRename intent;
            Require(VolumeRenameFromWal(debt[0].mutations[0], request) && DecodeNativeVolumeRename(request.inline_payload, intent) &&
                intent.container_uuid == container && intent.volume_uuid == uuid && intent.volume == oid && intent.new_label == label &&
                intent.checkpoint == debt[0].preimage_checkpoint_xid, "Original rename recovery binding mismatch");
            if (xid == intent.checkpoint)
            {
                Require(ValidateVolumeRenameMutation(*store, request, error), error);
                std::vector<std::uint64_t> pins;
                for (const auto& entry : census) pins.insert(pins.end(), entry.required_checkpoint_xids.begin(), entry.required_checkpoint_xids.end());
                AppleVolumeTransactionPlan preview;
                Require(PlanVolumeRenameCheckpoint(source, *checkpoint, intent, pins, preview, error), error);
            }
            else Require(VerifyPublishedVolumeRename(*store, intent, error), error);
            binding = request.inline_payload;
        }
        const auto append = [&](std::string_view text) {
            for (unsigned i = 0; i != 8; ++i) binding.push_back(std::byte((std::uint64_t(text.size()) >> (8 * i)) & 255));
            for (unsigned char c : text) binding.push_back(std::byte(c));
        };
        append(recover ? "rename-original-recover-v1" : "rename-original-apply-v1");
        append(Utf8(image.wstring())); append(source_identity); append(std::to_string(xid));
        for (const auto& [id, original] : originals)
        {
            append(std::to_string(id)); append(Utf8(paths.at(id).wstring())); append(original->identity); append(original->FileBinding());
            append(std::to_string(marks.at(id).accepted_sequence)); append(std::to_string(marks.at(id).apfs_durable_sequence)); append(std::to_string(marks.at(id).cleanup_sequence));
        }
        const auto token = volume_keeper::OriginalWal::Digest(binding);
        const auto label_hash = volume_keeper::OriginalWal::Digest(std::as_bytes(std::span(label.data(), label.size())));
        const auto preview = "{\"schema\":1,\"mode\":\"rename-original\",\"recover\":" + std::string(recover ? "true" : "false") +
            ",\"oid\":" + std::to_string(oid) + ",\"xid\":" + std::to_string(xid) + ",\"sourceIdentity\":\"" + source_identity +
            "\",\"labelSha256\":\"" + label_hash + "\",\"confirm\":\"" + token + "\"}";
        std::cout << preview << '\n'; std::cout.flush(); Require(std::cout.good(), "Rename plan output failed");
        if (dry) return 0;
        Require(Utf8(args.at(L"--confirm")) == token, "Rename confirmation mismatch");

        auto& original = *originals.at(oid);
        original.Verify(paths.at(oid));
        const auto identities = VolumeKeeperWalIdentities{"apfs-vol:" + container + ":" + std::to_string(oid), DerivePartitionlessVolumeRecoveryIdentity(container, oid)};
        // Keep namespace/file identity and the alternate legal identity pinned.
        // A racing selected lease can only make strict startup refuse.
        original.read_fence.reset();
        original.leases[original.identity == identities.canonical ? 0 : 1].reset();
        TransactionManager journal(L"Strict");
        Require(journal.OpenStartupJournal(paths.at(oid).wstring(), std::wstring(original.identity.begin(), original.identity.end()), error), error);
        Require(journal.EnrollCanonicalJournalIdentity(std::wstring(identities.canonical.begin(), identities.canonical.end())), "Original canonical identity enrollment failed");
        original.Verify(paths.at(oid));
        const auto current_marks = journal.Watermarks();
        Require(current_marks.accepted_sequence == marks.at(oid).accepted_sequence &&
            current_marks.apfs_durable_sequence == marks.at(oid).apfs_durable_sequence && current_marks.cleanup_sequence == marks.at(oid).cleanup_sequence,
            "Original marks changed during handoff");
        if (recover) Require(ReplayVolumeRename(*owner, journal, oid, error).value_or(false), error);
        else
        {
            const auto result = ApplyVolumeRename(*owner, journal, plan);
            Require(result.committed && !result.commit_recovery_required &&
                result.commit_status_code == static_cast<int>(MetadataStore::CommitStatus::Committed), result.error);
        }
        const auto final = journal.Watermarks();
        Require(final.accepted_sequence && final.accepted_sequence == final.apfs_durable_sequence && final.apfs_durable_sequence == final.cleanup_sequence,
            "Rename original boundary not durable and clean");
        std::cout << "{\"durable\":true,\"checkpointXid\":" << owner->CheckpointXid() << ",\"acceptedSequence\":" << final.accepted_sequence
            << ",\"apfsDurableSequence\":" << final.apfs_durable_sequence << ",\"cleanupSequence\":" << final.cleanup_sequence << "}\n";
        std::cout.flush(); Require(std::cout.good(), "Rename durable result output failed");
        return 0;
    }
    catch (const std::exception& error) { std::cerr << "REFUSED " << error.what() << '\n'; return 1; }
}
}
