#include "VolumeMetadata.h"
#include "VolumeRenameOriginal.h"
#include <filesystem>
#include <iostream>
#include <map>

using namespace apfsaccess;
namespace
{
std::string Utf8(const wchar_t* value)
{
    const auto count = WideCharToMultiByte(CP_UTF8, WC_ERR_INVALID_CHARS, value, -1, nullptr, 0, nullptr, nullptr);
    if (!count) throw std::runtime_error("Invalid UTF-16 argument");
    std::string text(count, '\0');
    if (!WideCharToMultiByte(CP_UTF8, WC_ERR_INVALID_CHARS, value, -1, text.data(), count, nullptr, nullptr))
        throw std::runtime_error("Invalid UTF-16 argument");
    text.pop_back(); return text;
}
std::uint64_t Number(const wchar_t* value)
{
    const std::wstring text(value);
    if (text.empty() || text.find_first_not_of(L"0123456789") != std::wstring::npos) throw std::runtime_error("Expected nonzero decimal identity/XID");
    std::size_t used = 0; const auto n = std::stoull(text, &used);
    if (!n || used != text.size()) throw std::runtime_error("Expected nonzero decimal identity/XID");
    return n;
}
void Require(bool value, const std::string& error) { if (!value) throw std::runtime_error(error); }
}
int wmain(int argc, wchar_t** argv)
{
    if (argc > 1 && std::wstring_view(argv[1]) == L"--original")
        return rw::rename_original::Run(argc, argv);
    try
    {
        const bool recover = argc > 1 && std::wstring_view(argv[1]) == L"recover";
        if ((!recover && (argc != 9 || std::wstring_view(argv[1]) != L"rename")) || (recover && argc != 7))
        {
            std::cerr << "Image only; use the same canonical journal directory on every invocation.\n"
                "VolumeRenameImage rename IMAGE CONTAINER_UUID VOLUME_UUID OID PREIMAGE_XID NEW_LABEL JOURNAL_DIR\n"
                "VolumeRenameImage recover IMAGE CONTAINER_UUID VOLUME_UUID OID JOURNAL_DIR\n";
            return 2;
        }
        const auto image = std::filesystem::absolute(argv[2]);
        const auto attributes = GetFileAttributesW(image.c_str());
        Require(attributes != INVALID_FILE_ATTRIBUTES && !(attributes & FILE_ATTRIBUTE_REPARSE_POINT) &&
            std::filesystem::is_regular_file(image), "Only an existing regular image file is supported");
        const auto container = Utf8(argv[3]), volume_uuid = Utf8(argv[4]);
        const auto oid = Number(argv[5]);
        Require(rw::ValidRenameUuid(container) && rw::ValidRenameUuid(volume_uuid), "Expected exact lowercase nonzero UUIDs");
        const auto label = recover ? std::string{} : Utf8(argv[7]);
        if (!recover) Require(rw::ValidNativeVolumeLabel(label), "Invalid volume label");
        const auto expected_xid = recover ? 0 : Number(argv[6]);
        const auto journals_path = std::filesystem::absolute(argv[recover ? 6 : 8]);
        std::string error;
        auto owner = catalog::ContainerMountCoordinator::Open(Utf8(image.c_str()), 0, error,
            catalog::CatalogLoadPolicy::StrictApple, true, true);
        Require(!!owner, error);
        Require(owner->Device().IsRegularFile() && owner->ContainerUuidHex() == container, "Image/container identity mismatch");
        if (!recover) Require(owner->CheckpointXid() == expected_xid, "Stale preimage XID");
        catalog::ApfsContainerCatalog catalog; std::wstring wide_error;
        Require(catalog::ApfsContainerCatalog::TryLoadDevice(owner->Device(), catalog, wide_error), "Strict image catalog failed");
        catalog::ResolvedMountVolume selected;
        Require(catalog.TryResolveVolume(container, oid, selected, error) && selected.volume_uuid_hex == volume_uuid,
            "Volume UUID/OID identity mismatch");
        std::filesystem::create_directories(journals_path);
        std::map<std::uint64_t, std::unique_ptr<rw::TransactionManager>> journals;
        std::vector<catalog::VolumeCheckpointPins> census;
        for (const auto& volume : catalog.Containers().front().volumes)
        {
            auto journal = std::make_unique<rw::TransactionManager>(L"Strict");
            const auto identity = "apfs-vol:" + container + ":" + std::to_string(volume.object_id);
            journal->SetVolumeIdentity(std::wstring(identity.begin(), identity.end()));
            journal->SetJournalPath((journals_path / (container + "-" + volume.volume_uuid_hex + "-" + std::to_string(volume.object_id) + ".wal")).wstring());
            catalog::VolumeCheckpointPins pins; pins.volume_object_id = volume.object_id;
            Require(journal->LoadRequiredCheckpointXidsSinceCleanup(pins.required_checkpoint_xids, &error), error);
            pins.unapplied_accepted_work = journal->HasUnappliedAcceptedWork();
            census.push_back(pins); journals.emplace(volume.object_id, std::move(journal));
        }
        catalog::ContainerVolumeSession session;
        session.volume_object_id = oid; session.container_uuid_hex = container;
        session.requested_write = true; session.use_canonical_transaction = true;
        session.recovery_identity = "apfs-vol:" + container + ":" + std::to_string(oid);
        session.metadata_context.allow_legacy_scaffold_for_fixtures = false;
        Require(owner->MountVolume(session, error), error);
        Require(owner->InitializeRequiredCheckpointCensus(census, error), error);
        if (recover)
        {
            const auto result = rw::ReplayVolumeRename(*owner, *journals.at(oid), oid, error);
            Require(!result.has_value() || *result, error);
            Require(!journals.at(oid)->HasUnappliedAcceptedWork(), "Other accepted work requires its original recovery owner");
            std::cout << (result.has_value() ? "Recovered" : "No accepted rename") << " oid=" << oid << " xid=" << owner->CheckpointXid() << "\n";
        }
        else
        {
            rw::VolumeRenamePlan plan;
            Require(rw::PrepareVolumeRename(*owner, oid, label, plan, error), error);
            const auto result = rw::ApplyVolumeRename(*owner, *journals.at(oid), plan);
            Require(result.committed && !result.commit_recovery_required &&
                result.commit_status_code == static_cast<int>(rw::MetadataStore::CommitStatus::Committed), result.error);
            std::cout << "Renamed oid=" << oid << " xid=" << result.checkpoint_xid << " label=" << label << "\n";
        }
        return 0;
    }
    catch (const std::exception& error) { std::cerr << "Rename refused or requires recovery: " << error.what() << "\n"; return 1; }
}
