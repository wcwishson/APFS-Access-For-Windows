#include "SnapshotRuntime.h"
#include <filesystem>
#include <iostream>
#include <map>
#include <iomanip>

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
struct ExclusiveImage {
    HANDLE handle = INVALID_HANDLE_VALUE;
    ~ExclusiveImage() { if (handle != INVALID_HANDLE_VALUE) CloseHandle(handle); }
    ExclusiveImage() = default; ExclusiveImage(const ExclusiveImage&) = delete;
};
// Sole-owner image lease: no sharing, so a mounted session, another command,
// or a concurrent writer cannot move the preimage underneath inspection.
// Failure names the active-owner conflict as durable refusal evidence.
HANDLE HoldExclusiveImage(const std::filesystem::path& image) {
    HANDLE held = CreateFileW(image.c_str(), GENERIC_READ | GENERIC_WRITE, 0, nullptr,
        OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL | FILE_FLAG_OPEN_REPARSE_POINT, nullptr);
    Require(held != INVALID_HANDLE_VALUE, "ImageOwnerActive: the image is held by another owner or cannot be opened exclusively");
    BY_HANDLE_FILE_INFORMATION info{};
    FILE_STANDARD_INFO standard{};
    Require(GetFileInformationByHandle(held, &info) && GetFileInformationByHandleEx(held, FileStandardInfo, &standard, sizeof(standard)) &&
        !(info.dwFileAttributes & (FILE_ATTRIBUTE_REPARSE_POINT | FILE_ATTRIBUTE_DIRECTORY | FILE_ATTRIBUTE_DEVICE)) &&
        !standard.DeletePending && standard.NumberOfLinks == 1 && standard.EndOfFile.QuadPart > 0 &&
        standard.EndOfFile.QuadPart <= 256ll * 1024 * 1024, "Exclusive bounded ordinary image required");
    return held;
}
}
int wmain(int argc, wchar_t** argv)
{
    try
    {
        const std::wstring action=argc>1?argv[1]:L"";
        // Inspect mode prefixes create/delete with a dry-run admission proof:
        // the tail parses identically, the plan is prepared and printed, and
        // nothing is applied. Shift the view so all positions below hold.
        const bool inspect = action==L"inspect";
        if (inspect)
        {
            Require(argc > 2 && (std::wstring_view(argv[2])==L"create" || std::wstring_view(argv[2])==L"delete"),
                "SnapshotImage inspect create|delete ...");
            ++argv; --argc;
        }
        const std::wstring subaction=argc>1?argv[1]:L"";
        const bool recover=subaction==L"recover",list=subaction==L"list",create=subaction==L"create",remove=subaction==L"delete";
        if ((!recover&&!list&&!create&&!remove) || ((recover||list)&&argc!=7) || (create&&argc!=11) || (remove&&argc!=17)) {
            std::cerr << "Image only; use the same canonical per-volume session journal directory on every invocation.\n"
                "SnapshotImage list|recover IMAGE CONTAINER_UUID VOLUME_UUID OID JOURNAL_DIR\n"
                "SnapshotImage create IMAGE CONTAINER_UUID VOLUME_UUID OID SOURCE_XID NAME TIME_NS INUM JOURNAL_DIR\n"
                "SnapshotImage delete IMAGE CONTAINER_UUID VOLUME_UUID OID SOURCE_XID SNAPSHOT_XID NAME APSB OMAP OMAP_TREE ROOT_OID ROOT_BLOCK EXTENTREF TIME_NS JOURNAL_DIR\n"
                "SnapshotImage inspect create|delete ... (dry-run admission proof; nothing is applied)\n";
            return 2;
        }
        const auto image = std::filesystem::absolute(argv[2]);
        const auto attributes = GetFileAttributesW(image.c_str());
        Require(attributes != INVALID_FILE_ATTRIBUTES && !(attributes & FILE_ATTRIBUTE_REPARSE_POINT) &&
            std::filesystem::is_regular_file(image), "Only an existing regular image file is supported");
        const auto container = Utf8(argv[3]), volume_uuid = Utf8(argv[4]);
        const auto oid = Number(argv[5]);
        Require(rw::ValidRenameUuid(container) && rw::ValidRenameUuid(volume_uuid), "Expected exact lowercase nonzero UUIDs");
        const auto expected_xid=(recover||list)?0:Number(argv[6]);
        const auto journals_path=std::filesystem::absolute(argv[(recover||list)?6:create?10:16]);
        std::string error;
        ExclusiveImage exclusive;
        exclusive.handle = HoldExclusiveImage(image);
        auto device = rw::BlockDevice::AdoptExclusiveRepairImage(image.wstring(), exclusive.handle, error);
        Require(!!device, error);
        auto owner = catalog::ContainerMountCoordinator::OpenRepairImage(device, error);
        Require(!!owner, error);
        Require(owner->ContainerUuidHex() == container, "Image/container identity mismatch");
        if (!recover&&!list) Require(owner->CheckpointXid() == expected_xid, "Stale preimage XID");
        catalog::ApfsContainerCatalog catalog; std::wstring wide_error;
        Require(catalog::ApfsContainerCatalog::TryLoadDevice(owner->Device(), catalog, wide_error), "Strict image catalog failed");
        catalog::ResolvedMountVolume selected;
        Require(catalog.TryResolveVolume(container, oid, selected, error) && selected.volume_uuid_hex == volume_uuid,
            "Volume UUID/OID identity mismatch");
        std::filesystem::create_directories(journals_path);
        std::map<std::uint64_t, std::unique_ptr<rw::TransactionManager>> journals;
        std::vector<catalog::VolumeCheckpointPins> census;
        auto journal_path_for = [&](const std::string& volume_uuid, std::uint64_t object_id) {
            return journals_path / (container + "-" + volume_uuid + "-" + std::to_string(object_id) + ".wal");
        };
        for (const auto& volume : catalog.Containers().front().volumes)
        {
            auto journal = std::make_unique<rw::TransactionManager>(L"Strict");
            const auto identity = "apfs-vol:" + container + ":" + std::to_string(volume.object_id);
            const auto wide_identity = std::wstring(identity.begin(), identity.end());
            const auto path = journal_path_for(volume.volume_uuid_hex, volume.object_id);
            std::error_code journal_ec;
            const bool journal_preexisted = std::filesystem::exists(path, journal_ec) && !journal_ec;
            if (journal_preexisted)
            {
                // Existing files open strictly: no creation, no tail repair,
                // no compaction handling. Anything unusual refuses with the
                // evidence retained for its original owner.
                Require(journal->OpenExistingRepairJournal(path.wstring(), wide_identity, error), error);
            }
            else
            {
                // Fresh journals are created exclusively by this owner; the
                // currency gate below still requires a history-free image.
                // OpenExistingRepairJournal then establishes the strict lease
                // on the file this owner just created.
                HANDLE fresh = CreateFileW(path.c_str(), GENERIC_READ | GENERIC_WRITE, 0, nullptr,
                    CREATE_NEW, FILE_ATTRIBUTE_NORMAL | FILE_FLAG_OPEN_REPARSE_POINT, nullptr);
                Require(fresh != INVALID_HANDLE_VALUE, "Journal cannot be established exclusively; another owner holds it");
                CloseHandle(fresh);
                Require(journal->OpenExistingRepairJournal(std::filesystem::absolute(path).wstring(), wide_identity, error), error);
            }
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
        session.metadata_context.allow_native_snapshot_runtime = true;
        Require(owner->MountVolume(session, error), error);
        Require(owner->InitializeRequiredCheckpointCensus(census, error), error);
        const auto journal_path = journal_path_for(volume_uuid, oid).wstring();
        auto& journal = *journals.at(oid);
        if(recover){
            Require(rw::VerifySnapshotRecoveryOwner(*owner, oid, journal, journal_path, error), error);
            Require(rw::VerifySnapshotJournalCurrency(*owner, oid, journal, error), error);
            const auto result=rw::ReplaySnapshot(*owner,journal,oid,error);
            Require(!result.has_value()||*result,error);
            Require(!journal.HasUnappliedAcceptedWork(),"Other accepted work requires its original recovery owner");
            std::cout<<(result.has_value()?"Recovered":"No accepted snapshot operation")<<" xid="<<owner->CheckpointXid()<<"\n";
        } else if(list) {
            Require(!journals.at(oid)->HasUnappliedAcceptedWork(),"Recover accepted work before listing");
            class Source final:public catalog::RandomAccessSource {const rw::BlockDevice&d;public:explicit Source(const rw::BlockDevice&v):d(v){}std::uint64_t SizeBytes()const override{return d.GetGeometry().total_bytes;}bool Read(std::uint64_t o,std::size_t n,std::vector<std::byte>&b)const override{return d.Read(o,n,b)&&b.size()==n;}} source(owner->Device());
            catalog::ApfsSnapshotScope scope{0,source.SizeBytes(),container,volume_uuid,oid,owner->CheckpointXid()};
            std::vector<catalog::ApfsSnapshotInfo> snapshots;Require(catalog::ApfsSnapshotStore::Enumerate(source,scope,snapshots,error),error);
            std::cout<<"container="<<container<<" volume="<<volume_uuid<<" oid="<<oid<<" source_xid="<<scope.checkpoint_xid<<" count="<<snapshots.size()<<"\n";
            for(const auto&entry:snapshots){const auto&id=entry.identity;
                std::cout<<"source_xid="<<id.scope.checkpoint_xid<<" snapshot_xid="<<id.snapshot_xid<<" name="<<std::quoted(id.name_utf8)
                    <<" apsb="<<id.superblock_physical_block<<" omap="<<id.omap_physical_block<<" omap_tree="<<id.omap_tree_physical_block
                    <<" root_oid="<<id.root_oid<<" root_block="<<id.root_physical_block<<" extentref="<<id.extentref_physical_block<<"\n";}
        } else {
            Require(rw::VerifySnapshotMaintenanceOwner(*owner, oid, journal, journal_path, error), error);
            Require(rw::VerifySnapshotJournalCurrency(*owner, oid, journal, error), error);
            rw::SnapshotRuntimePlan plan;
            if(create){
                const std::wstring inum_text=argv[9];const auto inum=inum_text==L"0"?0:Number(argv[9]);
                Require(rw::PrepareSnapshotCreate(*owner,oid,Utf8(argv[7]),Number(argv[8]),inum,plan,error),error);
            } else {
                catalog::ApfsSnapshotIdentity id;id.scope={0,owner->Device().GetGeometry().total_bytes,container,volume_uuid,oid,expected_xid};
                id.snapshot_xid=Number(argv[7]);id.name_utf8=Utf8(argv[8]);id.superblock_physical_block=Number(argv[9]);id.omap_physical_block=Number(argv[10]);
                id.omap_tree_physical_block=Number(argv[11]);id.root_oid=Number(argv[12]);id.root_physical_block=Number(argv[13]);id.extentref_physical_block=Number(argv[14]);
                Require(rw::PrepareSnapshotDelete(*owner,id,Number(argv[15]),plan,error),error);
            }
            if (inspect)
            {
                // Admission proof only: the prepared plan is printed and
                // discarded. Nothing is staged, accepted or published.
                std::cout<<"inspect="<<(create?"create":"delete")<<" container="<<container
                    <<" volume="<<volume_uuid<<" oid="<<oid<<" source_xid="<<expected_xid
                    <<" checkpoint_xid="<<owner->CheckpointXid()
                    <<" journal="<<Utf8(journal_path.c_str())<<"\n";
                return 0;
            }
            const auto result=rw::ApplySnapshot(*owner,*journals.at(oid),plan);
            Require(result.committed&&!result.commit_recovery_required&&result.commit_status_code==static_cast<int>(rw::MetadataStore::CommitStatus::Committed),result.error);
            std::cout<<"Published xid="<<result.checkpoint_xid<<"\n";
        }
        return 0;
    }
    catch (const std::exception& error) { std::cerr << "Snapshot refused or requires recovery: " << error.what() << "\n"; return 1; }
}
