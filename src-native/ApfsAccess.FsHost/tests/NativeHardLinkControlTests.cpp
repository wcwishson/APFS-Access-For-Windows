#include <cstdlib>
#include <new>
thread_local long hardlink_allocation_after = -1;
thread_local unsigned hardlink_allocation_count = 0;
void* operator new(std::size_t bytes)
{
    if (hardlink_allocation_after >= 0) {
        ++hardlink_allocation_count;
        if (hardlink_allocation_after-- == 0) throw std::bad_alloc();
    }
    if (void* value = std::malloc(bytes ? bytes : 1)) return value;
    throw std::bad_alloc();
}
void* operator new[](std::size_t bytes) { return ::operator new(bytes); }
void operator delete(void* value) noexcept { std::free(value); }
void operator delete[](void* value) noexcept { std::free(value); }
void operator delete(void* value, std::size_t) noexcept { std::free(value); }
void operator delete[](void* value, std::size_t) noexcept { std::free(value); }
#define APFSACCESS_FSHOST_UNIT_TEST 1
#include "../src/main.cpp"
#include "TestFixtureBuilder.h"
#include "NativeHardLinkPlan.h"

namespace
{
unsigned hardlink_checks = 0;
void CheckHardLink(bool value, const char* message)
{
    ++hardlink_checks;
    if (!value) throw std::runtime_error(message);
}

std::vector<std::byte> ReadFileBytes(const std::filesystem::path& path)
{
    std::ifstream input(path, std::ios::binary | std::ios::ate);
    if (!input) return {};
    const auto size = input.tellg();
    CheckHardLink(size >= 0 && size <= 8 * 1024 * 1024, "bounded regular evidence file");
    std::vector<std::byte> bytes(static_cast<std::size_t>(size)); input.seekg(0);
    input.read(reinterpret_cast<char*>(bytes.data()), bytes.size());
    CheckHardLink(!!input, "read regular evidence file"); return bytes;
}
bool WriteFileBytes(const std::filesystem::path& path, const std::vector<std::byte>& bytes)
{
    if (std::filesystem::exists(path)) return false;
    std::ofstream output(path, std::ios::binary);
    output.write(reinterpret_cast<const char*>(bytes.data()), bytes.size()); return !!output;
}

struct HardLinkHostEvidence
{
    struct Image { std::filesystem::path path; } image;
    std::unique_ptr<MountContext> context = std::make_unique<MountContext>();
    apfsaccess::rw::MetadataStore::VolumeContext volume;
    HardLinkHostEvidence()
    {
        static unsigned counter = 0;
        image.path = std::filesystem::current_path() / ("case-" + std::to_string(counter++) + ".apfs");
    }
};

struct HardLinkHostFixture
{
    HardLinkHostEvidence fixture;
    FSP_FILE_SYSTEM fs{};
    std::vector<PVOID> opens;
    std::vector<std::byte> original = std::vector<std::byte>(4096, std::byte{0x5d});

    explicit HardLinkHostFixture(bool enroll = true, std::uint64_t block_count = 1024)
    {
        using namespace apfsaccess::rw;
        apfsaccess::testfixture::BuilderStore builder;
        builder.volumes.front().projectable = true; builder.volumes.front().name = "Alpha";
        builder.spaceman_oid = 8; builder.spaceman_block = 60; builder.block_count = block_count;
        builder.authoritative_checkpoint = true; builder.dual_checkpoint = false; builder.xid = 20;
        builder.authoritative_internal_pool_blocks = 16; builder.authoritative_checkpoint_ring_blocks = 32;
        auto& volume = builder.volumes.front(); volume.incompat = 0; volume.next_object_id = 1000;
        volume.additional_file_system_allocated_blocks = 1;
        auto& rows = volume.filesystem_records; rows.clear(); volume.extentref_records.clear();
        apfsaccess::catalog::BtreeRecord encoded; std::string error;
        const auto add = [&](bool ok) { CheckHardLink(ok, "encode real hard-link host fixture"); rows.push_back(encoded); };
        AppleInodeRecord root; root.object_id = root.private_id = root.parent_id = 2;
        root.mode = 0040755; root.children_or_links = 1;
        add(EncodeAppleInodeRecord(root, encoded, error));
        AppleInodeRecord inode; inode.object_id = inode.private_id = 17; inode.parent_id = 2;
        inode.mode = 0100644; inode.children_or_links = 1;
        AppleExtendedField stream; stream.type = 8; stream.data.resize(40);
        apfsaccess::testfixture::PutU64LE(stream.data, 0, original.size());
        apfsaccess::testfixture::PutU64LE(stream.data, 8, original.size()); inode.extended_fields.push_back(stream);
        add(EncodeAppleInodeRecord(inode, encoded, error));
        add(EncodeAppleDirectoryRecord({2, 17, 0, 8, "source", {}}, encoded, error));
        add(EncodeAppleDataStreamIdRecord({17, 1}, encoded, error));
        add(EncodeAppleFileExtentRecord({17, 0, 4096, 128, 0, 4096}, encoded, error));
        CheckHardLink(EncodeApplePhysicalExtentRecord({128, 1, kApplePhysicalExtentKindNew, 17, 1}, encoded, error),
            "encode real hard-link extent owner");
        volume.extentref_records.push_back(encoded);
        CheckHardLink(SortAppleBtreeRecords(rows, AppleBtreeKeyOrder::FileSystemCaseSensitive, error), "sort real host fixture");
        builder.authoritative_seeded_main_blocks.push_back({128, original});
        CheckHardLink(WriteFileBytes(fixture.image.path, apfsaccess::testfixture::BuildStoreImage(builder)), "write fresh owned image");
        auto& c = *fixture.context;
        fixture.volume.device_path = fixture.image.path.wstring(); fixture.volume.volume_object_id = 101;
        fixture.volume.allow_legacy_scaffold_for_fixtures = false;
        c.args.device = fixture.image.path.wstring(); c.args.volume = L"Alpha"; c.args.volume_object_id = 101;
        c.args.readwrite = true; c.args.readonly = false; c.args.write_backend = L"Native";
        c.args.allow_legacy_scaffold_for_fixtures = false; c.args.incompatible_features = 0;
        c.args.write_max_dirty_transactions = 1; c.native_write_enabled = true;
        c.session_root = fixture.image.path; c.session_root += L".session"; c.cache_root = c.session_root / "hydrate";
        CheckHardLink(std::filesystem::create_directories(c.cache_root), "create fresh private cache root");
        c.recovery_marker_file = c.session_root / "recovery.marker";
        auto root_node = std::make_shared<Node>(); SetNodePath(*root_node, L"\\");
        root_node->hydration_key = root_node->path_key; root_node->is_directory = root_node->loaded = true;
        root_node->node_kind = NodeKind::Directory; root_node->timestamp = UtcNow();
        c.nodes.emplace(Key(&c, root_node->path), root_node);
        auto lease = BlockDevice::OpenExclusiveManagementImage(fixture.image.path.wstring(), 0, error);
        CheckHardLink(!!lease, "hold exclusive ordinary image owner");
        c.owned_metadata_store = std::make_unique<MetadataStore>(fixture.volume, lease);
        c.metadata_store = c.owned_metadata_store.get();
        CheckHardLink(c.metadata_store->PrepareNativeWritePath(), "prepare held ordinary image");
        const auto* checkpoint = c.metadata_store->AuthoritativeAppleCheckpointView();
        CheckHardLink(checkpoint != nullptr, "held owner checkpoint");
        const auto identity = Utf8ToWide("apfs-vol:" + checkpoint->container.superblock.uuid_hex + ":101");
        c.tx_manager = std::make_unique<TransactionManager>(L"Strict");
        CheckHardLink(c.tx_manager->OpenStartupJournal((c.session_root / "accepted.wal").wstring(), identity, error) &&
            (std::filesystem::exists(c.session_root / "accepted.wal") || c.tx_manager->MaterializeAbsentStartupJournal(error)) &&
            (!enroll || c.tx_manager->EnrollCanonicalJournalIdentity(identity)),
            "enroll actual original identity");
        c.payload_spool_volume_identity = "hardlink-control";
        c.payload_spool = std::make_unique<PayloadSpool>(PayloadSpool::Options{
            c.session_root / "payload-spool", c.payload_spool_volume_identity, 1024 * 1024});
        c.metadata_store->SetFilePayloadRangeProvider([&c](const auto& path, auto identity, auto offset, auto destination) {
            return ReadHydratedPayloadRangeForPath(&c, path, identity, offset, destination);
        });
        CheckHardLink(MergeCommittedInodeStateIntoNodeIndex(&c), "merge exact held-owner namespace");
        fs.UserContext = &c;
    }

    PVOID Open(const wchar_t* path, UINT32 access, bool directory = false)
    {
        PVOID result = nullptr; FSP_FSCTL_FILE_INFO info{};
        CheckHardLink(CB_Open(&fs, const_cast<PWSTR>(path), directory ? FILE_DIRECTORY_FILE : FILE_OPEN << 24,
            access, &result, &info) == STATUS_SUCCESS && result, "open actual host context");
        opens.push_back(result); return result;
    }
    NTSTATUS Export(PVOID source, apfsaccess::fshost::hardlink_control::ExportReply& reply)
    {
        using namespace apfsaccess::fshost::hardlink_control;
        ExportRequest request; ULONG done = 999;
        const auto result = ContainerServeInterface().Control(&fs, source, apfsaccess::fshost::hardlink_control::Export,
            &request, sizeof(request), &reply, sizeof(reply), &done);
        CheckHardLink(NT_SUCCESS(result) ? done == sizeof(reply) : done == 0, "exact export transfer");
        return result;
    }
    NTSTATUS Import(PVOID directory, const apfsaccess::fshost::hardlink_control::ExportReply& ticket,
        std::wstring_view leaf, apfsaccess::fshost::hardlink_control::ImportReply& reply)
    {
        using namespace apfsaccess::fshost::hardlink_control;
        ImportRequest request; request.ticket = ticket.ticket; request.leaf_chars = static_cast<std::uint32_t>(leaf.size());
        for (std::size_t i = 0; i < leaf.size() && i < request.leaf.size(); ++i) request.leaf[i] = leaf[i];
        ULONG done = 999;
        const auto result = ContainerServeInterface().Control(&fs, directory, apfsaccess::fshost::hardlink_control::Import,
            &request, sizeof(request), &reply, sizeof(reply), &done);
        CheckHardLink(NT_SUCCESS(result) ? done == sizeof(reply) : done == 0, "exact import transfer");
        return result;
    }
    void CloseAll()
    {
        for (auto context : opens) if (context) CB_Close(&fs, context);
        opens.clear(); StopDeferredCommitWorker(fixture.context.get());
    }
    void ReopenOwner(bool reset_namespace, bool enroll = true)
    {
        using namespace apfsaccess::rw;
        auto& c = *fixture.context;
        if (reset_namespace) {
            CloseAll(); c.nodes.clear(); c.shared_payload_owners.clear();
            c.hardlink_tickets.clear(); c.hardlink_live_opens.clear();
        }
        c.metadata_store = nullptr; c.owned_metadata_store.reset();
        std::string error;
        auto lease = BlockDevice::OpenExclusiveManagementImage(fixture.image.path.wstring(), 0, error);
        CheckHardLink(!!lease, "fresh exclusive host image owner");
        c.owned_metadata_store = std::make_unique<MetadataStore>(fixture.volume, lease);
        c.metadata_store = c.owned_metadata_store.get();
        CheckHardLink(c.metadata_store->PrepareNativeWritePath(), "fresh canonical host owner");
        c.metadata_store->SetFilePayloadRangeProvider([&c](const auto& path, auto identity, auto offset, auto destination) {
            return ReadHydratedPayloadRangeForPath(&c, path, identity, offset, destination);
        });
        if (reset_namespace) {
            const auto identity = c.tx_manager->ConfiguredVolumeIdentity();
            const auto canonical = c.tx_manager->EnrolledCanonicalJournalIdentity();
            c.tx_manager.reset(); c.tx_manager = std::make_unique<TransactionManager>(L"Strict");
            CheckHardLink(c.tx_manager->OpenStartupJournal((c.session_root / "accepted.wal").wstring(), identity, error) &&
                (!enroll || c.tx_manager->EnrollCanonicalJournalIdentity(canonical)), "fresh authenticated original history");
            CheckHardLink(MergeCommittedInodeStateIntoNodeIndex(&c), "fresh full alias namespace");
        }
        InvalidatePayloadIdentityCache(&c);
    }
    ~HardLinkHostFixture()
    {
        CloseAll();
    }
};

void HardLinkControlRefusals()
{
    using namespace apfsaccess::fshost::hardlink_control;
    HardLinkHostFixture f; auto& c = *f.fixture.context;
    const auto source = f.Open(L"\\source", FILE_READ_DATA);
    const auto execute = f.Open(L"\\source", FILE_EXECUTE);
    const auto directory = f.Open(L"\\", FILE_ADD_FILE, true);
    const auto denied = f.Open(L"\\", FILE_READ_ATTRIBUTES, true);
    const auto before = ReadFileBytes(f.fixture.image.path);
    ExportReply ticket, wrong;
    CheckHardLink(f.Export(execute, wrong) == STATUS_ACCESS_DENIED, "execute-only cannot export read authority");
    CheckHardLink(f.Export(source, ticket) == STATUS_SUCCESS, "retained source read handle exports ticket");
    CheckHardLink(f.Export(source, wrong) == STATUS_SUCCESS && wrong.ticket == ticket.ticket && c.hardlink_tickets.size() == 1,
        "repeat export retains one bounded ticket");
    ImportReply reply;
    CheckHardLink(f.Import(denied, ticket, L"alias", reply) == STATUS_ACCESS_DENIED, "directory requires add-file rights");
    wrong = ticket; wrong.ticket[0] ^= 1;
    CheckHardLink(f.Import(directory, wrong, L"alias", reply) == STATUS_INVALID_HANDLE, "foreign random ticket refuses");
    for (auto leaf : {L"", L".", L"..", L"a/b", L"a\\b", L"a:b", L"bad.", L"CON"})
        CheckHardLink(!NT_SUCCESS(f.Import(directory, ticket, leaf, reply)), "invalid leaf refuses");
    CheckHardLink(f.Import(directory, ticket, L"source", reply) == STATUS_OBJECT_NAME_COLLISION, "no replacement authority");
    CheckHardLink(ReadFileBytes(f.fixture.image.path) == before && !c.tx_manager->HasUnappliedAcceptedWork() &&
        c.tx_manager->Watermarks().accepted_sequence == 0, "all controls preserve original and image before acceptance");
    RevokeNativeHardLinkAuthority(static_cast<OpenContext*>(source));
    CheckHardLink(f.Import(directory, ticket, L"alias", reply) == STATUS_INVALID_HANDLE, "revoked source ticket refuses");
    CheckHardLink(f.Export(source, wrong) == STATUS_INVALID_HANDLE, "closed source authority cannot renew");
}

void HardLinkControlCache(bool warm, std::uint64_t block_count = 1024)
{
    using namespace apfsaccess::fshost::hardlink_control;
    HardLinkHostFixture f(true, block_count); auto& c = *f.fixture.context;
    const auto source = f.Open(L"\\source", FILE_READ_DATA | FILE_WRITE_DATA);
    const auto retained = f.Open(L"\\source", FILE_READ_DATA);
    const auto directory = f.Open(L"\\", FILE_ADD_FILE, true);
    auto* source_open = static_cast<OpenContext*>(source);
    auto* retained_open = static_cast<OpenContext*>(retained);
    if (warm) {
        CheckHardLink(EnsurePayloadHandleReadyForMutation(&c, source_open) == STATUS_SUCCESS &&
            EnsurePayloadHandleReadyForMutation(&c, retained_open) == STATUS_SUCCESS, "materialize both original cache handles");
    }
    const auto old_source_file = source_open->file.load(), old_retained_file = retained_open->file.load();
    const auto old_node = source_open->node;
    ExportReply ticket; ImportReply reply;
    CheckHardLink(f.Export(source, ticket) == STATUS_SUCCESS, "source exports actual owner tuple");
    CheckHardLink(f.Import(directory, ticket, L"alias", reply) == STATUS_SUCCESS && reply.object_id == 17 && reply.links == 2,
        "real dispatcher accepts and durably publishes first alias");
    CheckHardLink(source_open->node == old_node && source_open->file.load() == old_source_file &&
        retained_open->file.load() == old_retained_file && old_node->shared_payload, "publication preserves open node and cache handles");
    CheckHardLink(f.Import(directory, ticket, L"again", reply) == STATUS_INVALID_HANDLE, "accepted ticket cannot replay");
    const auto alias = f.Open(L"\\alias", FILE_READ_DATA | FILE_WRITE_DATA);
    auto* alias_open = static_cast<OpenContext*>(alias);
    CheckHardLink(alias_open->node->shared_payload == old_node->shared_payload, "all open aliases share one payload owner");
    CheckHardLink(EnsurePayloadHandleReadyForMutation(&c, alias_open) == STATUS_SUCCESS, "cold or warm alias gets same inode cache");
    std::array<std::byte, 32> read{}; ULONG done = 0;
    CheckHardLink(CB_Read(&f.fs, retained, read.data(), 0, static_cast<ULONG>(read.size()), &done) == STATUS_SUCCESS &&
        done == read.size() && std::all_of(read.begin(), read.end(), [](auto value) { return value == std::byte{0x5d}; }),
        "retained source handle reads exact original after promotion");
    const std::array<std::byte, 4> bytes{std::byte{1}, std::byte{2}, std::byte{3}, std::byte{4}};
    FSP_FSCTL_FILE_INFO info{}; done = 0;
    CheckHardLink(CB_Write(&f.fs, alias, const_cast<std::byte*>(bytes.data()), 7, static_cast<ULONG>(bytes.size()), false, false,
        &done, &info) == STATUS_SUCCESS && done == bytes.size(), "write through new alias commits same inode");
    CheckHardLink(DrainNativeMutationsByPolicy(&c, L"HardLinkTest", false, true) == STATUS_SUCCESS &&
        FinalizeMutationJournalBestEffort(&c, L"HardLinkTest"), "alias write reaches clean durable completion");
    done = 0;
    CheckHardLink(CB_Read(&f.fs, retained, read.data(), 0, static_cast<ULONG>(read.size()), &done) == STATUS_SUCCESS &&
        done == read.size() && std::equal(bytes.begin(), bytes.end(), read.begin() + 7), "old retained handle observes alias write");
    ExportReply third;
    CheckHardLink(f.Export(alias, third) == STATUS_SUCCESS && f.Import(directory, third, L"third", reply) == STATUS_SUCCESS &&
        reply.links == 3 && reply.object_id == 17, "actual later-alias dispatcher preserves shared inode");
    CheckHardLink(!c.tx_manager->HasUnappliedAcceptedWork() && c.tx_manager->RecoveryStateValid(), "all helper and write originals settled");
    f.ReopenOwner(true);
    const auto reopened = f.Open(L"\\third", FILE_READ_DATA | FILE_WRITE_DATA);
    done = 0;
    const auto status = CB_Write(&f.fs, reopened, const_cast<std::byte*>(bytes.data()), 19,
        static_cast<ULONG>(bytes.size()), false, false, &done, &info);
    if (status != STATUS_SUCCESS) std::cerr << "fresh alias write status=" << std::hex << status << std::dec << '\n';
    CheckHardLink(status == STATUS_SUCCESS && done == bytes.size(), "fresh owner alias write reuses or hydrates inode cache");
    CheckHardLink(DrainNativeMutationsByPolicy(&c, L"HardLinkFreshTest", false, true) == STATUS_SUCCESS &&
        FinalizeMutationJournalBestEffort(&c, L"HardLinkFreshTest"), "fresh alias write settles actual original");
    const auto fresh_source = f.Open(L"\\source", FILE_READ_DATA); done = 0;
    CheckHardLink(CB_Read(&f.fs, fresh_source, read.data(), 0, static_cast<ULONG>(read.size()), &done) == STATUS_SUCCESS &&
        done == read.size() && std::equal(bytes.begin(), bytes.end(), read.begin() + 7) &&
        std::equal(bytes.begin(), bytes.end(), read.begin() + 19), "fresh aliases retain both exact writes");
}

void HardLinkNamespaceAllocationCuts()
{
    using namespace apfsaccess::fshost::hardlink_control;
    HardLinkHostFixture f; auto& c = *f.fixture.context;
    const auto source = f.Open(L"\\source", FILE_READ_DATA);
    const auto directory = f.Open(L"\\", FILE_ADD_FILE, true);
    const auto retained = static_cast<OpenContext*>(source)->node;
    ExportReply ticket; ImportReply reply;
    CheckHardLink(f.Export(source, ticket) == STATUS_SUCCESS, "allocation cut source exports");
    const auto prior_children = TryGetNodeLockedNormalized(&c, L"\\")->children;
    g_hardlink_namespace_allocation_scope = [](bool entering) { hardlink_allocation_after = entering ? 0 : -1; };
    const auto status = f.Import(directory, ticket, L"alias", reply);
    g_hardlink_namespace_allocation_scope = {};
    CheckHardLink(!NT_SUCCESS(status) && c.tx_manager->HasUnappliedAcceptedWork() &&
        !TryGetNodeLockedNormalized(&c, L"\\alias") && retained == TryGetNodeLockedNormalized(&c, L"\\source"),
        "real post-image namespace allocation cut retains old namespace and accepted debt");
    const auto post_image = ReadFileBytes(f.fixture.image.path);
    f.ReopenOwner(false);
    const auto owner = retained->shared_payload;
    const auto prior_size = owner->file_size;
    const auto prior_generation = owner->visible_generation;
    unsigned failures = 0; bool complete = false;
    for (unsigned site = 0; site < 512; ++site) {
        g_hardlink_namespace_allocation_scope = [site](bool entering) {
            hardlink_allocation_after = entering ? static_cast<long>(site) : -1;
            if (entering) hardlink_allocation_count = 0;
        };
        bool published = false;
        try {
            std::lock_guard commit(c.commit_mutex); std::unique_lock reads(c.committed_read_gate);
            published = PublishNativeHardLinkNamespace(c, L"\\alias", 17, retained);
        } catch (const std::bad_alloc&) {}
        g_hardlink_namespace_allocation_scope = {}; hardlink_allocation_after = -1;
        if (published) { complete = true; break; }
        ++failures;
        CheckHardLink(!TryGetNodeLockedNormalized(&c, L"\\alias") && c.nodes.size() == 2 &&
            TryGetNodeLockedNormalized(&c, L"\\")->children == prior_children &&
            retained == TryGetNodeLockedNormalized(&c, L"\\source") && retained->shared_payload == owner &&
            owner->file_size == prior_size && owner->visible_generation == prior_generation && owner->aliases.size() == 1 &&
            c.tx_manager->HasUnappliedAcceptedWork(), "every failed namespace allocation preserves visible nodes/owner and original debt");
    }
    CheckHardLink(complete && failures > 20, "bounded census exercises every allocating namespace stage");
    CheckHardLink(ReadFileBytes(f.fixture.image.path) == post_image, "namespace allocation retries write no APFS bytes");
    const auto replay = ReplayIsolatedNativeHardLink(c);
    CheckHardLink(replay && *replay && !c.tx_manager->HasUnappliedAcceptedWork() && !c.write_degraded,
        "dedicated original replay verifies publication and completes namespace/fences");
    CheckHardLink(retained == TryGetNodeLockedNormalized(&c, L"\\source") &&
        TryGetNodeLockedNormalized(&c, L"\\alias")->shared_payload == owner, "replay keeps exact open node/cache owner");
    std::cout << "PASS namespace allocation cuts " << failures << " sites\n";
}

void HardLinkControlPublicationCuts()
{
    using namespace apfsaccess::fshost::hardlink_control;
    for (const auto cut : {"before-apple-checkpoint-switch", "before-apple-final-flush"}) {
        HardLinkHostFixture f; auto& c = *f.fixture.context;
        const auto source = f.Open(L"\\source", FILE_READ_DATA);
        const auto directory = f.Open(L"\\", FILE_ADD_FILE, true);
        const auto retained = static_cast<OpenContext*>(source)->node;
        ExportReply ticket; ImportReply reply;
        CheckHardLink(f.Export(source, ticket) == STATUS_SUCCESS, "publication cut exports source");
        c.metadata_store->SetCommitStageHook([&](std::string_view stage) { return stage != cut; });
        CheckHardLink(!NT_SUCCESS(f.Import(directory, ticket, L"alias", reply)) &&
            c.tx_manager->HasUnappliedAcceptedWork() && !TryGetNodeLockedNormalized(&c, L"\\alias"),
            "actual Control publication cut preserves accepted original and unpublished name");
        f.ReopenOwner(false);
        const auto replay = ReplayIsolatedNativeHardLink(c);
        CheckHardLink(replay && *replay && !c.tx_manager->HasUnappliedAcceptedWork() &&
            c.tx_manager->RecoveryStateValid() && !c.write_degraded, "fresh owner dedicated full-proof replay settles cut");
        const auto added = TryGetNodeLockedNormalized(&c, L"\\alias");
        CheckHardLink(added && added->object_id == 17 && retained == TryGetNodeLockedNormalized(&c, L"\\source") &&
            retained->shared_payload == added->shared_payload, "fresh replay preserves retained source and exact shared alias");
    }
}

void HardLinkCanonicalEnrollment()
{
    using namespace apfsaccess::fshost::hardlink_control;
    {
        HardLinkHostFixture f(false); auto& c = *f.fixture.context;
        const auto configured = c.tx_manager->ConfiguredVolumeIdentity();
        CheckHardLink(c.tx_manager->EnrolledCanonicalJournalIdentity().empty(), "direct owner begins without manifest enrollment");
        const auto source = f.Open(L"\\source", FILE_READ_DATA);
        const auto directory = f.Open(L"\\", FILE_ADD_FILE, true);
        ExportReply ticket; ImportReply reply;
        CheckHardLink(f.Export(source, ticket) == STATUS_SUCCESS &&
            c.tx_manager->EnrolledCanonicalJournalIdentity() == L"apfs-vol:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa:101" &&
            c.tx_manager->ConfiguredVolumeIdentity() == configured, "held direct owner enrolls canonical identity without changing configured original");
        c.metadata_store->SetCommitStageHook([](std::string_view stage) { return stage != "before-apple-final-flush"; });
        CheckHardLink(!NT_SUCCESS(f.Import(directory, ticket, L"alias", reply)) && c.tx_manager->HasUnappliedAcceptedWork(),
            "real post-switch cut retains complete original acceptance");
        f.ReopenOwner(true, false);
        CheckHardLink(c.tx_manager->EnrolledCanonicalJournalIdentity().empty(), "fresh direct replay owner starts unenrolled");
        const auto replay = ReplayIsolatedNativeHardLink(c);
        if (!replay || !*replay) std::cerr << "fresh unenrolled replay: " << c.hardlink_last_error << '\n';
        CheckHardLink(replay && *replay && !c.tx_manager->HasUnappliedAcceptedWork() &&
            c.tx_manager->ConfiguredVolumeIdentity() == configured &&
            TryGetNodeLockedNormalized(&c, L"\\alias")->object_id == 17,
            "dedicated fresh original replay enrolls held owner and completes exact postimage");
    }
    {
        HardLinkHostFixture f(false); auto& c = *f.fixture.context;
        CheckHardLink(c.tx_manager->EnrollCanonicalJournalIdentity(L"apfs-vol:bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb:101"),
            "install foreign enrollment control");
        const auto source = f.Open(L"\\source", FILE_READ_DATA);
        const auto before = ReadFileBytes(f.fixture.image.path);
        const auto original = ReadFileBytes(c.session_root / "accepted.wal");
        ExportReply ticket;
        CheckHardLink(!NT_SUCCESS(f.Export(source, ticket)) && !c.tx_manager->HasUnappliedAcceptedWork() &&
            ReadFileBytes(f.fixture.image.path) == before && ReadFileBytes(c.session_root / "accepted.wal") == original,
            "foreign canonical enrollment refuses without acceptance or image writes");
    }
    std::cout << "PASS direct canonical enrollment and original replay\n";
}

void HardLinkInlineAttributeAdmission()
{
    using namespace apfsaccess::rw;
    PSECURITY_DESCRIPTOR descriptor = nullptr;
    CheckHardLink(ConvertStringSecurityDescriptorToSecurityDescriptorW(L"O:SYG:SYD:P(A;;FA;;;SY)(A;;FR;;;WD)",
        SDDL_REVISION_1, &descriptor, nullptr) != FALSE, "Windows creates bounded descriptor");
    ScopeExit release{[&] { LocalFree(descriptor); }};
    std::vector<std::byte> security;
    CheckHardLink(EncodeWindowsSecurity(descriptor, security) == STATUS_SUCCESS, "existing security encoder produces source attribute");
    std::string error;
    std::vector<apfsaccess::catalog::BtreeRecord> base;
    apfsaccess::catalog::BtreeRecord encoded;
    AppleInodeRecord root; root.object_id = root.private_id = root.parent_id = 2; root.mode = 0040755; root.children_or_links = 1;
    CheckHardLink(EncodeAppleInodeRecord(root, encoded, error), "encode attribute census root"); base.push_back(encoded);
    AppleInodeRecord inode; inode.object_id = inode.private_id = 17; inode.parent_id = 2; inode.mode = 0100644; inode.children_or_links = 1;
    CheckHardLink(EncodeAppleInodeRecord(inode, encoded, error), "encode attribute census inode"); base.push_back(encoded);
    CheckHardLink(EncodeAppleDirectoryRecord({2, 17, 0, 8, "source", {}}, encoded, error), "encode attribute census name"); base.push_back(encoded);
    const auto attribute = [&](const char* name, const std::vector<std::byte>& data) {
        apfsaccess::catalog::BtreeRecord row;
        CheckHardLink(EncodeAppleXattrRecord({17, name, kAppleXattrDataEmbedded, data}, row, error), "canonical inline attribute encoder");
        return row;
    };
    base.push_back(attribute(kWindowsSecurityName, security));
    const auto dos_array = EncodeWindowsAttributes(FILE_ATTRIBUTE_HIDDEN | FILE_ATTRIBUTE_ARCHIVE);
    base.push_back(attribute(kWindowsAttributesName, {dos_array.begin(), dos_array.end()}));
    base.push_back(attribute("user.exact", {std::byte{0}, std::byte{0xff}, std::byte{0x71}}));
    const NativeHardLinkRequest request{17, 2, 1000, 1, "alias"};
    NativeHardLinkPlan plan;
    CheckHardLink(PrepareNativeHardLinkPlan(base, {}, request, plan, error), "complete inline attribute census is admitted");
    for (const auto& row : base) if ((apfsaccess::catalog::ReadU64LE(row.key, 0).value_or(0) >> 60) == 4)
        CheckHardLink(std::count_if(plan.after.begin(), plan.after.end(), [&](const auto& next) {
            return row.key == next.key && row.value == next.value;
        }) == 1, "every exact source attribute key and value survives metadata-only plan");
    for (unsigned control = 0; control != 16; ++control) {
        auto rows = base;
        auto& sd = rows[3]; auto& attributes = rows[4];
        switch (control) {
        case 0: sd.value[4] = std::byte{'X'}; break;
        case 1: sd.value[7] = std::byte{2}; break;
        case 2: sd.value[8] = std::byte{0}; break;
        case 3: sd.value[10] = sd.value[11] = std::byte{0}; break;
        case 4: apfsaccess::testfixture::PutU32LE(sd.value, 12, UINT32_MAX); break;
        case 5: sd.value.pop_back(); break;
        case 6: sd.value[0] = std::byte{3}; break;
        case 7: sd.value[0] = std::byte{1}; break;
        case 8: rows.push_back(sd); break;
        case 9: attributes.value[7] = std::byte{2}; break;
        case 10: attributes.value[9] = std::byte{0x80}; break;
        case 11: rows.push_back(attribute("com.apfsaccess.windows.symlink-kind", {})); break;
        case 12: rows.push_back(attribute(kAppleSecurityName, {})); break;
        case 13: rows.push_back(attribute("com.apple.ResourceFork", {})); break;
        case 14: {
            std::vector<std::byte> stream(kAppleXattrDataStreamBytes);
            apfsaccess::testfixture::PutU64LE(stream, 0, 201);
            CheckHardLink(EncodeAppleXattrRecord({17, "user.external", kAppleXattrDataStream, stream}, encoded, error),
                "canonical well-framed external attribute control");
            AppleXattrRecord external;
            CheckHardLink(ApfsExtendedRecordCodec::DecodeXattr(encoded, external, error), "existing parser accepts external framing");
            rows.push_back(encoded); break;
        }
        case 15: sd.value[0] |= std::byte{4}; break;
        }
        const auto before = rows;
        CheckHardLink(!PrepareNativeHardLinkPlan(rows, {}, request, plan, error) && plan.before.empty() && plan.after.empty(),
            "malformed or unsupported inline/out-of-line census refuses without a usable plan");
        CheckHardLink(rows.size() == before.size() && std::equal(rows.begin(), rows.end(), before.begin(),
            [](const auto& a, const auto& b) { return a.key == b.key && a.value == b.value; }), "refusal preserves original attribute evidence");
    }
    std::cout << "PASS inline security/attribute admission controls\n";
}

void HardLinkSharedSecurityExecutor()
{
    using namespace apfsaccess::rw;
    for (const auto cut : {"", "before-apple-checkpoint-switch", "before-apple-final-flush", "retention-existing", "retention-collision"}) {
        HardLinkHostFixture f(true, 512); auto& c = *f.fixture.context;
        PSECURITY_DESCRIPTOR descriptor = nullptr;
        CheckHardLink(ConvertStringSecurityDescriptorToSecurityDescriptorW(L"O:SYG:SYD:P(A;;FA;;;SY)(A;;FR;;;WD)",
            SDDL_REVISION_1, &descriptor, nullptr) != FALSE, "create actual Windows source descriptor");
        ScopeExit release{[&] { LocalFree(descriptor); }};
        std::vector<std::byte> security;
        CheckHardLink(EncodeWindowsSecurity(descriptor, security) == STATUS_SUCCESS, "encode actual source security bytes");
        PVOID created = nullptr; FSP_FSCTL_FILE_INFO info{};
        const auto created_status = CB_Create(&f.fs, const_cast<PWSTR>(L"\\secured"), FILE_NON_DIRECTORY_FILE | (FILE_CREATE << 24),
            FILE_READ_DATA | FILE_WRITE_DATA | READ_CONTROL, FILE_ATTRIBUTE_HIDDEN, descriptor, 0, &created, &info);
        if (created_status != STATUS_SUCCESS) std::cerr << "secure create status=" << std::hex << created_status << std::dec << '\n';
        CheckHardLink(created_status == STATUS_SUCCESS && created, "actual CB_Create persists normal Windows source security");
        f.opens.push_back(created);
        std::array<std::byte, 71> payload{};
        for (unsigned i = 0; i < payload.size(); ++i) payload[i] = std::byte(i * 3);
        ULONG done = 0;
        CheckHardLink(CB_Write(&f.fs, created, payload.data(), 0, static_cast<ULONG>(payload.size()), false, false, &done, &info) ==
            STATUS_SUCCESS && done == payload.size(), "write actual protected-metadata source data");
        CheckHardLink(DrainNativeMutationsByPolicy(&c, L"HardLinkSecurityTest", false, true) == STATUS_SUCCESS &&
            FinalizeMutationJournalBestEffort(&c, L"HardLinkSecurityTest"), "complete real create/write original history");
        const auto source = f.Open(L"\\secured", FILE_READ_ATTRIBUTES | READ_CONTROL);
        const auto directory = f.Open(L"\\", FILE_ADD_FILE, true);
        auto* source_open = static_cast<OpenContext*>(source);
        auto* parent_open = static_cast<OpenContext*>(directory);
        CheckHardLink(!(source_open->granted_access & FILE_READ_DATA), "shared executor receives real open with no source READ_DATA");
        apfsaccess::fshost::hardlink_control::ExportReply ticket;
        CheckHardLink(f.Export(source, ticket) == STATUS_ACCESS_DENIED, "private export still requires READ_DATA");
        const auto image_before = ReadFileBytes(f.fixture.image.path);
        const auto wal_before = ReadFileBytes(c.session_root / "accepted.wal");
        CheckHardLink(f.Export(created, ticket) == STATUS_NOT_SUPPORTED && ReadFileBytes(f.fixture.image.path) == image_before &&
            ReadFileBytes(c.session_root / "accepted.wal") == wal_before, "private ancestry policy remains strict without acceptance");
        NativeHardLinkOpenEntry source_entry, parent_entry;
        {
            std::lock_guard metadata(c.metadata_mutex);
            CheckHardLink(CaptureNativeHardLinkOpenEntry(*c.metadata_store, L"\\secured", source_entry) &&
                CaptureNativeHardLinkOpenEntry(*c.metadata_store, L"\\", parent_entry), "capture actual opaque source and parent identities");
        }
        const auto old_security = c.metadata_store->LookupCommittedExtendedAttribute(source_entry.object_id, kWindowsSecurityName);
        const auto old_attributes = c.metadata_store->LookupCommittedExtendedAttribute(source_entry.object_id, kWindowsAttributesName);
        CheckHardLink(old_security && old_security->flags == 2 && old_security->data == security && old_attributes,
            "actual Windows security and source metadata attributes are committed");
        NativeHardLinkExecutionResult result;
        auto wrong = source_entry; ++wrong.generation;
        CheckHardLink(ExecuteNativeHardLink(c, source_open->node, wrong, parent_open->node, parent_entry, L"linked", result) ==
            STATUS_INVALID_HANDLE && !result.acceptance_observed && ReadFileBytes(f.fixture.image.path) == image_before &&
            ReadFileBytes(c.session_root / "accepted.wal") == wal_before, "stale captured authority refuses before original or image changes");
        c.metadata_store->SetCommitStageHook([&](std::string_view stage) { return stage != cut; });
        CheckHardLink(ExecuteNativeHardLink(c, source_open->node, source_entry, parent_open->node, parent_entry, L"linked", result) ==
            STATUS_NOT_SUPPORTED && !result.acceptance_observed && c.hardlink_last_error == "HardLinkStaleCacheHasOpenHandles" &&
            ReadFileBytes(f.fixture.image.path) == image_before && ReadFileBytes(c.session_root / "accepted.wal") == wal_before,
            "stale materialized handle refuses without weakening cache or accepting an original");
        const auto stale_path = HydrationPath(&c, *source_open->node);
        CB_Close(&f.fs, created);
        for (auto& open : f.opens) if (open == created) open = nullptr;
        {
            std::lock_guard metadata(c.metadata_mutex);
            CheckHardLink(CaptureNativeHardLinkOpenEntry(*c.metadata_store, L"\\secured", source_entry) &&
                CaptureNativeHardLinkOpenEntry(*c.metadata_store, L"\\", parent_entry), "recapture exact entries after source close");
        }
        const auto quarantine = std::filesystem::path(stale_path.wstring() + L".hardlink-stale." +
            std::to_wstring(source_entry.object_id) + L"." + std::to_wstring(source_entry.generation));
        bool retain_expected = false;
        std::vector<std::byte> stale_bytes;
        const std::vector<std::byte> foreign{std::byte{0x7a}, std::byte{0x31}};
        if (std::string_view(cut).starts_with("retention-")) g_hardlink_cache_preparation_hook = [&] {
            // Finalization may evict the old sidecar. Inject at the exact later
            // preparation boundary, without changing any original/APFS bytes.
            if (!std::filesystem::exists(stale_path))
                CheckHardLink(WriteFileBytes(stale_path, {std::byte{0xde}, std::byte{0xad}, std::byte{0x71}}),
                    "inject unknown stale sidecar at real cache preparation boundary");
            std::lock_guard names(c.mutex);
            c.stale_hydration_keys.insert(HydrationStateKey(&c, *source_open->node));
            stale_bytes = ReadFileBytes(stale_path); retain_expected = true;
            if (std::string_view(cut) == "retention-collision")
                CheckHardLink(WriteFileBytes(quarantine, foreign), "create retained-name collision control");
        };
        ScopeExit clear_cache_hook{[] { g_hardlink_cache_preparation_hook = {}; }};
        const auto status = ExecuteNativeHardLink(c, source_open->node, source_entry, parent_open->node, parent_entry, L"linked", result);
        g_hardlink_cache_preparation_hook = {};
        if (!NT_SUCCESS(status)) std::cerr << "shared mode=" << cut << " status=" << std::hex << status << std::dec << " reason=" << c.hardlink_last_error << '\n';
        if (std::string_view(cut) == "retention-collision") {
            CheckHardLink(status == STATUS_NOT_SUPPORTED && !result.acceptance_observed &&
                ReadFileBytes(quarantine) == foreign && ReadFileBytes(stale_path) == stale_bytes &&
                ReadFileBytes(f.fixture.image.path) == image_before && ReadFileBytes(c.session_root / "accepted.wal") == wal_before,
                "no-replace collision preserves both cache files and refuses before original/image mutation");
            continue;
        }
        if (retain_expected) CheckHardLink(std::filesystem::exists(quarantine) && ReadFileBytes(quarantine) == stale_bytes,
            "cold promotion preserves exact stale cache evidence separately from canonical payload");
        if (std::string_view(cut).starts_with("before-")) {
            CheckHardLink(!NT_SUCCESS(status) && result.acceptance_observed && !result.object_id &&
                c.tx_manager->HasUnappliedAcceptedWork(), "shared executor cut retains accepted original and no completion receipt");
            f.ReopenOwner(false);
            const auto replay = ReplayIsolatedNativeHardLink(c);
            CheckHardLink(replay && *replay && !c.tx_manager->HasUnappliedAcceptedWork(), "fresh held owner replays exact security-bearing original");
        } else {
            if (status != STATUS_SUCCESS) std::cerr << "shared hardlink: " << c.hardlink_last_error << '\n';
            CheckHardLink(status == STATUS_SUCCESS && result.object_id == source_entry.object_id && result.links == 2 &&
                result.accepted_sequence && result.checkpoint_xid, "shared executor reaches original/publication/cache/marker completion");
        }
        f.ReopenOwner(true);
        const auto reopened = f.Open(L"\\linked", FILE_READ_DATA | READ_CONTROL);
        const auto inode = c.metadata_store->LookupCommittedInodeByPath(L"\\linked");
        const auto sd = c.metadata_store->LookupCommittedExtendedAttribute(source_entry.object_id, kWindowsSecurityName);
        const auto attributes = c.metadata_store->LookupCommittedExtendedAttribute(source_entry.object_id, kWindowsAttributesName);
        CheckHardLink(inode && inode->object_id == source_entry.object_id && inode->link_count == 2 && sd && attributes &&
            sd->flags == old_security->flags && sd->data == old_security->data &&
            attributes->flags == old_attributes->flags && attributes->data == old_attributes->data,
            "fresh owner preserves exact source SD/metadata and inode/link identity");
        std::array<std::byte, 3804> actual_sd{}; SIZE_T sd_size = actual_sd.size();
        CheckHardLink(CB_GetSecurity(&f.fs, reopened, actual_sd.data(), &sd_size) == STATUS_SUCCESS && sd_size == security.size() - 4 &&
            std::equal(security.begin() + 4, security.end(), actual_sd.begin()), "fresh security callback returns exact original descriptor");
        std::array<std::byte, 71> actual{}; done = 0;
        CheckHardLink(CB_Read(&f.fs, reopened, actual.data(), 0, static_cast<ULONG>(actual.size()), &done) == STATUS_SUCCESS &&
            done == actual.size() && actual == payload, "fresh-owner linked data is exact");
    }
    std::cout << "PASS shared executor actual Windows source metadata and both publication cuts\n";
}

void HardLinkInFlightOpenControl()
{
    HardLinkHostFixture f(true, 512); auto& c = *f.fixture.context;
    const auto source = f.Open(L"\\source", FILE_READ_ATTRIBUTES);
    const auto directory = f.Open(L"\\", FILE_ADD_FILE, true);
    const auto node = static_cast<OpenContext*>(source)->node;
    const auto parent = static_cast<OpenContext*>(directory)->node;
    CheckHardLink(EnsureHydrated(&c, node), "materialize canonical cache before real open boundary");
    apfsaccess::rw::NativeHardLinkOpenEntry entry, destination;
    CheckHardLink(CaptureNativeHardLinkOpenEntry(*c.metadata_store, node->path, entry) &&
        CaptureNativeHardLinkOpenEntry(*c.metadata_store, parent->path, destination), "capture source for concurrent open boundary");
    const auto before = ReadFileBytes(f.fixture.image.path);
    const auto wal = ReadFileBytes(c.session_root / "accepted.wal");
    bool observed = false;
    g_hardlink_before_open_accounting = [&](OpenContext* opening) {
        CheckHardLink(opening && opening->node == node && opening->file != INVALID_HANDLE_VALUE &&
            c.hardlink_payload_opens_inflight.load() != 0 && !c.hardlink_live_opens.contains(opening),
            "actual cache handle exists before its open census registration");
        NativeHardLinkExecutionResult result;
        CheckHardLink(ExecuteNativeHardLink(c, node, entry, parent, destination, L"during-open", result) == STATUS_NOT_SUPPORTED &&
            c.hardlink_last_error == "HardLinkCacheOpenInFlight" && !result.acceptance_observed && !node->shared_payload &&
            ReadFileBytes(f.fixture.image.path) == before && ReadFileBytes(c.session_root / "accepted.wal") == wal,
            "in-flight real handle prevents cache promotion/original acceptance before census");
        observed = true;
    };
    ScopeExit clear{[] { g_hardlink_before_open_accounting = {}; }};
    const auto reader = f.Open(L"\\source", FILE_READ_DATA);
    g_hardlink_before_open_accounting = {};
    CheckHardLink(observed && !c.hardlink_payload_opens_inflight.load(), "real open publishes census before clearing in-flight barrier");
    const auto handle = static_cast<OpenContext*>(reader)->file.load();
    NativeHardLinkExecutionResult result;
    CheckHardLink(ExecuteNativeHardLink(c, node, entry, parent, destination, L"after-open", result) == STATUS_SUCCESS &&
        result.object_id == 17 && static_cast<OpenContext*>(reader)->file.load() == handle,
        "registered warm handle survives the subsequent shared publication");
    std::array<std::byte, 32> bytes{}; ULONG done = 0;
    CheckHardLink(CB_Read(&f.fs, reader, bytes.data(), 0, static_cast<ULONG>(bytes.size()), &done) == STATUS_SUCCESS &&
        done == bytes.size() && std::all_of(bytes.begin(), bytes.end(), [](auto value) { return value == std::byte{0x5d}; }),
        "same actual pre-publication handle reads exact canonical data afterward");
    std::cout << "PASS actual in-flight payload open and census barrier\n";
}
}

int main(int argc, char** argv)
{
    try {
        CheckHardLink(argc == 2 || (argc == 3 && (std::string_view(argv[2]) == "--fixture100" ||
            std::string_view(argv[2]) == "--enrollment" || std::string_view(argv[2]) == "--shared")), "fresh absolute evidence root required");
        const auto root = std::filesystem::path(argv[1]);
        CheckHardLink(root.is_absolute() && root.wstring().starts_with(L"D:\\") && !std::filesystem::exists(root), "fresh D root required");
        for (auto at = root.parent_path(); !at.empty(); at = at.parent_path()) {
            const auto attributes = GetFileAttributesW(at.c_str());
            CheckHardLink(attributes == INVALID_FILE_ATTRIBUTES || !(attributes & FILE_ATTRIBUTE_REPARSE_POINT), "no reparse evidence parent");
            if (at == at.root_path()) break;
        }
        CheckHardLink(std::filesystem::create_directories(root), "create fresh private evidence root");
        SetEnvironmentVariableW(L"TEMP", root.c_str()); SetEnvironmentVariableW(L"TMP", root.c_str());
        std::filesystem::current_path(root);
        if (argc == 3 && std::string_view(argv[2]) == "--shared") {
            HardLinkInlineAttributeAdmission(); HardLinkSharedSecurityExecutor();
            HardLinkInFlightOpenControl();
            HardLinkControlCache(false, 512); HardLinkControlCache(true, 512);
            std::cout << "PASS shared hard-link/security " << hardlink_checks << " checks\n"; return 0;
        }
        if (argc == 3 && std::string_view(argv[2]) == "--enrollment") {
            HardLinkCanonicalEnrollment();
            std::cout << "PASS direct canonical enrollment " << hardlink_checks << " checks\n"; return 0;
        }
        if (argc == 3) {
            HardLinkHostFixture fixture; auto& store = *fixture.fixture.context->metadata_store;
            for (unsigned i = 1; i < 100; ++i) {
                apfsaccess::rw::MetadataStore::MutationRequest create;
                create.operation = apfsaccess::rw::MetadataStore::MutationOperation::CreateFile;
                create.path = L"\\empty-" + std::to_wstring(i); create.offset = 0644;
                CheckHardLink(store.StageMutation(create) == apfsaccess::rw::MetadataStore::MutationStatus::Applied,
                    "stage bounded fixture-only empty inode");
            }
            CheckHardLink(store.CommitPendingMutations() == apfsaccess::rw::MetadataStore::CommitStatus::Committed &&
                store.PrepareNativeWritePath(), "canonical 100-file fixture publication");
            const auto root_inode = store.LookupCommittedInodeByPath(L"\\");
            CheckHardLink(root_inode.has_value(), "canonical fixture root identity");
            const auto children = store.SnapshotCommittedDirectoryChildInodes(root_inode->object_id);
            CheckHardLink(children && children->size() == 100 && !store.PendingMutationCount(), "exact canonical fixture census");
            const auto* view = store.AuthoritativeAppleCheckpointView();
            CheckHardLink(view != nullptr, "fixture authoritative identity");
            std::ofstream output("fixture.json");
            output << "{\"scope\":\"synthetic ordinary input factory, no original acceptance claim\",\"files\":100,\"volumeOid\":101,\"checkpoint\":"
                << store.CheckpointXid().value_or(0) << ",\"containerUuid\":\"" << view->container.superblock.uuid_hex
                << "\",\"volumeUuid\":\"" << view->volumes.front().superblock.uuid_hex << "\",\"image\":\"case-0.apfs\"}";
            CheckHardLink(!!output, "write fixture identity receipt");
            std::cout << "PASS canonical 100-file input factory " << hardlink_checks << " checks\n"; return 0;
        }
        HardLinkControlRefusals(); HardLinkControlCache(false); HardLinkControlCache(true);
        HardLinkNamespaceAllocationCuts(); HardLinkControlPublicationCuts(); HardLinkCanonicalEnrollment();
        std::cout << "PASS actual hard-link Control/cache " << hardlink_checks << " checks\n";
        return 0;
    } catch (const std::exception& error) {
        std::cerr << "FAIL hard-link Control " << error.what() << '\n'; return 1;
    }
}
