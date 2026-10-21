#pragma once
namespace
{
class RuntimeSource final : public ImmutableEncryptedReadSource
{
public:
    std::shared_ptr<Source> inner = std::make_shared<Source>();
    EncryptedRuntimeReadLimits limits;
    mutable std::uint64_t runtime_reads = 0, identity_calls = 0;
    mutable std::function<void()> identity_callback;
    std::function<void()> runtime_callback;
    bool capable = true;
    std::uint64_t SizeBytes() const override { return inner->SizeBytes(); }
    std::uint64_t Revision() const override { return inner->Revision(); }
    std::string SourceIdentity() const override
    { ++identity_calls; if (identity_callback) identity_callback(); return inner->SourceIdentity(); }
    std::shared_ptr<ApfsReadBudget> ReadBudget() const override { return inner->budget; }
    bool Read(std::uint64_t offset, std::size_t size, std::vector<std::byte>& out) const override
    { return inner->Read(offset, size, out); }
    std::optional<EncryptedRuntimeReadLimits> RuntimeReadLimits() const override
    { return capable ? std::optional{limits} : std::nullopt; }
    bool ReadRuntime(const RuntimeRead& request, std::vector<std::byte>& out) const override
    {
        out.clear();
        CHECK(request.IsFor(*this)); CHECK(!request.IsFor(*inner));
        CHECK(request.Offset() <= SizeBytes() && request.Size() <= SizeBytes() - request.Offset());
        ++runtime_reads;
        if (runtime_callback) runtime_callback();
        return inner->ReadFixture(request.Offset(), request.Size(), out);
    }
};
std::unique_ptr<ApfsEncryptedReadSession> OpenRuntime(const std::shared_ptr<RuntimeSource>& source,
    bool names = false, std::shared_ptr<const std::atomic<bool>> cancellation = {})
{
    if (names) InstallNamespace(source->inner, NamespaceRecords());
    E error; UnlockError unlock; PasswordUnlockBudget attempts;
    auto session = ApfsEncryptedReadSession::Unlock(source, source->inner->identity, source->inner->revision,
        Request(), Hex(k::Password), attempts, error, unlock, std::move(cancellation));
    CHECK(session); CHECK(error == E::None); CHECK(unlock == UnlockError::None);
    CHECK(source->runtime_reads == 0);
    return session;
}
void RuntimeRepeatedReads()
{
    ++groups;
    auto source = std::make_shared<RuntimeSource>();
    source->inner->budget = std::make_shared<ApfsReadBudget>(100000,256ULL*1024*1024,1000000,256ULL*1024*1024);
    auto session = OpenRuntime(source);
    const auto expected = Expected(4096);
    std::vector<std::byte> bytes;
    // 106,496 sector reads / 52 MiB actual ciphertext and plaintext. This
    // exceeds production's 100,000 lifetime-read ceiling using canonical data.
    for (unsigned i = 0; i < 6656; ++i)
    {
        CHECK(session->ReadFile(1000,0,8192,bytes) == E::None);
        CHECK(bytes.size() == 8192 && std::equal(bytes.begin(),bytes.end(),expected.begin()));
    }
    CHECK(source->runtime_reads == 106496); CHECK(!source->inner->budget->Failed());
    session->Close(); Released();
}
void RuntimeRepeatedMetadata()
{
    ++groups;
    auto source = std::make_shared<RuntimeSource>();
    source->inner->budget = std::make_shared<ApfsReadBudget>(100000,256ULL*1024*1024,1000000,256ULL*1024*1024);
    auto session = OpenRuntime(source,true);
    const auto reads = source->inner->reads;
    EncryptedDirectoryEntry entry;
    // > 256 MiB of charged canonical name materializations, without source I/O.
    for (unsigned i = 0; i < 40000; ++i)
    {
        CHECK(session->LookupWindows(2,L"Report.txt",entry) == E::None);
        CHECK(entry.inode_id == 100 && entry.name_utf8 == "Report.txt");
    }
    CHECK(source->inner->reads == reads); CHECK(!source->inner->budget->Failed());
    session->Close(); Released();
}
void RuntimeLimitsAndRecovery()
{
    ++groups;
    for (unsigned kind = 0; kind < 4; ++kind)
    {
        auto source = std::make_shared<RuntimeSource>();
        if (kind == 0) source->limits.reads = 1;
        if (kind == 1) source->limits.read_bytes = 512;
        if (kind == 2) source->limits.materialized_bytes = 2048;
        if (kind == 3) source->limits.materialized_bytes = 1000;
        auto session = OpenRuntime(source);
        std::vector<std::byte> bytes{std::byte{1}};
        // Kind 2 fails after one read; kind 3 fails the initial reservation.
        CHECK(session->ReadFile(1000,0,1024,bytes) == E::ResourceLimit); CHECK(bytes.empty());
        CHECK(source->runtime_reads == (kind == 3 ? 0 : 1));
        CHECK(!source->inner->budget->Failed());
        CHECK(session->ReadFile(1000,0,kind == 3 ? 0 : 1,bytes) == E::None);
        if (kind != 3) CHECK(bytes.size() == 1 && bytes[0] == Expected(4096)[0]);
        std::vector<EncryptedFileInfo> files;
        CHECK(session->ListFiles(files) == E::None && files.size() == 1);
        session->Close(); Released();
    }
    // Record and materialization refusals in cached operations do not poison
    // independent calls; even metadata on a capable source receives a budget.
    for (unsigned kind = 0; kind < 2; ++kind)
    {
        auto source = std::make_shared<RuntimeSource>();
        if (kind == 0) source->limits.records = 1;
        else source->limits.materialized_bytes = 200;
        auto session = OpenRuntime(source,true);
        std::vector<EncryptedDirectoryEntry> entries(1);
        CHECK(session->ListDirectory(2,entries) == E::ResourceLimit && entries.empty());
        EncryptedNodeInfo node;
        CHECK(session->GetMetadata(100,node) == E::None && node.inode_id == 100);
        CHECK(source->runtime_reads == 0 && !source->inner->budget->Failed());
        session->Close(); Released();
    }
    // A valid large sparse file tests the explicit output-size cap without
    // making a new ciphertext parser or inventing unencrypted data transport.
    auto source = std::make_shared<RuntimeSource>();
    auto records = NamespaceRecords();
    for (auto& record : records)
    {
        if (ReadU64LE(record.key,0) == ((3ULL<<60)|100))
        {
            rw::AppleInodeRecord inode; std::string detail;
            CHECK(rw::ApfsExtendedRecordCodec::DecodeInode(record,inode,detail));
            inode.internal_flags = rw::kAppleInodeSparseFlag;
            for (auto& field : inode.extended_fields) if (field.type == 8)
                PutU64LE(field.data,0,SecureBytes::kMaxBytes+4096);
            CHECK(rw::EncodeAppleInodeRecord(inode,record,detail));
        }
    }
    BtreeRecord hole; std::string detail;
    CHECK(rw::EncodeAppleFileExtentRecord(rw::AppleFileExtentRecord{100,4096,SecureBytes::kMaxBytes,0,0,4096},hole,detail));
    records.push_back(std::move(hole)); InstallNamespace(source->inner,std::move(records));
    auto session = OpenRuntime(source);
    std::vector<std::byte> bytes{std::byte{1}};
    CHECK(session->ReadFile(100,0,SecureBytes::kMaxBytes+1,bytes) == E::ResourceLimit && bytes.empty());
    CHECK(source->runtime_reads == 0);
    CHECK(session->ReadFile(100,4096,512,bytes) == E::None && bytes.size() == 512);
    CHECK(std::all_of(bytes.begin(),bytes.end(),[](auto b){return b == std::byte{};}));
    session->Close(); Released();
    // Legacy sources still charge the original object, including cached output.
    source = std::make_shared<RuntimeSource>(); source->capable = false;
    session = OpenRuntime(source,true);
    source->inner->budget->LimitRemainingTo(UINT64_MAX,UINT64_MAX,0,0);
    EncryptedNodeInfo node;
    CHECK(session->GetMetadata(100,node) == E::ResourceLimit);
    CHECK(source->inner->budget->Failed() && source->runtime_reads == 0);
    CHECK(session->GetMetadata(100,node) == E::ResourceLimit);
    session->Close(); Released();
    // No remaining initialization credits are needed by capable runtime calls.
    // Limits were captured at admission; later changes cannot raise or lower
    // them, and the exact original budget object remains attached and unfailed.
    source = std::make_shared<RuntimeSource>(); session = OpenRuntime(source,true);
    const auto parse_budget = source->inner->budget;
    parse_budget->LimitRemainingTo(0,0,0,0);
    source->limits = {0,0,0,0}; source->capable = false;
    CHECK(session->GetMetadata(100,node) == E::None && node.inode_id == 100);
    CHECK(session->ReadFile(100,0,512,bytes) == E::None && bytes.size() == 512);
    CHECK(source->inner->budget == parse_budget && !parse_budget->Failed());
    CHECK(!parse_budget->Read(1)); // Still zero: runtime did not refill it.
    CHECK(session->GetMetadata(100,node) == E::ResourceLimit && node.inode_id == 0);
    session->Close(); Released();
}
void RuntimeStickyBindingAndParse()
{
    ++groups;
    for (unsigned kind = 0; kind < 5; ++kind)
    {
        auto source = std::make_shared<RuntimeSource>();
        auto stop = std::make_shared<std::atomic<bool>>(false);
        auto session = OpenRuntime(source,true,stop);
        const auto budget = source->inner->budget;
        const auto identity = source->inner->identity;
        const auto revision = source->inner->revision, size = source->inner->size;
        if (kind == 0) source->inner->budget = std::make_shared<ApfsReadBudget>(100000,1ULL<<30,1000000,1ULL<<30);
        if (kind == 1) source->inner->identity += "changed";
        if (kind == 2) ++source->inner->revision;
        if (kind == 3) ++source->inner->size;
        if (kind == 4) stop->store(true);
        EncryptedNodeInfo node;
        const auto error = kind == 4 ? E::Cancelled : E::SourceIdentityMismatch;
        CHECK(session->GetMetadata(100,node) == error && node.inode_id == 0);
        source->inner->budget = budget; source->inner->identity = identity;
        source->inner->revision = revision; source->inner->size = size; stop->store(false);
        CHECK(session->GetMetadata(100,node) == error && node.inode_id == 0);
        std::vector<std::byte> bytes;
        CHECK(session->ReadFile(100,0,1,bytes) == error && bytes.empty());
        CHECK(source->runtime_reads == 0); session->Close(); Released();
    }
    // An exhausted initialization allowance cannot be reset through opt-in,
    // LimitRemainingTo, or retrying open on the same source.
    auto source = std::make_shared<RuntimeSource>();
    source->inner->budget = std::make_shared<ApfsReadBudget>(1,1ULL<<30,1000000,1ULL<<30);
    E error;
    CHECK(!ApfsEncryptedReadSession::OpenForTesting(source,Key(),error));
    CHECK(error == E::ResourceLimit && source->inner->budget->Failed());
    const auto reads = source->inner->reads;
    source->inner->budget->LimitRemainingTo(UINT64_MAX,UINT64_MAX,UINT64_MAX,UINT64_MAX);
    CHECK(!ApfsEncryptedReadSession::OpenForTesting(source,Key(),error));
    CHECK(error == E::ResourceLimit && source->inner->reads == reads && source->runtime_reads == 0);
    // An externally refused bound parse budget blocks runtime as well.
    source = std::make_shared<RuntimeSource>(); auto session = OpenRuntime(source,true);
    source->inner->budget->Refuse("runtime-test-sticky-parser"); EncryptedNamespaceInfo info;
    CHECK(session->GetNamespaceInfo(info) == E::ResourceLimit && info.root_inode_id == 0);
    CHECK(session->GetNamespaceInfo(info) == E::ResourceLimit); session->Close(); Released();
}
void RuntimeFailuresAndCleanup()
{
    ++groups;
    auto source = std::make_shared<RuntimeSource>(); auto session = OpenRuntime(source,true);
    std::vector<std::byte> bytes;
    for (int fault = 0; fault < 5; ++fault)
    {
        source->inner->fault_offset = 100ULL*4096; source->inner->fault = fault;
        CHECK(session->ReadFile(100,17,23,bytes) == (fault == 3 ? E::ResourceLimit : E::ReadFailure));
        CHECK(bytes.empty()); CHECK(!source->inner->budget->Failed()); Released();
        source->inner->fault_offset = UINT64_MAX;
        CHECK(session->ReadFile(100,17,23,bytes) == E::None && bytes.size() == 23);
    }
    // Crypto/secure allocation failure ends the operation scope too.
    for (unsigned kind = 0; kind < 3; ++kind)
    {
        testing::hooks = {};
        if (kind == 0) testing::hooks.allocation_failure_at = 0;
        if (kind == 1) testing::hooks.lock_failure_at = 0;
        if (kind == 2) { testing::hooks.cng_failure_at = 0; testing::hooks.cng_fail_after_call = true; }
        CHECK(session->ReadFile(100,17,23,bytes) != E::None && bytes.empty()); Released();
        testing::hooks = {};
        CHECK(session->ReadFile(100,17,23,bytes) == E::None); Released();
    }
    // Observe late publication exceptions after decrypted bytes are copied to
    // ordinary heap storage, then prove the next independent call succeeds.
    const auto payload = NamespacePayload();
    source->identity_calls = 0;
    CHECK(session->ReadXattr(100,"user.note",bytes) == E::None);
    const auto final_check = source->identity_calls; bytes.clear(); source->identity_calls = 0;
    source->identity_callback = [&] { if (source->identity_calls == final_check) throw std::runtime_error("runtime publication"); };
    allocation_observer::Watch watch(payload);
    CHECK(session->ReadXattr(100,"user.note",bytes) == E::ReadFailure && bytes.empty());
    const auto observed = watch.Stop();
    CHECK(observed.intact == 0 && observed.zero > 0 && observed.live == 0 && !observed.overflow);
    source->identity_callback = {};
    allocation_observer::Watch allocation(payload); allocation.FailAllocation(payload.size(),0);
    CHECK(session->ReadXattr(100,"user.note",bytes) == E::ResourceLimit && bytes.empty());
    CHECK(allocation.Failures() == 1); const auto failed = allocation.Stop();
    CHECK(failed.live == 0 && failed.intact == 0 && !failed.overflow);
    CHECK(session->ReadXattr(100,"user.note",bytes) == E::None && bytes == payload);
    // Failure after ordinary file plaintext publication allocation is wiped.
    CHECK(session->ReadFile(100,17,23,bytes) == E::None); const auto expected = bytes; bytes.clear();
    source->identity_calls = 0; CHECK(session->ReadFile(100,17,23,bytes) == E::None);
    const auto read_final = source->identity_calls; bytes.clear(); source->identity_calls = 0;
    source->identity_callback = [&] { if (source->identity_calls == read_final) throw std::runtime_error("runtime file publication"); };
    allocation_observer::Watch file_watch(expected);
    CHECK(session->ReadFile(100,17,23,bytes) == E::ReadFailure && bytes.empty());
    const auto file_observed = file_watch.Stop();
    CHECK(file_observed.intact == 0 && file_observed.zero > 0 && file_observed.live == 0 && !file_observed.overflow);
    source->identity_callback = {};
    CHECK(session->ReadFile(100,17,23,bytes) == E::None && bytes == expected);
    session->Close(); Released();
}
void RuntimePublicationAndClose()
{
    ++groups;
    // Late changes during the last publication check must refuse output, even
    // for metadata calls that never enter the transport override.
    for (unsigned operation = 0; operation < 10; ++operation)
    for (unsigned kind = 0; kind < 5; ++kind)
    {
        auto source = std::make_shared<RuntimeSource>();
        auto stop = std::make_shared<std::atomic<bool>>(false);
        auto session = OpenRuntime(source,true,stop);
        const auto invoke = [&](E expected) {
            EncryptedNamespaceInfo info; EncryptedNodeInfo node; EncryptedDirectoryEntry entry;
            std::vector<EncryptedDirectoryEntry> entries; std::vector<EncryptedXattr> attrs;
            std::vector<std::byte> bytes; std::vector<EncryptedFileInfo> files; E result = E::None;
            switch (operation)
            {
            case 0: result = session->GetNamespaceInfo(info); break;
            case 1: result = session->GetMetadata(100,node); break;
            case 2: result = session->ListDirectory(2,entries); break;
            case 3: result = session->Lookup(2,"Report.txt",entry); break;
            case 4: result = session->LookupWindows(2,L"Report.txt",entry); break;
            case 5: result = session->ResolvePath(L"\\Folder\\Other.txt",node); break;
            case 6: result = session->ListXattrs(100,attrs); break;
            case 7: result = session->ReadXattr(100,"user.note",bytes); break;
            case 8: result = session->ListFiles(files); break;
            case 9: result = session->ReadFile(100,17,23,bytes); break;
            }
            CHECK(result == expected);
            if (expected != E::None) CHECK(info.root_inode_id == 0 && node.inode_id == 0 && entry.inode_id == 0 &&
                entries.empty() && attrs.empty() && bytes.empty() && files.empty());
        };
        source->identity_calls = 0; invoke(E::None); const auto final_check = source->identity_calls;
        source->identity_calls = 0;
        source->identity_callback = [&] {
            if (source->identity_calls != final_check) return;
            if (kind == 0) stop->store(true);
            if (kind == 1) ++source->inner->revision;
            if (kind == 2) ++source->inner->size;
            if (kind == 3) source->inner->budget = std::make_shared<ApfsReadBudget>(100000,1ULL<<30,1000000,1ULL<<30);
            if (kind == 4) source->inner->budget->Refuse("runtime-final-parser-refusal");
        };
        const auto error = kind == 0 ? E::Cancelled : kind == 4 ? E::ResourceLimit : E::SourceIdentityMismatch;
        invoke(error); source->identity_callback = {}; stop->store(false); invoke(error);
        session->Close(); invoke(E::Closed); Released();
    }
    // Hold a real runtime ciphertext read while Close cancels and drains it.
    auto source = std::make_shared<RuntimeSource>(); auto session = OpenRuntime(source);
    std::mutex mutex; std::condition_variable cv; bool entered = false, release = false;
    std::atomic<bool> closing = false, closed = false; E result = E::None; std::vector<std::byte> bytes;
    source->runtime_callback = [&] {
        std::unique_lock lock(mutex); entered = true; cv.notify_all(); cv.wait(lock,[&]{return release;});
    };
    std::thread reader([&]{ result = session->ReadFile(1000,0,1024,bytes); });
    { std::unique_lock lock(mutex); cv.wait(lock,[&]{return entered;}); }
    session->Cancel(); std::thread closer([&]{closing = true; session->Close(); closed = true;});
    while (!closing.load()) std::this_thread::yield();
    const bool drained_early = closed.load();
    { std::lock_guard lock(mutex); release = true; } cv.notify_all();
    reader.join(); closer.join();
    CHECK(!drained_early && closed.load()); CHECK(result == E::Cancelled && bytes.empty());
    CHECK(source->runtime_reads == 1);
    CHECK(session->ReadFile(1000,0,1,bytes) == E::Closed && bytes.empty());
    std::weak_ptr<RuntimeSource> weak = source; source.reset(); CHECK(weak.expired()); Released();
}
}
