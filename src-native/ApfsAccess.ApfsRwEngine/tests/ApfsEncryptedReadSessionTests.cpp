#include "ApfsEncryptedReadSession.h"
#include "ApfsEncryptedReadVectors.h"
#include "ApfsKeybagUnlockVectors.h"
#include "ApfsCryptoTestHooks.h"
#include "TestFixtureBuilder.h"
#include <algorithm>
#include <atomic>
#include <condition_variable>
#include <functional>
#include <iostream>
#include <mutex>
#include <stdexcept>
#include <thread>
#include "EncryptedReadAllocationObserver.h"

using namespace apfsaccess::catalog;
using namespace apfsaccess::crypto;
using namespace apfsaccess::testfixture;
namespace f = apfsaccess::encrypted_fixture;
namespace k = apfsaccess::keybag_fixture;
using E = EncryptedReadError;
namespace
{
unsigned checks = 0, groups = 0;
#define CHECK(x) do { ++checks; if (!(x)) throw std::runtime_error("check failed at line " + std::to_string(__LINE__)); } while(false)
std::vector<std::byte> Hex(std::string_view s) { return HexToBytes(std::string(s)); }
KeybagUuid Uuid(std::string_view text)
{
    KeybagUuid uuid{}; const auto bytes = Hex(text); std::copy(bytes.begin(), bytes.end(), uuid.begin()); return uuid;
}
PasswordUnlockRequest Request()
{
    PasswordUnlockRequest r;
    r.checkpoint_xid = 7; r.volume_oid = 101;
    r.container_uuid = Uuid(k::ContainerUuid); r.volume_uuid = Uuid(k::VolumeUuid); r.user_uuid = Uuid(k::UserUuid);
    r.container_bag = {901, 7}; r.volume_bag = {902, 7}; r.length = KeybagLength::IncludesHeader;
    return r;
}
PasswordUnlockResult Key(bool legacy = false)
{
    PasswordUnlockBudget budget;
    auto decoded = DecodePasswordKeyRecords(Hex(legacy ? k::Class2Vek : k::Vek), Hex(k::Kek), Hex(k::Password), budget);
    CHECK(decoded);
    PasswordUnlockResult result;
    result.error = UnlockError::None; result.xts_key = std::move(decoded.xts_key);
    result.container_uuid = Uuid(k::ContainerUuid); result.volume_uuid = Uuid(k::VolumeUuid);
    result.checkpoint_xid = 7; result.volume_oid = 101; result.volume_xid = 7;
    return result;
}
class Source final : public ImmutableEncryptedReadSource
{
public:
    std::uint32_t bs;
    std::uint64_t root_block, size, revision = 521;
    std::string identity = "public-fixture-521";
    std::shared_ptr<ApfsReadBudget> budget;
    std::vector<std::byte> image, root, child, data, last;
    mutable std::uint64_t reads = 0;
    mutable std::function<void(std::uint64_t)> before;
    std::uint64_t fault_offset = UINT64_MAX;
    int fault = -1;
    explicit Source(unsigned profile = 0, std::uint64_t allowance = 100000)
        : bs(profile == 1 ? 65536 : 4096), root_block(profile == 2 ? 0x100000050ULL : 80),
          size((profile == 2 ? root_block + 128 : 128) * bs),
          budget(std::make_shared<ApfsReadBudget>(allowance, 1024ULL*1024*1024, 1000000, 1024ULL*1024*1024))
    {
        BuilderStore spec;
        spec.authoritative_checkpoint = true; spec.block_count = 128; spec.block_size = bs;
        spec.uuid_hex = std::string(k::ContainerUuid); spec.volumes[0].uuid_hex = std::string(k::VolumeUuid);
        spec.volumes[0].fs_flags = kFsFlagOneKey;
        image = BuildStoreImage(spec);
        for (std::size_t offset = 0; offset + bs <= image.size(); offset += bs)
        {
            if (ReadU32LE(image, offset + 32) != kNxsbMagic) continue;
            MutateAt(offset / bs, [&](auto& block) {
                PutU32LE(block, 24, kObjectEphemeral | kNxSuperblockObjectType);
                PutU64LE(block, 40, size / bs); PutU64LE(block, 0x510, 60); PutU64LE(block, 0x518, 1);
            });
        }
        const auto volume_map = ReadU64LE(image, 4ULL * bs + 0x80).value();
        const auto tree = ReadU64LE(image, volume_map * bs + 48).value();
        const auto omap = BuildBtreeNode({OmapRecordSpec{8293, root_block, 4, 7}, OmapRecordSpec{9000, root_block+1, 4, 7}},
            7, bs, 0, tree, 0x40000002, 11);
        std::copy(omap.begin(), omap.end(), image.begin() + tree * bs);
        root = Hex(profile == 1 ? f::LargeRoot : profile == 2 ? f::HighRoot : f::SmallRoot);
        child = Hex(profile == 1 ? f::LargeChild : profile == 2 ? f::HighChild : f::SmallChild);
        data = Hex(profile == 1 ? f::LargeData : profile == 2 ? f::HighData : f::SmallData);
        last = Hex(profile == 1 ? f::LargeLast : profile == 2 ? f::HighLast : f::SmallLast);
        if (!profile)
        {
            const auto container = Hex(k::ContainerCipher), volume = Hex(k::VolumeCipher);
            std::copy(container.begin(), container.end(), image.begin() + 60 * bs);
            std::copy(volume.begin(), volume.end(), image.begin() + 61 * bs);
        }
    }
    void MutateAt(std::uint64_t block_index, const std::function<void(std::vector<std::byte>&)>& change)
    {
        const auto offset = block_index * bs;
        std::vector<std::byte> block(image.begin()+offset, image.begin()+offset+bs);
        change(block); (void)FletcherForBlock(block, bs);
        std::copy(block.begin(), block.end(), image.begin()+offset);
    }
    std::uint64_t SizeBytes() const override { return size; }
    std::uint64_t Revision() const override { return revision; }
    std::string SourceIdentity() const override { return identity; }
    std::shared_ptr<ApfsReadBudget> ReadBudget() const override { return budget; }
    bool Read(std::uint64_t offset, std::size_t count, std::vector<std::byte>& out) const override
    {
        out.clear();
        if (!budget->Read(count)) return false;
        return ReadFixture(offset, count, out);
    }
    bool ReadFixture(std::uint64_t offset, std::size_t count, std::vector<std::byte>& out) const
    {
        ++reads;
        if (before) before(offset);
        if (offset == fault_offset)
        {
            out.assign(count+1, std::byte{0x55});
            if (fault == 0) { out.resize(count-1); return true; }
            if (fault == 1) return true;
            if (fault == 2) return false;
            if (fault == 3) throw std::bad_alloc();
            throw std::runtime_error("public source fault");
        }
        for (const auto& part : {std::pair{root_block*bs, &root}, { (root_block+1)*bs, &child },
                {100ULL*bs, &data}, {104ULL*bs, &last}})
        {
            if (offset >= part.first && offset-part.first < part.second->size())
            {
                const auto relative = offset-part.first;
                if (count > part.second->size()-relative) return false;
                out.assign(part.second->begin()+relative, part.second->begin()+relative+count); return true;
            }
        }
        if (offset > image.size() || count > image.size()-offset) return false;
        out.assign(image.begin()+offset, image.begin()+offset+count); return true;
    }
};
std::vector<std::byte> Expected(std::uint32_t bs)
{
    std::vector<std::byte> bytes(4ULL*bs-137);
    for (std::size_t i = 0; i < 2ULL*bs; ++i) bytes[i] = static_cast<std::byte>((i*29+i/251+17)%256);
    for (std::size_t i = 0; i < bs-137; ++i) bytes[3ULL*bs+i] = static_cast<std::byte>((i*13+i/71+83)%256);
    return bytes;
}
std::unique_ptr<ApfsEncryptedReadSession> Open(std::shared_ptr<Source> source, E& error, bool legacy = false)
{
    return ApfsEncryptedReadSession::OpenForTesting(std::move(source), Key(legacy), error);
}
void Released()
{
    CHECK(testing::hooks.all_released_bytes_zero);
    CHECK(testing::hooks.wipes == testing::hooks.releases);
}
void ReadsAndBinding()
{
    ++groups;
    for (unsigned profile = 0; profile < 3; ++profile)
    {
        auto source = std::make_shared<Source>(profile); E error;
        auto session = Open(source, error, profile == 1); if(!session) throw std::runtime_error("profile " + std::to_string(profile) + " open error " + std::to_string(static_cast<int>(error))); CHECK(session); CHECK(error == E::None);
        std::vector<EncryptedFileInfo> files;
        CHECK(session->ListFiles(files) == E::None); CHECK(files.size() == 1);
        CHECK(files[0].inode_id == 1000); CHECK(files[0].default_crypto_id == 0x999);
        const auto expected = Expected(source->bs);
        for (auto [offset, count] : std::vector<std::pair<std::size_t,std::size_t>>{
                {0,(std::min)(expected.size(),std::size_t{65536})}, {17,711}, {500,1100}, {source->bs-5,1029},
                {2ULL*source->bs-47,source->bs+153}, {expected.size()-99,99}, {expected.size(),0}})
        {
            std::vector<std::byte> out{std::byte{0x55}};
            const auto read_error = session->ReadFile(1000,offset,count,out); if(read_error != E::None) throw std::runtime_error("profile " + std::to_string(profile) + " read size " + std::to_string(count) + " error " + std::to_string(static_cast<int>(read_error))); CHECK(read_error == E::None);
            CHECK(std::equal(out.begin(),out.end(),expected.begin()+offset,expected.begin()+offset+count));
        }
        std::vector<std::byte> out;
        for (std::size_t offset=0; offset<expected.size(); offset+=32768)
        {
            const auto count=(std::min)(std::size_t{32768},expected.size()-offset);
            CHECK(session->ReadFile(1000,offset,count,out)==E::None);
            CHECK(std::equal(out.begin(),out.end(),expected.begin()+offset,expected.begin()+offset+count));
        }
        const auto reads = source->reads;
        CHECK(session->ReadFile(1000,2ULL*source->bs+33,777,out) == E::None);
        CHECK(source->reads == reads); CHECK(std::all_of(out.begin(),out.end(),[](auto b){return b==std::byte{};}));
        CHECK(session->ReadFile(1000,expected.size()-1,2,out) == E::InvalidArgument); CHECK(out.empty());
        CHECK(session->ReadFile(1000,UINT64_MAX,1,out) == E::InvalidArgument); CHECK(out.empty());
        CHECK(session->ReadFile(999,0,1,out) == E::FileNotFound);
        ++source->revision;
        CHECK(session->ReadFile(1000,0,1,out) == E::SourceIdentityMismatch); CHECK(out.empty());
        --source->revision; source->identity += "changed";
        CHECK(session->ReadFile(1000,0,1,out) == E::SourceIdentityMismatch);
        session->Close(); session->Close();
        CHECK(session->ReadFile(1000,0,1,out) == E::Closed); CHECK(out.empty());
        Released();
    }
    // The production entry point owns one source across actual keybag unlock and
    // encrypted root/child projection; the public fixture password is compiled only.
    auto source = std::make_shared<Source>(); E error; UnlockError unlock;
    PasswordUnlockBudget attempts;
    auto session = ApfsEncryptedReadSession::Unlock(source,source->identity,source->revision,
        Request(),Hex(k::Password),attempts,error,unlock);
    CHECK(session); CHECK(error == E::None); CHECK(unlock == UnlockError::None);
    std::vector<std::byte> bytes;
    CHECK(session->ReadFile(1000,509,521,bytes) == E::None);
    const auto expected = Expected(4096);
    CHECK(std::equal(bytes.begin(),bytes.end(),expected.begin()+509,expected.begin()+1030));
    session->Close(); Released();
}
void MetadataRefusals()
{
    ++groups;
    for (auto bad : {f::WrongOid,f::WrongXid,f::ZeroXid,f::UnknownType,f::NoHeader,f::UnknownNode,f::WrongSubtype,
            f::ZeroCrypto,f::OverflowCrypto,f::OutOfOrder,f::DuplicateKey})
    {
        auto source = std::make_shared<Source>(); source->child = Hex(bad); E error;
        CHECK(!Open(source,error)); CHECK(error != E::None); Released();
    }
    for (unsigned what = 0; what < 18; ++what)
    {
        auto source = std::make_shared<Source>(); E error;
        if (what == 0) source->root[77] ^= std::byte{1};
        if (what == 1) source->child[99] ^= std::byte{1};
        if (what >= 2 && what <= 6)
        {
            const auto map = ReadU64LE(source->image,4ULL*4096+0x80).value();
            const auto tree = ReadU64LE(source->image,map*4096+48).value();
            source->MutateAt(tree,[&](auto& b){
                // first root mapping value starts 16 bytes before root footer
                PutU32LE(b,b.size()-40-16,what==2?8u:what==3?16u:what==4?0x24u:what==5?0u:1u);
            });
        }
        if (what >= 7 && what <= 12) source->MutateAt(4,[&](auto& b){
            if(what==7) PutU64LE(b,8,102);
            if(what==8) PutU64LE(b,16,6);
            if(what==9) b[0xf0] ^= std::byte{1};
            if(what==10) PutU64LE(b,0x108,0);
            if(what==11) PutU64LE(b,0x38,0x1000);
            if(what==12) PutU64LE(b,0x30,1);
        });
        if (what == 13) source->MutateAt(2,[](auto& b){PutU64LE(b,16,0);});
        if (what == 14) source->MutateAt(3,[](auto& b){PutU16LE(b,32,0x43);});
        if (what == 15) source->MutateAt(3,[](auto& b){PutU32LE(b,24,0x50000002);});
        if (what == 16) source->MutateAt(3,[](auto& b){PutU64LE(b,16,0);});
        if (what == 17) source->MutateAt(3,[](auto& b){PutU32LE(b,24,0x60000002);});
        CHECK(!Open(source,error)); CHECK(error != E::None); Released();
    }
    for(unsigned what=0;what<5;++what)
    {
        auto source=std::make_shared<Source>(); auto key=Key(); E error;
        if(what==0) key.xts_key.Bytes()[0]^=std::byte{1};
        if(what==1) ++key.checkpoint_xid;
        if(what==2) ++key.volume_xid;
        if(what==3) key.container_uuid[0]^=std::byte{1};
        if(what==4) ++key.volume_oid;
        CHECK(!ApfsEncryptedReadSession::OpenForTesting(source,std::move(key),error)); Released();
    }
}
void BudgetAndSourceFailures()
{
    ++groups;
    bool reached = false;
    for (std::uint64_t limit=0; limit<100; ++limit)
    {
        auto source=std::make_shared<Source>(0,limit); E error;
        auto session=Open(source,error);
        if(session) { reached=true; break; }
        CHECK(error==E::ResourceLimit); CHECK(source->budget->Failed()); Released();
    }
    CHECK(reached);
    for(std::uint64_t cutoff=0;cutoff<3;++cutoff)
    {
        auto probe=std::make_shared<Source>(); E error;auto opened=Open(probe,error);CHECK(opened);
        const auto initialization_reads=probe->reads;opened->Close();
        auto source=std::make_shared<Source>(0,initialization_reads+cutoff);auto session=Open(source,error);CHECK(session);
        std::vector<std::byte> bytes{std::byte{1}};
        const auto result=session->ReadFile(1000,0,1024,bytes);
        CHECK(result==(cutoff<2?E::ResourceLimit:E::None));
        if(cutoff<2) {CHECK(bytes.empty());CHECK(source->budget->Failed());}
        session->Close();Released();
    }
    for(std::uint64_t materialization:{0ULL,100ULL,1000ULL})
    {
        auto source=std::make_shared<Source>();E error;
        source->budget=std::make_shared<ApfsReadBudget>(1000,1024*1024,10000,materialization);
        CHECK(!Open(source,error));CHECK(error==E::ResourceLimit);CHECK(source->budget->Failed());Released();
    }
    for (auto offset : {80ULL*4096,81ULL*4096,100ULL*4096,100ULL*4096+512})
    for (int fault=0;fault<5;++fault)
    {
        auto source=std::make_shared<Source>(); E error;
        if(offset<100ULL*4096)
        {
            source->fault_offset=offset; source->fault=fault;
            CHECK(!Open(source,error)); CHECK(error==(fault==3?E::ResourceLimit:E::ReadFailure));
        }
        else
        {
            auto session=Open(source,error); CHECK(session);
            source->fault_offset=offset; source->fault=fault;
            std::vector<std::byte> out{std::byte{1}};
            CHECK(session->ReadFile(1000,17,1024,out)==(fault==3?E::ResourceLimit:E::ReadFailure));
            CHECK(out.empty()); session->Close();
        }
        Released();
    }
    auto source=std::make_shared<Source>(); E error; auto session=Open(source,error); CHECK(session);
    source->budget->Refuse("public-test-cutoff");
    std::vector<std::byte> out{std::byte{1}};
    CHECK(session->ReadFile(1000,0,5,out)==E::ResourceLimit); CHECK(out.empty());
    CHECK(session->ReadFile(1000,0,5,out)==E::ResourceLimit); session->Close(); Released();
}
void CryptoFailures()
{
    ++groups;
    auto source=std::make_shared<Source>(); E error; auto session=Open(source,error); CHECK(session);
    testing::hooks={};
    std::vector<std::byte> out;
    CHECK(session->ReadFile(1000,17,23,out)==E::None);
    const auto baseline=testing::hooks;
    for(int kind=0;kind<4;++kind)
    {
        const auto count=kind==0?baseline.allocations:kind==1?baseline.locks:baseline.cng_calls;
        for(int i=0;i<count;++i)
        {
            testing::hooks={};
            if(kind==0) testing::hooks.allocation_failure_at=i;
            else if(kind==1) testing::hooks.lock_failure_at=i;
            else {testing::hooks.cng_failure_at=i;testing::hooks.cng_fail_after_call=kind==3;}
            CHECK(session->ReadFile(1000,17,23,out)!=E::None); CHECK(out.empty()); Released();
        }
    }
    testing::hooks={}; session->Close(); Released();
    // Every secure allocation/lock along metadata loading, after a VEK already
    // exists. This isolates session cleanup from the separately tested KDF.
    source=std::make_shared<Source>(); auto key=Key(); testing::hooks={};
    session=ApfsEncryptedReadSession::OpenForTesting(source,std::move(key),error); CHECK(session);
    const auto metadata=testing::hooks; session->Close();
    for(int kind=0;kind<2;++kind)
    for(int i=0;i<(kind==0?metadata.allocations:metadata.locks);++i)
    {
        testing::hooks={}; source=std::make_shared<Source>(); key=Key(); testing::hooks={};
        if(kind==0) testing::hooks.allocation_failure_at=i; else testing::hooks.lock_failure_at=i;
        CHECK(!ApfsEncryptedReadSession::OpenForTesting(source,std::move(key),error));
        CHECK(error==E::ResourceLimit); Released();
    }
    testing::hooks={};
    // Provider failures at the beginning/end of both metadata objects, both
    // before CNG and after it has produced output. Per-sector exhaustive cases
    // above exercise the same transform's every provider call.
    for(bool after:{false,true})
    for(int point:{0,metadata.cng_calls/2,metadata.cng_calls-1})
    {
        source=std::make_shared<Source>();key=Key();testing::hooks={};
        testing::hooks.cng_failure_at=point;testing::hooks.cng_fail_after_call=after;
        CHECK(!ApfsEncryptedReadSession::OpenForTesting(source,std::move(key),error));
        CHECK(error==E::CryptoFailure);Released();testing::hooks={};
    }

}
void LifecycleAndUnauthenticatedData()
{
    ++groups;
    for(const auto offset:{UINT64_MAX,80ULL*4096,81ULL*4096})
    {
        auto source=std::make_shared<Source>();auto stop=std::make_shared<std::atomic<bool>>(offset==UINT64_MAX);
        source->before=[&,stop](auto at){if(at==offset) stop->store(true);};E error;
        CHECK(!ApfsEncryptedReadSession::OpenForTesting(source,Key(),error,stop));CHECK(error==E::Cancelled);Released();
    }
    auto source=std::make_shared<Source>(); E error; auto session=Open(source,error); CHECK(session);
    std::vector<std::byte> out;
    source->data[7]^=std::byte{1};
    CHECK(session->ReadFile(1000,0,512,out)==E::None);
    auto expected=Expected(4096); CHECK(!std::equal(out.begin(),out.end(),expected.begin()));
    source->data[7]^=std::byte{1};
    // Substituting the physical sector number is observably wrong, without an
    // invented raw-data authentication error.
    auto key=Key(); std::array<std::byte,16> tweak{}; const std::uint64_t physical=100*8;
    for(unsigned i=0;i<8;++i) tweak[i]=static_cast<std::byte>(physical>>(i*8));
    auto wrong=XtsTransform(key.xts_key.Bytes(),tweak,std::span<const std::byte>(source->data).first(512),XtsDirection::Decrypt);
    CHECK(wrong); CHECK(!std::equal(wrong.bytes.Bytes().begin(),wrong.bytes.Bytes().end(),expected.begin()));
    key.xts_key.Clear(); wrong.bytes.Clear();
    source->before=[&](auto offset){if(offset==100ULL*4096+512) session->Cancel();};
    CHECK(session->ReadFile(1000,0,1024,out)==E::Cancelled); CHECK(out.empty());
    session->Close(); Released();

    // Deterministic held I/O: Close cannot return while a reader still borrows
    // the session. It marks cancellation before waiting for the reader mutex.
    source=std::make_shared<Source>(); session=Open(source,error); CHECK(session);
    std::mutex mutex; std::condition_variable cv; bool entered=false, resume=false;
    source->before=[&](auto offset){
        if(offset!=100ULL*4096) return;
        std::unique_lock lock(mutex); entered=true; cv.notify_all(); cv.wait(lock,[&]{return resume;});
    };
    E read_result=E::None; std::atomic<bool> closed=false;
    std::thread reader([&]{read_result=session->ReadFile(1000,0,512,out);});
    {std::unique_lock lock(mutex);cv.wait(lock,[&]{return entered;});}
    session->Cancel();
    bool close_zeroized=false;
    std::thread closer([&]{testing::hooks={};session->Close();
        close_zeroized=testing::hooks.all_released_bytes_zero && testing::hooks.releases>0;
        closed.store(true);});
    CHECK(!closed.load());
    {std::lock_guard lock(mutex);resume=true;} cv.notify_all();
    reader.join();closer.join();
    CHECK(closed.load());CHECK(read_result==E::Cancelled);CHECK(out.empty());
    CHECK(close_zeroized);
    CHECK(session->ReadFile(1000,0,1,out)==E::Closed);
    source->before={}; auto fresh=Open(source,error);CHECK(fresh);
    CHECK(fresh->ReadFile(1000,0,512,out)==E::None);fresh->Close();
}

// Keep these failed-operation checks in this target: the allocator replacement
// is test-only, thread-local, and inactive during the existing threaded tests.
class ThrowingIdentity final : public ImmutableEncryptedReadSource
{
public:
    std::shared_ptr<Source> inner = std::make_shared<Source>();
    mutable unsigned calls = 0;
    unsigned throw_at = 0;
    std::string SourceIdentity() const override
    {
        if (++calls == throw_at) throw std::runtime_error("publication identity fault");
        return inner->SourceIdentity();
    }
    std::uint64_t Revision() const override { return inner->Revision(); }
    std::uint64_t SizeBytes() const override { return inner->SizeBytes(); }
    std::shared_ptr<ApfsReadBudget> ReadBudget() const override { return inner->ReadBudget(); }
    bool Read(std::uint64_t o, std::size_t n, std::vector<std::byte>& b) const override
    { return inner->Read(o, n, b); }
};
void PlainMetadata(const std::shared_ptr<Source>& source, bool wrong_counts)
{
    source->root = Hex(f::PlainRoot); source->child = Hex(f::PlainChild);
    PutU32LE(source->root, 24, kObjectTypeBtree);
    PutU32LE(source->child, 24, kObjectTypeBtreeNode);
    if (wrong_counts) PutU64LE(source->root, source->bs - 16, 5);
    (void)FletcherForBlock(source->root, source->bs);
    (void)FletcherForBlock(source->child, source->bs);
    const auto map = ReadU64LE(source->image, 4ULL * source->bs + 0x80).value();
    const auto tree = ReadU64LE(source->image, map * source->bs + 48).value();
    const auto node = BuildBtreeNode({OmapRecordSpec{8293, source->root_block, 0, 7},
        OmapRecordSpec{9000, source->root_block + 1, 0, 7}}, 7, source->bs, 0, tree, 0x40000002, 11);
    std::copy(node.begin(), node.end(), source->image.begin() + tree * source->bs);
}
void CleanupControls()
{
    ++groups;
    auto source = std::make_shared<Source>();
    E error; UnlockError unlock; PasswordUnlockBudget attempts;
    auto session = ApfsEncryptedReadSession::Unlock(source, source->identity, source->revision,
        Request(), Hex(k::Password), attempts, error, unlock);
    CHECK(session); CHECK(error == E::None); CHECK(unlock == UnlockError::None);
    std::vector<std::byte> bytes;
    CHECK(session->ReadFile(1000, 509, 521, bytes) == E::None);
    const auto expected = Expected(4096);
    CHECK(std::equal(bytes.begin(), bytes.end(), expected.begin()+509, expected.begin()+1030));
    session->Close(); Released();
    source->MutateAt(2, [](auto& b) { PutU32LE(b, 32, 1); });
    std::string detail;
    CHECK(ResolveOmapValue(*source, 4096, 2, 101, 7, detail));
    CHECK(!ResolveOmapValue(*source, 4096, 2, 101, 7, detail, true));
}
void PublicationExceptionCleanup()
{
    ++groups;
    auto source = std::make_shared<ThrowingIdentity>(); E error;
    auto session = ApfsEncryptedReadSession::OpenForTesting(source, Key(), error);
    CHECK(session);
    const auto expected = Expected(4096);
    std::vector<std::byte> output;
    // Calibrate the last identity check with a successful one-sector read.
    // Observe its returned allocation on caller destruction as a positive
    // control: exactly these plaintext bytes must be visible to the observer.
    source->calls = 0;
    allocation_observer::Watch success(std::span(expected).first(512));
    CHECK(session->ReadFile(1000, 0, 512, output) == E::None);
    const auto final_check = source->calls;
    CHECK(final_check > 0); CHECK(output.size() == 512);
    CHECK(std::equal(output.begin(), output.end(), expected.begin()));
    std::vector<std::byte>().swap(output);
    const auto positive = success.Stop();
    CHECK(!positive.overflow); CHECK(positive.intact == 1); CHECK(positive.live == 0);
    source->calls = 0; source->throw_at = final_check;
    allocation_observer::Watch failure(std::span(expected).first(512));
    const auto result = session->ReadFile(1000, 0, 512, output);
    const auto observed = failure.Stop();
    std::cout << "observed intact=" << observed.intact << " zero=" << observed.zero
        << " live=" << observed.live << " overflow=" << observed.overflow << "\n";
    CHECK(source->calls == final_check); CHECK(result == E::ReadFailure); CHECK(output.empty());
    CHECK(!observed.overflow); CHECK(observed.live == 0); CHECK(observed.zero > 0);
    CHECK(observed.intact == 0);
    session->Close(); Released();
}
void IncompleteRecordCleanup()
{
    ++groups;
    auto source = std::make_shared<Source>(); PlainMetadata(source, false);
    // Extract the complete fixture inode through the ordinary parser. This is
    // also a positive control for observation of an actual parser allocation.
    BtreeReadPolicy policy; policy.require_complete_traversal = true;
    policy.reject_unsupported_flags = true;
    policy.virtual_child_resolver = [&](std::uint64_t, std::string&)
        -> std::optional<BtreeVirtualChildMapping> { return BtreeVirtualChildMapping{81, 7}; };
    std::string detail; std::vector<BtreeRecord> records;
    CHECK(ReadBtreeLeafRecords(*source, 4096, 80, false, 0, 7, policy, records, detail));
    CHECK(!records.empty()); CHECK(records.front().value.size() == 140);
    const auto inode = records.front().value;
    records.clear();
    allocation_observer::Watch positive_watch(inode);
    CHECK(ReadBtreeLeafRecords(*source, 4096, 80, false, 0, 7, policy, records, detail));
    records.clear();
    const auto positive = positive_watch.Stop();
    CHECK(!positive.overflow); CHECK(positive.intact == 1); CHECK(positive.live == 0);
    E error; auto session = Open(source, error); CHECK(session); session->Close();
    PlainMetadata(source, true); auto key = Key();
    allocation_observer::Watch failure(inode);
    auto failed = ApfsEncryptedReadSession::OpenForTesting(source, std::move(key), error);
    const auto observed = failure.Stop();
    std::cout << "observed intact=" << observed.intact << " zero=" << observed.zero
        << " live=" << observed.live << " overflow=" << observed.overflow << "\n";
    CHECK(!failed); CHECK(error == E::MetadataIntegrityFailure);
    CHECK(!observed.overflow); CHECK(observed.live == 0); CHECK(observed.zero > 0);
    CHECK(observed.intact == 0); Released();
}


void RoutingExceptionCleanup()
{
    ++groups;
    auto source = std::make_shared<Source>(); PlainMetadata(source, false);
    struct Context : BtreeNodeReadContext
    {
        Source& source;
        std::vector<std::byte> owned;
        unsigned reads = 0, releases = 0;
        explicit Context(Source& s) : source(s) {}
        bool ReadNode(std::uint64_t, std::uint64_t block, bool,
            std::span<const std::byte>& out, std::string&) override
        { ++reads; const bool ok = source.Read(block * 4096, 4096, owned); out = owned; return ok; }
        void ReleaseNode() noexcept override { ++releases; owned.clear(); }
    } context(*source);
    BtreeReadPolicy policy; policy.require_complete_traversal = true;
    policy.reject_unsupported_flags = true;
    policy.virtual_child_resolver = [](std::uint64_t, std::string&)
        -> std::optional<BtreeVirtualChildMapping> { return BtreeVirtualChildMapping{81, 7}; };
    std::vector<std::uint64_t> visited; policy.visited_physical_blocks = &visited;
    bool throw_comparator = false;
    BtreeRoutingPolicy routing{[&](const auto& a, const auto& b, std::string&) -> std::optional<int> {
        // After the inode has been parsed, comparing an extent throws with
        // an active previous key and retained ancestor separator.
        if (throw_comparator && a.size() == 16) throw std::runtime_error("routing comparator fault");
        const auto left = std::make_pair(ReadU64LE(a, 0).value(), ReadU64LE(a, 8).value_or(0));
        const auto right = std::make_pair(ReadU64LE(b, 0).value(), ReadU64LE(b, 8).value_or(0));
        return left == right ? 0 : left < right ? -1 : 1;
    }};
    std::vector<BtreeRecord> records; std::string detail;
    CHECK(ReadBtreeLeafRecords(*source, 4096, 80, false, 0, 7, policy, routing, records, detail, &context));
    CHECK(records.size() == 4); CHECK(records.front().key.size() == 8);
    const auto key = records.front().key; records.clear();
    // Ordinary traversal deliberately releases intact keys; this verifies the
    // exact-key observer and the unchanged ordinary cleanup policy together.
    allocation_observer::Watch positive_watch(key);
    CHECK(ReadBtreeLeafRecords(*source, 4096, 80, false, 0, 7, policy, routing, records, detail));
    records.clear(); const auto positive = positive_watch.Stop();
    CHECK(!positive.overflow); CHECK(positive.intact > 0); CHECK(positive.live == 0);
    throw_comparator = true; bool caught = false;
    allocation_observer::Watch failure(key);
    try { (void)ReadBtreeLeafRecords(*source, 4096, 80, false, 0, 7, policy, routing, records, detail, &context); }
    catch (const std::runtime_error& e) { caught = std::string_view(e.what()) == "routing comparator fault"; }
    const auto observed = failure.Stop();
    std::cout << "observed intact=" << observed.intact << " zero=" << observed.zero
        << " live=" << observed.live << " overflow=" << observed.overflow << "\n";
    CHECK(caught); CHECK(records.empty()); CHECK(visited.empty());
    CHECK(context.reads == context.releases); CHECK(context.owned.empty());
    CHECK(!observed.overflow); CHECK(observed.live == 0); CHECK(observed.zero > 0);
    CHECK(observed.intact == 0);
}


void IncompleteProjectionCopyCleanup()
{
    ++groups;
    auto source = std::make_shared<Source>(); PlainMetadata(source, false);
    E error; auto session = Open(source, error); CHECK(session); session->Close();
    // The first inode value allocation belongs to parser output. The second
    // belongs to the sorting copy; fail it after its key has been allocated.
    const auto key_offset = 0x38 + ReadU16LE(source->child, 0x28).value() +
        ReadU16LE(source->child, 0x2a).value() +
        ReadU16LE(source->child, 0x38 + ReadU16LE(source->child, 0x28).value()).value();
    const auto expected_key = std::span(source->child).subspan(key_offset, 8);
    auto key = Key();
    allocation_observer::Watch failure(expected_key);
    failure.FailAllocation(140, 1);
    auto failed = ApfsEncryptedReadSession::OpenForTesting(source, std::move(key), error);
    const auto observed = failure.Stop();
    std::cout << "projection_copy intact=" << observed.intact << " zero=" << observed.zero
        << " injected=" << failure.Failures() << "\n";
    CHECK(failure.Failures() == 1); CHECK(!failed); CHECK(error == E::ResourceLimit);
    CHECK(!observed.overflow); CHECK(observed.live == 0); CHECK(observed.zero > 0);
    CHECK(observed.intact == 0); Released();
}

}
#include "ApfsEncryptedNamespaceTests.h"
#include "ApfsEncryptedRuntimeBudgetTests.h"
namespace
{
void AppleImageMetadataProfiles()
{
    ++groups;
    auto records = NamespaceRecords();
    for (auto& record : records)
        if (ReadU64LE(record.key, 0).value() >> 60 == 3)
            PutU64LE(record.value, 0x30, 0x8000); // INODE_NO_RSRC_FORK, including directories.
    auto source = std::make_shared<Source>();
    InstallNamespace(source, records);
    E error; auto session = Open(source, error);
    CHECK(session); CHECK(error == E::None);
    EncryptedNodeInfo inode;
    CHECK(session->GetMetadata(2, inode) == E::None && inode.internal_flags == 0x8000);
    CHECK(session->GetMetadata(100, inode) == E::None && inode.internal_flags == 0x8000);
    session->Close(); Released();
}
void AppleImageFramingAndRolling()
{
    ++groups;
    auto records = NamespaceRecords(1);
    for (auto& record : records)
    {
        const auto type = ReadU64LE(record.key, 0).value() >> 60;
        const auto offset = type == 3 ? 92u : type == 9 ? 18u : 0u;
        if (!offset || record.value.size() <= offset) continue;
        const auto count = ReadU16LE(record.value, offset).value();
        const auto used = ReadU16LE(record.value, offset + 2).value();
        CHECK(used >= count * 4);
        PutU16LE(record.value, offset + 2, used - count * 4);
    }
    for (unsigned fault = 0; fault < 9; ++fault)
    {
        auto changed = records;
        if (fault >= 1 && fault <= 4)
        {
            auto found = std::find_if(changed.begin(), changed.end(), [](const auto& r) {
                return ReadU64LE(r.key,0).value() == ((3ULL << 60) | 100);
            });
            auto& value = found->value;
            if (fault == 1) PutU16LE(value,94,ReadU16LE(value,94).value()+1);
            if (fault == 2) value.push_back(std::byte{1});
            if (fault == 3) PutU16LE(value,92,1025);
            if (fault == 4) PutU16LE(value,98,UINT16_MAX);
        }
        auto source = std::make_shared<Source>();
        InstallNamespace(source,changed,1);
        source->MutateAt(4, [&](auto& bytes) {
            PutU64LE(bytes,0x38, fault == 8 ? 0x1001 : 5); // Historical ENC_ROLLED.
            if (fault == 5) PutU64LE(bytes,0x3D0,77); // Active rolling state.
        });
        if (fault == 6 || fault == 7)
        {
            const auto map = ReadU64LE(source->image,4ULL*4096+0x80).value();
            const auto tree = ReadU64LE(source->image,map*4096+48).value();
            if (fault == 6) source->MutateAt(map,[](auto& b) { PutU32LE(b,32,0x10); });
            if (fault == 7) source->MutateAt(tree,[](auto& b) { PutU32LE(b,b.size()-40-16,0x14); });
        }
        E error; auto session = Open(source,error);
        CHECK(static_cast<bool>(session) == (fault == 0));
        if (session)
        {
            EncryptedDirectoryEntry entry;
            CHECK(session->LookupWindows(2,L"report.txt",entry) == E::None && entry.inode_id == 100);
            std::vector<std::byte> bytes;
            CHECK(session->ReadFile(100,509,191,bytes) == E::None && bytes.size() == 191);
            session->Close();
        }
        else CHECK(error != E::None);
        Released();
    }
}
std::vector<BtreeRecord> SymbolicLinkRecords()
{
    auto records = NamespaceRecords(); std::string detail;
    for (auto& record : records)
        if (ReadU64LE(record.key,0).value() == ((3ULL << 60) | 2)) PutU32LE(record.value,56,4);
    rw::AppleInodeRecord inode;
    inode.object_id = inode.private_id = 200; inode.parent_id = 2;
    inode.mode = 0120777; inode.children_or_links = 1; inode.internal_flags = 0x8000;
    BtreeRecord record; CHECK(rw::EncodeAppleInodeRecord(inode,record,detail)); records.push_back(record);
    rw::AppleDirectoryRecord entry; entry.parent_id = 2; entry.file_id = 200;
    entry.name_utf8 = "Link"; entry.flags = 10;
    CHECK(rw::EncodeAppleDirectoryRecord(entry,record,detail)); records.push_back(record);
    const std::string target = "../outside/target";
    rw::AppleXattrRecord attr{200,"com.apple.fs.symlink",6,{}};
    for (auto byte : target) attr.data.push_back(static_cast<std::byte>(byte));
    attr.data.push_back(std::byte{});
    CHECK(rw::EncodeAppleXattrRecord(attr,record,detail)); records.push_back(record);
    return records;
}
void SymbolicLinkMetadataOnly()
{
    ++groups;
    auto source = std::make_shared<Source>(); InstallNamespace(source,SymbolicLinkRecords());
    E error; auto session = Open(source,error); CHECK(session); CHECK(error == E::None);
    const auto reads = source->reads;
    EncryptedNodeInfo inode;
    CHECK(session->ResolvePath(L"\\Link",inode) == E::None && inode.inode_id == 200);
    CHECK((inode.mode & 0170000) == 0120000);
    CHECK(session->ResolvePath(L"\\Link\\target",inode) == E::NotDirectory && inode.inode_id == 0);
    std::vector<std::byte> bytes;
    CHECK(session->ReadFile(200,0,1,bytes) == E::FileNotFound && bytes.empty());
    CHECK(session->ReadXattr(200,"com.apple.fs.symlink",bytes) == E::None);
    const std::string target = "../outside/target";
    CHECK(bytes.size() == target.size()+1 && bytes.back() == std::byte{});
    CHECK(std::equal(target.begin(),target.end(),bytes.begin(),[](char a,auto b) { return std::byte(a) == b; }));
    CHECK(source->reads == reads); session->Close(); Released();
}
void AppleCryptoPlaceholderAndExtentProfiles()
{
    ++groups;
    for (unsigned fault = 0; fault < 13; ++fault)
    {
        auto records = NamespaceRecords();
        BtreeRecord crypto; crypto.key.resize(8); crypto.value.resize(24);
        PutU64LE(crypto.key,0,(7ULL << 60) | 4); PutU32LE(crypto.value,0,1);
        if (fault != 0)
        {
            PutU16LE(crypto.value,4,5); PutU32LE(crypto.value,12,3);
            PutU32LE(crypto.value,16,306250119); PutU16LE(crypto.value,20,1);
        }
        if (fault == 2) PutU16LE(crypto.value,4,6);
        if (fault == 3) PutU16LE(crypto.value,6,1);
        if (fault == 4) PutU32LE(crypto.value,8,1);
        if (fault == 5) PutU32LE(crypto.value,12,4);
        if (fault == 6) PutU16LE(crypto.value,22,1);
        if (fault == 7) PutU64LE(crypto.key,0,(7ULL << 60) | 5);
        if (fault == 8) crypto.value.push_back(std::byte{});
        if (fault == 9) PutU32LE(crypto.value,0,0x80000000u);
        if (fault == 10) PutU16LE(crypto.value,20,2);
        records.push_back(std::move(crypto));
        for (auto& record : records)
            if (ReadU64LE(record.key,0).value() >> 60 == 8)
                record.value[7] = static_cast<std::byte>(fault == 11 ? 2 : fault == 12 ? 0x81 : 1);
        auto source = std::make_shared<Source>(); InstallNamespace(source,records);
        E error; auto session = Open(source,error);
        CHECK(static_cast<bool>(session) == (fault <= 1));
        if (session)
        {
            std::vector<std::byte> bytes;
            CHECK(session->ReadFile(100,509,191,bytes) == E::None && bytes.size() == 191);
            for (std::size_t i=0;i<bytes.size();++i) CHECK(bytes[i] == static_cast<std::byte>(((i+509)*7+3)%256));
            session->Close();
        }
        else CHECK(error == E::UnsupportedEncryptionLayout);
        Released();
    }
}
void ExplicitEncryptedExtentCodec()
{
    ++groups;
    constexpr auto profile = rw::AppleEncryptedExtentProfile::OneKeyGenerationZero;
    for (const auto flags : {0u, 1u})
    {
        auto records = NamespaceRecords();
        std::string detail;
        unsigned extents = 0;
        for (auto& record : records)
        {
            if (ReadU64LE(record.key, 0).value() >> 60 != 8) continue;
            rw::AppleEncryptedFileExtentRecord decoded;
            CHECK(rw::DecodeAppleEncryptedFileExtentRecord(record, 4096, profile, decoded, detail));
            decoded.flags = static_cast<std::uint8_t>(flags);
            CHECK(decoded.extent.physical_block == 100 && decoded.extent.crypto_id == 500);
            CHECK(rw::EncodeAppleEncryptedFileExtentRecord(decoded, profile, record, detail));
            CHECK(record.value[7] == static_cast<std::byte>(flags));
            ++extents;
        }
        CHECK(extents == 1);
        auto source = std::make_shared<Source>();
        InstallNamespace(source, records);
        E error;
        auto session = Open(source, error);
        CHECK(session && error == E::None);
        std::vector<std::byte> bytes;
        CHECK(session->ReadFile(100, 0, 700, bytes) == E::None && bytes.size() == 700);
        for (std::size_t i = 0; i < bytes.size(); ++i)
            CHECK(bytes[i] == static_cast<std::byte>((i * 7 + 3) % 256));
        session->Close();
        Released();
    }
}
void ReservedPrivateDirectoryProfiles()
{
    ++groups;
    for (unsigned fault = 0; fault < 10; ++fault)
    {
        auto records = NamespaceRecords(); std::string detail;
        rw::AppleInodeRecord inode;
        inode.object_id = inode.private_id = 3; inode.parent_id = fault == 1 ? 2 : 1;
        inode.mode = 0040700; inode.internal_flags = 0x8000;
        inode.children_or_links = fault == 2 ? 1 : 0;
        rw::AppleExtendedField name; name.type = 4;
        const std::string text = fault == 3 ? "other-dir" : "private-dir";
        for (auto byte : text) name.data.push_back(static_cast<std::byte>(byte));
        name.data.push_back(std::byte{}); inode.extended_fields.push_back(std::move(name));
        BtreeRecord record; CHECK(rw::EncodeAppleInodeRecord(inode,record,detail)); records.push_back(record);
        rw::AppleDirectoryRecord entry;
        entry.parent_id = fault == 7 ? 2 : 1; entry.file_id = 3;
        entry.name_utf8 = fault == 6 ? "other-dir" : "private-dir"; entry.flags = fault == 9 ? 8 : 4;
        CHECK(rw::EncodeAppleDirectoryRecord(entry,record,detail));
        if (fault != 5) records.push_back(record);
        if (fault == 8) records.push_back(record);
        if (fault == 4)
        {
            CHECK(rw::EncodeAppleXattrRecord(rw::AppleXattrRecord{3,"user.hidden",2,{}},record,detail));
            records.push_back(record);
        }
        if (fault == 8)
        {
            records.pop_back();
            CHECK(rw::SortAppleBtreeRecords(records,rw::AppleBtreeKeyOrder::FileSystemCaseSensitive,detail));
            const auto at=std::find_if(records.begin(),records.end(),[&](const auto& r) { return r.key == record.key; });
            CHECK(at != records.end()); records.insert(at+1,record);
        }
        auto source = std::make_shared<Source>(); InstallNamespace(source,records,0,fault != 8);
        E error; auto session = Open(source,error);
        CHECK(static_cast<bool>(session) == (fault == 0));
        if (session)
        {
            EncryptedNodeInfo metadata;
            CHECK(session->GetMetadata(3,metadata) == E::FileNotFound && metadata.inode_id == 0);
            EncryptedNamespaceInfo info;
            CHECK(session->GetNamespaceInfo(info) == E::None && info.inode_count == 3);
            session->Close();
        }
        else CHECK(error == E::UnsupportedEncryptionLayout || (fault == 8 && error == E::MetadataIntegrityFailure));
        Released();
    }
}
void SymbolicLinkRefusals()
{
    ++groups;
    for (unsigned fault=0;fault<5;++fault)
    {
        auto records = SymbolicLinkRecords();
        const auto target = std::find_if(records.begin(),records.end(),[](const auto& r) {
            return ReadU64LE(r.key,0).value() == ((4ULL << 60) | 200);
        });
        if (fault == 0) records.erase(target);
        if (fault == 1) PutU64LE(target->key,0,(4ULL << 60) | 100);
        if (fault == 2) PutU16LE(target->value,0,2);
        if (fault == 3) target->value.back() = std::byte{1};
        if (fault == 4) target->value[5] = std::byte{};
        auto source=std::make_shared<Source>(); InstallNamespace(source,records);
        E error; auto session=Open(source,error); CHECK(!session); CHECK(error != E::None); Released();
    }
}
void ReservedRootDirectoryEntry()
{
    ++groups;
    for (unsigned fault=0;fault<6;++fault)
    {
        auto records=NamespaceRecords(); std::string detail;
        for (auto& record : records)
            if (ReadU64LE(record.key,0).value() == ((3ULL << 60) | 2))
            {
                rw::AppleInodeRecord inode;
                CHECK(rw::ApfsExtendedRecordCodec::DecodeInode(record,inode,detail));
                rw::AppleExtendedField name; name.type=4;
                name.data={std::byte{'r'},std::byte{'o'},std::byte{'o'},std::byte{'t'},std::byte{}};
                inode.extended_fields.push_back(std::move(name));
                CHECK(rw::EncodeAppleInodeRecord(inode,record,detail));
            }
        rw::AppleDirectoryRecord entry;
        entry.parent_id=fault==1?10:1; entry.file_id=2; entry.flags=fault==2?8:4;
        entry.name_utf8=fault==3?"Root":"root";
        if (fault==5) { rw::AppleExtendedField sibling; sibling.type=1; sibling.data.resize(8); PutU64LE(sibling.data,0,900); entry.extended_fields.push_back(sibling); }
        BtreeRecord record; CHECK(rw::EncodeAppleDirectoryRecord(entry,record,detail)); records.push_back(record);
        if (fault==4)
        {
            CHECK(rw::SortAppleBtreeRecords(records,rw::AppleBtreeKeyOrder::FileSystemCaseSensitive,detail));
            const auto at=std::find_if(records.begin(),records.end(),[&](const auto& r) { return r.key == record.key; });
            CHECK(at != records.end()); records.insert(at+1,record);
        }
        auto source=std::make_shared<Source>(); InstallNamespace(source,records,0,fault != 4);
        E error; auto session=Open(source,error); CHECK(static_cast<bool>(session)==(fault==0));
        if(session) { EncryptedNamespaceInfo info; CHECK(session->GetNamespaceInfo(info)==E::None && info.entry_count==4); session->Close(); }
        else CHECK(error==E::MetadataIntegrityFailure);
        Released();
    }
}
}
namespace
{
std::shared_ptr<Source> CanonicalSource()
{
    auto source = std::make_shared<Source>();
    // The reader vector replaces the OMAP with only FS nodes. Its synthetic
    // snapshot declaration therefore has no mapping and is not a full view.
    source->MutateAt(4,[](auto& block){PutU64LE(block,0x98,0);});
    return source;
}
void CanonicalEncryptedContext()
{
    ++groups;
    auto source = CanonicalSource(); E error;
    auto session = Open(source, error); CHECK(session);
    auto context = session->CreateMetadataReadContext(error); CHECK(context); CHECK(error == E::None);
    std::string detail;
    CHECK(!LoadAppleCheckpointView(*source, 0, source->size, detail));
    CHECK(detail == "AppleTreeChecksumInvalid");
    auto view = LoadAppleCheckpointView(*source, 0, source->size, detail, *context);
    if (!view) throw std::runtime_error("canonical context: " + detail);
    CHECK(view); CHECK(view->volumes.size() == 1);
    CHECK(view->volumes.front().root_tree.type == 0x10000002u);
    CHECK(view->volumes.front().superblock.fs_flags == kFsFlagOneKey);
    std::vector<BtreeRecord> records;
    CHECK(ReadAppleVolumeFileSystemRecords(*source, view->container, view->volumes.front(), records, detail, *context));
    CHECK(!records.empty());
    const auto count = records.size();
    for (auto& row : records) { std::fill(row.key.begin(),row.key.end(),std::byte{}); std::fill(row.value.begin(),row.value.end(),std::byte{}); }
    CHECK(ReadAppleVolumeFileSystemRecords(*source, view->container, view->volumes.front(), records, detail, *context));
    CHECK(records.size() == count);
    session->Close();
    CHECK(!ReadAppleVolumeFileSystemRecords(*source, view->container, view->volumes.front(), records, detail, *context));
    CHECK(records.empty()); CHECK(detail == "AppleEncryptedContextClosed");
    CHECK(!session->CreateMetadataReadContext(error)); CHECK(error == E::Closed);
    Released();
}
void CanonicalEncryptedContextRefusals()
{
    ++groups;
    auto source = CanonicalSource(); E error;
    auto session = Open(source, error); CHECK(session);
    auto context = session->CreateMetadataReadContext(error); CHECK(context);
    std::string detail;
    auto view = LoadAppleCheckpointView(*source, 0, source->size, detail, *context); CHECK(view);
    auto other = std::make_shared<Source>();
    CHECK(!LoadAppleCheckpointView(*other, 0, other->size, detail, *context));
    CHECK(detail == "AppleEncryptedOriginalSourceMismatch");
    CHECK(!LoadAppleCheckpointView(*source, 1, source->size-1, detail, *context));
    CHECK(!LoadAppleCheckpointView(*source, 0, source->size, detail, *context, 6));
    std::vector<BtreeRecord> records(1);
    auto volume = view->volumes.front(); ++volume.root_tree.physical_block;
    CHECK(!ReadAppleVolumeFileSystemRecords(*source,view->container,volume,records,detail,*context)); CHECK(records.empty());
    volume = view->volumes.front(); ++volume.superblock.omap_oid;
    CHECK(!ReadAppleVolumeFileSystemRecords(*source,view->container,volume,records,detail,*context)); CHECK(records.empty());
    auto checkpoint = view->container; ++checkpoint.superblock.block_size;
    CHECK(!ReadAppleVolumeFileSystemRecords(*source,checkpoint,view->volumes.front(),records,detail,*context)); CHECK(records.empty());
    ++source->revision;
    CHECK(!LoadAppleCheckpointView(*source,0,source->size,detail,*context));
    --source->revision;
    CHECK(!LoadAppleCheckpointView(*source,0,source->size,detail,*context));
    session->Close(); Released();
    // Fault injection changes the held fixture in memory only, after unlock.
    // A complete earlier parse must never turn a later failed walk into success.
    for (unsigned fault = 0; fault < 6; ++fault)
    {
        auto input = CanonicalSource();
        auto protected_session = Open(input,error); CHECK(protected_session);
        auto bound = protected_session->CreateMetadataReadContext(error); CHECK(bound);
        auto selected = LoadAppleCheckpointView(*input,0,input->size,detail,*bound); CHECK(selected);
        if (fault == 0) input->child[0] ^= std::byte{1};
        if (fault == 1) input->root = Hex(f::WrongOid);
        if (fault == 2) protected_session->Cancel();
        if (fault == 3) input->budget->LimitRemainingTo(0,0,0,0);
        if (fault == 4 || fault == 5)
        {
            const auto map = selected->volumes.front().superblock.omap_oid;
            const auto tree = ReadU64LE(input->image,map*input->bs+48).value();
            auto changed = BuildBtreeNode({OmapRecordSpec{8293,input->root_block,fault == 4 ? 8u : 4u,7},
                OmapRecordSpec{9000,input->root_block+1,4,7}},7,input->bs,0,tree,0x40000002,11);
            if (fault == 5) input->MutateAt(map,[](auto& block){PutU32LE(block,32,2);});
            std::copy(changed.begin(),changed.end(),input->image.begin()+tree*input->bs);
        }
        records.resize(1);
        CHECK(!ReadAppleVolumeFileSystemRecords(*input,selected->container,selected->volumes.front(),records,detail,*bound));
        CHECK(records.empty());
        protected_session->Close(); Released();
    }
    auto runtime = std::make_shared<RuntimeSource>();
    runtime->limits.materialized_bytes = 1;
    auto bounded_session = OpenRuntime(runtime);
    auto bounded = bounded_session->CreateMetadataReadContext(error); CHECK(bounded);
    CHECK(!LoadAppleCheckpointView(*runtime,0,runtime->SizeBytes(),detail,*bounded));
    CHECK(!runtime->inner->budget->Failed());
    bounded_session->Close(); Released();
}
void CanonicalEncryptedContextMetadataOnly()
{
    ++groups;
    auto source = CanonicalSource(); E error;
    auto session = Open(source, error); CHECK(session);
    auto context = session->CreateMetadataReadContext(error); CHECK(context);
    std::string detail;
    auto full = LoadAppleCheckpointView(*source, 0, source->size, detail, *context); CHECK(full);
    CHECK(!full->spaceman.bytes.empty());
    const auto xid = full->container.superblock.xid;
    source->fault_offset = full->spaceman.object.physical_block * source->bs;
    source->fault = 2;
    auto metadata = LoadAppleCheckpointView(*source, 0, source->size, detail, *context, xid, false);
    CHECK(metadata); CHECK(detail.empty()); CHECK(metadata->volumes.size() == 1);
    CHECK(metadata->container.superblock_bytes == full->container.superblock_bytes);
    CHECK(metadata->volumes.front().root_tree.physical_block == full->volumes.front().root_tree.physical_block);
    CHECK(metadata->volumes.front().object_map.object.physical_block == full->volumes.front().object_map.object.physical_block);
    CHECK(metadata->spaceman.bytes.empty()); CHECK(metadata->spaceman.chunks.empty());
    CHECK(metadata->spaceman.object.physical_block == 0);
    std::vector<BtreeRecord> records;
    CHECK(ReadAppleVolumeFileSystemRecords(*source, metadata->container, metadata->volumes.front(), records, detail, *context));
    CHECK(!records.empty());
    for (auto& row : records) { std::fill(row.key.begin(),row.key.end(),std::byte{}); std::fill(row.value.begin(),row.value.end(),std::byte{}); }
    CHECK(!LoadAppleCheckpointView(*source, 0, source->size, detail, *context));
    source->fault_offset = UINT64_MAX;
    CHECK(LoadAppleCheckpointView(*source, 0, source->size, detail, *context, xid, true));
    auto other = CanonicalSource();
    CHECK(!LoadAppleCheckpointView(*other, 0, other->size, detail, *context, xid, false));
    CHECK(detail == "AppleEncryptedOriginalSourceMismatch");
    CHECK(!LoadAppleCheckpointView(*source, 1, source->size - 1, detail, *context, xid, false));
    CHECK(detail == "AppleEncryptedGeometryOrCheckpointMismatch");
    CHECK(!LoadAppleCheckpointView(*source, 0, source->size, detail, *context, xid + 1, false));
    CHECK(detail == "AppleEncryptedGeometryOrCheckpointMismatch");
    ++source->revision;
    CHECK(!LoadAppleCheckpointView(*source, 0, source->size, detail, *context, xid, false));
    --source->revision;
    CHECK(!LoadAppleCheckpointView(*source, 0, source->size, detail, *context, xid, false));
    session->Close(); Released();

    auto cancelled_source = CanonicalSource();
    auto cancelled_session = Open(cancelled_source, error); CHECK(cancelled_session);
    auto cancelled_context = cancelled_session->CreateMetadataReadContext(error); CHECK(cancelled_context);
    cancelled_session->Cancel();
    CHECK(!LoadAppleCheckpointView(*cancelled_source, 0, cancelled_source->size, detail, *cancelled_context, xid, false));
    CHECK(detail == "AppleEncryptedContextCancelled");
    cancelled_session->Close();
    CHECK(!LoadAppleCheckpointView(*cancelled_source, 0, cancelled_source->size, detail, *cancelled_context, xid, false));
    CHECK(detail == "AppleEncryptedContextClosed"); Released();

    auto corrupt_source = CanonicalSource();
    auto corrupt_session = Open(corrupt_source, error); CHECK(corrupt_session);
    auto corrupt_context = corrupt_session->CreateMetadataReadContext(error); CHECK(corrupt_context);
    corrupt_source->root[0] ^= std::byte{1};
    CHECK(!LoadAppleCheckpointView(*corrupt_source, 0, corrupt_source->size, detail, *corrupt_context, xid, false));
    CHECK(!detail.empty()); corrupt_session->Close(); Released();
}
}
namespace {
void EncryptedOwnershipGraph()
{
    ++groups;
    namespace rw = apfsaccess::rw;
    std::string detail;
    rw::AppleEncryptedFileExtentRecord extent{{21,0,4096,44,77,4096},1};
    BtreeRecord file, reference;
    CHECK(rw::EncodeAppleEncryptedFileExtentRecord(extent,rw::AppleEncryptedExtentProfile::OneKeyGenerationZero,file,detail));
    CHECK(rw::EncodeApplePhysicalExtentRecord({44,1,rw::kApplePhysicalExtentKindNew,21,1},reference,detail));
    const auto raw=file.value;
    std::vector<rw::ApplePhysicalExtentRecord> owners;
    CHECK(rw::ValidateAppleEncryptedPayloadExtentGraph({file},{reference},4096,128,owners,detail));
    CHECK(owners.size()==1 && owners.front().physical_block==44 && file.value==raw);
    CHECK(!rw::ValidateApplePayloadExtentGraph({file},{reference},4096,128,owners,detail));
    CHECK(owners.empty());
    auto wrong=file; wrong.value[7]=std::byte{2};
    CHECK(!rw::ValidateAppleEncryptedPayloadExtentGraph({wrong},{reference},4096,128,owners,detail)); CHECK(owners.empty());
    CHECK(rw::EncodeApplePhysicalExtentRecord({45,1,rw::kApplePhysicalExtentKindNew,21,1},reference,detail));
    CHECK(!rw::ValidateAppleEncryptedPayloadExtentGraph({file},{reference},4096,128,owners,detail)); CHECK(owners.empty());
    CHECK(rw::EncodeApplePhysicalExtentRecord({44,1,rw::kApplePhysicalExtentKindNew,21,2},reference,detail));
    CHECK(!rw::ValidateAppleEncryptedPayloadExtentGraph({file},{reference},4096,128,owners,detail)); CHECK(owners.empty());
}
}
int main(int argc,char** argv)
{
    const std::pair<const char*,void(*)()> tests[]={
        {"EncryptedOwnershipGraph",EncryptedOwnershipGraph},
        {"CanonicalEncryptedContext",CanonicalEncryptedContext},
        {"CanonicalEncryptedContextRefusals",CanonicalEncryptedContextRefusals},
        {"CanonicalEncryptedContextMetadataOnly",CanonicalEncryptedContextMetadataOnly},
        {"AppleImageMetadataProfiles",AppleImageMetadataProfiles},
        {"AppleImageFramingAndRolling",AppleImageFramingAndRolling},
        {"SymbolicLinkMetadataOnly",SymbolicLinkMetadataOnly},
        {"AppleCryptoPlaceholderAndExtentProfiles",AppleCryptoPlaceholderAndExtentProfiles},
        {"ExplicitEncryptedExtentCodec",ExplicitEncryptedExtentCodec},
        {"ReservedPrivateDirectoryProfiles",ReservedPrivateDirectoryProfiles},
        {"SymbolicLinkRefusals",SymbolicLinkRefusals},
        {"ReservedRootDirectoryEntry",ReservedRootDirectoryEntry},
        {"RuntimeRepeatedReads",RuntimeRepeatedReads},{"RuntimeRepeatedMetadata",RuntimeRepeatedMetadata},
        {"RuntimeLimitsAndRecovery",RuntimeLimitsAndRecovery},{"RuntimeStickyBindingAndParse",RuntimeStickyBindingAndParse},
        {"RuntimeFailuresAndCleanup",RuntimeFailuresAndCleanup},{"RuntimePublicationAndClose",RuntimePublicationAndClose},
        {"NamespaceBudgetsAndReferences",NamespaceBudgetsAndReferences},{"NamespaceCloseDrain",NamespaceCloseDrain},
        {"NamespaceLifecycle",NamespaceLifecycle},{"NamespacePublicationCleanup",NamespacePublicationCleanup},{"NamespaceGraphsAndEdges",NamespaceGraphsAndEdges},
        {"NamespaceRoundTrip",NamespaceRoundTrip},{"NamespaceNames",NamespaceNames},{"NamespaceRefusals",NamespaceRefusals},
        {"IncompleteProjectionCopyCleanup",IncompleteProjectionCopyCleanup},
        {"RoutingExceptionCleanup",RoutingExceptionCleanup},{"CleanupControls",CleanupControls},{"PublicationExceptionCleanup",PublicationExceptionCleanup},
        {"IncompleteRecordCleanup",IncompleteRecordCleanup},{"ReadsAndBinding",ReadsAndBinding},{"MetadataRefusals",MetadataRefusals},
        {"BudgetAndSourceFailures",BudgetAndSourceFailures},{"CryptoFailures",CryptoFailures},
        {"LifecycleAndUnauthenticatedData",LifecycleAndUnauthenticatedData}};
    try
    {
        for(const auto& test:tests)
        {
            if(argc>1 && std::none_of(argv+1,argv+argc,[&](const char* arg){return std::string_view(arg)==test.first;})) continue;
            const auto before=checks;test.second();
            std::cout<<"PASS "<<test.first<<" "<<(checks-before)<<" assertions\n";
        }
        std::cout<<"PASS "<<groups<<" groups / "<<checks<<" assertions\n";return 0;
    }
    catch(const std::exception& e){std::cerr<<"FAIL "<<e.what()<<" after "<<checks<<" assertions\n";return 1;}
}
