#include "ApfsKeybagUnlock.h"
#include "ApfsCryptoTestHooks.h"
#include "ApfsKeybagUnlockVectors.h"
#include "TestFixtureBuilder.h"
#include <algorithm>
#include <iostream>
#include <stdexcept>
#include <thread>
#include <type_traits>

using namespace apfsaccess::catalog;
using namespace apfsaccess::crypto;
using namespace apfsaccess::testfixture;
namespace f = apfsaccess::keybag_fixture;
namespace
{
unsigned checks = 0, groups = 0;
#define CHECK(x) do { ++checks; if (!(x)) throw std::runtime_error("check failed at line " + std::to_string(__LINE__)); } while(false)
std::vector<std::byte> Hex(std::string_view s)
{
    const auto nibble = [](char c) -> unsigned { return c <= '9' ? static_cast<unsigned>(c-'0') : static_cast<unsigned>(c-'a'+10); };
    std::vector<std::byte> bytes;
    for (std::size_t i = 0; i < s.size(); i += 2)
        bytes.push_back(static_cast<std::byte>((nibble(s[i]) << 4) | nibble(s[i+1])));
    return bytes;
}
KeybagUuid Uuid(std::string_view s)
{
    const auto bytes = Hex(s);
    KeybagUuid result{};
    std::copy(bytes.begin(), bytes.end(), result.begin());
    return result;
}
bool Same(std::span<const std::byte> a, std::span<const std::byte> b)
{
    return std::equal(a.begin(),a.end(),b.begin(),b.end());
}
void Released()
{
    CHECK(testing::hooks.all_released_bytes_zero);
    CHECK(testing::hooks.wipes == testing::hooks.releases);
}
PasswordRecordResult Decode(std::span<const std::byte> vek, std::span<const std::byte> kek,
    std::span<const std::byte> password)
{
    PasswordUnlockBudget budget;
    return DecodePasswordKeyRecords(vek,kek,password,budget);
}
void Fails(const PasswordRecordResult& result, UnlockError error)
{
    CHECK(!result);
    CHECK(result.error == error);
    CHECK(result.xts_key.Size() == 0);
    CHECK(!result.xts_key.IsLocked());
}
void RecordVectors()
{
    ++groups;
    const auto password = Hex(f::Password), vek = Hex(f::Vek), kek = Hex(f::Kek), expected = Hex(f::ExpectedVek);
    for (auto kek_hex : {f::Kek, f::Kek16})
    {
        testing::hooks = {};
        auto result = Decode(vek,Hex(kek_hex),password);
        CHECK(result);
        CHECK(result.xts_key.IsLocked());
        CHECK(Same(result.xts_key.Bytes(),expected));
        auto moved = std::move(result.xts_key);
        CHECK(result.xts_key.Size() == 0);
        moved.Clear();
        moved.Clear();
        Released();
        CHECK(testing::hooks.releases > 0);
    }
    const auto bad = [](auto v, auto k, UnlockError error) {
        Fails(Decode(Hex(v),Hex(k),Hex(f::Password)),error); Released();
    };
    for (auto unknown : {f::UnknownKek,f::Class2PaddedKek,f::ShortInfo})
        bad(f::Vek,unknown,UnlockError::UnsupportedFormat);
    bad(f::UnknownVek,f::Kek,UnlockError::UnsupportedFormat);
    bad(f::EqualVek,f::Kek,UnlockError::UnsupportedFormat);
    bad(f::ExtraField,f::Kek,UnlockError::UnsupportedFormat);
    for (auto invalid : {f::NegativeInteger,f::NonminimalInteger,f::EmptyInteger,f::OversizedInteger})
        bad(f::Vek,invalid,UnlockError::Malformed);
    for (auto invalid : {f::ZeroIterations,f::OverIterations})
        bad(f::Vek,invalid,UnlockError::ResourceLimit);
    bad(f::BadVekWrap,f::Kek,UnlockError::CredentialOrKeyMismatch);
    bad(f::Vek,f::BadKekWrap,UnlockError::CredentialOrKeyMismatch);
    for (const auto& pair : {std::pair{f::Class2Vek,f::Kek}, std::pair{f::Class2VekUnderClass2Kek,f::Class2Kek},
                            std::pair{f::VekUnderClass2Kek,f::Class2Kek}})
    {
        auto r=Decode(Hex(pair.first),Hex(pair.second),password);
        CHECK(r); CHECK(Same(r.xts_key.Bytes(),Hex(pair.first==f::VekUnderClass2Kek?f::ExpectedVek:f::ExpectedClass2Vek)));
    }
    auto wrong = password;
    wrong[0] ^= std::byte{1};
    Fails(Decode(vek,kek,wrong),UnlockError::CredentialOrKeyMismatch);
    wrong[0] = std::byte{};
    Fails(Decode(vek,kek,wrong),UnlockError::InvalidArgument);
    Fails(Decode(vek,kek,std::vector<std::byte>(1025,std::byte{1})),UnlockError::InvalidArgument);
    Released();
}
void DerAdversaries()
{
    ++groups;
    const auto password = Hex(f::Password), vek = Hex(f::Vek), kek = Hex(f::Kek);
    for (bool is_kek : {false,true})
    {
        const auto& input = is_kek ? kek : vek;
        for (std::size_t i = 0; i < input.size(); ++i)
        {
            auto short_bytes = std::span<const std::byte>(input).first(i);
            auto r = is_kek ? Decode(vek,short_bytes,password) : Decode(short_bytes,kek,password);
            CHECK(!r); CHECK(r.xts_key.Size() == 0);
        }
        auto trailing = input;
        trailing.push_back(std::byte{});
        auto r = is_kek ? Decode(vek,trailing,password) : Decode(trailing,kek,password);
        Fails(r,UnlockError::Malformed);
    }
    for (auto bad : {"30800000", "3082007f", "308100", "3f00", "3082ffff"})
        Fails(Decode(Hex(bad),kek,password),UnlockError::Malformed);
    // All 32 envelope HMAC bytes; first field is 80 01 00, then 81 20.
    for (std::size_t i = 0; i < 32; ++i)
    {
        auto bad = vek;
        const std::size_t sequence_header = bad[1] == std::byte{0x81} ? 3 : 2;
        bad[sequence_header+5+i] ^= std::byte{1};
        Fails(Decode(bad,kek,password),UnlockError::IntegrityFailure);
    }
    Released();
}
void FailureSweeps()
{
    ++groups;
    const auto password = Hex(f::Password), kek = Hex(f::Kek);
    for (auto encoded_vek : {f::Vek,f::Class2Vek})
    {
    const auto vek=Hex(encoded_vek);
    testing::hooks = {};
    { auto r = Decode(vek,kek,password); CHECK(r); }
    const auto success = testing::hooks;
    for (int kind = 0; kind < 4; ++kind)
    {
        const int count = kind == 0 ? success.allocations : kind == 1 ? success.locks : success.cng_calls;
        for (int i = 0; i < count; ++i)
        {
            testing::hooks = {};
            if (kind == 0) testing::hooks.allocation_failure_at = i;
            else if (kind == 1) testing::hooks.lock_failure_at = i;
            else { testing::hooks.cng_failure_at = i; testing::hooks.cng_fail_after_call = kind == 3; }
            auto r = Decode(vek,kek,password);
            CHECK(!r); CHECK(r.xts_key.Size() == 0); Released();
        }
    }
    testing::hooks = {};
    }
}
void RetryControl()
{
    ++groups;
    PasswordUnlockBudget budget;
    const auto vek = Hex(f::Vek), kek = Hex(f::Kek);
    auto wrong = Hex(f::Password); wrong[0] ^= std::byte{1};
    PasswordUnlockBudget timing;
    CHECK(timing.Begin()); CHECK(!timing.Begin());
    for (int i = 0; i < 8; ++i)
    {
        Fails(DecodePasswordKeyRecords(vek,kek,wrong,budget),UnlockError::CredentialOrKeyMismatch);
        Released();
        std::this_thread::sleep_for(std::chrono::milliseconds(260));
    }
    Fails(DecodePasswordKeyRecords(vek,kek,Hex(f::Password),budget),UnlockError::RateLimited);
    PasswordUnlockBudget work;
    CHECK(work.Charge(1'000'000)); CHECK(work.Charge(1'000'000));
    CHECK(!work.Charge(1)); CHECK(!work.Charge(1));
}
void OuterVectors()
{
    ++groups;
    const auto cu = Uuid(f::ContainerUuid), vu = Uuid(f::VolumeUuid);
    for (bool container : {true,false})
    {
        auto r = DecryptApfsUuidKeybagBlock(container ? cu : vu, container ? 60 : 61,
            Hex(container ? f::ContainerCipher : f::VolumeCipher));
        CHECK(r);
        CHECK(Same(r.bytes.Bytes(),Hex(container ? f::ContainerPlain : f::VolumePlain)));
    }
    auto combined = Hex(f::ContainerUuid); combined.insert(combined.end(),cu.begin(),cu.end());
    auto general = XtsTransform(combined,std::array<std::byte,16>{},Hex(f::ContainerCipher),XtsDirection::Decrypt);
    CHECK(!general); CHECK(general.error == CryptoError::InvalidArgument);
    const auto cipher = Hex(f::ContainerCipher);
    for (const auto length : {0u,16u,512u,4095u})
        CHECK(!DecryptApfsUuidKeybagBlock(cu,60,std::span<const std::byte>(cipher).first(length)));
    CHECK(!DecryptApfsUuidKeybagBlock(cu,UINT64_MAX,cipher));
    CHECK(!DecryptApfsUuidKeybagBlock({},60,cipher));
    std::vector<std::byte> large;
    for (auto chunk : {f::LargeCipher0,f::LargeCipher1,f::LargeCipher2,f::LargeCipher3})
    { auto part=Hex(chunk); large.insert(large.end(),part.begin(),part.end()); }
    { auto r=DecryptApfsUuidKeybagBlock(cu,0x102030405,large); CHECK(r);
      for (std::size_t i=0;i<large.size();++i) CHECK(r.bytes.Bytes()[i] == static_cast<std::byte>(i & 255)); }
    testing::hooks = {};
    { auto r=DecryptApfsUuidKeybagBlock(cu,60,cipher); CHECK(r); }
    const auto success=testing::hooks;
    for (int kind=0;kind<4;++kind)
    {
        const int n=kind==0?success.allocations:kind==1?success.locks:success.cng_calls;
        for (int i=0;i<n;++i)
        {
            testing::hooks={};
            if(kind==0) testing::hooks.allocation_failure_at=i;
            else if(kind==1) testing::hooks.lock_failure_at=i;
            else { testing::hooks.cng_failure_at=i; testing::hooks.cng_fail_after_call=kind==3; }
            auto r=DecryptApfsUuidKeybagBlock(cu,60,cipher);
            CHECK(!r); CHECK(r.bytes.Size()==0); Released();
        }
    }
    testing::hooks={};
}
std::vector<std::byte> Image(bool entries_only=false)
{
    BuilderStore spec;
    spec.authoritative_checkpoint=true;
    spec.block_count=128;
    spec.uuid_hex=std::string(f::ContainerUuid);
    spec.volumes[0].uuid_hex=std::string(f::VolumeUuid);
    spec.volumes[0].fs_flags=kFsFlagOneKey;
    auto bytes=BuildStoreImage(spec);
    // The existing generic builder emits NX type 1; this profile requires the
    // explicit Apple ephemeral NX type. Only test bytes are changed.
    for (std::size_t offset=0; offset+4096<=bytes.size(); offset+=4096)
    {
        if (ReadU32LE(bytes,offset+32)!=kNxsbMagic) continue;
        std::vector<std::byte> block(bytes.begin()+offset,bytes.begin()+offset+4096);
        PutU32LE(block,24,kObjectEphemeral|kNxSuperblockObjectType);
        PutU64LE(block,0x510,60); PutU64LE(block,0x518,1);
        (void)FletcherForBlock(block,block.size());
        std::copy(block.begin(),block.end(),bytes.begin()+offset);
    }
    const auto cb=Hex(entries_only?f::ContainerCipherEntries:f::ContainerCipher);
    const auto vb=Hex(entries_only?f::VolumeCipherEntries:f::VolumeCipher);
    std::copy(cb.begin(),cb.end(),bytes.begin()+60*4096);
    std::copy(vb.begin(),vb.end(),bytes.begin()+61*4096);
    return bytes;
}
PasswordUnlockRequest Request(bool entries=false)
{
    PasswordUnlockRequest r;
    r.checkpoint_xid=7; r.volume_oid=101;
    r.container_uuid=Uuid(f::ContainerUuid); r.volume_uuid=Uuid(f::VolumeUuid); r.user_uuid=Uuid(f::UserUuid);
    r.container_bag={901,7}; r.volume_bag={902,7};
    r.length=entries?KeybagLength::EntriesOnly:KeybagLength::IncludesHeader;
    return r;
}
PasswordUnlockResult Unlock(std::vector<std::byte> image, const PasswordUnlockRequest& request)
{
    VectorRandomAccessSource raw(std::move(image));
    auto reads=std::make_shared<ApfsReadBudget>(4096,16*1024*1024,100000,16*1024*1024);
    BudgetedRandomAccessSource source(raw,reads);
    PasswordUnlockBudget budget;
    return UnlockPasswordKeybags(source,request,Hex(f::Password),budget);
}
void FailedBound(const PasswordUnlockResult& result)
{
    CHECK(!result); CHECK(result.xts_key.Size()==0); CHECK(result.checkpoint_xid==0);
    CHECK(result.volume_oid==0); CHECK(result.volume_xid==0);
    CHECK(result.container_uuid==KeybagUuid{}); CHECK(result.volume_uuid==KeybagUuid{});
    Released();
}
void LoaderBinding()
{
    ++groups;
    for(bool entries:{false,true})
    {
        auto result=Unlock(Image(entries),Request(entries));
        CHECK(result); CHECK(Same(result.xts_key.Bytes(),Hex(f::ExpectedVek)));
        CHECK(result.checkpoint_xid==7); CHECK(result.volume_oid==101); CHECK(result.volume_xid==7);
        CHECK(result.container_uuid==Uuid(f::ContainerUuid)); CHECK(result.volume_uuid==Uuid(f::VolumeUuid));
        CHECK(result.user_uuid==Uuid(f::UserUuid));
    }
    const auto original=Image();
    for (int which=0;which<10;++which)
    {
        auto request=Request();
        if(which==0) request.container_uuid[0]^=std::byte{1};
        if(which==1) request.volume_uuid[0]^=std::byte{1};
        if(which==2) request.user_uuid[0]^=std::byte{1};
        if(which==3) request.checkpoint_xid=8;
        if(which==4) request.volume_oid=102;
        if(which==5) request.container_bag.oid=60; // no guessed paddr-as-OID
        if(which==6) request.volume_bag.xid=6;
        if(which==7) request.length=KeybagLength::EntriesOnly;
        if(which==8) request.length=static_cast<KeybagLength>(99);
        if(which==9) request.container_bag.xid=8;
        FailedBound(Unlock(original,request));
    }
    for(auto bad:{f::DuplicateContainer,f::TruncatedRef,f::MultiBlockRef,f::WrongBagType,
        f::WrongBagSubtype,f::WrongBagOid,f::FutureBagXid,f::BadLockerLength})
    {
        auto image=original; const auto bytes=Hex(bad);
        std::copy(bytes.begin(),bytes.end(),image.begin()+60*4096);
        FailedBound(Unlock(std::move(image),Request()));
    }
    for(auto bad:{f::UnknownVolumeTag,f::BadVolumeClass,f::DuplicateUser})
    {
        auto image=original; const auto bytes=Hex(bad);
        std::copy(bytes.begin(),bytes.end(),image.begin()+61*4096);
        FailedBound(Unlock(std::move(image),Request()));
    }
    for (const auto offset:{60u*4096,61u*4096,4u*4096})
    { auto image=original; image[offset]^=std::byte{1}; FailedBound(Unlock(std::move(image),Request())); }
    for (const auto length:{0u,4095u,61u*4096+4095})
    { auto image=original; image.resize(length); FailedBound(Unlock(std::move(image),Request())); }
    // The same wrapped records cannot be relocated or swapped across UUIDs.
    { auto image=original; const auto wrong=Hex(f::ContainerCipher);
      std::copy(wrong.begin(),wrong.end(),image.begin()+61*4096);
      FailedBound(Unlock(std::move(image),Request())); }
    // Valid checksum but wrong APSB OID/XID/full type, ONEKEY, OMAP identity.
    for (int which=0;which<6;++which)
    {
        auto image=original;
        const std::size_t offset=(which==5 ? 2u : 4u)*4096;
        std::vector<std::byte> block(image.begin()+offset,image.begin()+offset+4096);
        if(which==0) PutU64LE(block,8,102);
        if(which==1) PutU64LE(block,16,6);
        if(which==2) PutU32LE(block,24,kObjectPhysical|kObjectTypeFs);
        if(which==3) PutU64LE(block,0x108,0);
        if(which==4) PutU64LE(block,0x108,kFsFlagOneKey|kFsFlagUnencrypted);
        if(which==5) PutU64LE(block,8,3);
        (void)FletcherForBlock(block,block.size());
        std::copy(block.begin(),block.end(),image.begin()+offset);
        FailedBound(Unlock(std::move(image),Request()));
    }
    VectorRandomAccessSource raw(original);
    PasswordUnlockBudget budget;
    FailedBound(UnlockPasswordKeybags(raw,Request(),Hex(f::Password),budget)); // mandatory read budget
    auto exhausted=std::make_shared<ApfsReadBudget>(0,0,0,0);
    BudgetedRandomAccessSource blocked(raw,exhausted);
    PasswordUnlockBudget blocked_attempt;
    FailedBound(UnlockPasswordKeybags(blocked,Request(),Hex(f::Password),blocked_attempt));
}
void LoaderBudgets()
{
    ++groups;
    // Every cumulative read-count cutoff must preserve ResourceLimit rather
    // than masquerading as corrupt identity, unsupported layout, or I/O.
    const auto original=Image();
    VectorRandomAccessSource raw(original);
    unsigned refused=0;
    for (std::uint64_t limit=0;limit<128;++limit)
    {
        auto reads=std::make_shared<ApfsReadBudget>(limit,16*1024*1024,100000,16*1024*1024);
        BudgetedRandomAccessSource source(raw,reads);
        PasswordUnlockBudget budget;
        auto result=UnlockPasswordKeybags(source,Request(),Hex(f::Password),budget);
        if(result) { CHECK(refused>0); CHECK(!reads->Failed()); return; }
        ++refused;
        FailedBound(result);
        CHECK(reads->Failed());
        if(result.error!=UnlockError::ResourceLimit)
            throw std::runtime_error("budget cutoff " + std::to_string(limit) +
                " returned error " + std::to_string(static_cast<int>(result.error)) +
                "; expected ResourceLimit");
        CHECK(result.error==UnlockError::ResourceLimit);
    }
    CHECK(false);
}
class FaultSource final : public RandomAccessSource
{
public:
    enum class Fault { ShortTrue, LongTrue, PartialFalse, Allocation, Exception };
    FaultSource(std::vector<std::byte> bytes, std::uint64_t block, Fault fault)
        : raw_(std::move(bytes)), offset_(block*4096), fault_(fault) {}
    std::uint64_t SizeBytes() const override { return raw_.SizeBytes(); }
    bool Read(std::uint64_t offset, std::size_t size, std::vector<std::byte>& out) const override
    {
        if(offset!=offset_) return raw_.Read(offset,size,out);
        ++hits;
        out.assign(size+1,std::byte{0x5a}); // public sentinel, never credentials
        if(fault_==Fault::Allocation) throw std::bad_alloc();
        if(fault_==Fault::Exception) throw std::runtime_error("synthetic source failure");
        if(fault_!=Fault::LongTrue) out.resize(size-1);
        return fault_!=Fault::PartialFalse;
    }
    mutable unsigned hits=0;
private:
    VectorRandomAccessSource raw_;
    std::uint64_t offset_;
    Fault fault_;
};
void LoaderSourceFailures()
{
    ++groups;
    for(const auto block:{60u,61u})
    for(const auto fault:{FaultSource::Fault::ShortTrue,FaultSource::Fault::LongTrue,
        FaultSource::Fault::PartialFalse,FaultSource::Fault::Allocation,FaultSource::Fault::Exception})
    {
        testing::hooks={};
        FaultSource raw(Image(),block,fault);
        auto reads=std::make_shared<ApfsReadBudget>(4096,16*1024*1024,100000,16*1024*1024);
        BudgetedRandomAccessSource source(raw,reads);
        PasswordUnlockBudget budget;
        bool threw=false;
        try
        {
            auto result=UnlockPasswordKeybags(source,Request(),Hex(f::Password),budget);
            FailedBound(result);
            CHECK(result.error==(fault==FaultSource::Fault::Allocation?
                UnlockError::ResourceLimit:UnlockError::ReadFailure));
        }
        catch(const std::runtime_error& e)
        {
            if(std::string_view(e.what())!="synthetic source failure") throw;
            threw=true;
        }
        CHECK(threw==(fault==FaultSource::Fault::Exception));
        CHECK(raw.hits==1);
        CHECK(!reads->Failed());
        Released();
        CHECK(testing::hooks.allocations==testing::hooks.releases);
        CHECK(testing::hooks.locks==testing::hooks.unlocks);
        if(block==61) CHECK(testing::hooks.releases>0); // live decrypted first bag unwound
    }
}
void LoaderIdentityReview()
{
    ++groups;
    const auto original=Image();
    const auto selected=ReadU64LE(original,0x70).value()+1;
    struct Mutation { std::uint64_t block; std::size_t offset; std::uint64_t value; bool wide; };
    const Mutation mutations[] = {
        {selected,8,2,true}, {selected,16,6,true},
        {selected,24,kNxSuperblockObjectType,false}, {selected,28,1,false},
        {selected,0x510,UINT64_MAX,true}, {selected,0x518,2,true},
        {2,16,8,true}, {2,24,kObjectTypeOmap,false}, {2,28,1,false},
        {2,40,kObjectTypeBtree,false}, {2,48,128,true},
        {3,8,99,true}, {3,16,8,true}, {3,24,kObjectTypeBtree,false}, {3,28,0,false},
        {4,28,1,false}, {4,0xf0,0,true}};
    for(const auto& mutation:mutations)
    {
        auto bytes=original;
        const auto offset=static_cast<std::size_t>(mutation.block*4096);
        std::vector<std::byte> block(bytes.begin()+offset,bytes.begin()+offset+4096);
        if(mutation.wide) PutU64LE(block,mutation.offset,mutation.value);
        else PutU32LE(block,mutation.offset,static_cast<std::uint32_t>(mutation.value));
        (void)FletcherForBlock(block,block.size());
        std::copy(block.begin(),block.end(),bytes.begin()+offset);
        FailedBound(Unlock(std::move(bytes),Request()));
    }
}
void OmapProfileRefusals()
{
    ++groups;
    for(int which=0;which<5;++which)
    {
        auto bytes=Image();
        constexpr std::size_t offset=3*4096;
        std::vector<std::byte> block(bytes.begin()+offset,bytes.begin()+offset+4096);
        if(which==0) PutU64LE(block,16,0);
        if(which==1) PutU32LE(block,24,kObjectPhysical|kObjectTypeBtree|0x10000000u);
        if(which==2) PutU16LE(block,32,ReadU16LE(block,32).value()|0x20u);
        if(which==3) PutU16LE(block,32,ReadU16LE(block,32).value()|0x10u);
        if(which==4) PutU16LE(block,32,ReadU16LE(block,32).value()|0x08u);
        (void)FletcherForBlock(block,block.size());
        std::copy(block.begin(),block.end(),bytes.begin()+offset);
        auto result=Unlock(std::move(bytes),Request());
        if(result) throw std::runtime_error("unsupported OMAP node profile " +
            std::to_string(which) + " incorrectly unlocked");
        FailedBound(result);
    }
}
} // namespace
int main(int argc, char** argv)
{
    static_assert(!std::is_copy_constructible_v<PasswordUnlockResult>);
    static_assert(!std::is_copy_constructible_v<PasswordUnlockBudget>);
    try
    {
        const std::pair<std::string_view,void(*)()> suite[] = {
            {"RecordVectors",RecordVectors}, {"DerAdversaries",DerAdversaries},
            {"FailureSweeps",FailureSweeps}, {"RetryControl",RetryControl},
            {"OuterVectors",OuterVectors}, {"LoaderBinding",LoaderBinding},
            {"LoaderBudgets",LoaderBudgets}, {"LoaderSourceFailures",LoaderSourceFailures},
            {"LoaderIdentityReview",LoaderIdentityReview}, {"OmapProfileRefusals",OmapProfileRefusals}};
        for (const auto& [name,run]:suite)
        {
            bool selected=argc==1;
            for(int i=1;i<argc;++i) if(name==argv[i]) selected=true;
            if(!selected) continue;
            const auto before=checks;
            run();
            std::cout<<"PASS "<<name<<" / "<<(checks-before)<<" assertions\n";
        }
        if(groups==0) throw std::runtime_error("no test group selected");
        std::cout<<groups<<" groups / "<<checks<<" assertions passed (synthetic software fixtures)\n";
        return 0;
    }
    catch(const std::exception& e) { std::cerr<<e.what()<<'\n'; return 1; }
}
