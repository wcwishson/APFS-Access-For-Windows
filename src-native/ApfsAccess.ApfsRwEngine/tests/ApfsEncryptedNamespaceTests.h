#pragma once
// Canonical Apple records encoded by existing codecs, checksummed, then encrypted
// sector-by-sector. Existing independent OpenSSL ciphertext vectors remain neighbors.
#include "ApfsExtendedRecordCodec.h"
#include <map>
namespace
{
namespace rw = apfsaccess::rw;
std::vector<std::byte> NamespacePayload()
{
    std::vector<std::byte> bytes(173);
    for (std::size_t i=0; i<bytes.size(); ++i) bytes[i]=static_cast<std::byte>((i*17+91)%256);
    return bytes;
}
std::vector<BtreeRecord> NamespaceRecords(std::uint64_t features = 0)
{
    const auto policy=rw::ApfsNamePolicy::FromIncompatibleFeatures(features);
    std::string detail; std::vector<BtreeRecord> records;
    const auto add=[&](auto encode, const auto& value) {
        BtreeRecord record; CHECK(encode(value,record,detail)); records.push_back(std::move(record));
    };
    for (const auto id : {2ULL,10ULL,100ULL})
    {
        rw::AppleInodeRecord inode;
        inode.object_id=id; inode.private_id=id; inode.parent_id=id==2?1:2;
        inode.mode=id==100?0100640:0040750; inode.owner=501; inode.group=20;
        inode.children_or_links=id==10?1:3;
        inode.create_time=111; inode.modification_time=222; inode.change_time=333; inode.access_time=444;
        if(id==100)
        {
            rw::AppleExtendedField stream;stream.type=8;stream.flags=0x20;stream.data.resize(40);
            PutU64LE(stream.data,0,700);PutU64LE(stream.data,8,4096);PutU64LE(stream.data,16,500);
            inode.extended_fields.push_back(std::move(stream));
        }
        add(rw::EncodeAppleInodeRecord,inode);
    }
    const auto directory=[&](std::uint64_t parent,std::uint64_t child,std::string name,std::uint64_t sibling){
        rw::AppleDirectoryRecord d;d.parent_id=parent;d.file_id=child;d.name_utf8=std::move(name);
        d.flags=child==10?4:8;d.date_added=555;
        if(sibling){rw::AppleExtendedField field;field.type=1;field.data.resize(8);PutU64LE(field.data,0,sibling);d.extended_fields.push_back(std::move(field));}
        BtreeRecord record;CHECK(rw::EncodeAppleDirectoryRecord(d,policy,record,detail));records.push_back(std::move(record));
        if(sibling)
        {
            add(rw::EncodeAppleSiblingLinkRecord,rw::AppleSiblingLinkRecord{child,sibling,parent,d.name_utf8});
            add(rw::EncodeAppleSiblingMapRecord,rw::AppleSiblingMapRecord{sibling,child});
        }
    };
    directory(2,10,"Folder",0);directory(2,100,"Report.txt",700);
    directory(2,100,"Alias.txt",701);directory(10,100,"Other.txt",702);
    add(rw::EncodeAppleFileExtentRecord,rw::AppleFileExtentRecord{100,0,4096,100,500,4096});
    add(rw::EncodeAppleDataStreamIdRecord,rw::AppleDataStreamIdRecord{100,1});
    add(rw::EncodeAppleXattrRecord,rw::AppleXattrRecord{100,"user.note",rw::kAppleXattrDataEmbedded,NamespacePayload()});
    add(rw::EncodeAppleXattrRecord,rw::AppleXattrRecord{100,"user.Note",rw::kAppleXattrDataEmbedded,{std::byte{7}}});
    add(rw::EncodeAppleXattrRecord,rw::AppleXattrRecord{2,"user.empty",rw::kAppleXattrDataEmbedded,{}});
    return records;
}
void EncryptNamespaceBytes(std::vector<std::byte>& bytes,std::uint64_t first_unit)
{
    auto key=Key();
    for(std::size_t offset=0;offset<bytes.size();offset+=512)
    {
        std::array<std::byte,16> tweak{};
        const auto unit=first_unit+offset/512;
        for(unsigned i=0;i<8;++i)tweak[i]=static_cast<std::byte>(unit>>(8*i));
        auto encrypted=XtsTransform(key.xts_key.Bytes(),tweak,std::span(bytes).subspan(offset,512),XtsDirection::Encrypt);
        CHECK(encrypted);std::copy(encrypted.bytes.Bytes().begin(),encrypted.bytes.Bytes().end(),bytes.begin()+offset);
    }
}
void InstallNamespace(const std::shared_ptr<Source>& source,std::vector<BtreeRecord> records,std::uint64_t features=0,bool sort=true)
{
    std::string detail;
    if(sort)CHECK(rw::SortAppleBtreeRecords(records,features?rw::AppleBtreeKeyOrder::FileSystemHashedDirectory:rw::AppleBtreeKeyOrder::FileSystemCaseSensitive,detail));
    std::vector<std::vector<std::byte>> keys,values;
    for(auto& r:records){keys.push_back(std::move(r.key));values.push_back(std::move(r.value));}
    source->root=BuildRawLeafNode(keys,values,7,4096,0,8293,0x10000002,14);
    EncryptNamespaceBytes(source->root,80*8);
    source->MutateAt(4,[&](auto& block){PutU64LE(block,56,features);});
    source->data.resize(4096);
    for(std::size_t i=0;i<4096;++i)source->data[i]=static_cast<std::byte>((i*7+3)%256);
    EncryptNamespaceBytes(source->data,500*8);
}
void RenameNamespaceEntry(std::vector<BtreeRecord>& records,std::string_view before,std::string_view after,std::uint64_t features)
{
    const auto policy=rw::ApfsNamePolicy::FromIncompatibleFeatures(features);std::string detail;
    for(auto& record:records)
    {
        const auto type=ReadU64LE(record.key,0).value()>>60;
        if(type==9){rw::AppleDirectoryRecord d;CHECK(rw::ApfsExtendedRecordCodec::DecodeDirectory(record,policy,d,detail));
            if(d.name_utf8==before){d.name_utf8=after;CHECK(rw::EncodeAppleDirectoryRecord(d,policy,record,detail));}}
        if(type==5){rw::AppleSiblingLinkRecord link;CHECK(rw::ApfsExtendedRecordCodec::DecodeSiblingLink(record,link,detail));
            if(link.name_utf8==before){link.name_utf8=after;CHECK(rw::EncodeAppleSiblingLinkRecord(link,record,detail));}}
    }
}
void NamespaceRoundTrip()
{
    ++groups;
    auto source=std::make_shared<Source>();InstallNamespace(source,NamespaceRecords());
    E error;UnlockError unlock;PasswordUnlockBudget attempts;
    auto session=ApfsEncryptedReadSession::Unlock(source,source->identity,source->revision,Request(),Hex(k::Password),attempts,error,unlock);
    CHECK(session);CHECK(error==E::None);CHECK(unlock==UnlockError::None);
    EncryptedNamespaceInfo info;CHECK(session->GetNamespaceInfo(info)==E::None);
    CHECK(info.root_inode_id==2);CHECK(info.inode_count==3);CHECK(info.entry_count==4);
    CHECK(info.name_policy.case_mode==rw::ApfsCaseMode::Sensitive);
    EncryptedNodeInfo node;CHECK(session->GetMetadata(2,node)==E::None);CHECK(node.parent_id==2);CHECK(node.IsDirectory());
    CHECK(session->GetMetadata(100,node)==E::None);CHECK(node.uid==501&&node.gid==20&&node.mode==0100640);
    CHECK(node.size==700&&node.allocated_size==4096&&node.default_crypto_id==500&&node.children_or_links==3);
    CHECK(node.create_time==111&&node.modification_time==222&&node.change_time==333&&node.access_time==444);
    std::vector<EncryptedDirectoryEntry> entries;CHECK(session->ListDirectory(2,entries)==E::None);CHECK(entries.size()==3);
    CHECK(entries[0].name_utf8=="Alias.txt"&&entries[1].name_utf8=="Folder"&&entries[2].name_utf8=="Report.txt");
    CHECK(entries[2].sibling_id==700&&entries[2].date_added==555);
    CHECK(session->ListDirectory(10,entries)==E::None);CHECK(entries.size()==1&&entries[0].inode_id==100&&entries[0].parent_id==10);
    EncryptedDirectoryEntry entry;CHECK(session->Lookup(2,"Report.txt",entry)==E::None);CHECK(entry.inode_id==100&&entry.windows_name==L"Report.txt");
    CHECK(session->LookupWindows(2,L"Alias.txt",entry)==E::None);CHECK(entry.sibling_id==701);
    CHECK(session->ResolvePath(L"\\Folder\\Other.txt",node)==E::None);CHECK(node.inode_id==100&&node.parent_id==2);
    CHECK(session->ResolvePath(L"\\",node)==E::None&&node.inode_id==2);
    std::vector<EncryptedXattr> attrs;CHECK(session->ListXattrs(100,attrs)==E::None);CHECK(attrs.size()==2);
    CHECK(attrs[0].name_utf8=="user.Note"&&attrs[1].data==NamespacePayload());
    std::vector<std::byte> bytes;CHECK(session->ReadXattr(100,"user.note",bytes)==E::None&&bytes==NamespacePayload());
    CHECK(session->ReadXattr(2,"user.empty",bytes)==E::None&&bytes.empty());
    CHECK(session->ReadXattr(100,"USER.NOTE",bytes)==E::XattrNotFound&&bytes.empty());
    CHECK(session->ReadFile(100,509,191,bytes)==E::None);CHECK(bytes.size()==191);
    for(std::size_t i=0;i<bytes.size();++i)CHECK(bytes[i]==static_cast<std::byte>(((i+509)*7+3)%256));
    const auto read_count=source->reads;CHECK(session->GetMetadata(100,node)==E::None);CHECK(source->reads==read_count);
    const auto saved=attrs[1].data;session->Close();CHECK(attrs[1].data==saved);Released();
}
void NamespaceNames()
{
    ++groups;
    for(const auto features:{0ULL,1ULL,8ULL})
    {
        auto source=std::make_shared<Source>();auto records=NamespaceRecords(features);
        RenameNamespaceEntry(records,"Report.txt","Straße",features);
        RenameNamespaceEntry(records,"Alias.txt","é.txt",features);
        RenameNamespaceEntry(records,"Other.txt","bad:name.",features);
        InstallNamespace(source,std::move(records),features);E error;auto session=Open(source,error);CHECK(session);
        EncryptedDirectoryEntry entry;
        CHECK(session->Lookup(2,"STRASSE",entry)==(features==1?E::None:E::FileNotFound));
        CHECK(session->Lookup(2,"é.txt",entry)==(features?E::None:E::FileNotFound));
        CHECK(session->Lookup(10,"bad:name.",entry)==E::None);CHECK(entry.windows_name.starts_with(rw::ApfsNameCodec::EscapePrefix()));
        const auto windows=entry.windows_name;CHECK(session->LookupWindows(10,windows,entry)==E::None);
        EncryptedNodeInfo node;CHECK(session->ResolvePath(L"\\Folder\\"+windows,node)==E::None&&node.inode_id==100);
        CHECK(session->LookupWindows(10,L"bad:name.",entry)==E::InvalidArgument&&entry.inode_id==0);
        session->Close();Released();
    }
    for(const auto pair:{std::pair{"Report.txt","report.txt"},std::pair{"é.txt","é.txt"},std::pair{"Straße","STRASSE"}})
    for(const auto features:{0ULL,1ULL,8ULL})
    {
        auto records=NamespaceRecords(features);RenameNamespaceEntry(records,"Report.txt",pair.first,features);
        RenameNamespaceEntry(records,"Alias.txt",pair.second,features);
        auto source=std::make_shared<Source>();InstallNamespace(source,std::move(records),features);
        E error;auto session=Open(source,error);
        const bool collision=features==1||(features==8&&std::string_view(pair.first)=="é.txt");
        CHECK(static_cast<bool>(session)==!collision);CHECK(error==(collision?E::MetadataIntegrityFailure:E::None));
        if(session)session->Close();Released();
    }
}
void NamespaceRefusals()
{
    ++groups;
    for(int fault=0;fault<20;++fault)
    {
        auto records=NamespaceRecords();
        for(auto& r:records)
        {
            const auto header=ReadU64LE(r.key,0).value(),type=header>>60,id=header&0x0fffffffffffffffULL;
            if(fault==0&&type==9&&id==10)PutU64LE(r.value,0,999); // dangling child
            if(fault==1&&type==9&&id==10)PutU64LE(r.key,0,(9ULL<<60)|999); // missing parent
            if(fault==2&&type==9&&id==10)PutU64LE(r.key,0,(9ULL<<60)|100); // file parent
            if(fault==3&&type==3&&id==100)PutU64LE(r.value,0,999); // primary parent
            if(fault==4&&type==3&&id==2)PutU32LE(r.value,56,7); // child count
            if(fault==5&&type==3&&id==100)PutU32LE(r.value,56,2); // link count
            if(fault==6&&type==12&&id==700)PutU64LE(r.value,0,999); // map owner
            if(fault==7&&type==5&&ReadU64LE(r.key,8)==700)PutU64LE(r.value,0,10); // sibling parent
            if(fault==8&&type==9&&id==10)PutU16LE(r.value,16,4); // drec type
            if(fault==9&&type==4)PutU64LE(r.key,0,(4ULL<<60)|999); // xattr owner
            if(fault==10&&type==3&&id==100)PutU32LE(r.value,68,rw::kAppleBsdCompressedFlag);
            if(fault==11&&type==3&&id==100)PutU16LE(r.value,80,0120777); // symlink
            if(fault==12&&type==9&&id==10)r.value.push_back(std::byte{1}); // bad xfield envelope
            if(fault==13&&type==3&&id==2)PutU64LE(r.value,0,999); // root parent
            if(fault==14&&type==9&&id==10)PutU64LE(r.value,0,2); // root incoming
            if(fault==15&&type==3&&id==100)PutU64LE(r.value,48,0x40000000); // unknown inode layout
            if(fault==16&&type==9&&id==10)PutU16LE(r.value,16,0x108); // special drec flag
            if(fault==17&&type==9&&id==10)r.key.back()=std::byte{1}; // missing NUL
            if(fault==18&&type==9&&id==10){r.key[10]=std::byte{0xc0};r.key[11]=std::byte{0x80};} // invalid UTF-8
            if(fault==19&&type==9&&id==10){r.key[10]=std::byte{'.'};r.key.resize(12);r.key[11]=std::byte{};PutU16LE(r.key,8,2);} // dot
        }
        auto source=std::make_shared<Source>();InstallNamespace(source,std::move(records),0,fault!=17);
        E error;auto session=Open(source,error);CHECK(!session);
        CHECK(error==((fault==10||fault==11||fault==15||fault==16)?E::UnsupportedEncryptionLayout:E::MetadataIntegrityFailure));Released();
    }
    for(const auto type:{5ULL,7ULL,12ULL})
    {
        auto records=NamespaceRecords();
        if(type==7){BtreeRecord r;r.key.resize(8);PutU64LE(r.key,0,7ULL<<60|100);r.value.resize(24);records.push_back(r);}
        else records.erase(std::find_if(records.begin(),records.end(),[&](const auto& r){return ReadU64LE(r.key,0).value()>>60==type;}));
        auto source=std::make_shared<Source>();InstallNamespace(source,std::move(records));E error;CHECK(!Open(source,error));
        CHECK(error==(type==7?E::UnsupportedEncryptionLayout:E::MetadataIntegrityFailure));Released();
    }
    // Valid external-xattr descriptor is an explicit unsupported layout.
    auto records=NamespaceRecords();std::string detail;rw::AppleXattrRecord xattr{100,"user.external",rw::kAppleXattrDataStream,{}};
    xattr.data.resize(48);PutU64LE(xattr.data,0,900);PutU64LE(xattr.data,8,4096);PutU64LE(xattr.data,16,4096);PutU64LE(xattr.data,24,500);
    BtreeRecord r;CHECK(rw::EncodeAppleXattrRecord(xattr,r,detail));records.push_back(r);
    auto source=std::make_shared<Source>();InstallNamespace(source,std::move(records));E error;CHECK(!Open(source,error));CHECK(error==E::UnsupportedEncryptionLayout);
    // Baseline inode-only support is preserved without a fabricated namespace.
    source=std::make_shared<Source>();auto session=Open(source,error);CHECK(session);EncryptedNamespaceInfo info;
    CHECK(session->GetNamespaceInfo(info)==E::NamespaceUnavailable&&info.root_inode_id==0);session->Close();Released();
}
}
namespace
{
class NamespaceIdentity final : public ImmutableEncryptedReadSource
{
public:
    std::shared_ptr<Source> inner=std::make_shared<Source>();
    std::shared_ptr<std::atomic<bool>> stop=std::make_shared<std::atomic<bool>>(false);
    mutable unsigned calls=0;
    unsigned trigger=0;int action=0;
    std::string SourceIdentity() const override
    {
        if(++calls==trigger)
        {
            if(action==0)throw std::runtime_error("namespace publication fault");
            if(action==1)stop->store(true);
            if(action==2)++inner->revision;
            if(action==3)inner->budget->Refuse("namespace-final-check");
        }
        return inner->identity;
    }
    std::uint64_t Revision() const override{return inner->Revision();}
    std::uint64_t SizeBytes() const override{return inner->SizeBytes();}
    std::shared_ptr<ApfsReadBudget> ReadBudget() const override{return inner->ReadBudget();}
    bool Read(std::uint64_t o,std::size_t n,std::vector<std::byte>& out) const override{return inner->Read(o,n,out);}
};
void NamespaceLifecycle()
{
    ++groups;
    for(int operation=0;operation<8;++operation)
    for(int fault=0;fault<4;++fault)
    {
        auto source=std::make_shared<NamespaceIdentity>();InstallNamespace(source->inner,NamespaceRecords());
        E error;auto session=ApfsEncryptedReadSession::OpenForTesting(source,Key(),error,source->stop);CHECK(session);
        const auto invoke=[&](E expected){
            E got=E::None;
            EncryptedNamespaceInfo info;info.root_inode_id=123;
            EncryptedNodeInfo inode;inode.inode_id=123;
            EncryptedDirectoryEntry entry;entry.inode_id=123;entry.name_utf8="sentinel";
            std::vector<EncryptedDirectoryEntry> entries{entry};
            std::vector<EncryptedXattr> attrs(1);std::vector<std::byte> bytes{std::byte{1}};
            switch(operation)
            {
            case 0:got=session->GetNamespaceInfo(info);break;
            case 1:got=session->GetMetadata(100,inode);break;
            case 2:got=session->ListDirectory(2,entries);break;
            case 3:got=session->Lookup(2,"Report.txt",entry);break;
            case 4:got=session->LookupWindows(2,L"Report.txt",entry);break;
            case 5:got=session->ResolvePath(L"\\Folder\\Other.txt",inode);break;
            case 6:got=session->ListXattrs(100,attrs);break;
            case 7:got=session->ReadXattr(100,"user.note",bytes);break;
            }
            if(got!=expected)std::cerr<<"operation="<<operation<<" fault="<<fault<<" got="<<static_cast<int>(got)<<" expected="<<static_cast<int>(expected)<<"\n";
            CHECK(got==expected);
            if(expected!=E::None)
            {
                if(operation==0)CHECK(info.root_inode_id==0);
                if(operation==1||operation==5)CHECK(inode.inode_id==0);
                if(operation==2)CHECK(entries.empty());
                if(operation==3||operation==4)CHECK(entry.inode_id==0&&entry.name_utf8.empty()&&entry.windows_name.empty());
                if(operation==6)CHECK(attrs.empty());
                if(operation==7)CHECK(bytes.empty());
            }
        };
        source->calls=0;invoke(E::None);const auto final_check=source->calls;CHECK(final_check>0);
        source->calls=0;source->trigger=final_check;source->action=fault;
        const auto expected=fault==0?E::ReadFailure:fault==1?E::Cancelled:fault==2?E::SourceIdentityMismatch:E::ResourceLimit;
        invoke(expected);CHECK(source->calls==final_check);
        session->Close();invoke(E::Closed);Released();
    }
    // Sticky cancellation while traversing encrypted metadata.
    auto source=std::make_shared<NamespaceIdentity>();InstallNamespace(source->inner,NamespaceRecords());
    source->inner->before=[&](auto offset){if(offset==80ULL*4096)source->stop->store(true);};
    E error;CHECK(!ApfsEncryptedReadSession::OpenForTesting(source,Key(),error,source->stop));CHECK(error==E::Cancelled);Released();
    // Every operation also refuses a substituted read budget, even at equal revision.
    source=std::make_shared<NamespaceIdentity>();InstallNamespace(source->inner,NamespaceRecords());
    auto session=ApfsEncryptedReadSession::OpenForTesting(source,Key(),error);CHECK(session);
    source->inner->budget=std::make_shared<ApfsReadBudget>(10000,10000000,100000,10000000);EncryptedNamespaceInfo info;
    CHECK(session->GetNamespaceInfo(info)==E::SourceIdentityMismatch&&info.root_inode_id==0);session->Close();Released();
}
void NamespacePublicationCleanup()
{
    ++groups;
    const auto payload=NamespacePayload();
    for(const bool list:{false,true})
    {
        auto source=std::make_shared<NamespaceIdentity>();InstallNamespace(source->inner,NamespaceRecords());
        E error;auto session=ApfsEncryptedReadSession::OpenForTesting(source,Key(),error);CHECK(session);
        std::vector<std::byte> bytes;std::vector<EncryptedXattr> attrs;
        const auto invoke=[&]{return list?session->ListXattrs(100,attrs):session->ReadXattr(100,"user.note",bytes);};
        source->calls=0;CHECK(invoke()==E::None);const auto final_check=source->calls;
        bytes.clear();attrs.clear();source->calls=0;source->trigger=final_check;
        allocation_observer::Watch watch(payload);
        CHECK(invoke()==E::ReadFailure);const auto observed=watch.Stop();
        CHECK(bytes.empty()&&attrs.empty());CHECK(observed.intact==0&&observed.zero>0&&observed.live==0&&!observed.overflow);
        source->trigger=0;
        // Allocation failure in an unpublished xattr payload after a name copy.
        allocation_observer::Watch allocation(payload);allocation.FailAllocation(payload.size(),0);
        CHECK(invoke()==E::ResourceLimit);CHECK(allocation.Failures()==1);const auto failed=allocation.Stop();
        CHECK(bytes.empty()&&attrs.empty());CHECK(failed.intact==0&&failed.live==0&&!failed.overflow);
        session->Close();Released();
    }
    // Observe owned payload at failed initialization and at Close. No returned
    // caller-owned copy is present in either watched scope.
    for(const bool late_failure:{false,true})
    {
        auto source=std::make_shared<NamespaceIdentity>();InstallNamespace(source->inner,NamespaceRecords());
        E error;source->calls=0;auto session=ApfsEncryptedReadSession::OpenForTesting(source,Key(),error);CHECK(session);
        const auto final_check=source->calls;session->Close();source->calls=0;
        if(late_failure)source->trigger=final_check;
        auto key=Key();allocation_observer::Watch watch(payload);
        session=ApfsEncryptedReadSession::OpenForTesting(source,std::move(key),error);
        CHECK(static_cast<bool>(session)==!late_failure);
        if(session)session->Close();
        const auto observed=watch.Stop();CHECK(observed.intact==0&&observed.zero>0&&observed.live==0&&!observed.overflow);Released();
    }
}
void NamespaceGraphsAndEdges()
{
    ++groups;
    std::string detail;
    // Empty root is complete and enumerable.
    auto records=NamespaceRecords();records.erase(std::remove_if(records.begin(),records.end(),[](const auto& r){return ReadU64LE(r.key,0)!=(3ULL<<60|2);}),records.end());
    PutU32LE(records[0].value,56,0);
    auto source=std::make_shared<Source>();InstallNamespace(source,records);E error;auto session=Open(source,error);CHECK(session);
    std::vector<EncryptedDirectoryEntry> entries(1);CHECK(session->ListDirectory(2,entries)==E::None&&entries.empty());session->Close();
    // A detached cycle can satisfy all local counts and parent references.
    records=NamespaceRecords();
    for(const auto id:{20ULL,30ULL})
    {
        rw::AppleInodeRecord inode;inode.object_id=id;inode.private_id=id;inode.parent_id=id==20?30:20;
        inode.mode=0040755;inode.children_or_links=1;BtreeRecord r;CHECK(rw::EncodeAppleInodeRecord(inode,r,detail));records.push_back(r);
        rw::AppleDirectoryRecord d;d.parent_id=inode.parent_id;d.file_id=id;d.flags=4;d.name_utf8=id==20?"twenty":"thirty";
        CHECK(rw::EncodeAppleDirectoryRecord(d,rw::ApfsNamePolicy{},r,detail));records.push_back(r);
    }
    source=std::make_shared<Source>();InstallNamespace(source,records);CHECK(!Open(source,error));CHECK(error==E::MetadataIntegrityFailure);Released();
    // Genuine hash collision with distinct canonical names must stay usable.
    std::map<std::uint32_t,std::string> names;std::pair<std::string,std::string> collision;
    const auto policy=rw::ApfsNamePolicy::FromIncompatibleFeatures(1);
    std::uint64_t random=0x9e3779b97f4a7c15ULL;
    for(unsigned i=0;i<30000&&collision.first.empty();++i)
    {
        random^=random<<13;random^=random>>7;random^=random<<17;
        const auto name="collision-"+std::to_string(random);
        const auto decoded=rw::ApfsNameCodec::Decode(std::as_bytes(std::span(name)),policy);CHECK(decoded.ok());
        const auto [at,inserted]=names.emplace(*decoded.value->directory_hash,name);
        if(!inserted)collision={at->second,name};
    }
    CHECK(!collision.first.empty());std::cout<<"distinct canonical hash collision: "<<collision.first<<" / "<<collision.second<<"\n";records=NamespaceRecords(1);
    RenameNamespaceEntry(records,"Report.txt",collision.first,1);RenameNamespaceEntry(records,"Alias.txt",collision.second,1);
    source=std::make_shared<Source>();InstallNamespace(source,records,1);session=Open(source,error);CHECK(session);
    EncryptedDirectoryEntry entry;CHECK(session->Lookup(2,collision.first,entry)==E::None&&entry.sibling_id==700);
    CHECK(session->Lookup(2,collision.second,entry)==E::None&&entry.sibling_id==701);session->Close();
    for(auto& r:records)if(ReadU64LE(r.key,0).value()>>60==9){PutU32LE(r.key,8,ReadU32LE(r.key,8).value()^0x400);break;}
    source=std::make_shared<Source>();InstallNamespace(source,records,1);CHECK(!Open(source,error));CHECK(error==E::MetadataIntegrityFailure);Released();
    source=std::make_shared<Source>();InstallNamespace(source,NamespaceRecords());session=Open(source,error);CHECK(session);
    EncryptedNodeInfo node;std::vector<EncryptedXattr> attrs(1);
    CHECK(session->ListDirectory(100,entries)==E::NotDirectory&&entries.empty());
    CHECK(session->ListDirectory(999,entries)==E::FileNotFound&&entries.empty());
    CHECK(session->Lookup(100,"name",entry)==E::NotDirectory&&entry.inode_id==0);
    CHECK(session->Lookup(2,"report.txt",entry)==E::FileNotFound&&entry.inode_id==0);
    CHECK(session->ListXattrs(999,attrs)==E::FileNotFound&&attrs.empty());
    CHECK(session->GetMetadata(999,node)==E::FileNotFound&&node.inode_id==0);
    for(const auto path:{L"",L"relative",L"\\Folder\\",L"\\\\Folder",L"\\.\\Folder",L"\\..",L"\\Report.txt\\child",L"/Folder"})
    {CHECK(session->ResolvePath(path,node)!=E::None);CHECK(node.inode_id==0);}
    CHECK(session->ResolvePath(std::wstring(32769,L'a'),node)==E::InvalidArgument);
    for(const auto name:{"",".","..","a/b"})CHECK(session->Lookup(2,name,entry)==E::InvalidArgument&&entry.inode_id==0);
    CHECK(session->Lookup(2,std::string(256,'a'),entry)==E::InvalidArgument);
    session->Cancel();CHECK(session->GetMetadata(100,node)==E::Cancelled&&node.inode_id==0);session->Close();Released();
}
}
namespace
{
void NamespaceBudgetsAndReferences()
{
    ++groups;
    for(int fault=0;fault<4;++fault)
    {
        auto records=NamespaceRecords();
        for(auto& r:records)
        {
            const auto h=ReadU64LE(r.key,0).value(),type=h>>60;
            if(fault==0&&type==6)PutU64LE(r.key,0,6ULL<<60|999);
            if(fault==1&&type==6)PutU32LE(r.value,0,2);
            if(fault==2&&type==3&&(h&0x0fffffffffffffffULL)==100)
            {rw::AppleInodeRecord inode;std::string detail;CHECK(rw::ApfsExtendedRecordCodec::DecodeInode(r,inode,detail));PutU64LE(inode.extended_fields[0].data,8,8192);CHECK(rw::EncodeAppleInodeRecord(inode,r,detail));}
            if(fault==3&&type==4){rw::AppleXattrRecord a;std::string detail;CHECK(rw::ApfsExtendedRecordCodec::DecodeXattr(r,a,detail));
                if(a.name_utf8=="user.note"){a.name_utf8="com.apple.decmpfs";CHECK(rw::EncodeAppleXattrRecord(a,r,detail));}}
        }
        auto source=std::make_shared<Source>();InstallNamespace(source,std::move(records));E error;CHECK(!Open(source,error));
        CHECK(error==(fault==3?E::UnsupportedEncryptionLayout:E::MetadataIntegrityFailure));Released();
    }
    // An output reservation failure after a complete open must not yield a
    // successful partial directory or xattr list. Repeated attempts stay refused.
    for(const auto bytes:{0ULL,128ULL,500ULL})
    for(const bool attributes:{false,true})
    {
        auto source=std::make_shared<Source>();InstallNamespace(source,NamespaceRecords());E error;auto session=Open(source,error);CHECK(session);
        source->budget->LimitRemainingTo(UINT64_MAX,UINT64_MAX,UINT64_MAX,bytes);
        std::vector<EncryptedDirectoryEntry> directory(1);std::vector<EncryptedXattr> attrs(1);
        const auto result=attributes?session->ListXattrs(100,attrs):session->ListDirectory(2,directory);
        // Larger budgets may admit a complete list; smaller reservations refuse.
        if(result==E::None)CHECK(bytes==500);
        else {CHECK(result==E::ResourceLimit);CHECK(attributes?attrs.empty():directory.empty());CHECK(source->budget->Failed());}
        session->Close();Released();
    }
    // Scalar, lookup and path reservations use the same held cumulative budget.
    for(int operation=0;operation<6;++operation)
    {
        auto source=std::make_shared<Source>();InstallNamespace(source,NamespaceRecords());E error;auto session=Open(source,error);CHECK(session);
        source->budget->LimitRemainingTo(UINT64_MAX,UINT64_MAX,0,0);
        EncryptedNamespaceInfo info;EncryptedNodeInfo inode;EncryptedDirectoryEntry entry;std::vector<std::byte> out;
        const auto result=operation==0?session->GetNamespaceInfo(info):operation==1?session->GetMetadata(100,inode):
            operation==2?session->Lookup(2,"Report.txt",entry):operation==3?session->LookupWindows(2,L"Report.txt",entry):
            operation==4?session->ResolvePath(L"\\Folder\\Other.txt",inode):session->ReadXattr(100,"user.note",out);
        CHECK(result==E::ResourceLimit);CHECK(info.root_inode_id==0&&inode.inode_id==0&&entry.inode_id==0&&out.empty());
        session->Close();Released();
    }
}
class BlockingNamespaceIdentity final : public ImmutableEncryptedReadSource
{
public:
    std::shared_ptr<Source> inner=std::make_shared<Source>();
    mutable std::mutex mutex;mutable std::condition_variable cv;
    mutable bool entered=false,resume=false;bool armed=false;
    std::string SourceIdentity() const override
    {
        if(armed){std::unique_lock lock(mutex);entered=true;cv.notify_all();cv.wait(lock,[&]{return resume;});}
        return inner->SourceIdentity();
    }
    std::uint64_t Revision() const override{return inner->Revision();}
    std::uint64_t SizeBytes() const override{return inner->SizeBytes();}
    std::shared_ptr<ApfsReadBudget> ReadBudget() const override{return inner->ReadBudget();}
    bool Read(std::uint64_t o,std::size_t n,std::vector<std::byte>& out) const override{return inner->Read(o,n,out);}
};
void NamespaceCloseDrain()
{
    ++groups;
    auto source=std::make_shared<BlockingNamespaceIdentity>();InstallNamespace(source->inner,NamespaceRecords());
    E error;auto session=ApfsEncryptedReadSession::OpenForTesting(source,Key(),error);CHECK(session);
    source->armed=true;std::vector<EncryptedXattr> out;E result=E::None;std::atomic<bool> closed=false;
    std::thread reader([&]{result=session->ListXattrs(100,out);});
    {std::unique_lock lock(source->mutex);source->cv.wait(lock,[&]{return source->entered;});}
    session->Cancel();std::thread closer([&]{session->Close();closed=true;});CHECK(!closed.load());
    {std::lock_guard lock(source->mutex);source->resume=true;}source->cv.notify_all();
    reader.join();closer.join();CHECK(closed.load());CHECK(result==E::Cancelled&&out.empty());
    CHECK(session->ListXattrs(100,out)==E::Closed);Released();
}
}
