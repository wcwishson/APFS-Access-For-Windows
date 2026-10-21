#include "NativeApfsReader.h"
#include "ApfsExtendedRecordCodec.h"
#include "TestFixtureBuilder.h"
#include <iostream>
using namespace apfsaccess::rw;
using namespace apfsaccess::catalog;
using namespace apfsaccess::testfixture;
using Record=apfsaccess::catalog::BtreeRecord;
namespace
{
unsigned cases=0,checks=0;
void Check(bool okay,const char* why){++checks;if(!okay)throw std::runtime_error(why);}
std::vector<Record> Records(unsigned fault)
{
    std::vector<Record> rows;std::string error;
    const auto add=[&](auto value,auto encode){Record raw;Check(encode(value,raw,error),error.c_str());rows.push_back(std::move(raw));};
    AppleInodeRecord root;root.object_id=root.private_id=root.parent_id=2;root.mode=0040755;root.children_or_links=1;add(root,EncodeAppleInodeRecord);
    AppleInodeRecord link;link.object_id=link.private_id=30;link.parent_id=2;link.mode=0120777;link.children_or_links=1;
    link.uncompressed_size=77;
    if(fault==1||fault==2||fault==8){link.internal_flags=kAppleInodeHasUncompressedSize;link.uncompressed_size=fault==2?7:6;}
    if(fault==7)link.extended_fields.push_back({8,0,std::vector<std::byte>(40)});
    add(link,EncodeAppleInodeRecord);
    AppleDirectoryRecord entry;entry.parent_id=2;entry.file_id=30;entry.flags=10;entry.name_utf8="link";
    Record dir;Check(EncodeAppleDirectoryRecord(entry,{},dir,error),error.c_str());rows.push_back(std::move(dir));
    AppleXattrRecord target;target.object_id=30;target.name_utf8="com.apple.fs.symlink";target.flags=kAppleXattrDataEmbedded|kAppleXattrFileSystemOwned;
    for(const auto c:std::string("target"))target.data.push_back(std::byte(c));target.data.push_back(std::byte{0});
    if(fault==3)target.data[2]=std::byte{0};
    if(fault==4)target.data.push_back(std::byte{0});
    if(fault==5)target.flags=kAppleXattrDataEmbedded;
    if(fault==6)target.data={std::byte{0}};
    if(fault==8){target.flags=kAppleXattrDataEmbedded;target.data.pop_back();}
    add(target,EncodeAppleXattrRecord);
    Check(SortAppleBtreeRecords(rows,AppleBtreeKeyOrder::FileSystemCaseSensitive,error),error.c_str());return rows;
}
}
int main()try
{
    BuilderStore spec;auto image=BuildStoreImage(spec);const auto nx=ParseNxSuperblock(std::vector<std::byte>(image.begin(),image.begin()+4096));
    auto apsb=ParseApsb(std::vector<std::byte>(image.begin()+4*4096,image.begin()+5*4096));Check(nx&&apsb,"canonical container/volume fixture");
    for(unsigned fault=0;fault<9;++fault)
    {
        const auto records=Records(fault);auto budget=std::make_shared<ApfsReadBudget>(10000,1<<20,10000,1<<20);std::string error;
        NativeApfsVolumeProjection projection;
        const auto okay=NativeApfsReader::TryProjectObservationalFileSystemRecords(records,*nx,*apsb,budget,projection,error);
        const bool expected=fault==0||fault==1||fault==8;
        Check(okay==expected,("observational target variant "+std::to_string(fault)+":"+error).c_str());
        if(okay){const auto link=std::find_if(projection.inodes.begin(),projection.inodes.end(),[](const auto& inode){return inode.object_id==30;});
            Check(link!=projection.inodes.end()&&link->logical_size==6&&link->symlink_target_utf8=="target","exact target excludes one terminator");}
        else Check(projection.inodes.empty(),"malformed target cannot publish partial namespace");
        for(unsigned repeat=0;repeat<2;++repeat)
            Check(NativeApfsReader::ValidateOrdinaryFileSystemRecords(records,*nx,*apsb,budget,error)==(fault==8),"strict mutation/default import unchanged cold/warm");
        ++cases;
    }
    std::cout<<"PASS "<<cases<<" cases / "<<checks<<" checks; exact observational symlink target\n";return 0;
}
catch(const std::exception& error){std::cerr<<"FAIL "<<error.what()<<'\n';return 1;}
