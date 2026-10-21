#include "../include/NativeSnapshotIntent.h"
#include "WriteAheadLog.h"
#include "BlockDevice.h"
#include <bcrypt.h>
#include <iostream>
#include <fstream>
#include <iterator>
#include <limits>
#include <stdexcept>
#include <utility>
using namespace apfsaccess::rw;

namespace {
std::uint64_t ReadWire64(std::span<const std::byte> bytes,std::size_t at){
    if(at>bytes.size()||bytes.size()-at<8)throw std::runtime_error("test wire field truncated");
    std::uint64_t value=0;for(unsigned i=0;i<8;++i)value|=std::uint64_t(std::to_integer<unsigned char>(bytes[at+i]))<<(8*i);return value;
}
void PatchWire64(std::vector<std::byte>& bytes,std::size_t at,std::uint64_t value){
    (void)ReadWire64(bytes,at);for(unsigned i=0;i<8;++i)bytes[at+i]=std::byte((value>>(8*i))&255);
}
struct TextWire {std::size_t length=0,data=0,size=0;};
struct PeerWire {std::size_t oid=0;TextWire uuid,journal;};
struct ReceiptWire {
    std::size_t version=0,kind=0,bus=0,code_set=0,vpd_type=0,vpd_length=0,identifier=0;
    TextWire vendor,product,revision,serial,selected;
    std::size_t disk_guid=0,partition_guid=0,partition_offset=0,partition_length=0,base=0,limit=0,disk_size=0;
    std::size_t logical_sector=0,physical_sector=0,peer_count=0,end=0;
    std::vector<PeerWire> peers;
};
ReceiptWire LocateReceipt(std::span<const std::byte> bytes,std::size_t start){
    // Walk only the valid fixture to locate fields; malformed bytes never use the production encoder.
    std::size_t at=start;
    const auto word=[&](){const auto field=at;(void)ReadWire64(bytes,at);at+=8;return field;};
    const auto skip=[&](std::uint64_t count){if(at>bytes.size()||count>bytes.size()-at)throw std::runtime_error("test wire extent truncated");at+=static_cast<std::size_t>(count);};
    const auto text=[&](){TextWire field;field.length=word();field.data=at;const auto count=ReadWire64(bytes,field.length);skip(count);field.size=static_cast<std::size_t>(count);return field;};
    ReceiptWire result;result.version=word();result.kind=word();result.bus=word();
    result.vendor=text();result.product=text();result.revision=text();result.serial=text();
    result.code_set=word();result.vpd_type=word();result.vpd_length=word();result.identifier=at;skip(ReadWire64(bytes,result.vpd_length));
    result.disk_guid=at;skip(16);result.partition_guid=at;skip(16);
    result.partition_offset=word();result.partition_length=word();result.base=word();result.limit=word();result.disk_size=word();
    result.logical_sector=word();result.physical_sector=word();result.selected=text();result.peer_count=word();
    const auto count=ReadWire64(bytes,result.peer_count);if(count>100)throw std::runtime_error("test fixture peer count invalid");
    for(std::uint64_t i=0;i<count;++i){PeerWire peer;peer.oid=word();peer.uuid=text();peer.journal=text();result.peers.push_back(peer);}
    result.end=at;return result;
}
void ReplaceWireText(std::vector<std::byte>& bytes,const TextWire& field,std::string_view text){
    bytes.erase(bytes.begin()+field.data,bytes.begin()+field.data+field.size);
    std::vector<std::byte> replacement;for(unsigned char c:text)replacement.push_back(std::byte(c));
    bytes.insert(bytes.begin()+field.data,replacement.begin(),replacement.end());PatchWire64(bytes,field.length,text.size());
}
void ReplaceWireIdentifier(std::vector<std::byte>& bytes,const ReceiptWire& fields,std::span<const std::byte> identifier){
    const auto old=ReadWire64(bytes,fields.vpd_length);
    bytes.erase(bytes.begin()+fields.identifier,bytes.begin()+fields.identifier+static_cast<std::size_t>(old));
    bytes.insert(bytes.begin()+fields.identifier,identifier.begin(),identifier.end());PatchWire64(bytes,fields.vpd_length,identifier.size());
}
void AppendWalLe(std::vector<std::uint8_t>& bytes,std::uint64_t value,unsigned width){
    for(unsigned i=0;i<width;++i)bytes.push_back(static_cast<std::uint8_t>((value>>(8*i))&255));
}
void PatchWal32(std::vector<std::uint8_t>& bytes,std::size_t at,std::uint32_t value){
    for(unsigned i=0;i<4;++i)bytes.at(at+i)=static_cast<std::uint8_t>((value>>(8*i))&255);
}
void RepairWalChecksum(std::vector<std::uint8_t>& bytes){
    PatchWal32(bytes,12,0);std::uint32_t checksum=2166136261u;
    for(auto byte:bytes){checksum^=byte;checksum*=16777619u;}PatchWal32(bytes,12,checksum);
}
std::vector<std::uint8_t> IndependentSnapshotWal(const WriteAheadLog::Record& record){
    // Fixed v2 envelope construction bypasses EncodeForTest's shape rejection.
    std::vector<std::uint8_t> bytes;
    AppendWalLe(bytes,0x574c4141,4);AppendWalLe(bytes,2,2);AppendWalLe(bytes,152,2);AppendWalLe(bytes,0,4);AppendWalLe(bytes,0,4);
    AppendWalLe(bytes,record.transaction_id,8);AppendWalLe(bytes,record.sequence,8);
    AppendWalLe(bytes,static_cast<std::uint32_t>(record.operation),4);AppendWalLe(bytes,static_cast<std::uint32_t>(record.state),4);
    for(auto value:{record.object_id,record.parent_object_id,record.payload_spool_id,record.payload_offset,record.payload_length,
        record.logical_offset,record.logical_length,record.flags})AppendWalLe(bytes,value,8);
    for(auto size:{record.path_utf8.size(),record.secondary_path_utf8.size(),record.volume_identity.size(),record.inline_payload.size()})AppendWalLe(bytes,size,4);
    bytes.insert(bytes.end(),record.payload_sha256.begin(),record.payload_sha256.end());
    if(bytes.size()!=152)throw std::runtime_error("test v2 header size invalid");
    for(const auto* text:{&record.path_utf8,&record.secondary_path_utf8,&record.volume_identity})bytes.insert(bytes.end(),text->begin(),text->end());
    for(auto byte:record.inline_payload)bytes.push_back(std::to_integer<std::uint8_t>(byte));
    if(bytes.size()>UINT32_MAX)throw std::runtime_error("test WAL size overflow");
    PatchWal32(bytes,8,static_cast<std::uint32_t>(bytes.size()));RepairWalChecksum(bytes);return bytes;
}
bool IntentIsReset(const NativeSnapshotIntent& value){
    const NativeSnapshotIntent empty;
    return value.create==empty.create&&value.scope==empty.scope&&value.snapshot_xid==0&&value.time_ns==0&&value.inum==0&&value.name.empty()&&
        value.expected_identity==empty.expected_identity&&value.inventory.empty()&&value.pins.empty()&&value.preimage_hash==empty.preimage_hash&&
        value.publication_hash==empty.publication_hash&&value.checkpoint_slot==0&&value.checkpoint_slot_preimage.empty()&&!value.raw_receipt;
}
}

int main(){NativeSnapshotIntent p;p.scope={0,4096*1024,std::string(32,'a'),std::string(32,'b'),101,20};p.snapshot_xid=21;p.name="one";p.time_ns=1;p.pins={20};p.expected_identity={p.scope,21,"one",1,2,3,4,5,6};p.expected_identity.scope.checkpoint_xid=21;
    WriteAheadLog::Record r;r.operation=static_cast<WriteAheadLog::OperationKind>(18);r.object_id=101;r.parent_object_id=21;r.path_utf8="\\";r.inline_payload=EncodeNativeSnapshotIntent(p);r.payload_length=r.inline_payload.size();
    BCRYPT_ALG_HANDLE a=nullptr;if(BCryptOpenAlgorithmProvider(&a,BCRYPT_SHA256_ALGORITHM,nullptr,0)<0)return 2;
    auto s=BCryptHash(a,nullptr,0,reinterpret_cast<PUCHAR>(r.inline_payload.data()),static_cast<ULONG>(r.inline_payload.size()),r.payload_sha256.data(),32);BCryptCloseAlgorithmProvider(a,0);if(s<0)return 2;
    unsigned checks=0;auto check=[&](bool value){++checks;if(!value)throw std::runtime_error("snapshot WAL invariant "+std::to_string(checks));};
    unsigned decoder_negatives=0,reset_checks=0,vpd_roundtrips=0,unknown_sector_roundtrips=0,wal_shape_negatives=0,wal_integrity_negatives=0,wal_rid_negatives=0,wal_controls=0;
    const auto require=[&](bool value,const std::string& label){++checks;if(!value)throw std::runtime_error(label+" (check "+std::to_string(checks)+")");};
    try{
        check(WriteAheadLog::InlinePayloadIsConsistent(r));
        r.volume_identity="apfs-vol:"+p.scope.container_uuid_hex+":101";r.transaction_id=1;r.sequence=1;
        const auto hash=[&](auto&record){BCRYPT_ALG_HANDLE a=nullptr;check(BCryptOpenAlgorithmProvider(&a,BCRYPT_SHA256_ALGORITHM,nullptr,0)>=0);check(BCryptHash(a,nullptr,0,reinterpret_cast<PUCHAR>(record.inline_payload.data()),static_cast<ULONG>(record.inline_payload.size()),record.payload_sha256.data(),32)>=0);BCryptCloseAlgorithmProvider(a,0);};
        for(auto version:{1,3,99})check(WriteAheadLog::EncodeForTest(r,static_cast<std::uint16_t>(version)).empty());
        const auto encoded=WriteAheadLog::EncodeForTest(r,2);check(!encoded.empty());{std::ofstream f("snapshot-envelope.wal",std::ios::binary);f.write(reinterpret_cast<const char*>(encoded.data()),encoded.size());}
        auto read=WriteAheadLog::ReadAll("snapshot-envelope.wal",r.volume_identity);check(read.status==WriteAheadLog::ReadStatus::Ok&&read.records.size()==1&&read.records[0].inline_payload==r.inline_payload);
        for(unsigned mode=0;mode<6;++mode){auto bad=r;if(mode==0)++bad.parent_object_id;if(mode==1)bad.operation=static_cast<WriteAheadLog::OperationKind>(17);if(mode==2)bad.operation=static_cast<WriteAheadLog::OperationKind>(19);if(mode==3)bad.inline_payload[0]^=std::byte{1};if(mode==4)bad.inline_payload.push_back(std::byte{});if(mode==5)bad.logical_length=1;hash(bad);check(WriteAheadLog::EncodeForTest(bad).empty());}
        for(unsigned mode=0;mode<5;++mode){auto bad=p;if(mode==0)bad.pins={0};if(mode==1)bad.pins={20,20};if(mode==2)bad.scope.container_uuid_hex=std::string(32,'0');if(mode==3)bad.name=std::string(256,'x');if(mode==4)bad.snapshot_xid=19;NativeSnapshotIntent decoded;check(!DecodeNativeSnapshotIntent(EncodeNativeSnapshotIntent(bad),decoded));}
        const auto original_snp1=EncodeNativeSnapshotIntent(p);NativeSnapshotIntent legacy;
        constexpr std::array<std::uint8_t,32> golden_snp1={
            0x5b,0x2d,0xce,0xce,0xa3,0x27,0x81,0x2e,0xd9,0x4a,0xd7,0x88,0xe6,0x33,0xe5,0xa6,
            0x05,0x23,0xd2,0x21,0x1d,0x51,0xce,0x61,0x69,0x73,0xfe,0xe2,0xa3,0xeb,0x9c,0xb3};
        check(original_snp1.size()==334&&r.payload_sha256==golden_snp1);
        check(DecodeNativeSnapshotIntent(original_snp1,legacy)&&!legacy.raw_receipt&&EncodeNativeSnapshotIntent(legacy)==original_snp1);
        NativeRawSnapshotReceipt receipt;auto&binding=receipt.binding;
        binding.hardware.kind=RawHardwareIdentityKind::QualifiedSerialTuple;binding.hardware.bus_type=BusTypeUsb;
        binding.hardware.vendor="Samsung";binding.hardware.product="Flash Drive FIT";binding.hardware.revision="1100";binding.hardware.serial="AA00000000000489";
        binding.media.disk_guid.fill(std::byte{0x0a});binding.media.partition_guid.fill(std::byte{0x0b});
        binding.media.partition_offset_bytes=binding.media.base_offset_bytes=1048576;
        binding.media.partition_length_bytes=binding.media.limit_bytes=p.scope.store_size_bytes;binding.media.disk_size_bytes=8388608;
        binding.media.logical_sector_bytes=512;binding.media.physical_sector_bytes=4096;
        receipt.selected_journal_identity="apfs-recovery-v1-selected";
        receipt.peers={{101,p.scope.volume_uuid_hex,receipt.selected_journal_identity},{102,std::string(32,'c'),"apfs-recovery-v1-sibling"}};
        auto raw=p;raw.raw_receipt=receipt;const auto snp2=EncodeNativeSnapshotIntent(raw);NativeSnapshotIntent decoded;
        check(!snp2.empty()&&snp2!=original_snp1&&DecodeNativeSnapshotIntent(snp2,decoded));
        check(decoded.raw_receipt==raw.raw_receipt&&EncodeNativeSnapshotIntent(decoded)==snp2);
        auto raw_record=r;raw_record.volume_identity=receipt.selected_journal_identity;
        raw_record.inline_payload=snp2;raw_record.payload_length=snp2.size();hash(raw_record);
        check(WriteAheadLog::SnapshotIntentIsConsistent(raw_record));
        const auto raw_encoded=WriteAheadLog::EncodeForTest(raw_record);check(!raw_encoded.empty());
        {std::ofstream f("snapshot-raw-envelope.wal",std::ios::binary);f.write(reinterpret_cast<const char*>(raw_encoded.data()),raw_encoded.size());check(!!f);}
        const auto raw_read=WriteAheadLog::ReadAll("snapshot-raw-envelope.wal",raw_record.volume_identity);
        check(raw_read.status==WriteAheadLog::ReadStatus::Ok&&raw_read.records.size()==1&&raw_read.records[0].inline_payload==snp2);
        auto raw_delete=raw;raw_delete.create=false;raw_delete.snapshot_xid=18;
        raw_delete.expected_identity.scope=raw_delete.scope;raw_delete.expected_identity.snapshot_xid=18;
        raw_delete.inventory={raw_delete.expected_identity};const auto delete_snp2=EncodeNativeSnapshotIntent(raw_delete);
        check(!delete_snp2.empty()&&DecodeNativeSnapshotIntent(delete_snp2,decoded)&&!decoded.create&&decoded.raw_receipt==raw.raw_receipt);
        auto delete_record=raw_record;delete_record.operation=WriteAheadLog::OperationKind::DeleteSnapshot;
        delete_record.inline_payload=delete_snp2;delete_record.payload_length=delete_snp2.size();hash(delete_record);
        check(WriteAheadLog::SnapshotIntentIsConsistent(delete_record)&&!WriteAheadLog::EncodeForTest(delete_record).empty());
        auto wrong_record=raw_record;wrong_record.volume_identity="apfs-recovery-v1-substitute";
        check(!WriteAheadLog::SnapshotIntentIsConsistent(wrong_record)&&WriteAheadLog::EncodeForTest(wrong_record).empty());
        wrong_record=raw_record;wrong_record.inline_payload.back()^=std::byte{1};
        check(!WriteAheadLog::SnapshotIntentIsConsistent(wrong_record));
        for(unsigned mode=0;mode<11;++mode){
            auto bad=raw;auto&proof=*bad.raw_receipt;
            if(mode==0)proof.binding.version=2;
            if(mode==1)proof.binding.hardware.serial="0000000000000000";
            if(mode==2)proof.binding.hardware.kind=RawHardwareIdentityKind::Unavailable;
            if(mode==3)proof.binding.media.limit_bytes+=4096;
            if(mode==4)proof.binding.media.disk_guid={};
            if(mode==5)proof.peers.push_back(proof.peers.back());
            if(mode==6)std::swap(proof.peers[0],proof.peers[1]);
            if(mode==7)proof.peers.erase(proof.peers.begin());
            if(mode==8)proof.peers[1].journal_identity=proof.peers[0].journal_identity;
            if(mode==9)proof.selected_journal_identity="apfs-recovery-v1-other";
            if(mode==10)proof.peers[0].volume_uuid_hex=std::string(32,'d');
            check(EncodeNativeSnapshotIntent(bad).empty());
        }
        for(std::size_t at=0;at<snp2.size();++at)check(!DecodeNativeSnapshotIntent(std::span<const std::byte>(snp2).first(at),decoded));
        auto malformed=snp2;malformed.push_back(std::byte{0});check(!DecodeNativeSnapshotIntent(malformed,decoded));
        malformed=snp2;malformed[0]=std::byte{0x53};malformed[3]=std::byte{0x33};check(!DecodeNativeSnapshotIntent(malformed,decoded));

        const auto receipt_start=original_snp1.size()-64;
        const auto fields=LocateReceipt(snp2,receipt_start);
        require(receipt_start==270&&fields.end+64==snp2.size()&&fields.peers.size()==2,"serial receipt field map");
        require(ReadWire64(snp2,230)==0&&ReadWire64(snp2,238)==1&&ReadWire64(snp2,262)==0,"golden fixture count offsets");
        NativeSnapshotIntent populated=raw_delete;populated.checkpoint_slot=7;populated.checkpoint_slot_preimage={std::byte{0xa5},std::byte{0x5a}};
        populated.preimage_hash.fill(0x5a);populated.publication_hash.fill(0xa5);
        const auto populated_bytes=EncodeNativeSnapshotIntent(populated);
        require(DecodeNativeSnapshotIntent(populated_bytes,populated),"populated output fixture decodes");
        const auto reject_decode=[&](const std::string& label,const std::vector<std::byte>& bytes){
            auto output=populated;output.inum=7;++decoder_negatives;
            require(!DecodeNativeSnapshotIntent(bytes,output),label+": decoder rejection");
            ++reset_checks;require(IntentIsReset(output),label+": complete output reset");
        };
        const auto read_independent=[&](const std::string& label,const std::vector<std::uint8_t>& bytes,const std::string& identity){
            const char* path="snapshot-raw-independent.wal";
            {std::ofstream file(path,std::ios::binary|std::ios::trunc);require(!!file,label+": open WAL");
                file.write(reinterpret_cast<const char*>(bytes.data()),static_cast<std::streamsize>(bytes.size()));file.close();require(!!file,label+": write WAL");}
            auto result=WriteAheadLog::ReadAll(path,identity);
            std::ifstream file(path,std::ios::binary);require(!!file,label+": reopen evidence");
            const std::vector<std::uint8_t> after((std::istreambuf_iterator<char>(file)),{});
            require(!file.bad()&&after==bytes,label+": reader preserves exact WAL bytes");return result;
        };
        const auto reject_wal=[&](const std::string& label,const std::vector<std::uint8_t>& bytes,const std::string& identity,WriteAheadLog::ReadStatus status){
            const auto result=read_independent(label,bytes,identity);
            require(result.status==status&&result.records.empty()&&!result.recovered_torn_tail,label+": exact reader rejection status");
        };
        const auto independent=IndependentSnapshotWal(raw_record);
        require(independent==raw_encoded,"independent v2 bytes match valid serial envelope");
        const auto independent_read=read_independent("serial WAL control",independent,raw_record.volume_identity);++wal_controls;
        require(independent_read.status==WriteAheadLog::ReadStatus::Ok&&independent_read.records.size()==1&&
            independent_read.records[0].inline_payload==snp2&&!independent_read.recovered_torn_tail,"independent serial WAL control");

        struct Negative {std::string label;std::vector<std::byte> bytes;};
        std::vector<Negative> negatives;
        const auto word_case=[&](const std::string& label,const std::vector<std::byte>& valid,std::size_t at,std::uint64_t value){
            auto bytes=valid;PatchWire64(bytes,at,value);negatives.push_back({label,std::move(bytes)});
        };
        const auto text_case=[&](const std::string& label,const std::vector<std::byte>& valid,const TextWire& field,std::string_view text){
            auto bytes=valid;ReplaceWireText(bytes,field,text);negatives.push_back({label,std::move(bytes)});
        };
        constexpr auto u64max=(std::numeric_limits<std::uint64_t>::max)();
        constexpr auto narrow_overflow=std::uint64_t{UINT32_MAX}+1;
        for(const auto& entry:std::vector<std::pair<const char*,std::size_t>>{
            {"version",fields.version},{"bus",fields.bus},{"VPD code set",fields.code_set},{"VPD type",fields.vpd_type},
            {"logical sector",fields.logical_sector},{"physical sector",fields.physical_sector}})
            word_case(std::string(entry.first)+" uint32 overflow",snp2,entry.second,narrow_overflow);
        for(const auto& entry:std::vector<std::pair<const char*,std::size_t>>{
            {"vendor length",fields.vendor.length},{"product length",fields.product.length},{"revision length",fields.revision.length},
            {"serial length",fields.serial.length},{"selected journal length",fields.selected.length},{"peer UUID length",fields.peers[1].uuid.length},
            {"peer journal length",fields.peers[1].journal.length},{"VPD length",fields.vpd_length},{"peer count",fields.peer_count},
            {"inventory count",230},{"pin count",238},{"preimage length",262}})
            word_case(std::string(entry.first)+" UINT64_MAX",snp2,entry.second,u64max);
        word_case("inventory count 65",snp2,230,65);word_case("pin count 65",snp2,238,65);
        word_case("preimage length 65537",snp2,262,65537);
        word_case("preimage length beyond remaining",snp2,262,snp2.size()-receipt_start+1);
        word_case("peer count zero",snp2,fields.peer_count,0);word_case("peer count 101",snp2,fields.peer_count,101);
        word_case("identifier length 257",snp2,fields.vpd_length,257);
        word_case("text length 256",snp2,fields.vendor.length,256);
        word_case("bounded text beyond remaining",snp2,fields.peers[1].journal.length,snp2.size()-fields.peers[1].journal.data+1);
        word_case("unsupported binding version",snp2,fields.version,2);
        word_case("binding version zero",snp2,fields.version,0);
        for(auto kind:{0ull,3ull,256ull})word_case("unsupported hardware kind "+std::to_string(kind),snp2,fields.kind,kind);
        for(auto bus:{BusTypeUnknown,BusTypeVirtual,BusTypeFileBackedVirtual,BusTypeSpaces,BusTypeMax})
            word_case("unsupported bus "+std::to_string(static_cast<unsigned>(bus)),snp2,fields.bus,static_cast<std::uint64_t>(bus));
        for(const auto& entry:std::vector<std::pair<const char*,TextWire>>{
            {"vendor",fields.vendor},{"product",fields.product},{"revision",fields.revision},{"serial",fields.serial}}){
            text_case(std::string(entry.first)+" above shape text bound",snp2,entry.second,std::string(129,'x'));
            for(auto byte:{0u,0x1fu,0x7fu,0x80u}){auto bytes=snp2;bytes[entry.second.data]=std::byte(byte);
                negatives.push_back({std::string(entry.first)+" invalid byte "+std::to_string(byte),std::move(bytes)});}
        }
        text_case("generic vendor",snp2,fields.vendor,"UNKNOWN");text_case("generic product",snp2,fields.product,"GENERIC");
        text_case("generic serial",snp2,fields.serial,"0000000000000000");text_case("short serial",snp2,fields.serial,"AB1");
        text_case("noncanonical vendor padding",snp2,fields.vendor," Samsung");
        text_case("noncanonical revision padding",snp2,fields.revision,"1100 ");
        text_case("selected journal empty",snp2,fields.selected,"");
        text_case("peer journal empty",snp2,fields.peers[1].journal,"");
        for(auto byte:{0u,0x20u,0x7fu,0x80u}){
            auto bytes=snp2;bytes[fields.selected.data]=std::byte(byte);negatives.push_back({"selected journal invalid byte "+std::to_string(byte),std::move(bytes)});
            bytes=snp2;bytes[fields.peers[1].journal.data]=std::byte(byte);negatives.push_back({"peer journal invalid byte "+std::to_string(byte),std::move(bytes)});
        }
        word_case("selected peer OID zero",snp2,fields.peers[0].oid,0);
        word_case("duplicate peer OID",snp2,fields.peers[1].oid,101);
        word_case("selected peer absent",snp2,fields.peers[0].oid,100);
        {auto bytes=snp2;PatchWire64(bytes,fields.peers[0].oid,102);PatchWire64(bytes,fields.peers[1].oid,101);negatives.push_back({"peer OIDs out of order",std::move(bytes)});}
        text_case("duplicate peer UUID",snp2,fields.peers[1].uuid,receipt.peers[0].volume_uuid_hex);
        text_case("duplicate peer journal",snp2,fields.peers[1].journal,receipt.peers[0].journal_identity);
        text_case("selected UUID belongs to sibling",snp2,fields.peers[0].uuid,receipt.peers[1].volume_uuid_hex);
        text_case("selected journal belongs to sibling",snp2,fields.selected,receipt.peers[1].journal_identity);
        text_case("peer UUID zero",snp2,fields.peers[1].uuid,std::string(32,'0'));
        text_case("peer UUID uppercase",snp2,fields.peers[1].uuid,std::string(32,'C'));
        word_case("serial scheme with VPD code set",snp2,fields.code_set,StorageIdCodeSetBinary);
        word_case("serial scheme with VPD type",snp2,fields.vpd_type,StorageIdTypeEUI64);
        for(auto at:{fields.disk_guid,fields.partition_guid}){auto bytes=snp2;std::fill_n(bytes.begin()+at,16,std::byte{0});
            negatives.push_back({at==fields.disk_guid?"zero disk GUID":"zero partition GUID",std::move(bytes)});}
        word_case("store limit mismatch",snp2,fields.limit,p.scope.store_size_bytes+4096);
        word_case("logical sector not power of two",snp2,fields.logical_sector,513);
        word_case("logical sector zero",snp2,fields.logical_sector,0);
        for(auto physical:{1u,256u,768u})word_case("invalid nonzero physical sector "+std::to_string(physical),snp2,fields.physical_sector,physical);
        {auto bytes=snp2;PatchWire64(bytes,fields.logical_sector,4096);PatchWire64(bytes,fields.physical_sector,512);negatives.push_back({"physical sector below logical",std::move(bytes)});}
        word_case("base below partition",snp2,fields.base,0);
        word_case("base unaligned",snp2,fields.base,1048577);
        word_case("partition length unaligned",snp2,fields.partition_length,p.scope.store_size_bytes+1);
        word_case("disk size unaligned",snp2,fields.disk_size,8388609);
        word_case("disk size zero",snp2,fields.disk_size,0);
        word_case("partition exceeds disk",snp2,fields.partition_length,8388608);
        word_case("base window exceeds partition",snp2,fields.base,1048576+512);
        word_case("base window arithmetic overflow",snp2,fields.base,u64max-511);
        {auto bytes=snp2;PatchWire64(bytes,fields.partition_offset,u64max-1048575);PatchWire64(bytes,fields.base,u64max-1048575);
            PatchWire64(bytes,fields.disk_size,u64max-511);negatives.push_back({"partition end arithmetic overflow",std::move(bytes)});}
        word_case("checkpoint increment overflow",snp2,120,u64max);
        word_case("unsupported SNP magic",snp2,0,0x33504e53);word_case("unsupported operation",snp2,8,17);
        {auto bytes=snp2;bytes.resize(fields.disk_guid+31);negatives.push_back({"truncated GUID pair",std::move(bytes)});}
        {auto bytes=snp2;bytes.resize(fields.peers[1].journal.data+fields.peers[1].journal.size-1);negatives.push_back({"truncated peer text",std::move(bytes)});}
        {auto bytes=snp2;bytes.pop_back();negatives.push_back({"63 trailing digest bytes",std::move(bytes)});}
        {auto bytes=snp2;bytes.push_back(std::byte{0});negatives.push_back({"65 trailing digest bytes",std::move(bytes)});}

        struct VpdCase {const char* label;std::uint32_t type;std::vector<std::byte> identifier;};
        std::vector<VpdCase> vpd_cases={{"EUI64",StorageIdTypeEUI64,{std::byte{0x00},std::byte{0x11},std::byte{0x22},std::byte{0x33},std::byte{0x44},std::byte{0x55},std::byte{0x66},std::byte{0x77}}}};
        for(auto naa:{2u,3u,5u,6u}){std::vector<std::byte> identifier(naa==6?16:8);identifier[0]=std::byte((naa<<4)|1);
            for(std::size_t i=1;i<identifier.size();++i)identifier[i]=std::byte(i);
            vpd_cases.push_back({naa==2?"NAA2":naa==3?"NAA3":naa==5?"NAA5":"NAA6",StorageIdTypeFCPHName,std::move(identifier)});}
        for(const auto& vpd:vpd_cases){
            for(bool deletion:{false,true}){
                auto valid=deletion?raw_delete:raw;auto&hardware=valid.raw_receipt->binding.hardware;
                hardware.kind=RawHardwareIdentityKind::QualifiedDeviceVpd;hardware.serial.clear();hardware.vpd_code_set=StorageIdCodeSetBinary;
                hardware.vpd_type=vpd.type;hardware.vpd_identifier=vpd.identifier;
                const auto bytes=EncodeNativeSnapshotIntent(valid);const auto label=std::string(vpd.label)+(deletion?" delete":" create");
                NativeSnapshotIntent output=populated;
                require(!bytes.empty()&&DecodeNativeSnapshotIntent(bytes,output),label+": canonical decode");
                require(output.create==valid.create&&output.raw_receipt==valid.raw_receipt&&EncodeNativeSnapshotIntent(output)==bytes,label+": canonical round trip");++vpd_roundtrips;
                auto record=deletion?delete_record:raw_record;record.inline_payload=bytes;record.payload_length=bytes.size();hash(record);
                require(WriteAheadLog::SnapshotIntentIsConsistent(record),label+": valid WAL shape");
                const auto wal=IndependentSnapshotWal(record);require(wal==WriteAheadLog::EncodeForTest(record),label+": independent WAL bytes");
                const auto result=read_independent(label,wal,record.volume_identity);++wal_controls;
                require(result.status==WriteAheadLog::ReadStatus::Ok&&result.records.size()==1&&result.records[0].inline_payload==bytes&&!result.recovered_torn_tail,label+": valid WAL reader");
                if(deletion)continue;
                const auto vpd_fields=LocateReceipt(bytes,receipt_start);
                require(vpd_fields.end+64==bytes.size(),label+": VPD field map");
                word_case(label+" ASCII code set",bytes,vpd_fields.code_set,StorageIdCodeSetAscii);
                word_case(label+" UTF8 code set",bytes,vpd_fields.code_set,StorageIdCodeSetUtf8);
                word_case(label+" unsupported code set",bytes,vpd_fields.code_set,UINT32_MAX);
                word_case(label+" unsupported VPD type",bytes,vpd_fields.vpd_type,StorageIdTypeScsiNameString);
                word_case(label+" VPD type zero",bytes,vpd_fields.vpd_type,0);
                word_case(label+" VPD type overflow",bytes,vpd_fields.vpd_type,narrow_overflow);
                word_case(label+" VPD code set overflow",bytes,vpd_fields.code_set,narrow_overflow);
                word_case(label+" VPD length overflow",bytes,vpd_fields.vpd_length,u64max);
                word_case(label+" VPD length 257",bytes,vpd_fields.vpd_length,257);
                text_case(label+" mixed serial scheme",bytes,vpd_fields.serial,"AA00000000000489");
                for(auto size:{std::size_t{0},vpd.identifier.size()-1,vpd.identifier.size()+1}){
                    auto bad=bytes;auto identifier=vpd.identifier;identifier.resize(size,std::byte{0x12});ReplaceWireIdentifier(bad,vpd_fields,identifier);
                    negatives.push_back({label+" identifier size "+std::to_string(size),std::move(bad)});
                }
                for(auto fill:{std::byte{0},std::byte{0x11}}){auto bad=bytes;std::fill_n(bad.begin()+vpd_fields.identifier,vpd.identifier.size(),fill);
                    negatives.push_back({label+" generic identifier "+std::to_string(std::to_integer<unsigned>(fill)),std::move(bad)});}
                {auto bad=bytes;bad.resize(vpd_fields.identifier+vpd.identifier.size()-1);negatives.push_back({label+" identifier exceeds remaining",std::move(bad)});}
                if(vpd.type==StorageIdTypeFCPHName){
                    for(auto first:{0x01u,0x11u,0x41u,0x71u,vpd.identifier.size()==16?0x51u:0x61u}){
                        auto bad=bytes;bad[vpd_fields.identifier]=std::byte(first);negatives.push_back({label+" invalid NAA prefix "+std::to_string(first),std::move(bad)});
                    }
                }else{auto bad=bytes;auto identifier=vpd.identifier;identifier.resize(16,std::byte{0x12});ReplaceWireIdentifier(bad,vpd_fields,identifier);
                    negatives.push_back({label+" 16-byte EUI",std::move(bad)});}
            }
        }
        for(const auto& negative:negatives){
            reject_decode(negative.label,negative.bytes);
            auto record=raw_record;record.inline_payload=negative.bytes;record.payload_length=negative.bytes.size();hash(record);
            // SHA-256 and outer checksum are valid, so the reader must reach snapshot decoding.
            reject_wal(negative.label,IndependentSnapshotWal(record),record.volume_identity,WriteAheadLog::ReadStatus::Corrupt);++wal_shape_negatives;
        }
        {auto bytes=snp2;bytes.resize(131073);reject_decode("payload above decoder size limit",bytes);}
        {auto bytes=snp2;bytes.resize(199);reject_decode("payload below decoder size limit",bytes);}

        {
            auto bytes=snp2;PatchWire64(bytes,fields.physical_sector,0);
            auto expected=raw;expected.raw_receipt->binding.media.physical_sector_bytes=0;
            NativeSnapshotIntent output=populated;
            require(DecodeNativeSnapshotIntent(bytes,output),"unknown physical sector zero decodes as data");
            require(output.raw_receipt==expected.raw_receipt&&output.scope==expected.scope&&EncodeNativeSnapshotIntent(output)==bytes,
                "unknown physical sector round trip preserves logical sector and remaining binding");++unknown_sector_roundtrips;
            auto record=raw_record;record.inline_payload=bytes;record.payload_length=bytes.size();hash(record);
            require(WriteAheadLog::SnapshotIntentIsConsistent(record),"unknown physical sector valid WAL shape");
            const auto wal=IndependentSnapshotWal(record);
            require(wal==WriteAheadLog::EncodeForTest(record),"unknown physical sector independent WAL bytes");
            const auto result=read_independent("unknown physical sector WAL control",wal,record.volume_identity);++wal_controls;
            require(result.status==WriteAheadLog::ReadStatus::Ok&&result.records.size()==1&&result.records[0].inline_payload==bytes&&!result.recovered_torn_tail,
                "unknown physical sector valid WAL reader");
        }

        auto stale=raw_record;stale.inline_payload[fields.serial.data+fields.serial.size-1]^=std::byte{1};
        NativeSnapshotIntent changed;
        require(DecodeNativeSnapshotIntent(stale.inline_payload,changed)&&changed.raw_receipt&&
            changed.raw_receipt->binding.hardware.serial!=receipt.binding.hardware.serial&&EncodeNativeSnapshotIntent(changed)==stale.inline_payload,
            "receipt-only mutation retains canonical shape");
        require(!WriteAheadLog::SnapshotIntentIsConsistent(stale),"receipt-only mutation rejects stale payload digest");
        reject_wal("receipt-only stale payload digest",IndependentSnapshotWal(stale),stale.volume_identity,WriteAheadLog::ReadStatus::Corrupt);++wal_integrity_negatives;
        hash(stale);require(WriteAheadLog::SnapshotIntentIsConsistent(stale),"receipt-only mutation accepts repaired digest");
        const auto repaired_read=read_independent("receipt digest repair control",IndependentSnapshotWal(stale),stale.volume_identity);++wal_controls;
        require(repaired_read.status==WriteAheadLog::ReadStatus::Ok&&repaired_read.records.size()==1&&
            repaired_read.records[0].inline_payload==stale.inline_payload,"receipt digest repair reader control");
        {auto bytes=independent;bytes.back()^=1;reject_wal("unrepaired outer checksum",bytes,raw_record.volume_identity,WriteAheadLog::ReadStatus::ChecksumMismatch);++wal_integrity_negatives;}
        for(const auto& identity:std::vector<std::string>{receipt.peers[1].journal_identity,receipt.selected_journal_identity+"x",""}){
            auto record=raw_record;record.volume_identity=identity;
            require(!WriteAheadLog::SnapshotIntentIsConsistent(record),"exact selected RID rejects "+identity);
            reject_wal("selected RID mismatch "+identity,IndependentSnapshotWal(record),identity,WriteAheadLog::ReadStatus::Corrupt);++wal_rid_negatives;
        }
        reject_wal("configured RID mismatch",independent,receipt.peers[1].journal_identity,WriteAheadLog::ReadStatus::VolumeMismatch);++wal_rid_negatives;
        check(EncodeNativeSnapshotIntent(p)==original_snp1);
        std::cout<<"SnapshotRuntimeWalTests: "<<checks<<" checks, 0 failures\n"
            <<"SNP2 decoder negatives: "<<decoder_negatives<<", output reset checks: "<<reset_checks
            <<", canonical VPD round trips: "<<vpd_roundtrips<<", unknown physical sector round trips: "<<unknown_sector_roundtrips<<"\n"
            <<"Independent WAL shape negatives: "<<wal_shape_negatives<<", integrity negatives: "<<wal_integrity_negatives
            <<", RID negatives: "<<wal_rid_negatives<<", valid reader controls: "<<wal_controls<<"\n";return 0;
    }catch(const std::exception&e){std::cerr<<e.what()<<"\n"
        <<"Progress: decoder negatives="<<decoder_negatives<<", output resets="<<reset_checks<<", VPD round trips="<<vpd_roundtrips
        <<", unknown physical sector round trips="<<unknown_sector_roundtrips
        <<", WAL shape negatives="<<wal_shape_negatives<<", WAL integrity negatives="<<wal_integrity_negatives
        <<", WAL RID negatives="<<wal_rid_negatives<<", WAL controls="<<wal_controls<<"\n";return 1;}
}
