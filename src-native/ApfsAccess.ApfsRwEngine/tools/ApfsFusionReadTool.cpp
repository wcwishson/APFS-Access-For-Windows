// Narrow clean-layout Windows Fusion image reader. No test-source admission.
#include "ApfsFusionReadSession.h"
#include <algorithm>
#include <atomic>
#include <map>
#include <set>
#include <sstream>
#include <thread>
#include <iomanip>
using namespace apfsaccess;
namespace {
struct PublicFailure { const char* name; int exit; };
std::atomic<bool> control_cancel{false};
BOOL WINAPI Control(DWORD event) {
    if (event <= CTRL_SHUTDOWN_EVENT) { control_cancel = true; return TRUE; }
    return FALSE;
}
std::uint64_t Number(const std::wstring& text)
{
    if (text.empty()) throw PublicFailure{"InvalidPublicNumber", 2};
    std::uint64_t value = 0;
    for (wchar_t c : text)
    {
        if (c < L'0' || c > L'9' || value > (UINT64_MAX - (c-L'0'))/10)
            throw PublicFailure{"InvalidPublicNumber", 2};
        value = value*10 + c-L'0';
    }
    return value;
}
std::string Ascii(const std::wstring& value)
{
    std::string result;
    for (wchar_t c : value)
    {
        if (c < 0x20 || c > 0x7e) throw PublicFailure{"InvalidPublicSelector", 2};
        result.push_back(static_cast<char>(c));
    }
    return result;
}
struct Handle
{
    HANDLE value = nullptr;
    ~Handle() { if (value && value != INVALID_HANDLE_VALUE) CloseHandle(value); }
};
// Watchdog outlives exception cleanup and final diagnostics. No buffered output.
class Operation final
{
public:
    std::shared_ptr<std::atomic<bool>> cancellation = std::make_shared<std::atomic<bool>>(false);
    Operation()
    {
        if (!DuplicateHandle(GetCurrentProcess(), GetCurrentThread(), GetCurrentProcess(),
            &main_thread_.value, THREAD_TERMINATE, FALSE, 0)) throw PublicFailure{"CancellationSetupFailure",3};
        SetDeadline(30000);
        monitor_ = std::jthread([this](std::stop_token stop) {
            while (!stop.stop_requested()) {
                const auto event = external_.load();
                if (control_cancel.load() || GetTickCount64() >= deadline_.load() ||
                    (event && WaitForSingleObject(event, 0) == WAIT_OBJECT_0)) cancellation->store(true);
                if (cancellation->load()) {
                    CancelSynchronousIo(main_thread_.value);
                    if (!cancel_at_) cancel_at_ = GetTickCount64();
                    if (GetTickCount64() - cancel_at_ > 1000) TerminateProcess(GetCurrentProcess(), 6);
                }
                Sleep(5);
            }
        });
    }
    void SetDeadline(std::uint64_t ms) { deadline_.store(GetTickCount64() + ms); }
    bool IsCancelled() noexcept
    {
        const auto event = external_.load();
        if (control_cancel.load() || GetTickCount64() >= deadline_.load() ||
            (event && WaitForSingleObject(event, 0) == WAIT_OBJECT_0))
            cancellation->store(true);
        return cancellation->load();
    }
    void Check()
    {
        if (IsCancelled()) throw PublicFailure{"Cancelled", 6};
    }
    void SetCancellationHandle(std::uint64_t value)
    {
        const auto inherited = reinterpret_cast<HANDLE>(static_cast<uintptr_t>(value));
        DWORD flags = 0;
        if (!value || value > UINTPTR_MAX || inherited == GetStdHandle(STD_INPUT_HANDLE) ||
            inherited == GetStdHandle(STD_OUTPUT_HANDLE) || inherited == GetStdHandle(STD_ERROR_HANDLE) ||
            !GetHandleInformation(inherited, &flags) || !(flags & HANDLE_FLAG_INHERIT))
            throw PublicFailure{"InvalidCancellationHandle",2};
        Handle candidate;
        if (!DuplicateHandle(GetCurrentProcess(), inherited, GetCurrentProcess(), &candidate.value,
                SYNCHRONIZE | 0x0001 /* EVENT_QUERY_STATE */, FALSE, 0)) throw PublicFailure{"InvalidCancellationHandle",2};
        // NtQueryEvent rejects non-events. NotificationEvent (0) is manual reset.
        using QueryEvent = LONG (NTAPI*)(HANDLE, int, void*, ULONG, ULONG*);
        const auto query = reinterpret_cast<QueryEvent>(GetProcAddress(GetModuleHandleW(L"ntdll.dll"), "NtQueryEvent"));
        struct EventInfo { LONG type, state; } info{};
        ULONG returned = 0;
        if (!query || query(candidate.value, 0, &info, sizeof(info), &returned) < 0 ||
            returned != sizeof(info) || info.type != 0) throw PublicFailure{"InvalidCancellationHandle",2};
        external_owner_.value = candidate.value; candidate.value = nullptr;
        external_.store(external_owner_.value);
        CloseHandle(inherited);
    }
    void Output(HANDLE handle, const void* data, std::size_t size)
    {
        Check();
        // One process emits at most 64 MiB, including repeated JSON results.
        if (size > 64 * 1024 * 1024 - output_bytes_)
            throw PublicFailure{"OutputLimit", 2};
        output_bytes_ += size;
        const auto* bytes = static_cast<const std::byte*>(data);
        std::size_t done = 0;
        while (done < size) {
            Check();
            DWORD written = 0;
            if (!WriteFile(handle, bytes+done, static_cast<DWORD>((std::min)(size-done,std::size_t{4096})), &written,nullptr) || !written)
                throw PublicFailure{cancellation->load() ? "Cancelled" : "OutputFailure", cancellation->load() ? 6 : 8};
            done += written;
        }
        Check();
    }
    void Output(const std::string& text) { Output(GetStdHandle(STD_OUTPUT_HANDLE),text.data(),text.size()); }
    // Best effort; the watchdog remains active during this synchronous write.
    void Status(const std::string& text) noexcept
    {
        DWORD written = 0;
        WriteFile(GetStdHandle(STD_ERROR_HANDLE),text.data(),
            static_cast<DWORD>((std::min)(text.size(), std::size_t{4096})),&written,nullptr);
    }
private:
    Handle main_thread_, external_owner_;
    std::atomic<HANDLE> external_{nullptr};
    std::atomic<ULONGLONG> deadline_{0};
    ULONGLONG cancel_at_ = 0;
    std::size_t output_bytes_ = 0;
    std::jthread monitor_; // Joins before handles/cancellation are destroyed.
};

std::string Hex(std::span<const std::byte> bytes) {
    constexpr char digits[]="0123456789abcdef"; std::string out;
    for(auto b:bytes) { const auto n=std::to_integer<unsigned>(b); out+=digits[n>>4];out+=digits[n&15]; } return out;
}
std::string Identity(const catalog::FusionImageIdentity& id) {
    return std::to_string(id.volume_serial)+":"+Hex(id.file_id)+":"+std::to_string(id.size_bytes)+":"+
        std::to_string(id.creation_time)+":"+std::to_string(id.write_time);
}
catalog::FusionImageIdentity ParseIdentity(const std::wstring& text) {
    std::vector<std::wstring> fields; std::wistringstream input(text); std::wstring part;
    while(std::getline(input,part,L':')) fields.push_back(part);
    if(fields.size()!=5 || text.back()==L':' || fields[1].size()!=32) throw PublicFailure{"InvalidIdentity",2};
    catalog::FusionImageIdentity id;
    id.volume_serial=Number(fields[0]);id.size_bytes=Number(fields[2]);
    id.creation_time=Number(fields[3]);id.write_time=Number(fields[4]);
    auto digit=[](wchar_t c)->unsigned {if(c>=L'0'&&c<=L'9')return c-L'0';if(c>=L'a'&&c<=L'f')return c-L'a'+10;throw PublicFailure{"InvalidIdentity",2};};
    for(unsigned i=0;i<16;++i)id.file_id[i]=std::byte(digit(fields[1][2*i])*16+digit(fields[1][2*i+1]));
    return id;
}
std::string JsonName(std::wstring_view name) {
    // Escape UTF-16 code units; preserves surrogate pairs in JSON without lossy conversion.
    std::ostringstream out;out<<'"';for(auto c:name)out<<"\\u"<<std::hex<<std::setw(4)<<std::setfill('0')<<unsigned(c);out<<'"';return out.str();
}
int Run(int argc,wchar_t** argv,Operation& op) {
    if (argc == 2 && std::wstring_view(argv[1]) == L"--help") {
        op.Output("ApfsFusionReadTool: bounded read-only Windows member images\n"
            "Modes: inspect, catalog, enumerate, lookup, read, xattr.\n"
            "Inspect: --mode inspect --image D:\\path\\member.img\n"
            "Binding requires both paths, inspected identities, explicit main/tier2 roles,\n"
            "store IDs/ranges, container/fusion UUIDs, checkpoint XID and\n"
            "--role-convention linux-apfs-last-byte-low-bit.\n"
            "Reads require exact volume UUID/OID, inode, offset, length and --binary-stdout.\n"
            "Only clean anchors, empty caches and a main-tier checkpoint are supported.\n"
            "See ApfsFusionReadTool.md for complete selectors and limits.\n");
        return 0;
    }
    std::map<std::wstring,std::wstring> opts;
    const std::set<std::wstring> allowed={L"--mode",L"--image",L"--member-a",L"--member-b",L"--identity-a",L"--identity-b",
        L"--role-a",L"--role-b",L"--store-id-a",L"--store-id-b",L"--store-offset-a",L"--store-offset-b",L"--store-size-a",L"--store-size-b",
        L"--container-uuid",L"--fusion-uuid",L"--checkpoint-xid",L"--role-convention",L"--volume-uuid",L"--volume-oid",
        L"--directory",L"--name",L"--inode",L"--xattr",L"--offset",L"--length",L"--operation-timeout-ms",L"--cancel-handle",
        L"--budget-reads",L"--budget-bytes",L"--budget-records",L"--budget-material",L"--repeat",L"--interval-ms"};
    bool binary=false;
    for(int i=1;i<argc;++i){std::wstring key(argv[i]);if(key==L"--binary-stdout"){if(binary)throw PublicFailure{"DuplicateOption",2};binary=true;continue;}
        if(!allowed.contains(key)||i+1==argc||opts.contains(key))throw PublicFailure{"InvalidOptions",2};
        opts.emplace(key,argv[++i]);}
    auto get=[&](const std::wstring& key)->const std::wstring& {auto it=opts.find(key);if(it==opts.end())throw PublicFailure{"MissingExactSelector",2};return it->second;};
    auto limit=[&](const wchar_t* key,std::uint64_t def,std::uint64_t max){auto n=opts.contains(key)?Number(get(key)):def;if(n>max)throw PublicFailure{"ResourceLimit",2};return n;};
    const auto timeout=limit(L"--operation-timeout-ms",10000,30000);
    if(timeout<100)throw PublicFailure{"InvalidTimeout",2};op.SetDeadline(timeout);
    if(opts.contains(L"--cancel-handle"))op.SetCancellationHandle(Number(get(L"--cancel-handle")));
    op.Check();
    const auto mode=get(L"--mode");const bool read=mode==L"read"||mode==L"xattr";
    if(mode!=L"inspect"&&mode!=L"catalog"&&mode!=L"enumerate"&&mode!=L"lookup"&&!read)throw PublicFailure{"InvalidMode",2};
    if(binary!=read)throw PublicFailure{"ExplicitBinaryOutputRequired",2};
    if (read) {
        Number(get(L"--inode"));
        Number(get(L"--offset"));
        if (Number(get(L"--length")) > 16 * 1024 * 1024)
            throw PublicFailure{"ReadLimit", 2};
        const auto type = GetFileType(GetStdHandle(STD_OUTPUT_HANDLE));
        if (type != FILE_TYPE_PIPE && type != FILE_TYPE_DISK)
            throw PublicFailure{"RedirectedBinaryOutputRequired", 2};
    }
    const auto repeat=limit(L"--repeat",1,64),interval=limit(L"--interval-ms",0,1000);
    if(!repeat || ((repeat!=1||interval)&&mode!=L"enumerate"))throw PublicFailure{"RepeatRequiresEnumeration",2};
    std::string error;
    if(mode==L"inspect") {
        catalog::FusionImageIdentity id;
        if(!catalog::ApfsFusionStore::InspectImage(get(L"--image"),id,error))throw std::runtime_error(error);
        op.Output("{\"identity\":\""+Identity(id)+"\",\"size\":\""+std::to_string(id.size_bytes)+"\"}\n");return 0;
    }
    if(get(L"--role-convention")!=L"linux-apfs-last-byte-low-bit")throw PublicFailure{"UnsupportedRoleConvention",2};
    catalog::FusionBindRequest request;
    request.convention=catalog::FusionRoleConvention::LinuxApfsLastByteLowBit;
    request.container_uuid_hex=Ascii(get(L"--container-uuid"));request.fusion_uuid_hex=Ascii(get(L"--fusion-uuid"));
    request.checkpoint_xid=Number(get(L"--checkpoint-xid"));
    request.budget=std::make_shared<catalog::ApfsReadBudget>(limit(L"--budget-reads",10000,100000),limit(L"--budget-bytes",67108864,268435456),
        limit(L"--budget-records",100000,1000000),limit(L"--budget-material",67108864,268435456));
    rw::FusionVolumeSelection selection;selection.container_uuid_hex=request.container_uuid_hex;selection.checkpoint_xid=request.checkpoint_xid;
    for(const std::wstring suffix:{L"-a",L"-b"}) {
        catalog::FusionImageMember m;m.path=get(L"--member"+suffix);m.exact_identity=ParseIdentity(get(L"--identity"+suffix));
        m.stable_store_id=Ascii(get(L"--store-id"+suffix));m.store_offset=Number(get(L"--store-offset"+suffix));m.store_size=Number(get(L"--store-size"+suffix));
        const auto role=get(L"--role"+suffix);if(role!=L"main"&&role!=L"tier2")throw PublicFailure{"UnknownMemberRole",2};
        m.role=role==L"main"?catalog::FusionMemberRole::Main:catalog::FusionMemberRole::Tier2;
        selection.member_store_ids[role==L"main"?0:1]=m.stable_store_id;request.members.push_back(std::move(m));
    }
    op.Check();
    auto store=catalog::ApfsFusionStore::BindImages(request,error);if(!store)throw std::runtime_error(error);
    constexpr auto profile="{\"profile\":\"clean-anchors-empty-caches-main-checkpoint\",\"roleConvention\":\"linux-apfs-last-byte-low-bit\",\"generalFusionSupport\":false";
    if(mode==L"catalog") {
        catalog::ApfsContainerCatalog c;if(!catalog::ApfsContainerCatalog::TryLoadFusion(*store,"fusion","held-images",c,error))throw std::runtime_error(error);
        std::ostringstream out;out<<profile<<",\"volumes\":[";bool first=true;
        const auto* view=c.TryGetReadOnlyVolumeView();if(!view)throw PublicFailure{"Unavailable",3};
        for(const auto& v:view->volumes){if(!first)out<<',';first=false;out<<"{\"oid\":\""<<v.superblock.object_id<<"\",\"uuid\":\""<<v.superblock.uuid_hex<<"\"}";}
        out<<"]}\n";if(!store->CheckAvailable(error))throw std::runtime_error(error);op.Output(out.str());return 0;
    }
    selection.volume_uuid_hex=Ascii(get(L"--volume-uuid"));selection.volume_oid=Number(get(L"--volume-oid"));
    rw::FusionReadStatus status;auto session=rw::ApfsFusionReadSession::Open(std::move(store),selection,status,error);
    if(!session)throw std::runtime_error(error);
    auto check=[&]{if(op.IsCancelled()){session->Cancel();throw PublicFailure{"Cancelled",6};}if(!session->CheckAvailable(error))throw std::runtime_error(error);};
    check();
    if(mode==L"enumerate") {
        const auto directory=Number(get(L"--directory"));
        for(std::uint64_t n=0;n<repeat;++n){
            if(n){const auto end=GetTickCount64()+interval;while(GetTickCount64()<end){check();Sleep(5);}}
            check();std::vector<rw::MetadataStore::DirectoryLink> links;
            if(!session->Enumerate(directory,links,error))throw std::runtime_error(error);
            std::string out="{\"entries\":[";bool first=true;
            for(const auto& link:links){if(!first)out+=',';first=false;
                out+="{\"oid\":\""+std::to_string(link.child_object_id)+"\",\"name\":"+JsonName(link.entry_name)+"}";
                if(out.size()>1024*1024)throw PublicFailure{"OutputLimit",2};}
            out+="]}\n";check();op.Output(out);
        }return 0;
    }
    if(mode==L"lookup") {std::uint64_t oid=0;if(!session->Lookup(Number(get(L"--directory")),get(L"--name"),oid,error))throw std::runtime_error(error);
        check();op.Output("{\"oid\":\""+std::to_string(oid)+"\"}\n");return 0;}
    const auto inode=Number(get(L"--inode")),offset=Number(get(L"--offset")),length=Number(get(L"--length"));
    if(length>16*1024*1024)throw PublicFailure{"ReadLimit",2};
    const auto type=GetFileType(GetStdHandle(STD_OUTPUT_HANDLE));if(type!=FILE_TYPE_PIPE&&type!=FILE_TYPE_DISK)throw PublicFailure{"RedirectedBinaryOutputRequired",2};
    std::vector<std::byte> bytes;
    const bool ok=mode==L"read"?session->ReadFile(inode,offset,static_cast<std::size_t>(length),bytes,error):
        session->ReadXattr(inode,Ascii(get(L"--xattr")),offset,static_cast<std::size_t>(length),bytes,error);
    if(!ok)throw std::runtime_error(error);check();op.Output(GetStdHandle(STD_OUTPUT_HANDLE),bytes.data(),bytes.size());check();return 0;
}
}
int wmain(int argc,wchar_t** argv) {
    SetConsoleCtrlHandler(Control,TRUE);
    try {Operation op;try {return Run(argc,argv,op);}
        catch(const PublicFailure& e){op.Status(std::string("ERROR ")+e.name+"\n");return e.exit;}
        catch(const std::exception& e){
            if (op.IsCancelled()) { op.Status("ERROR Cancelled\n"); return 6; }
            op.Status(std::string("ERROR ")+e.what()+"\n");return 3;}}
    catch(...){return 3;}
}
