#pragma once
#include "../../ApfsAccess.ApfsRwEngine/include/ApfsFusionReadSession.h"
#include "../../ApfsAccess.ApfsRwEngine/include/FusionImageRuntime.h"
#include "../../ApfsAccess.ApfsRwEngine/tools/FusionImageArguments.h"
namespace fusion_mount {
struct Options {
    bool enabled=false;
    std::wstring write_root;
    std::map<std::wstring,std::wstring> selectors;
};
struct State {
    std::shared_ptr<std::atomic<bool>> cancelled=std::make_shared<std::atomic<bool>>(false);
    std::shared_ptr<apfsaccess::catalog::ApfsReadBudget> budget;
    std::unique_ptr<apfsaccess::rw::ApfsFusionReadSession> session;
    std::unique_ptr<apfsaccess::rw::FusionImageRuntime> writer;
    bool write_mode=false;
    std::atomic<std::uint64_t> total_bytes{0},free_bytes{0},checkpoint{0},accepted{0},durable{0},cleaned{0};
    apfsaccess::rw::FusionNamespaceInfo names;
    std::array<apfsaccess::catalog::FusionImageMember,2> members;
    std::wstring label;
    std::atomic<bool> failed{false}, admitted{false},status_dirty{false},deadline_expired{false};
    std::atomic<unsigned> missing_members{0};
    std::string error;
    mutable std::mutex diagnostic_lock;
    std::string last_failure;
    void Failure(const char* operation,NTSTATUS status) {std::lock_guard lock(diagnostic_lock);last_failure=std::string(operation)+":"+std::to_string(static_cast<unsigned long>(status))+":"+error+(deadline_expired.load()?":FusionIoDeadlineExpired":"");status_dirty=true;}
    std::string LastFailure() const {std::lock_guard lock(diagnostic_lock);return last_failure;}
    // All session use, publication and Close are serialized. Watchdog only
    // touches atomics/registered thread handles, never the mutable parser.
    std::mutex serial, operations, close_owner;
    std::map<HANDLE,ULONGLONG> threads;
    HANDLE active_thread=nullptr;
    std::uint64_t completed_boundary=0;
    // Outstanding Cleanup callbacks, not delayed kernel Close callbacks.
    std::map<std::uint64_t,unsigned> open_counts;
    std::jthread monitor;
    void Cancel() noexcept { cancelled->store(true); }
    void Close() noexcept {
        Cancel();
        std::lock_guard close_lock(close_owner);
        { std::lock_guard lock(serial); if(session) session->Cancel(); if(writer)writer->Cancel();writer.reset();session.reset(); admitted=false; }
        if(monitor.joinable()) {monitor.request_stop();monitor.join();}
    }
    ~State() {Close();}
    bool Writable() const {return write_mode&&admitted.load()&&!failed.load()&&!cancelled->load();}
    template<class F> auto Query(F&& call) {if(writer)return call(*writer);return call(*session);}
    bool CheckAvailable(std::string& e) {return Query([&](auto& r){return r.CheckAvailable(e);});}
    unsigned UnavailableMembers() {return Query([](auto& r){return r.UnavailableMembers();});}
    auto LastStatus() {return Query([](auto& r){return r.LastStatus();});}
    bool GetMetadata(std::uint64_t id,apfsaccess::rw::FusionNodeInfo& out,std::string& e) {return Query([&](auto& r){return r.GetMetadata(id,out,e);});}
    bool LookupEntry(std::uint64_t id,std::wstring_view name,apfsaccess::rw::MetadataStore::DirectoryLink& out,std::string& e) {return Query([&](auto& r){return r.LookupEntry(id,name,out,e);});}
    bool Enumerate(std::uint64_t id,std::vector<apfsaccess::rw::MetadataStore::DirectoryLink>& out,std::string& e) {return Query([&](auto& r){return r.Enumerate(id,out,e);});}
    bool ListXattrs(std::uint64_t id,std::vector<apfsaccess::rw::FusionXattrInfo>& out,std::string& e) {return Query([&](auto& r){return r.ListXattrs(id,out,e);});}
    bool ReadFile(std::uint64_t id,std::uint64_t at,std::size_t n,std::vector<std::byte>& out,std::string& e) {return Query([&](auto& r){return r.ReadFile(id,at,n,out,e);});}
    bool ReadXattr(std::uint64_t id,const std::string& name,std::uint64_t at,std::size_t n,std::vector<std::byte>& out,std::string& e) {return Query([&](auto& r){return r.ReadXattr(id,name,at,n,out,e);});}
    bool Cache(std::string& e) {
        if(!writer)return true;
        auto water=writer->Watermarks();accepted=water.accepted_sequence;durable=water.apfs_durable_sequence;cleaned=water.cleanup_sequence;
        apfsaccess::rw::FusionRuntimeVolumeInfo info;if(!writer->GetVolumeInfo(info,e))return false;
        names=info.names;total_bytes=info.total_bytes;free_bytes=info.free_bytes;checkpoint=info.checkpoint_xid;status_dirty=true;return true;
    }
    void PublicationCompleted() {
        if(!writer)return;
        const auto water=writer->Watermarks();
        if(!water.accepted_sequence||water.accepted_sequence!=water.apfs_durable_sequence||
            water.accepted_sequence!=water.cleanup_sequence)return;
        std::lock_guard lock(operations);
        const auto found=threads.find(active_thread);
        const auto now=GetTickCount64();
        if(found==threads.end()||cancelled->load()||failed.load()||now>=found->second||
            water.accepted_sequence<=completed_boundary)return;
        // Only a newly completed original publication renews the bounded IO
        // window. Waiting, preflight and accepted debt never renew it.
        completed_boundary=water.accepted_sequence;found->second=now+30000;
    }
    struct Operation {
        State& state; HANDLE thread=nullptr;
        explicit Operation(State& s):state(s) {
            if(!DuplicateHandle(GetCurrentProcess(),GetCurrentThread(),GetCurrentProcess(),&thread,THREAD_TERMINATE,FALSE,0))
                throw std::runtime_error("FusionIoRegistration");
            const auto boundary=s.writer?s.writer->Watermarks().accepted_sequence:0;
            try {std::lock_guard lock(s.operations);s.threads.emplace(thread,GetTickCount64()+30000);
                s.active_thread=thread;s.completed_boundary=boundary;}
            catch(...) {CloseHandle(thread);throw;}
        }
        ~Operation() {std::lock_guard lock(state.operations);state.active_thread=nullptr;state.threads.erase(thread);CloseHandle(thread);}
    };
    void Watch(const std::function<bool()>& alive) {
        monitor=std::jthread([this,alive](std::stop_token stop) {
            while(!stop.stop_requested()) {
                if(!alive()) Cancel();
                {std::lock_guard lock(operations);for(const auto& [thread,deadline]:threads) {
                    if(GetTickCount64()>=deadline) {deadline_expired=true;failed=true;Cancel();}
                    if(cancelled->load()) CancelSynchronousIo(thread);
                }}
                Sleep(10);
            }
        });
    }
};
struct Handle {
    apfsaccess::rw::FusionNodeInfo node;
    std::uint64_t entry_parent=0,sibling=0,stream_size=0;
    std::string xattr;
    bool stream=false,protocol=false,enumerated=false,writable=false,cleaned=false,deleted=false;
    std::uint64_t enumeration_xid=0;
    std::vector<apfsaccess::rw::MetadataStore::DirectoryLink> entries;
    std::size_t cursor=0;
    std::mutex mutex;
};
// Called under the serial owner before the callback lifetime guard is released.
inline void DiscardUnpublishedHandle(State& s,PVOID* out,FSP_FSCTL_FILE_INFO* info)
{
    if(info)*info={};
    if(!out)return;
    std::unique_ptr<Handle> handle(static_cast<Handle*>(*out));
    *out=nullptr;
    if(handle && !handle->cleaned) {
        auto it=s.open_counts.find(handle->node.inode_id);
        if(it!=s.open_counts.end() && !--it->second)s.open_counts.erase(it);
    }
}
}
