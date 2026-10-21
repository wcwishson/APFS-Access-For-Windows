#pragma once
#include "../../ApfsAccess.ApfsRwEngine/tools/EncryptedReadTransport.h"
#include "EncryptedImageRuntime.h"
#include "EncryptedCallbackProgress.h"

// Owned by MountContext until the dispatcher has stopped. No plaintext spool.
namespace encrypted_mount
{
template<class T> void Wipe(T& value) noexcept
{ if (!value.empty()) SecureZeroMemory(value.data(), value.size()*sizeof(value[0])); value.clear(); }
struct Bytes : std::vector<std::byte> { ~Bytes() { Wipe(*this); } };
struct Entries : std::vector<apfsaccess::catalog::EncryptedDirectoryEntry>
{
    void Clear() noexcept { for (auto& e:*this) { Wipe(e.name_utf8); Wipe(e.windows_name); } clear(); }
    ~Entries() { Clear(); }
};
struct Xattrs : std::vector<apfsaccess::catalog::EncryptedXattr>
{ ~Xattrs() { for(auto& x:*this) { Wipe(x.name_utf8); Wipe(x.data); } } };
struct Options
{
    bool enabled = false;
    bool container_bag_oid_supplied = false, volume_bag_oid_supplied = false;
    std::wstring source_id, volume_uuid, user_uuid, bag_length, write_root;
    std::uint64_t store_size=0, checkpoint=0, container_bag_oid=0, container_bag_xid=0,
        volume_bag_oid=0, volume_bag_xid=0;
};
struct OpenStream
{
    std::size_t contexts = 0, active_handles = 0;
    bool removed = false;
};
struct OpenEntry
{
    std::uint64_t parent = 0;
    std::string name;
    std::size_t handles = 0;
    bool delete_pending = false, unlinked = false;
    std::shared_ptr<apfsaccess::catalog::EncryptedImageRuntime::ReadInode> read_inode;
    std::set<std::string> delete_pending_streams;
    std::map<std::string,std::shared_ptr<OpenStream>> streams;
    ~OpenEntry()
    {
        Wipe(name);
        while(!delete_pending_streams.empty()){auto key=delete_pending_streams.extract(delete_pending_streams.begin());Wipe(key.value());}
        while(!streams.empty()){auto key=streams.extract(streams.begin());Wipe(key.key());}
    }
};
struct State
{
    enum class Failure : std::uint8_t
    {
        None, IoDeadlineExceeded, EncCallException, ReadSessionFailure, ReadSourceChanged,
        ReadViewOpenFailure, RootMetadataFailure, RuntimeApplyDebt, RuntimeWriteDebt,
        StreamActiveCounterUnderflow, StreamContextCounterUnderflow, OpenContextCounterUnderflow,
        CleanupRemoveFailure, CloseRemoveFailure, CloseUnlinkFailure, CloseOperationException,
        PendingDeleteAtClose, UncleanRuntimeAtClose, CachedRootMutationRequested,
        CallbackDeadlineExceeded, InvalidCompletedProgress, CallbackAbsoluteCeilingExceeded
    };
    std::shared_ptr<std::atomic<bool>> cancelled = std::make_shared<std::atomic<bool>>(false);
    std::shared_ptr<apfsaccess::transport::OwnedEncryptedImageSource> source;
    std::shared_ptr<apfsaccess::catalog::ApfsEncryptedReadSession> session;
    std::unique_ptr<apfsaccess::catalog::EncryptedImageRuntime> writer;
    std::uint64_t read_xid = 0;
    apfsaccess::catalog::EncryptedNamespaceInfo names;
    std::wstring label;
    std::atomic<bool> failed{false};
    std::atomic<std::uint64_t> pending_deletes{0};
    std::atomic<std::uint64_t> completed_barriers{0},publication_barriers{0};
    std::atomic<UINT32> root_attributes{0};
    std::mutex root_cache_mutex;
    FSP_FSCTL_FILE_INFO root_info{};
    std::atomic<std::uint64_t> first_failure{0};
    std::recursive_mutex callbacks;
    std::map<std::uint64_t, std::shared_ptr<OpenEntry>> open_entries;
    std::mutex operations;
    std::map<HANDLE, ULONGLONG> threads;
    std::map<HANDLE, ULONGLONG> absolute_deadlines;
    std::jthread monitor;
    void SetDeletePending(OpenEntry& entry,bool pending) noexcept
    {
        if(entry.delete_pending==pending)return;
        entry.delete_pending=pending;
        if(pending)pending_deletes.fetch_add(1);
        else pending_deletes.fetch_sub(1);
    }
    bool Writable() const noexcept
    {
        if(!writer || failed.load() || cancelled->load()) return false;
        const auto status=writer->CachedStatus();
        using Phase=apfsaccess::catalog::EncryptedImageWritePhase;
        return !status.closed && !status.image.recovery_required &&
            (status.image.phase==Phase::Ready || status.image.phase==Phase::Preparing || status.image.phase==Phase::Publishing);
    }
    void Cancel() noexcept { cancelled->store(true); if(writer) writer->Cancel(); }
    void Fail(Failure reason) noexcept
    {
        // Publish one immutable reason/timestamp pair before signalling cancellation.
        std::uint64_t expected=0;
        first_failure.compare_exchange_strong(expected,(std::uint64_t(reason)<<56)|(GetTickCount64()&0x00ffffffffffffffULL));
        failed=true;Cancel();
    }
    struct FailureStatus { const char* reason; ULONGLONG tick_ms; };
    static const char* FailureReasonName(Failure reason) noexcept
    {
        switch(reason) {
        case Failure::None:return "None";
        case Failure::IoDeadlineExceeded:return "IoDeadlineExceeded";
        case Failure::EncCallException:return "EncCallException";
        case Failure::ReadSessionFailure:return "ReadSessionFailure";
        case Failure::ReadSourceChanged:return "ReadSourceChanged";
        case Failure::ReadViewOpenFailure:return "ReadViewOpenFailure";
        case Failure::RootMetadataFailure:return "RootMetadataFailure";
        case Failure::RuntimeApplyDebt:return "RuntimeApplyDebt";
        case Failure::RuntimeWriteDebt:return "RuntimeWriteDebt";
        case Failure::StreamActiveCounterUnderflow:return "StreamActiveCounterUnderflow";
        case Failure::StreamContextCounterUnderflow:return "StreamContextCounterUnderflow";
        case Failure::OpenContextCounterUnderflow:return "OpenContextCounterUnderflow";
        case Failure::CleanupRemoveFailure:return "CleanupRemoveFailure";
        case Failure::CloseRemoveFailure:return "CloseRemoveFailure";
        case Failure::CloseUnlinkFailure:return "CloseUnlinkFailure";
        case Failure::CloseOperationException:return "CloseOperationException";
        case Failure::PendingDeleteAtClose:return "PendingDeleteAtClose";
        case Failure::UncleanRuntimeAtClose:return "UncleanRuntimeAtClose";
        case Failure::CachedRootMutationRequested:return "CachedRootMutationRequested";
        case Failure::CallbackDeadlineExceeded:return "CallbackDeadlineExceeded";
        case Failure::InvalidCompletedProgress:return "InvalidCompletedProgress";
        case Failure::CallbackAbsoluteCeilingExceeded:return "CallbackAbsoluteCeilingExceeded";
        }
        return "InvalidFailure";
    }
    FailureStatus CachedFailureStatus() const noexcept
    {
        const auto value=first_failure.load();
        return {FailureReasonName(static_cast<Failure>(value>>56)),value&0x00ffffffffffffffULL};
    }
    ULONGLONG FailureTickMs() const noexcept { return CachedFailureStatus().tick_ms; }
    const char* FailureReasonName() const noexcept { return CachedFailureStatus().reason; }
    void Close() noexcept
    {
        if(pending_deletes.load()!=0)Fail(Failure::PendingDeleteAtClose);
        Cancel();
        if(session) session->Close();
        if(writer) {
            const auto status=writer->CachedStatus();
            if(status.recovery_required || status.accepted!=status.durable || status.durable!=status.cleaned)Fail(Failure::UncleanRuntimeAtClose);
            for(const auto& [inode,entry]:open_entries) {
                (void)inode;
                if(entry->delete_pending && !entry->unlinked)Fail(Failure::PendingDeleteAtClose);
            }
            writer->Close();
        }
        if(monitor.joinable()) { monitor.request_stop(); monitor.join(); }
        session.reset(); source.reset(); open_entries.clear(); Wipe(label);
        {std::lock_guard lock(root_cache_mutex);SecureZeroMemory(&root_info,sizeof(root_info));root_attributes=0;}
    }
    ~State() { Close(); }
    // Register every thread that can block in a leased read. The watchdog
    // cancels synchronous I/O, then the existing host drain retains ownership.
    struct Operation
    {
        State& state; HANDLE thread=nullptr;
        explicit Operation(State& s,bool callback=false) : state(s),
            deadline_(GetTickCount64(),s.writer.get(),GetCurrentThreadId(),callback),previous_(current_)
        {
            if(!DuplicateHandle(GetCurrentProcess(),GetCurrentThread(),GetCurrentProcess(),
                &thread,THREAD_TERMINATE,FALSE,0)) throw std::runtime_error("EncryptedIoRegistration");
            try {
                std::lock_guard lock(s.operations);s.threads.emplace(thread,deadline_.Deadline());
                try {s.absolute_deadlines.emplace(thread,deadline_.AbsoluteDeadline());}
                catch(...){s.threads.erase(thread);throw;}
            }
            catch(...) { CloseHandle(thread); throw; }
            current_=this;
        }
        Operation(const Operation&)=delete;
        Operation& operator=(const Operation&)=delete;
        ~Operation()
        {
            current_=previous_;
            std::lock_guard lock(state.operations);state.threads.erase(thread);state.absolute_deadlines.erase(thread);CloseHandle(thread);
        }
    private:
        friend struct RuntimeProgressObserver;
#ifdef APFSACCESS_FSHOST_UNIT_TEST
        friend struct DeadlineStateTestAccess;
#endif
        OperationDeadline deadline_;
        Operation* previous_;
        inline static thread_local Operation* current_=nullptr;
        bool CompleteAt(const apfsaccess::catalog::EncryptedImageRuntime& owner,
            std::uint64_t invocation,std::uint64_t ordinal,OperationDeadline::Boundary boundary,ULONGLONG now)
        {
            if(current_!=this)return false;
            std::lock_guard lock(state.operations);
            const auto registered=state.threads.find(thread);
            if(registered==state.threads.end() || state.failed.load() || state.cancelled->load() ||
                state.writer.get()!=&owner)return false;
            // A flush completing after expiry cannot beat a delayed monitor poll.
            if(now>=registered->second){state.Fail(now>=deadline_.AbsoluteDeadline() ?
                Failure::CallbackAbsoluteCeilingExceeded : Failure::CallbackDeadlineExceeded);return false;}
            const auto result=deadline_.Complete(now,&owner,GetCurrentThreadId(),invocation,ordinal,boundary);
            if(result==OperationDeadline::Result::Expired){state.Fail(Failure::CallbackDeadlineExceeded);return false;}
            if(result==OperationDeadline::Result::AbsoluteExpired){state.Fail(Failure::CallbackAbsoluteCeilingExceeded);return false;}
            if(result!=OperationDeadline::Result::Renewed)return false;
            registered->second=deadline_.Deadline();
            ++state.completed_barriers;
            if(boundary==OperationDeadline::Boundary::Publication)++state.publication_barriers;
            return true;
        }
    };
    void Watch(const std::function<bool()>& alive,const std::function<bool()>& callback_active={})
    {
        monitor=std::jthread([this,alive,callback_active](std::stop_token stop) {
            while(!stop.stop_requested()) {
                if(!alive()) Cancel();
                {
                    std::lock_guard lock(operations);
                    for(const auto& [thread,deadline]:threads) {
                        const auto now=GetTickCount64();
                        const auto absolute=absolute_deadlines.find(thread);
                        if(absolute!=absolute_deadlines.end() && now>=absolute->second)Fail(Failure::CallbackAbsoluteCeilingExceeded);
                        else if(now>=deadline)Fail(callback_active && callback_active() ?
                            Failure::CallbackDeadlineExceeded : Failure::IoDeadlineExceeded);
                        if(cancelled->load()) CancelSynchronousIo(thread);
                    }
                }
                // Stop is requested only after the session's serialized reader drains.
                Sleep(10);
            }
        });
    }
};
struct Handle
{
    apfsaccess::catalog::EncryptedNodeInfo node;
    std::uint64_t entry_parent=0, sibling=0;
    std::string entry_name;
    std::shared_ptr<OpenEntry> open_entry;
    std::shared_ptr<OpenStream> open_stream;
    bool writable = false;
    bool cached_root_observation = false;
    std::string xattr;
    bool stream=false;
    bool stream_delete_pending=false, stream_removed=false;
    bool stream_active=false;
    bool protocol=false;
    std::uint64_t stream_size=0;
    Entries entries;
    bool enumerated=false;
    std::uint64_t enumeration_xid=0;
    std::size_t cursor=0;
    std::mutex mutex;
    bool StreamRemoved() const noexcept { return stream_removed || (open_stream && open_stream->removed); }
    ~Handle() { Wipe(xattr); Wipe(entry_name); SecureZeroMemory(&node,sizeof(node)); }
};
}
