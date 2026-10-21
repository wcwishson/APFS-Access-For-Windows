#pragma once
#include "ApfsFirmlinkProducer.h"

namespace system_data_mount {
struct Options {
    bool enabled=false;
    std::wstring group;
    std::uint64_t data_oid=0,checkpoint_xid=0;
};
struct State {
    std::shared_ptr<const apfsaccess::rw::ApfsFirmlinkProducer> session;
    std::wstring label=L"System + Data (read-only)";
    std::atomic<bool> cancelled{false},failed{false},admitted{false};
    std::atomic<std::size_t> pair_count{0};
    std::mutex serial;
    std::string error;
    void Cancel() noexcept {cancelled=true;}
    void Close() {Cancel();std::lock_guard lock(serial);session.reset();admitted=false;}
    ~State(){Close();}
};
struct Handle {
    std::string path;
    apfsaccess::rw::MetadataStore::InodeRecord node;
    std::uint64_t index=0;
};
}
