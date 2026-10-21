#pragma once
#include "NativeHardLinkProtocol.h"
#include <memory>
#include <mutex>
#include <string>
#ifndef APFSACCESS_ENABLE_NATIVE_HARD_LINK_CONTROL
#define APFSACCESS_ENABLE_NATIVE_HARD_LINK_CONTROL 0
#endif

struct MountContext;
struct OpenContext;
struct Node;
struct NativeHardLinkTicketState
{
    std::mutex mutex;
    apfsaccess::fshost::hardlink_control::Ticket ticket{};
    std::shared_ptr<Node> source;
    std::uint64_t object_id = 0, generation = 0, parent_object_id = 0, sibling_id = 0;
    std::string name_utf8;
    bool consumed = false, revoked = false;
    ~NativeHardLinkTicketState() { SecureZeroMemory(ticket.data(), ticket.size()); }
};

void RevokeNativeHardLinkAuthority(OpenContext*);
bool NativeHardLinkHasMaterializedHandlesLocked(const MountContext&, const Node&);
bool PrepareNativeHardLinkCache(MountContext&, const std::shared_ptr<Node>&, std::uint64_t);
