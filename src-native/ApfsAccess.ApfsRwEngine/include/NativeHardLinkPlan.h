#pragma once
#include "ApfsExtendedRecordCodec.h"

namespace apfsaccess::rw
{
struct NativeHardLinkRequest
{
    std::uint64_t source_inode = 0, destination_parent = 0, next_object_id = 0, timestamp_ns = 0;
    std::string leaf_utf8;
};
struct NativeHardLinkPlan
{
    std::uint64_t source_inode = 0, next_object_id = 0, primary_parent = 0;
    std::uint32_t source_links = 0;
    std::string primary_name;
    std::vector<catalog::BtreeRecord> before, after;
};
enum class NativeHardLinkPlanState { Refused, Preimage, Published };

// Pure alias preparation over an already admitted complete ordinary
// filesystem. No I/O, WAL acceptance, OID reservation or publication authority.
// The owner must reserve the returned OID floor and bind the exact plan to a new
// validated hard-link intent before it can stage/publish/recover this mutation.
bool PrepareNativeHardLinkPlan(const std::vector<catalog::BtreeRecord>& filesystem,
    const ApfsNamePolicy& policy, const NativeHardLinkRequest& request,
    NativeHardLinkPlan& plan, std::string& error);
NativeHardLinkPlanState ClassifyNativeHardLinkPlan(const std::vector<catalog::BtreeRecord>& filesystem,
    const NativeHardLinkPlan& accepted_plan);
}
