#pragma once
#include "ApfsTransactionWriter.h"
#include <algorithm>
#include <set>
#include <span>

namespace apfsaccess::catalog::encrypted_delta
{
struct NodeReservation { std::uint64_t oid = 0, physical = 0; };
struct TreeSize { std::size_t nodes = 0; std::uint16_t height = 0; };
inline void EraseTree(rw::AppleSerializedBtree& tree) noexcept
{
    for (auto& object : tree.objects) {
        volatile std::byte* bytes = object.bytes.data();
        for (std::size_t i = 0; i < object.bytes.size(); ++i) bytes[i] = std::byte{};
    }
    tree = {};
}
struct ScopedTreeErase
{
    rw::AppleSerializedBtree& tree;
    ~ScopedTreeErase() { EraseTree(tree); }
};
inline bool SizeTree(const std::vector<BtreeRecord>& records, rw::AppleBtreeOptions shape,
    rw::AppleBtreeKeyOrder order, std::size_t maximum_nodes, TreeSize& size, std::string& error)
{
    size = {}; shape.key_order = order; shape.max_nodes = maximum_nodes;
    shape.root_object_id = shape.root_physical_block = 1;
    shape.first_child_object_id = shape.first_child_physical_block = 2;
    shape.child_object_ids.clear(); shape.child_physical_blocks.clear();
    if (!shape.xid) shape.xid = 1;
    rw::AppleSerializedBtree tree;
    ScopedTreeErase cleanup{tree};
    if (!rw::SerializeAppleBtree(records, shape, tree, error)) return false;
    size = {tree.objects.size(), tree.height};
    return true;
}
inline bool SerializeReservedTree(const std::vector<BtreeRecord>& records, rw::AppleBtreeOptions shape,
    rw::AppleBtreeKeyOrder order, std::span<const NodeReservation> nodes,
    rw::AppleSerializedBtree& output, std::string& error)
{
    EraseTree(output);
    if (nodes.empty() || nodes.size() > 4096) { error = "EncryptedDeltaTreeReservationLimit"; return false; }
    std::set<std::uint64_t> oids, blocks;
    for (const auto& node : nodes)
        if (!node.oid || !node.physical || !oids.insert(node.oid).second || !blocks.insert(node.physical).second ||
            ((shape.storage_type & kObjectStorageTypeMask) == kObjectPhysical && node.oid != node.physical))
        { error = "EncryptedDeltaTreeReservationOverlap"; return false; }
    shape.key_order = order; shape.max_nodes = nodes.size();
    shape.root_object_id = nodes.front().oid; shape.root_physical_block = nodes.front().physical;
    shape.first_child_object_id = shape.first_child_physical_block = 0;
    shape.child_object_ids.clear(); shape.child_physical_blocks.clear();
    for (std::size_t i = 1; i < nodes.size(); ++i)
    { shape.child_object_ids.push_back(nodes[i].oid); shape.child_physical_blocks.push_back(nodes[i].physical); }
    rw::AppleSerializedBtree tree;
    ScopedTreeErase cleanup{tree};
    if (!rw::SerializeAppleBtree(records, shape, tree, error)) return false;
    if (tree.objects.size() != nodes.size()) { error = "EncryptedDeltaTreeReservationCoverageInvalid"; return false; }
    for (const auto& object : tree.objects)
        if (std::none_of(nodes.begin(), nodes.end(), [&](const auto& node) {
            return node.oid == object.location.object_id && node.physical == object.location.physical_block;
        })) { error = "EncryptedDeltaTreeReservationCoverageInvalid"; return false; }
    output = std::move(tree); return true;
}
}
