#include "ApfsFormat.h"
#include "ApfsTransactionWriter.h"
#include "TestFixtureBuilder.h"
#include <iostream>
#include <stdexcept>
using namespace apfsaccess::catalog;
using namespace apfsaccess::rw;
using namespace apfsaccess::testfixture;
using Bytes = std::vector<std::byte>;
namespace {
unsigned checks = 0;
void Check(bool ok, const std::string& text) { ++checks; if (!ok) throw std::runtime_error(text); }
std::size_t KeyAt(const Bytes& b, unsigned index) {
    const auto table = 0x38 + ReadU16LE(b, 0x28).value();
    const auto stride = (ReadU16LE(b, 0x20).value() & 4) ? 4 : 8;
    return table + ReadU16LE(b, 0x2A).value() + ReadU16LE(b, table + index * stride).value();
}
struct LeasedNodeContext : BtreeNodeReadContext {
    const RandomAccessSource& source;
    Bytes owned;
    unsigned reads = 0, releases = 0;
    bool fail_read = false;
    explicit LeasedNodeContext(const RandomAccessSource& source) : source(source) {}
    bool ReadNode(std::uint64_t, std::uint64_t block, bool,
        std::span<const std::byte>& out, std::string&) override {
        ++reads;
        if (!source.Read(block * 4096, 4096, owned)) return false;
        out = owned;
        return !fail_read;
    }
    void ReleaseNode() noexcept override { ++releases; owned.clear(); }
};
}
int main() {
    try {
        std::vector<apfsaccess::catalog::BtreeRecord> records;
        for (unsigned i = 0; i < 22000; ++i) {
            apfsaccess::catalog::BtreeRecord record{Bytes(16), Bytes(16)};
            PutU64LE(record.key, 0, 256 + i / 3); PutU64LE(record.key, 8, 1 + i % 3);
            PutU32LE(record.value, 4, 4096); PutU64LE(record.value, 8, 1); records.push_back(record);
        }
        AppleBtreeOptions options; options.block_size = 4096; options.xid = 20;
        options.root_object_id = options.root_physical_block = 1;
        options.first_child_object_id = options.first_child_physical_block = 2;
        options.storage_type = kObjectPhysical; options.subtype = kObjectTypeOmap;
        options.tree_flags = kAppleBtreePhysical; options.fixed_key_size = options.fixed_value_size = 16;
        options.key_order = AppleBtreeKeyOrder::ObjectMap;
        AppleSerializedBtree tree; std::string error;
        Check(SerializeAppleBtree(records, options, tree, error), error);
        Check(tree.height >= 2, "fixture has ancestor and intermediate separators");
        std::uint64_t last = 0; for (const auto& object : tree.objects) last = (std::max)(last, object.location.physical_block);
        Bytes image((last + 1) * 4096);
        for (const auto& object : tree.objects) std::copy(object.bytes.begin(), object.bytes.end(), image.begin() + object.location.physical_block * 4096);
        BtreeReadPolicy policy; policy.enforce_object_identity = policy.require_complete_traversal = policy.reject_unsupported_flags = true;
        policy.root_object_id = 1; policy.storage_type = kObjectPhysical; policy.subtype = kObjectTypeOmap;
        std::vector<std::uint64_t> visited; policy.visited_physical_blocks = &visited;
        BtreeRoutingPolicy routing{[](const auto& a, const auto& b, std::string& error) -> std::optional<int> {
            if (a.size() != 16 || b.size() != 16) { error = "test numeric key width"; return std::nullopt; }
            auto left = std::make_pair(ReadU64LE(a, 0).value(), ReadU64LE(a, 8).value());
            auto right = std::make_pair(ReadU64LE(b, 0).value(), ReadU64LE(b, 8).value());
            return left == right ? 0 : left < right ? -1 : 1;
        }};
        std::vector<apfsaccess::catalog::BtreeRecord> result;
        const auto walk = [&](bool strict) {
            VectorRandomAccessSource source(image);
            return strict ? ReadBtreeLeafRecords(source, 4096, 1, true, 0, 20, policy, routing, result, error) :
                ReadBtreeLeafRecords(source, 4096, 1, true, 0, 20, policy, result, error);
        };
        Check(walk(true), "unsigned tuple routing: " + error);
        Check(result.size() == records.size() && visited.size() == tree.objects.size(), "all nodes and leaves read");
        const auto context_walk = [&](bool fail_read) {
            VectorRandomAccessSource source(image);
            LeasedNodeContext context(source); context.fail_read = fail_read;
            const bool ok = ReadBtreeLeafRecords(source, 4096, 1, true, 0, 20,
                policy, routing, result, error, &context);
            Check(context.reads > 0 && context.reads == context.releases && context.owned.empty(),
                "node storage is released after combined traversal and refusal");
            return ok;
        };
        Check(context_walk(false) && result.size() == records.size(), "routing over leased node storage");
        Check(!context_walk(true) && result.empty() && visited.empty(), "failed node provider clears proof outputs");
        const Bytes original(image.begin() + 4096, image.begin() + 8192);
        const auto install = [&](Bytes root) { FletcherForBlock(root, 4096); std::copy(root.begin(), root.end(), image.begin() + 4096); };
        auto root = original; PutU64LE(root, KeyAt(root, 0), 255); install(root);
        Check(walk(false) && result.size() == records.size(), "default parser behavior preserved for wrong minimum");
        Check(!walk(true) && error == "CatalogBtreeRoutingChildMinimumMismatch", "wrong minimum rejected: " + error);
        Check(result.empty() && visited.empty(), "routing failure clears all proof outputs");
        Check(!context_walk(false) && error == "CatalogBtreeRoutingChildMinimumMismatch" &&
            result.empty() && visited.empty(), "leased node storage cannot bypass separator proof");
        root = original; const auto at = KeyAt(root, 1); Bytes separator(root.begin() + at, root.begin() + at + 16);
        auto found = std::find_if(records.begin(), records.end(), [&](const auto& record) { return record.key == separator; });
        Check(found != records.begin() && found != records.end(), "second subtree minimum located");
        std::copy((found - 1)->key.begin(), (found - 1)->key.end(), root.begin() + at); install(root);
        Check(walk(false), "default traversal still sees sorted leaves after upper-bound corruption");
        Check(!walk(true) && (error == "CatalogBtreeRoutingChildUpperBound" || error == "CatalogBtreeRoutingChildMinimumMismatch"),
            "ancestor separator inconsistency rejected: " + error);
        Check(result.empty() && visited.empty(), "ancestor failure clears output");
        install(original);
        bool leaf_changed = false;
        for (const auto& object : tree.objects) {
            if (ReadU16LE(object.bytes, 0x22).value() != 0 || object.location.physical_block == 1) continue;
            const auto count = ReadU32LE(object.bytes, 0x24).value();
            if (count < 2) continue;
            const auto table = 0x38 + ReadU16LE(object.bytes, 0x28).value();
            const auto key = table + ReadU16LE(object.bytes, 0x2A).value() + ReadU16LE(object.bytes, table + (count - 1) * 4).value();
            if (!std::equal((found - 1)->key.begin(), (found - 1)->key.end(), object.bytes.begin() + key)) continue;
            auto leaf = object.bytes; std::copy(separator.begin(), separator.end(), leaf.begin() + key);
            FletcherForBlock(leaf, 4096); std::copy(leaf.begin(), leaf.end(), image.begin() + object.location.physical_block * 4096);
            leaf_changed = true; break;
        }
        Check(leaf_changed, "last leaf below ancestor separator found");
        Check(!walk(true) && error == "CatalogBtreeRoutingChildUpperBound", "exclusive ancestor range enforced at leaf");
        for (const auto& object : tree.objects) if (object.location.physical_block != 1)
            std::copy(object.bytes.begin(), object.bytes.end(), image.begin() + object.location.physical_block * 4096);
        root = original; const auto first = KeyAt(root, 0); const auto second = KeyAt(root, 1);
        std::copy_n(root.begin() + first, 16, root.begin() + second); install(root);
        Check(!walk(true) && error == "CatalogBtreeRoutingSeparatorOrder", "duplicate separator rejected");
        install(original); policy.require_complete_traversal = false;
        Check(!walk(true) && error == "CatalogBtreeRoutingRequiresCompleteTraversal", "routing cannot claim partial traversal");
        std::cout << "PASS Btree routing " << checks << " checks\n"; return 0;
    } catch (const std::exception& e) { std::cerr << "FAIL " << e.what() << '\n'; return 1; }
}
