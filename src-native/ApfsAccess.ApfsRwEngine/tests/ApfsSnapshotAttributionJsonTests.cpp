#include "ApfsVerificationJson.h"
#define APFS_SNAPSHOT_ATTRIBUTION_FIXTURES_ONLY
#include "ApfsSnapshotAttributionTests.cpp"
#undef APFS_SNAPSHOT_ATTRIBUTION_FIXTURES_ONLY
#include <chrono>

namespace
{
const std::string wire_path = "D:\\wire\\\"snapshot\"\nimage.apfs";
using Attribution = std::optional<ApfsSnapshotSpaceAttribution>;

Attribution Fresh(Fixture& f) { return Attribute(f); }

std::string EncodeAttribution(const Attribution& result, const VerificationScope& scope)
{
    std::string output = "must clear"; payload::Reason failure = payload::Reason::None;
    const auto budget = result->read_budget;
    const auto encoded = SerializeSnapshotSpaceAttribution(result, scope, wire_path,
        [] { return true; }, MaxSnapshotSpaceAttributionJsonBytes, output, failure);
    Check(encoded && failure == payload::Reason::None && budget == result->read_budget,
        "bounded attribution encoding: " + std::string(payload::Name(failure)));
    return output;
}

void SaveAttribution(const std::filesystem::path& directory, const char* name, Fixture& f)
{
    const auto result = Fresh(f); const auto json = EncodeAttribution(result, f.scope);
    std::ofstream file(directory / (std::string(name) + "-v1.json"), std::ios::binary);
    file << json; file.close(); Check(static_cast<bool>(file), "encoded attribution evidence written");
    Check(json.starts_with("{\"format\":\"apfs-access-snapshot-space-attribution\",\"version\":1,") &&
        (json.find("\"applePurgeable\":null,\"reclaimable\":null") != std::string::npos) == !result->snapshots.empty(),
        "separate v1 format and unknown policy amounts");
    Pass(std::string("encoded ") + name);
}

Fixture PartialWireFixture()
{
    Fixture f; Seed(f, false, false, 4); f.Create("partial", Pins(f));
    VectorRandomAccessSource source(f.image); std::string error;
    AppleVolumeTransactionRequest request; request.volume_object_id = 101; request.required_checkpoint_xids = Pins(f);
    Check(ReadAppleVolumeFileSystemRecords(source, f.checkpoint.container, f.checkpoint.volumes[0], request.filesystem_records, error), error);
    std::erase_if(request.filesystem_records, [](const auto& row) { return ReadU64LE(row.key, 0).value_or(0) >> 60 == 8; });
    request.filesystem_records.push_back(Encode(AppleFileExtentRecord{30, 0, f.bs, 220, 0, f.bs}, EncodeAppleFileExtentRecord));
    request.filesystem_records.push_back(Encode(AppleFileExtentRecord{30, 3ull * f.bs, f.bs, 223, 0, f.bs}, EncodeAppleFileExtentRecord));
    request.released_data_blocks = {{221, 2}};
    request.data_writes.push_back({30, f.bs, 0, Bytes(2ull * f.bs, std::byte{0x61})});
    AppleVolumeTransactionPlan plan;
    const auto planned = PlanAppleSnapshotLiveTransaction(source, f.checkpoint, request, plan, error);
    Check(planned, "wire partial COW: " + error); f.Publish(plan.commit.publication); return f;
}

void WirePositiveCases(const std::filesystem::path& directory)
{
    { Fixture f; SaveAttribution(directory, "empty", f); }
    for (const auto bs : {4096u, 8192u})
    {
        Fixture f(bs); f.Create("shared", Pins(f));
        SaveAttribution(directory, bs == 4096 ? "shared-4096" : "shared-8192", f);
    }
    { Fixture f; Seed(f, true, false); f.Create("clones", Pins(f)); SaveAttribution(directory, "clones", f); }
    { Fixture f; Seed(f, false, true); f.Create("attribute", Pins(f)); SaveAttribution(directory, "external-xattr", f); }
    { auto f = PartialWireFixture(); SaveAttribution(directory, "partial-overlap", f); }
    { Fixture f; f.Create("first", Pins(f)); f.Create("second", Pins(f)); f.Cow(true, Pins(f)); SaveAttribution(directory, "multiple", f); }
    { Fixture f; GrowMetadata(f); f.Create("multi-node", Pins(f)); SaveAttribution(directory, "multi-node", f); }
    { Fixture f; AddPeer(f, 221); f.Create("peer", Pins(f)); SaveAttribution(directory, "peers", f); }
    { Fixture f; f.Create("quoted-\"\xE9\x9B\xAA", Pins(f)); SaveAttribution(directory, "utf8-escaped", f); }
    {
        Fixture f; f.Create("window", Pins(f)); Bytes image(f.bs, std::byte{0x71});
        image.insert(image.end(), f.image.begin(), f.image.end()); f.scope.exact.store_offset_bytes = f.bs;
        VectorRandomAccessSource source(image); Attribution result; std::string error;
        const auto complete = TryAttributeAppleSnapshotSpace(source, f.scope, result, error);
        Check(complete, "nonzero store window: " + error);
        const auto json = EncodeAttribution(result, f.scope);
        std::ofstream file(directory / "offset-window-v1.json", std::ios::binary); file << json; file.close();
        Check(static_cast<bool>(file), "nonzero window evidence written"); Pass("encoded nonzero exact source window");
    }
}

void WireRejections()
{
    Fixture f; f.Create("first", Pins(f)); f.Create("second", Pins(f)); f.Cow(true, Pins(f));
    const auto original = Fresh(f);
    const auto reject = [&](const char* name, const auto& mutate, payload::Reason expected = payload::Reason::InvalidProjection) {
        auto result = original; auto scope = f.scope; mutate(result, scope);
        std::string output = "must clear"; payload::Reason failure = payload::Reason::None;
        const auto encoded = SerializeSnapshotSpaceAttribution(result, scope, wire_path, [] { return true; },
            MaxSnapshotSpaceAttributionJsonBytes, output, failure);
        Check(!encoded && output.empty() && failure == expected,
            std::string("invalid attribution rejected: ") + name + ":" + std::string(payload::Name(failure)));
        Pass(std::string("reject ") + name);
    };
    reject("absent result", [](auto& r, auto&) { r.reset(); }, payload::Reason::AdmissionNotComplete);
    reject("incomplete marker", [](auto& r, auto&) { r->complete = false; }, payload::Reason::AdmissionNotComplete);
    reject("missing original allowance", [](auto& r, auto&) { r->read_budget.reset(); }, payload::Reason::InvalidBinding);
    reject("wrong source label", [](auto& r, auto&) { r->source_identity += "other"; }, payload::Reason::InvalidBinding);
    reject("wrong selected volume", [](auto& r, auto&) { ++r->scope.volume_oid; }, payload::Reason::InvalidBinding);
    reject("wrong endpoint", [](auto& r, auto&) { ++r->scope.checkpoint_xid; }, payload::Reason::InvalidBinding);
    reject("wrong source window", [](auto& r, auto&) { r->scope.store_offset_bytes = 4096; }, payload::Reason::InvalidBinding);
    reject("unaligned geometry", [](auto& r, auto& s) { ++r->scope.store_size_bytes; s.exact = r->scope; });
    reject("overflowing window", [](auto& r, auto& s) { r->scope.store_offset_bytes = UINT64_MAX - 4095; s.exact = r->scope; });
    reject("invalid UUID", [](auto& r, auto& s) { r->scope.volume_uuid_hex[0] = 'G'; s.exact = r->scope; });
    reject("broader request", [](auto&, auto& s) { s.require_whole_volume = true; });
    reject("unsupported observation request", [](auto&, auto& s) { s.observe_payload_content = true; });
    reject("missing retained endpoint", [](auto& r, auto&) { r->retained_checkpoint_xids.pop_back(); });
    reject("unordered retained chain", [](auto& r, auto&) { std::reverse(r->retained_checkpoint_xids.begin(), r->retained_checkpoint_xids.end()); });
    reject("duplicate snapshot XID", [](auto& r, auto&) { r->snapshots[1].snapshot_xid = r->snapshots[0].snapshot_xid; });
    reject("duplicate snapshot name", [](auto& r, auto&) { r->snapshots[1].name_utf8 = r->snapshots[0].name_utf8; });
    reject("invalid UTF8", [](auto& r, auto&) { r->snapshots[0].name_utf8 = "\xC0\x80"; });
    reject("embedded NUL", [](auto& r, auto&) { r->snapshots[0].name_utf8.push_back('\0'); });
    reject("unbounded name", [](auto& r, auto&) { r->snapshots[0].name_utf8.assign(65536, 'x'); });
    reject("byte mismatch", [](auto& r, auto&) { ++r->snapshots[0].payload.referenced.bytes; });
    reject("physical overflow", [](auto& r, auto&) { r->snapshots[0].payload.referenced.blocks = UINT64_MAX; });
    reject("live partition mismatch", [](auto& r, auto&) { r->snapshots[0].payload.absent_from_live = {}; });
    reject("shared rows cannot be summed", [](auto& r, auto&) { r->referenced_payload = {2, 8192}; });
    reject("catalog excludes metadata footprint", [](auto& r, auto&) { r->catalog_metadata = {}; });
    reject("zero referenced snapshot metadata", [](auto& r, auto&) { r->snapshots[0].metadata = {}; });
    reject("invented visible uniqueness", [](auto& r, auto&) { r->snapshots[0].payload.unique_in_visible_inventory = {1,4096}; });
    reject("invented potential release", [](auto& r, auto&) { r->snapshots[0].payload.potential_reclaim_upper_bound = {1,4096}; });
    reject("invented zero Apple purgeability", [](auto& r, auto&) { r->snapshots[0].apple_purgeable = ApfsSpaceAmount{}; });
    reject("invented zero reclaimability", [](auto& r, auto&) { r->snapshots[0].reclaimable = ApfsSpaceAmount{}; });
    reject("nonzero purgeable marked payload", [](auto& r, auto&) { r->snapshots[0].purgeable_marked_payload = {1,4096}; });
    reject("invalid requested pin", [](auto&, auto& s) { s.retained_from_xid = 19; });
}

void WireCatalogCapacity(const std::filesystem::path& directory)
{
    for (const auto bs : {4096u, 8192u})
    {
        Fixture f(bs); f.Create("catalog-bound", Pins(f)); auto result = Fresh(f);
        const auto capacity = f.scope.exact.store_size_bytes / bs;
        Check(result->referenced_payload.blocks == 1 && result->referenced_metadata.blocks < capacity - 1,
            "catalog capacity fixture distinguishes snapshot union from complete catalog");
        result->catalog_metadata = {capacity - 1, (capacity - 1) * bs};
        const auto control = EncodeAttribution(result, f.scope);
        std::ofstream file(directory / ("catalog-bound-" + std::to_string(bs) + "-v1.json"), std::ios::binary);
        file << control; file.close(); Check(static_cast<bool>(file), "exact catalog plus payload boundary evidence");
        Pass("exact catalog plus payload capacity " + std::to_string(bs));

        result->catalog_metadata = {capacity, capacity * bs};
        std::string output = "must clear"; payload::Reason failure = payload::Reason::None;
        const auto encoded = SerializeSnapshotSpaceAttribution(result, f.scope, wire_path,
            [] { return true; }, MaxSnapshotSpaceAttributionJsonBytes, output, failure);
        Check(!encoded && output.empty() && failure == payload::Reason::InvalidProjection && !result->read_budget->Failed(),
            "catalog metadata plus payload exceeds store by one block: " + std::to_string(bs));
        result->catalog_metadata = {capacity - 1, (capacity - 1) * bs};
        Check(EncodeAttribution(result, f.scope) == control, "projection refusal preserves valid exact-boundary retry");
        Pass("reject contradictory catalog plus payload capacity " + std::to_string(bs));
    }
}

void WireLimits()
{
    Fixture f; f.Create("bounded", Pins(f)); const auto control = EncodeAttribution(Fresh(f), f.scope);
    {
        VectorRandomAccessSource raw(f.image);
        auto budget = std::make_shared<ApfsReadBudget>(65536, 256ull << 20, 4000000, 512ull << 20);
        Check(budget->Materialize(f.scope.max_records + 1, f.scope.max_records + 1), "caller spends before attribution");
        BudgetedRandomAccessSource source(raw, budget); Attribution result; std::string error;
        Check(TryAttributeAppleSnapshotSpace(source, f.scope, result, error) && result && result->read_budget == budget,
            "producer admits exact inherited allowance: " + error);
        const auto before = budget->Consumed();
        Check(before.records > f.scope.max_records, "cumulative caller work exceeds this operation's cap");
        Check(EncodeAttribution(result, f.scope) == control && budget->Consumed().records > before.records && !budget->Failed(),
            "serializer spends remaining inherited allowance without rejecting prior caller work");
        budget->LimitRemainingTo(0, 0, 0, 0);
        std::string output = "must clear"; payload::Reason failure = payload::Reason::None;
        Check(!SerializeSnapshotSpaceAttribution(result, f.scope, wire_path, [] { return true; }, MaxSnapshotSpaceAttributionJsonBytes, output, failure) &&
            output.empty() && failure == payload::Reason::SharedBudget && budget->Failed(), "inherited exhausted allowance cannot be replenished");
        Pass("inherited cumulative allowance and exhausted retry");
    }
    {
        auto result = Fresh(f); const auto budget = result->read_budget;
        std::string output; payload::Reason failure = payload::Reason::None;
        Check(SerializeSnapshotSpaceAttribution(result, f.scope, wire_path, [] { return true; }, control.size(), output, failure) &&
            output == control && budget == result->read_budget, "exact response boundary and original allowance");
        Pass("exact attribution response boundary");
    }
    {
        auto result = Fresh(f); const auto budget = result->read_budget;
        std::string output = "must clear"; payload::Reason failure = payload::Reason::None;
        Check(!SerializeSnapshotSpaceAttribution(result, f.scope, wire_path, [] { return true; }, control.size() - 1, output, failure) &&
            output.empty() && failure == payload::Reason::OutputLimit && budget->Failed() && budget == result->read_budget, "one-byte overflow is sticky without partial prefix");
        Check(!SerializeSnapshotSpaceAttribution(result, f.scope, wire_path, [] { return true; }, MaxSnapshotSpaceAttributionJsonBytes, output, failure) &&
            output.empty() && failure == payload::Reason::SharedBudget, "overflow retry cannot replace allowance");
        Pass("attribution overflow and sticky retry");
    }
    {
        auto result = Fresh(f); result->read_budget->LimitRemainingTo(65536, 256ull << 20, 0, 0);
        std::string output = "must clear"; payload::Reason failure = payload::Reason::None;
        Check(!SerializeSnapshotSpaceAttribution(result, f.scope, wire_path, [] { return true; }, MaxSnapshotSpaceAttributionJsonBytes, output, failure) &&
            output.empty() && failure == payload::Reason::SharedBudget && result->read_budget->Failed(), "validation spends native remaining allowance");
        Pass("attribution validation allowance");
    }
    {
        auto result = Fresh(f); const auto first = result->read_budget->Consumed();
        result->read_budget->LimitRemainingTo(65536, 256ull << 20, 1, 128);
        std::string output; payload::Reason failure = payload::Reason::None;
        Check(!SerializeSnapshotSpaceAttribution(result, f.scope, wire_path, [] { return true; }, MaxSnapshotSpaceAttributionJsonBytes, output, failure) &&
            output.empty() && failure == payload::Reason::SharedBudget && result->read_budget->Consumed().records == first.records + 1,
            "late response allocation fails after validation under the same allowance");
        Pass("attribution response materialization allowance");
    }
    {
        auto result = Fresh(f); unsigned calls = 0; std::string output; payload::Reason failure = payload::Reason::None;
        Check(SerializeSnapshotSpaceAttribution(result, f.scope, wire_path, [&] { ++calls; return true; }, MaxSnapshotSpaceAttributionJsonBytes, output, failure), "deadline control");
        result = Fresh(f); unsigned current = 0; output = "must clear";
        Check(!SerializeSnapshotSpaceAttribution(result, f.scope, wire_path, [&] { return ++current < calls; }, MaxSnapshotSpaceAttributionJsonBytes, output, failure) &&
            output.empty() && failure == payload::Reason::Deadline && result->read_budget->Failed(), "late emit deadline clears allocated JSON");
        Pass("late attribution encoding deadline");
    }
    {
        auto result = Fresh(f); std::string output = "must clear"; payload::Reason failure = payload::Reason::None;
        Check(!SerializeSnapshotSpaceAttribution(result, f.scope, wire_path, [] { return false; }, MaxSnapshotSpaceAttributionJsonBytes, output, failure) &&
            output.empty() && failure == payload::Reason::Deadline && result->read_budget->Failed(), "expired validation deadline");
        Pass("attribution validation deadline");
    }
    {
        auto result = Fresh(f); std::string output = "must clear"; payload::Reason failure = payload::Reason::None;
        Check(!SerializeSnapshotSpaceAttribution(result, f.scope, wire_path, []() -> bool { throw std::runtime_error("callback"); }, MaxSnapshotSpaceAttributionJsonBytes, output, failure) &&
            output.empty() && failure == payload::Reason::CallbackFailure, "throwing callback produces no document");
        Pass("attribution callback failure");
    }
    for (unsigned kind = 0; kind < 3; ++kind)
    {
        Fixture broken;
        if (kind == 0) AllocateOrphan(broken, 300);
        if (kind == 1) { broken = Ordinary(); BreakNextLink(broken); }
        if (kind == 2) broken.scope.exact.volume_uuid_hex = std::string(32, 'c');
        VectorRandomAccessSource source(broken.image); Attribution result{ApfsSnapshotSpaceAttribution{}}; std::string error;
        Check(!TryAttributeAppleSnapshotSpace(source, broken.scope, result, error) && !result, "actual incomplete attribution cleared");
        std::string output = "must clear"; payload::Reason failure = payload::Reason::None;
        Check(!SerializeSnapshotSpaceAttribution(result, broken.scope, wire_path, [] { return true; }, MaxSnapshotSpaceAttributionJsonBytes, output, failure) &&
            output.empty() && failure == payload::Reason::AdmissionNotComplete, "actual orphan/history/identity failure cannot manufacture empty JSON success");
        Pass("actual incomplete result has no attribution document " + std::to_string(kind));
    }
}
}

int main(int argc, char** argv)
{
    try
    {
        Check(argc == 1 || argc == 2, "optional D: evidence directory");
        const auto directory = argc == 2 ? std::filesystem::path(argv[1]) :
            std::filesystem::path("D:/ApfsAccessScratch/WindowsClosure/attribution-json-ctest") /
                std::to_string(std::chrono::steady_clock::now().time_since_epoch().count());
        Check(directory.is_absolute() && directory.root_name() == "D:", "all output remains private on D:");
        std::filesystem::create_directories(directory);
        WirePositiveCases(directory); WireRejections(); WireCatalogCapacity(directory); WireLimits();
        std::cout << "PASS " << cases << " cases, " << checks << " checks\n"; return 0;
    }
    catch (const std::exception& e) { std::cerr << "FAIL " << e.what() << '\n'; return 1; }
}
