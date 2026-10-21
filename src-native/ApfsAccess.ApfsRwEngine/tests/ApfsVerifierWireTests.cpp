// Directly compile with the same engine headers/objects as ApfsObserver.
#define main ObserverEntryForWireTests
#include "../tools/ApfsObserver.cpp"
#undef main
#define main VerifierFixtureEntryForWireTests
#include <ApfsVerifierTests.cpp>
#undef main

namespace {
void WriteImage(const std::filesystem::path& path, const Bytes& bytes)
{
    std::ofstream output(path, std::ios::binary);
    output.write(reinterpret_cast<const char*>(bytes.data()), bytes.size());
    Check(output.good(), "write private regular fixture");
}
void WireCase(const std::filesystem::path& directory, const std::string& name,
    const Bytes& bytes, VerificationScope scope, VerificationOutcome outcome,
    std::optional<VerificationCode> code = std::nullopt)
{
    const auto path = directory / (name + ".apfs"); WriteImage(path, bytes);
    VerificationImageLease lease(path.string()); scope.source_identity = lease.Identity();
    const auto report = ApfsVerifier::Verify(lease, scope);
    Check(report.outcome == outcome, name + ": " + Detail(report));
    if (code) Check(Has(report, *code), name + " finding");
    Check(lease.VerifyUnchanged(), "held source unchanged");
    Bytes after; Check(lease.Read(0, bytes.size(), after) && after == bytes, "same-handle bytes unchanged after verifier");
    Check(report.coverage.size() == 20 && !report.whole_volume_verified &&
        !report.payload_content_hashes_verified, "explicit subset coverage");
    Check(report.allocation_census.has_value() == (outcome == VerificationOutcome::Complete), "census publication");
    if (report.allocation_census)
        Check(report.allocation_census->block_size_bytes * report.allocation_census->container_block_count == scope.exact.store_size_bytes,
            "exact fixture geometry is published with census");
    const auto json = VerificationJson(report, path.string());
    Check(json.find("\"version\": 2") != std::string::npos, "wire v2");
    Check(json.find(outcome == VerificationOutcome::Complete ? "\"allocationCensus\": {" :
        "\"allocationCensus\": null") != std::string::npos, "wire census presence");
    Check(json.find("\"nextActionableCandidate\": null") != std::string::npos, "no repair candidate");
    if (outcome != VerificationOutcome::Complete)
        Check(report.covered_filesystem_records == 0 && report.covered_physical_extents == 0, "no late published counts");
    std::ofstream output(directory / (name + ".json")); output << json; Check(output.good(), "wire evidence");
    Pass(name);
}
}
int main(int argc, char** argv)
{
    try {
        Check(argc == 2, "private fixture output directory required");
        const std::filesystem::path directory(argv[1]); std::filesystem::create_directories(directory);
        for (const auto bs : {4096u, 8192u}) {
            Fixture f(bs); WireCase(directory, "healthy-" + std::to_string(bs), f.image, f.scope, VerificationOutcome::Complete);
        }
        {
            Fixture f;
            for (auto block : {221ull, 223ull, 224ull, 250ull})
                f.spec.authoritative_seeded_main_blocks.emplace_back(block, Bytes(f.bs, std::byte{0x4a}));
            f.Rebuild(); VectorRandomAccessSource source(f.image); std::string error;
            const auto cp = LoadAppleCheckpointView(source, 0, source.SizeBytes(), error, 20); Check(cp.has_value(), error);
            const auto& pool = cp->spaceman.internal_pool; std::uint64_t bit = 0;
            while (bit < pool.block_count && (std::to_integer<unsigned>(pool.active_bitmaps[0].bytes[bit/8]) & (1u << (bit%8)))) ++bit;
            Check(bit < pool.block_count, "free internal bit");
            f.Edit(pool.active_bitmaps[0].physical_block, [&](auto& b) { b[bit/8] |= std::byte(1u << (bit%8)); }, false);
            WireCase(directory, "residual", f.image, f.scope, VerificationOutcome::Complete);
        }
        {
            Fixture f; f.Edit(4, [](auto& b) { PutU64LE(b, 0x58, 6); });
            WireCase(directory, "undercount", f.image, f.scope, VerificationOutcome::Incomplete, VerificationCode::AllocatedCountUnderstated);
        }
        {
            Fixture f; f.fs = {Inode(2,0,0,true,f.bs)}; f.refs.clear(); f.spec.authoritative_seeded_main_blocks.clear();
            f.spec.volumes[0].additional_file_system_allocated_blocks = 0;
            BuilderVolume sibling; sibling.oid = 102; sibling.uuid_hex = std::string(32,'c'); f.spec.volumes.push_back(sibling); f.Rebuild();
            VectorRandomAccessSource source(f.image); std::string error;
            const auto cp = LoadAppleCheckpointView(source, 0, source.SizeBytes(), error, 20); Check(cp.has_value(), error);
            f.Edit(5, [&](auto& b) { PutU64LE(b, 0x90, cp->volumes[0].extentref_tree->physical_block); });
            WireCase(directory, "owner-conflict", f.image, f.scope, VerificationOutcome::Incomplete, VerificationCode::MetadataOwnerConflict);
        }
        {
            Fixture f; f.spec.volumes[0].quota_block_count = 1; f.Rebuild();
            WireCase(directory, "late-quota", f.image, f.scope, VerificationOutcome::Incomplete, VerificationCode::QuotaOrReserveInconsistent);
        }
        {
            Fixture f; f.scope.require_whole_volume = true;
            WireCase(directory, "whole-volume", f.image, f.scope, VerificationOutcome::Incomplete, VerificationCode::CoverageMissing);
        }
        {
            SnapshotFixture f; VectorRandomAccessSource source(f.image); std::string error;
            const auto cp = LoadAppleCheckpointView(source,0,source.SizeBytes(),error,20); Check(cp.has_value(), error);
            const auto& chunk = cp->spaceman.chunks[0]; unsigned added = 0;
            f.Edit(chunk.bitmap_block, [&](auto& b) {
                for (const auto block : {180ull,181ull,183ull,184ull,185ull,220ull}) {
                    const auto bit = block - chunk.start_block;
                    if ((std::to_integer<unsigned>(b[bit/8]) & (1u << (bit%8))) == 0) { b[bit/8] |= std::byte(1u << (bit%8)); ++added; }
                }
            }, false);
            f.Edit(cp->spaceman.devices[0].cibs[0].object.physical_block, [&](auto& b) { PutU32LE(b,0x3C,chunk.free_count-added); });
            f.Edit(cp->spaceman.object.physical_block, [&](auto& b) { PutU64LE(b,0x48,cp->spaceman.devices[0].free_count-added); });
            // Six ordinary objects plus the current OMAP snapshot-index node.
            f.Edit(4, [](auto& b) { PutU64LE(b,0x58,7); });
            VerificationScope scope; scope.exact = f.scope;
            WireCase(directory, "snapshot-current", f.image, scope, VerificationOutcome::Complete);
            auto unallocated=f;
            unallocated.Edit(chunk.bitmap_block, [&](auto& b) {
                const auto bit=181ull-chunk.start_block;
                b[bit/8]&=~std::byte(1u<<(bit%8));
            }, false);
            unallocated.Edit(cp->spaceman.devices[0].cibs[0].object.physical_block,
                [&](auto& b) { PutU32LE(b,0x3C,chunk.free_count-added+1); });
            unallocated.Edit(cp->spaceman.object.physical_block,
                [&](auto& b) { PutU64LE(b,0x48,cp->spaceman.devices[0].free_count-added+1); });
            WireCase(directory, "snapshot-omap-unallocated", unallocated.image, scope,
                VerificationOutcome::Incomplete, VerificationCode::MetadataAllocationInconsistent);
            auto broad = scope; broad.require_whole_volume = true;
            WireCase(directory, "snapshot-refused", f.image, broad, VerificationOutcome::Refused, VerificationCode::SnapshotAccountingUnsupported);
            f.Edit(183, [](auto& b) { b[0] ^= std::byte{1}; }, false);
            WireCase(directory, "snapshot-corrupt", f.image, scope, VerificationOutcome::Incomplete);
        }
        {
            Fixture f; auto report = Verify(f);
            report.allocation_census->current_payload_blocks = UINT64_MAX;
            Check(VerificationJson(report, "private.apfs").find("\"currentPayloadBlocks\": \"18446744073709551615\"") != std::string::npos,
                "serializer never rounds uint64 observations");
            report.coverage[0].scope_detail.assign(64ull * 1024 * 1024, 'x');
            bool refused = false;
            try { (void)VerificationJson(report, "private.apfs"); } catch (const std::length_error&) { refused = true; }
            Check(refused, "oversized report not returned for publication"); Pass("serialization bounds and uint64");
        }
        {
            // Codec-only shape controls; authenticated history is exercised by
            // ApfsVerifierHistoryTests and the real observer/CLI process gate.
            Fixture f; auto report = Verify(f);
            Check(report.outcome == VerificationOutcome::Complete && report.selected.has_value(), "history codec current fixture");
            report.requested_scope.retained_from_xid = 19;
            report.coverage.push_back({VerificationCheck::RequestedHistoryOwnership, true, true,
                VerificationCheckState::Verified, "codec-only requested history"});
            report.requested_history = RequestedHistoryVerification{19, *report.selected, {19,20},
                {{19, {{4,1}}, {{220,1}}}}};
            std::string output;
            payload::Reason reason;
            Check(!SerializeImageVerificationReport(report, "codec-fixture.apfs", [] { return true; },
                MaxImageVerificationJsonBytes, output, reason) && output.empty(), "legacy bounded codec rejects requested history");
            bool rejected = false;
            try { (void)VerificationJson(report, "codec-fixture.apfs"); }
            catch (const std::length_error&) { rejected = true; }
            Check(rejected, "legacy observer codec rejects requested history");
            Check(SerializeProtectedHistoryVerificationReport(report, "codec-fixture.apfs", [] { return true; },
                MaxImageVerificationJsonBytes, output, reason), "explicit history codec accepts coherent report shape");
            Check(output.find("\"format\":\"apfs-access-protected-history-verification\"") != std::string::npos &&
                output.find("\"retainedFromXid\":\"19\"") != std::string::npos &&
                output.find("\"requestedHistory\":{") != std::string::npos &&
                output.find("\"repair\"") == std::string::npos,
                "history wire separates requested scope and exposes no repair plan");
            const auto reject = [&](const std::function<void(VerificationReport&)>& mutate) {
                auto invalid = report;
                mutate(invalid);
                std::string partial = "must clear";
                payload::Reason failure;
                Check(!SerializeProtectedHistoryVerificationReport(invalid, "codec-fixture.apfs", [] { return true; },
                    MaxImageVerificationJsonBytes, partial, failure) && partial.empty() &&
                    failure == payload::Reason::InvalidProjection, "inconsistent history shape cannot publish bytes");
            };
            reject([](auto& r) { r.requested_history.reset(); });
            reject([](auto& r) { r.requested_history->endpoint.root_physical_block++; });
            reject([](auto& r) { r.requested_history->chain_xids.back()++; });
            reject([](auto& r) { r.requested_history->checkpoints.clear(); });
            reject([](auto& r) { r.requested_history->checkpoints[0].metadata_ranges[0].block_count = 0; });
            reject([](auto& r) { r.requested_history->checkpoints[0].metadata_ranges.push_back({5,1}); });
            reject([](auto& r) { r.requested_history->checkpoints[0].payload_ranges = {{4,1}}; });
            reject([](auto& r) { r.requested_history->checkpoints[0].payload_ranges = {{UINT64_MAX,1}}; });
            reject([](auto& r) { r.coverage[0] = r.coverage.back(); });
            reject([](auto& r) { r.coverage.back().state = VerificationCheckState::Unproven; });
            reject([](auto& r) { r.whole_volume_verified = true; });
            reject([](auto& r) { r.outcome = VerificationOutcome::Incomplete; });
            auto limited = report;
            limited.read_budget = std::make_shared<ApfsReadBudget>(65536,256ull<<20,1000000,256ull<<20);
            std::string partial = "must clear";
            Check(!SerializeProtectedHistoryVerificationReport(limited, "codec-fixture.apfs", [] { return true; },
                output.size() - 1, partial, reason) && partial.empty() && reason == payload::Reason::OutputLimit,
                "history response overflow publishes no partial JSON");
            auto cancelled = report;
            cancelled.read_budget = std::make_shared<ApfsReadBudget>(65536,256ull<<20,1000000,256ull<<20);
            Check(!SerializeProtectedHistoryVerificationReport(cancelled, "codec-fixture.apfs", [] { return false; },
                MaxImageVerificationJsonBytes, partial, reason) && partial.empty() && reason == payload::Reason::Deadline,
                "history deadline publishes no partial JSON");
            Pass("requested history codec shape, legacy isolation and failure controls");
        }
        std::cout << "WIRE " << cases << " cases, " << checks << " checks\n"; return 0;
    } catch (const std::exception& e) { std::cerr << "FAIL " << e.what() << '\n'; return 1; }
}
