#pragma once

namespace {
void SaveConsumerWire(const std::string& name, const std::string& wire)
{
    std::ofstream file(name, std::ios::binary); file << wire;
    Check(file.good(), "save actual consumer wire");
}

void Task10LiveMetadataOnlyConsumers()
{
    {
        HostVerification host("metadata-large-sparse", 0, true, false, false, payload::MaxLogicalBytes + 1);
        Unchanged unchanged(host);
        const auto full = host.Request();
        const auto bounded = host.Run(full);
        Check(!bounded.success && bounded.code == "VolumeVerificationReportBound",
            "full payload observation retains its fixed logical bound");
        auto metadata = full;
        metadata.action = ContainerControlAction::VolumeVerifyMetadata;
        ContainerControlRequest parsed; std::string error;
        Check(ParseContainerControlRequestContents(Envelope(metadata), std::string(64, 'b'), parsed, error) &&
            parsed.action == ContainerControlAction::VolumeVerifyMetadata && parsed.verification_scope,
            "metadata inspection uses the same authenticated exact-source envelope: " + error);
        const auto result = host.Run(parsed);
        Check(result.success && result.volume_verification, "large-file metadata-only request: " + result.code);
        const auto& report = result.volume_verification->report;
        Check(report.outcome == VerificationOutcome::Complete && report.findings.empty() &&
            !report.requested_scope.observe_payload_content && !report.payload_inventory && report.coverage.size() == 20 &&
            !report.whole_volume_verified && !report.payload_content_hashes_verified,
            "Fix metadata proof is independent of payload bytes and retains honest coverage");
        std::string wire;
        Check(BuildContainerControlResponse(parsed, result, wire) && wire.find("\"version\":1") != std::string::npos &&
            wire.size() <= kLiveVerificationResponseBytes, "bounded metadata-only wire");
        auto stale = parsed; ++stale.verification_scope->exact.checkpoint_xid;
        Refused(host.Run(stale), "metadata-only stale source still refuses");
        VerificationScope low; low.max_reads = 1;
        const auto exhausted = VolumeVerifyForControl(host.Context(), *host.owner, parsed, std::chrono::seconds(5), low);
        Check(!exhausted.success && exhausted.code == "VolumeVerificationReportBound",
            "metadata-only request preserves the shared resource allowance");
        unchanged.Assert();
        Pass("metadata-only Fix above full content limit preserves identity, budgets and bytes");
    }
}

void Task10LiveConsumers()
{
    for (const auto base : {0ull, 8192ull}) {
        HostVerification host("payload-" + std::to_string(base), base, true, true, true);
        const auto request = host.Request(); Unchanged unchanged(host);
        const auto result = host.Run(request);
        Check(result.success && result.volume_verification, "actual live payload caller: " + result.code);
        const auto& report = result.volume_verification->report;
        Check(report.requested_scope.observe_payload_content && report.payload_inventory && report.payload_inventory->exactComplete() &&
            PayloadState(report) == VerificationCheckState::Verified && report.payload_inventory->entries.size() == 8 &&
            report.payload_inventory->logicalBytesRead == 4137, "live admitted complete ordered projection: " + Detail(report) +
            " entries=" + std::to_string(report.payload_inventory ? report.payload_inventory->entries.size() : 0) +
            " logical=" + std::to_string(report.payload_inventory ? report.payload_inventory->logicalBytesRead : 0));
        Check(report.payload_inventory->entries.front().observedSha256 ==
            "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad", "live reads store coordinates exactly once");
        Check(!report.whole_volume_verified && !report.payload_content_hashes_verified &&
            report.read_budget == report.payload_inventory->sharedBudget, "no integrity authority or replacement budget");
        std::string wire;
        Check(BuildContainerControlResponse(request, result, wire) && wire == result.volume_verification->serialized_response &&
            wire.size() <= kLiveVerificationResponseBytes && wire.find("volume-verification-json/1\n") != std::string::npos &&
            wire.find("\"version\":2") != std::string::npos, "exact cached bounded live v2 transport");
        SaveConsumerWire("live-" + std::to_string(base) + "-v2.response", wire);
        // Exercise the untouched metadata-only default and actual legacy managed shape.
        VerificationScope legacy_scope = report.requested_scope; legacy_scope.observe_payload_content = false;
        RetainedVolumeVerificationSource source(host.Device(), legacy_scope, std::chrono::steady_clock::now() + std::chrono::seconds(5));
        LiveVolumeVerification legacy;
        legacy.report = ApfsVerifier::Verify(source, legacy_scope); legacy.source_kind = "retained-image";
        std::string old_json;
        Check(legacy.report.coverage.size() == 20 && !legacy.report.payload_inventory &&
            BuildLiveVolumeVerificationJson(legacy, old_json), "metadata-only legacy live serializer");
        SaveConsumerWire("live-" + std::to_string(base) + "-v1.json", old_json);
        auto mismatched = request; ++mismatched.verification_scope->exact.store_offset_bytes;
        Refused(host.Run(mismatched), "shifted store request refuses before reads");
        auto wrong_cp = request; ++wrong_cp.verification_scope->exact.checkpoint_xid;
        Refused(host.Run(wrong_cp), "wrong current checkpoint refuses");
        VerificationScope low; low.max_reads = 1;
        const auto exhausted = VolumeVerifyForControl(host.Context(), *host.owner, request, std::chrono::seconds(5), low);
        Check(!exhausted.success && exhausted.code == "VolumeVerificationReportBound" && !exhausted.volume_verification,
            "sticky exhausted read allowance uses typed refusal");
        Check(BuildContainerControlResponse(request, exhausted, wire) && wire.find("\nerror\nVolumeVerificationReportBound\n") != std::string::npos,
            "bounded refusal transport carries no JSON");
        const auto bound = VolumeVerifyForControl(host.Context(), *host.owner, request, std::chrono::seconds(5), {}, 1024);
        Check(!bound.success && bound.code == "VolumeVerificationReportBound" && !bound.volume_verification,
            "whole response cap before successful publication");
        const auto timeout = VolumeVerifyForControl(host.Context(), *host.owner, request, std::chrono::milliseconds(0));
        Check(!timeout.success && timeout.code == "VolumeVerificationTimedOut", "actual deadline admission refusal");
        auto expired = result; expired.volume_verification->deadline = std::chrono::steady_clock::now();
        Check(BuildContainerControlResponse(request, expired, wire) && wire.find("\nerror\nVolumeVerificationTimedOut\n") != std::string::npos,
            "expired prepared report cannot escape transport boundary");
        unchanged.Assert(); Pass("retained live payload/source-coordinate/budget/deadline/legacy " + std::to_string(base));
    }
    for (unsigned damage = 0; damage < 2; ++damage) {
        HostVerification host("damage-" + std::to_string(damage), 8192, true, false, true);
        const auto request = host.Request();
        const auto original = host.fixture.image;
        if (damage == 0) host.fixture.Edit(7, [](auto& bytes) { bytes[100] ^= std::byte{1}; }, false);
        else ClearMainAllocation(host.fixture, 222);
        if (damage == 0) host.ReplaceBlock(7);
        else {
            for (std::uint64_t block = 0; block < host.fixture.image.size() / host.fixture.bs; ++block) {
                const auto at = block * host.fixture.bs;
                if (!std::equal(original.begin() + at, original.begin() + at + host.fixture.bs, host.fixture.image.begin() + at))
                    host.ReplaceBlock(block);
            }
        }
        Unchanged unchanged(host); const auto result = host.Run(request);
        Check(result.success && result.volume_verification && result.volume_verification->report.outcome != VerificationOutcome::Complete &&
            !result.volume_verification->report.payload_inventory->enumerationComplete &&
            result.volume_verification->report.payload_inventory->entries.empty(), "corrupt metadata/allocator cannot acquire payload admission");
        std::string wire; Check(BuildContainerControlResponse(request, result, wire), "semantic refusal remains delivered");
        SaveConsumerWire("live-damage-" + std::to_string(damage) + "-v2.response", wire);
        unchanged.Assert(); Pass("actual live corruption gate " + std::to_string(damage));
    }
    for (unsigned changed = 0; changed < 3; ++changed) {
        HostVerification host("final-proof-" + std::to_string(changed), 8192, true, true, true);
        const auto request = host.Request();
        g_volume_verification_before_final_proof = [&](MountContext&) {
            if (changed == 0) host.contexts.back()->write_degraded = true;
            else if (changed == 1) host.contexts.back()->tx_manager->SetJournalPath(L"");
            else std::this_thread::sleep_for(std::chrono::milliseconds(600));
        };
        const auto result = VolumeVerifyForControl(host.Context(), *host.owner, request,
            changed == 2 ? std::chrono::milliseconds(500) : std::chrono::milliseconds(5000));
        g_volume_verification_before_final_proof = {};
        Check(!result.success && !result.volume_verification && result.code ==
            (changed == 2 ? "VolumeVerificationTimedOut" : "VolumeVerificationSourceChanged"),
            "post-serialization peer owner/deadline proof must remain valid: " + result.code);
        Pass("live final peer proof " + std::to_string(changed));
    }
}
}
