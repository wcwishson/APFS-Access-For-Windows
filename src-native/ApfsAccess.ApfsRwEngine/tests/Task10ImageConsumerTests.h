#pragma once

namespace {
void SaveImageConsumerBytes(const std::filesystem::path& path, const Bytes& bytes)
{
    std::ofstream file(path, std::ios::binary);
    file.write(reinterpret_cast<const char*>(bytes.data()), bytes.size()); Check(file.good(), "write real regular image");
}
void Task10ImageConsumers(const std::filesystem::path& directory)
{
    Check(directory.is_absolute() && directory.wstring().starts_with(L"D:"), "private D consumer evidence");
    std::filesystem::create_directories(directory);
    for (unsigned damage = 0; damage < 4; ++damage) {
        Fixture f = PayloadFixture();
        if (damage == 1) f.spec.authoritative_seeded_main_blocks[0].second[0] ^= std::byte{1};
        if (damage == 1) f.Rebuild();
        if (damage == 2) f.Edit(7, [](auto& b) { b[100] ^= std::byte{1}; }, false);
        if (damage == 3) ClearMainAllocation(f, 222);
        const auto bytes = PrefixStore(f);
        const auto image = directory / ("image-" + std::to_string(damage) + ".apfs");
        SaveImageConsumerBytes(image, bytes);
        ObserverOptions options;
        options.image = image.string(); options.out_path = (directory / ("image-" + std::to_string(damage) + "-v3.json")).string();
        options.container_uuid = f.scope.exact.container_uuid_hex; options.volume_uuid = f.scope.exact.volume_uuid_hex;
        options.volume_oid = std::to_string(f.scope.exact.volume_oid); options.checkpoint_xid = std::to_string(f.scope.exact.checkpoint_xid);
        options.store_offset_bytes = std::to_string(f.scope.exact.store_offset_bytes); options.store_size_bytes = std::to_string(f.scope.exact.store_size_bytes);
        const auto code = ObserveVerification(options);
        Check((damage < 2 && code == 0) || (damage >= 2 && code == 3), "actual Observer current-payload semantic exit");
        VerificationImageLease lease(image.string()); auto scope = f.scope; scope.source_identity = lease.Identity();
        for (const auto access : {DWORD(GENERIC_WRITE), DWORD(DELETE)}) {
            HANDLE writer = CreateFileW(image.c_str(), access, FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE,
                nullptr, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, nullptr);
            const bool denied = writer == INVALID_HANDLE_VALUE && GetLastError() == ERROR_SHARING_VIOLATION;
            if (writer != INVALID_HANDLE_VALUE) CloseHandle(writer);
            Check(denied, "actual held regular-image lease denies mutation and replacement");
        }
        VerificationReport report; std::string json; payload::Reason failure;
        Check(BuildObservedImageVerification(lease, scope, image.string(), [] { return true; }, MaxImageVerificationJsonBytes,
            report, json, failure), "actual held-lease pipeline");
        Check(lease.VerifyUnchanged() && !report.whole_volume_verified && !report.payload_content_hashes_verified,
            "same lease proof and no expected integrity claims");
        if (damage < 2) {
            Check(report.payload_inventory->exactComplete() && report.payload_inventory->entries.size() == 8 &&
                report.payload_inventory->logicalBytesRead == 4137 && PayloadState(report) == VerificationCheckState::Verified,
                "entire admitted projection including sparse/embedded/external/empty");
            Check((report.payload_inventory->entries[0].observedSha256 ==
                "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad") == (damage == 0),
                "changed bytes observed without independent expected authority");
        } else Check(!report.payload_inventory->enumerationComplete && report.payload_inventory->entries.empty(),
            "existing admission gate precedes any complete hashes");
        Bytes held; Check(lease.Read(0, bytes.size(), held) && held == bytes, "regular image unchanged after actual consumer");
        if (damage == 0) {
            auto expected_options = options;
            expected_options.require_payload_content_hashes = true;
            expected_options.out_path = (directory / "image-required-v3.json").string();
            Check(ObserveVerification(expected_options) == 3, "missing expected comparison remains incomplete after current hashes");
            scope.observe_payload_content = false;
            const auto legacy = ApfsVerifier::Verify(lease, scope);
            std::ofstream old(directory / "image-v2.json", std::ios::binary); old << VerificationJson(legacy, image.string());
            Check(old.good() && !legacy.payload_inventory && legacy.coverage.size() == 20, "legacy metadata-only v2 emitted");
            for (unsigned negative = 0; negative < 5; ++negative) {
                auto refused_scope = scope;
                if (negative == 0) ++refused_scope.exact.store_offset_bytes;
                if (negative == 1) refused_scope.max_reads = 1;
                VerificationReport rejected; std::string output = "must clear"; payload::Reason reason;
                const bool emitted = BuildObservedImageVerification(lease, refused_scope, image.string(),
                    [negative] { return negative != 2; }, negative == 3 ? 512 : MaxImageVerificationJsonBytes,
                    rejected, output, reason);
                if (negative == 0) Check(emitted && rejected.outcome != VerificationOutcome::Complete &&
                    !rejected.payload_inventory->enumerationComplete, "shifted parent coordinates cannot admit store");
                else if (negative == 4) Check(emitted, "fresh operation after separate refusals has own original allowance");
                else {
                    Check(!emitted && output.empty() && rejected.read_budget && rejected.read_budget->Failed(),
                        "failed original allowance forbids JSON publication");
                    Check(!SerializeImageVerificationReport(rejected, image.string(), [] { return true; },
                        MaxImageVerificationJsonBytes, output, reason) && output.empty(), "no retry/reset after failure");
                }
            }
            VerificationReport rejected; std::string output; payload::Reason reason;
            auto wrong = scope; wrong.source_identity = "wrong-held-object";
            Check(!BuildObservedImageVerification(lease, wrong, image.string(), [] { return true; },
                MaxImageVerificationJsonBytes, rejected, output, reason) && reason == payload::Reason::InvalidBinding,
                "identity pairing refused before engine");
            const auto truncated_path = directory / "truncated.apfs";
            auto truncated = bytes; truncated.resize(f.scope.exact.store_offset_bytes + 4096);
            SaveImageConsumerBytes(truncated_path, truncated);
            VerificationImageLease short_lease(truncated_path.string());
            auto short_scope = scope; short_scope.source_identity = short_lease.Identity();
            const bool short_output = BuildObservedImageVerification(short_lease, short_scope, truncated_path.string(),
                [] { return true; }, MaxImageVerificationJsonBytes, rejected, output, reason);
            Check(!short_output && output.empty() && !rejected.selected && short_lease.VerifyUnchanged(),
                "truncated regular source cannot yield admitted payload JSON");
        }
        Pass("actual Observer image payload " + std::to_string(damage));
    }
}
}
