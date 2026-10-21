#pragma once

// Included inside the observer's private namespace after its option/JSON helpers.
int ObserveCurrentProfile(const ObserverOptions& options, bool retained = false, bool snapshots = false)
{
#ifdef _WIN32
    using namespace apfsaccess;
    using namespace apfsaccess::catalog;
    const bool fusion = options.verification_profile == "fusion-clean-cache";
    const auto profile = fusion ? CurrentVerificationProfile::FusionCleanCache : CurrentVerificationProfile::EncryptedOneKeyGenerationZero;
    const auto deadline = std::chrono::steady_clock::now() + std::chrono::seconds(60);
    const auto alive = [deadline] { return std::chrono::steady_clock::now() < deadline; };
    try
    {
        const auto& main_path = fusion ? options.store_a : options.image;
        auto main = std::make_shared<transport::WindowsImageLease>(ToWide(main_path));
        std::shared_ptr<transport::WindowsImageLease> tier2;
        if (fusion) tier2 = std::make_shared<transport::WindowsImageLease>(ToWide(options.store_b));
        if ((!options.expected_main_identity.empty() && options.expected_main_identity != main->Identity()) ||
            (tier2 && !options.expected_tier2_identity.empty() && options.expected_tier2_identity != tier2->Identity()))
            Fail("profile held image identity does not match expected selector");
        VerificationScope scope;
        const auto image_offset = ExactDecimal(options.store_offset_bytes, "--store-offset-bytes", true);
        const auto size = ExactDecimal(options.store_size_bytes, "--store-size-bytes");
        if (image_offset > main->SizeBytes() || size > main->SizeBytes() - image_offset) Fail("profile main window outside image");
        scope.source_identity = main->Identity();
        if (fusion) scope.source_identity += ":fusion:" + options.fusion_uuid + ":" + tier2->Identity();
        scope.exact = {fusion ? image_offset : 0, size, options.container_uuid, options.volume_uuid,
            ExactDecimal(options.volume_oid, "--volume-oid"), ExactDecimal(options.checkpoint_xid, "--checkpoint-xid")};
        scope.require_whole_volume = options.require_whole_volume;
        scope.require_payload_content_hashes = options.require_payload_content_hashes;
        scope.account_retained_ownership = options.account_retained_ownership;
        if (!retained && !snapshots && !options.retained_from_xid.empty()) scope.retained_from_xid = ExactDecimal(options.retained_from_xid, "--retained-from-xid");
        CurrentProfileVerificationReport report;
        RetainedProfileHistoryReport history;
        ProfileSnapshotGraphReport snapshot_graph;
        bool history_ran = false;
        bool snapshot_ran = false;
        const auto from = retained || (snapshots && !options.retained_from_xid.empty()) ? ExactDecimal(options.retained_from_xid, "--retained-from-xid") : 0;
        const auto snapshot_from = from ? std::optional<std::uint64_t>{from} : std::nullopt;
        const auto failed_admission = [&](VerificationCheck check, VerificationCode code, const std::string& detail, bool refused) {
            report = {}; report.profile = profile; report.requested_scope = scope;
            report.outcome = refused ? VerificationOutcome::Refused : VerificationOutcome::Incomplete;
            for (const unsigned id : {1,2,3,5,6,7,8,9,11,13,17})
                report.coverage.push_back({static_cast<VerificationCheck>(id), id != 13, id != 13,
                    id == 13 ? VerificationCheckState::NotRequested : VerificationCheckState::Unproven, "Current profile admission incomplete"});
            for (const unsigned id : (fusion ? std::vector<unsigned>{16,18} : std::vector<unsigned>{15}))
                report.coverage.push_back({static_cast<VerificationCheck>(id), true, true, VerificationCheckState::Unproven, "Current profile admission incomplete"});
            for (auto& c : report.coverage) if (c.check == check)
                c.state = refused ? VerificationCheckState::Unsupported : VerificationCheckState::Inconsistent;
            report.findings.push_back({code, refused ? VerificationSeverity::Warning : VerificationSeverity::Error,
                check, scope.exact.volume_oid, {}, {}, scope.exact.checkpoint_xid, {}, detail});
        };
        std::vector<VerificationStoreBinding> expected;
        std::vector<std::string> labels{main_path};
        std::shared_ptr<ApfsReadBudget> budget;
        if (fusion)
        {
            const auto offset2 = ExactDecimal(options.tier2_offset, "--tier2-offset-bytes", true);
            const auto size2 = ExactDecimal(options.tier2_size, "--tier2-size-bytes");
            if (offset2 > tier2->SizeBytes() || size2 > tier2->SizeBytes() - offset2) Fail("profile tier2 window outside image");
            expected = {{main->Identity(), image_offset, size}, {tier2->Identity(), offset2, size2}};
            labels.push_back(options.store_b);
            FusionImageIdentity a, b; std::string error;
            if (!ApfsFusionStore::InspectImage(ToWide(main_path), a, error) || !ApfsFusionStore::InspectImage(ToWide(options.store_b), b, error))
                Fail("cannot establish exact Fusion image identities");
            budget = std::make_shared<ApfsReadBudget>(scope.max_reads, scope.max_read_bytes, scope.max_records, scope.max_record_bytes);
            FusionBindRequest request;
            request.members = {{ToWide(main_path), a, expected[0].store_id, FusionMemberRole::Main, image_offset, size},
                {ToWide(options.store_b), b, expected[1].store_id, FusionMemberRole::Tier2, offset2, size2}};
            request.container_uuid_hex = options.container_uuid; request.fusion_uuid_hex = options.fusion_uuid;
            request.checkpoint_xid = scope.exact.checkpoint_xid; request.budget = budget;
            request.convention = FusionRoleConvention::LinuxApfsLastByteLowBit;
            auto store = ApfsFusionStore::BindImages(request, error);
            if (store)
            {
                if (snapshots) { snapshot_graph = VerifyFusionSnapshotProfile(*store, scope, {expected[0].store_id, expected[1].store_id}, snapshot_from, alive); snapshot_ran = true; }
                else if (retained) { history = VerifyFusionRetainedHistory(*store, scope, {expected[0].store_id, expected[1].store_id}, from, alive); history_ran = true; }
                else report = ApfsVerifier::VerifyFusionCurrent(*store, scope, {expected[0].store_id, expected[1].store_id}, alive);
            }
            else
            {
                const bool checksum = error.find("Checksum") != std::string::npos;
                failed_admission(VerificationCheck::Fusion, checksum ? VerificationCode::ChecksumMismatch : VerificationCode::FusionUnsupported,
                    error.empty() ? "FusionProfileAdmissionFailed" : error, !checksum);
            }
        }
        else
        {
            auto held = std::make_shared<transport::OwnedEncryptedImageSource>(main, image_offset, size);
            scope.source_identity = held->SourceIdentity();
            auto source = std::make_shared<ApfsVerifierEncryptedSource>(held, scope, alive);
            budget = source->ReadBudget(); expected = {{scope.source_identity, 0, size}};
            UnlockError unlock_error;
            auto metadata = InspectPasswordKeybagMetadata(*source, scope.exact.volume_oid, KeybagLength::IncludesHeader, unlock_error);
            if (!metadata || metadata->users.size() != 1)
                failed_admission(VerificationCheck::Crypto, VerificationCode::CryptoUnsupported, "CanonicalSingleUserKeybagSelectionUnavailable", true);
            else
            {
                auto selection = metadata->selection; selection.user_uuid = metadata->users.front();
                std::atomic<bool> cancellation{false};
                auto credential = transport::ReceiveCredential(GetStdHandle(STD_INPUT_HANDLE), std::chrono::seconds(5), cancellation);
                if (!credential)
                    failed_admission(VerificationCheck::Crypto, VerificationCode::CryptoUnsupported,
                        std::string("CredentialTransport:") + transport::CredentialErrorName(credential.error), true);
                else
                {
                    PasswordUnlockBudget attempts; EncryptedReadError read_error;
                    auto session = ApfsEncryptedReadSession::Unlock(source, source->SourceIdentity(), source->Revision(), selection,
                        credential.bytes.Bytes(), attempts, read_error, unlock_error);
                    credential.bytes.Clear();
                    if (!session) failed_admission(VerificationCheck::Crypto, VerificationCode::CryptoUnsupported, "CanonicalCredentialUnlockFailed", true);
                    else
                    {
                        if (snapshots) { snapshot_graph = VerifyEncryptedSnapshotProfile(*source, *session, scope, snapshot_from, alive); snapshot_ran = true; }
                        else if (retained) { history = VerifyEncryptedRetainedHistory(*source, *session, scope, from, alive); history_ran = true; }
                        else report = ApfsVerifier::VerifyEncryptedCurrent(*source, *session, scope, alive);
                        session->Close();
                    }
                }
            }
        }
        report.read_budget = budget;
        const auto consumed = budget->Consumed();
        report.source_reads = consumed.reads; report.source_read_bytes = consumed.read_bytes;
        std::string json; payload::Reason failure;
        if (retained)
        {
            if (!history_ran) { history.profile = profile; history.endpoint_scope = scope; history.from_xid = from; history.outcome = report.outcome; history.findings = std::move(report.findings); }
            history.read_budget = budget; history.source_reads = consumed.reads; history.source_read_bytes = consumed.read_bytes;
        }
        if (snapshots)
        {
            if (!snapshot_ran) {
                snapshot_graph.profile = profile; snapshot_graph.endpoint_scope = scope; snapshot_graph.from_xid = snapshot_from;
                snapshot_graph.outcome = report.outcome; snapshot_graph.findings = std::move(report.findings);
                for (auto& finding : snapshot_graph.findings) finding.check = VerificationCheck::SnapshotReachableAllocation;
            }
            snapshot_graph.read_budget = budget; snapshot_graph.source_reads = consumed.reads; snapshot_graph.source_read_bytes = consumed.read_bytes;
        }
        const bool serialized = snapshots ? SerializeVisibleSnapshotProfileVerificationReport(snapshot_graph, profile, scope, snapshot_from, expected, labels, alive, MaxImageVerificationJsonBytes, json, failure) :
            retained ? SerializeRetainedProfileVerificationReport(history, profile, scope, from, expected, labels, alive, MaxImageVerificationJsonBytes, json, failure) :
            SerializeCurrentProfileVerificationReport(report, profile, scope, expected, labels, alive, MaxImageVerificationJsonBytes, json, failure);
        if (!serialized)
            Fail("profile response refused: " + std::string(payload::Name(failure)));
        if (!main->VerifyUnchanged() || (tier2 && !tier2->VerifyUnchanged())) Fail("profile source identity changed");
        const auto outcome = snapshots ? snapshot_graph.outcome : retained ? history.outcome : report.outcome;
        const int code = outcome == VerificationOutcome::Complete ? 0 : outcome == VerificationOutcome::Refused ? 4 : 3;
        if (options.out_path.empty()) return WriteStdoutEvidence(json, code);
        PublishEvidence(json, options.out_path, labels); return code;
    }
    catch (const std::exception&) { Fail("current profile source/admission failed"); }
#else
    (void)options; (void)retained; (void)snapshots; Fail("current profile verification requires Windows stable image leases");
#endif
}
