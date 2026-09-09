#pragma once
// Parent: include after NativeCompressionWriteTests.h in the test namespace.
// Register each named function separately; existing default 1/3/4 groups keep
// their original format matrix. All fixtures require the runner's D: TEMP/TMP.

bool RunNativeModernCompressionTests(unsigned type, bool interrupted)
{
    if (!CompressionReplay222ScratchReady()) return false;
    if (!Require(type >= 7 && type <= 14,
            "modern host selector names exactly one enabled compression format")) return false;
    if (interrupted) return TestNativeCompressionWriteCallbacks(true, type);
    return TestNativeCompressionRewritePreparation211(type) &&
        TestNativeCompressionRewriteWal211(type) && TestNativeCompressionWriteCallbacks(false, type);
}

// Suggested selectors: compression-modern-type{7,8,11,12} and
// compression-modern-type{7,8,11,12}-recovery.
bool TestNativeModernCompressionType7() { return RunNativeModernCompressionTests(7, false); }
bool TestNativeModernCompressionType8() { return RunNativeModernCompressionTests(8, false); }
bool TestNativeModernCompressionType11() { return RunNativeModernCompressionTests(11, false); }
bool TestNativeModernCompressionType12() { return RunNativeModernCompressionTests(12, false); }
bool TestNativeModernCompressionType7Recovery() { return RunNativeModernCompressionTests(7, true); }
bool TestNativeModernCompressionType8Recovery() { return RunNativeModernCompressionTests(8, true); }
bool TestNativeModernCompressionType11Recovery() { return RunNativeModernCompressionTests(11, true); }
bool TestNativeModernCompressionType12Recovery() { return RunNativeModernCompressionTests(12, true); }

bool TestNativeRemainingCompressionCallbacks(bool interrupted)
{
    for (const auto type : {9u, 10u, 13u, 14u})
        if (!RunNativeModernCompressionTests(type, interrupted)) return false;
    return true;
}

bool TestNativeModernCompressionBeforePublishRestart(bool remaining = false)
{
    using Store = apfsaccess::rw::MetadataStore;
    if (!CompressionReplay222ScratchReady()) return false;
    for (const unsigned type : remaining ? std::vector<unsigned>{9u, 10u, 13u, 14u} :
            std::vector<unsigned>{7u, 8u, 11u, 12u})
    {
        HostCompressionReplay222Fixture fixture;
        if (!Require(fixture.Initialize(type, true, false, true),
                "modern prepublication fixture accepts real external WAL and spool edits")) return false;
        auto& original = *fixture.owned.fixture.context;
        using Tx = apfsaccess::rw::TransactionManager;
        std::vector<Tx::AcceptedTransaction> batches;
        if (!Require(original.tx_manager->LoadUnappliedAcceptedTransactions(batches) && batches.size() == 1,
                "prepublication test reloads the real accepted range authority")) return false;
        auto records = batches.front().mutations;
        const auto read_records = [&]() {
            std::vector<const apfsaccess::rw::WriteAheadLog::Record*> pointers;
            for (const auto& record : records) pointers.push_back(&record);
            std::vector<std::byte> actual(fixture.expected.size());
            return ReadAppleReplayPayloadRange(original, pointers, {17, fixture.preimage + 1}, 0, actual) &&
                actual == fixture.expected;
        };
        if (!Require(read_records(), "source-generation conversion and staged-generation writes reconstruct exact bytes")) return false;
        ++records.front().parent_object_id;
        if (!Require(!read_records(), "altered conversion source generation is refused")) return false;
        records = batches.front().mutations;
        records.insert(records.begin() + 1, records.front());
        if (!Require(!read_records(), "a second conversion cannot reuse source identity after the transition")) return false;
        records = batches.front().mutations;
        records.front().inline_payload.back() ^= std::byte{1};
        if (!Require(!read_records(), "tampered conversion proof is refused before range reconstruction")) return false;
        bool reached = false;
        original.metadata_store->SetCommitStageHook([&](std::string_view stage) {
            if (stage != "before-apple-checkpoint-switch") return true;
            reached = true;
            return false;
        });
        if (!Require(!fixture.Publish() && reached && original.metadata_store->IsRecoveryRequired() &&
                original.tx_manager->HasUnappliedAcceptedWork() &&
                ArmRecoveryMarkerForPendingWriteAheadLog(original, true),
                "failure after data writes and before publication retains accepted recovery evidence")) return false;
        original.metadata_store->SetCommitStageHook({});
        {
            Store independently_opened(fixture.owned.fixture.volume);
            std::vector<std::byte> old_content;
            if (!Require(independently_opened.PrepareNativeWritePath() &&
                    independently_opened.CheckpointXid() == fixture.preimage &&
                    independently_opened.ReadCommittedFileRange(L"\\alias", 0, fixture.owned.eof, old_content) &&
                    old_content == fixture.owned.expected_source,
                    "independent reopen still exposes complete original compressed data")) return false;
        }
        if (!HostCompressionWriteRecoverAccepted(fixture.owned, fixture.expected, false)) return false;
    }
    return true;
}
