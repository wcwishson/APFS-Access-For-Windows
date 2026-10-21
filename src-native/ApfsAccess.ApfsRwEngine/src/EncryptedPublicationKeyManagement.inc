bool EncryptedPublicationJournal::KeyManagementEndpointClean(TransactionManager& tx, std::string& error)
{
    error.clear();
    if (poisoned_ || !tx.RecoveryStateValid() || tx.CurrentState() != TransactionManager::State::Idle ||
        tx.ProtectedJournalIdentity() != std::optional{options_.maintenance_original_journal_identity} ||
        tx.ProtectedSourceBinding() != std::optional{options_.witness.protected_persistence->source_binding})
        return Fail(error, "EncryptedPublicationEndpointOwnerRequired");
    try {
        const auto marks = tx.Watermarks();
        if (marks.accepted_sequence != marks.cleanup_sequence || marks.apfs_durable_sequence != marks.cleanup_sequence)
            return Fail(error, "EncryptedPublicationEndpointOriginalNotClean");
        auto records = witness_.ReadAllWithExclusiveWriterLease({64ull << 20, 4096}); Wipe wipe{records.records};
        std::vector<WitnessGroup> groups;
        if (records.status != WriteAheadLog::ReadStatus::Ok || records.recovered_torn_tail ||
            !ReadGroups(records.records, groups, error)) return Fail(error, "EncryptedPublicationEndpointWitnessIncomplete");
        std::vector<std::uint64_t> spent;
        if (!ValidateUnacceptedDispositions(tx, spent, error)) return false;
        for (const auto& group : groups) {
            auto body = Decode(group.bytes, options_, false, OriginalJournalBinding::Historical);
            if (body.accepted != group.accepted || body.transaction != group.transaction || body.inode != group.inode)
                return Fail(error, "EncryptedPublicationEndpointWitnessIdentityMismatch");
            if (body.accepted > marks.accepted_sequence && std::find(spent.begin(), spent.end(), body.accepted) == spent.end())
                return Fail(error, "EncryptedPublicationEndpointUnacceptedAuthorization");
        }
        return true;
    } catch (...) { return Fail(error, "EncryptedPublicationEndpointWitnessInvalid"); }
}
