namespace
{
bool KeyRotationWitness(const catalog::SoftwareVolumeKeyRotationPublication& prepared,
    const EncryptedPublicationJournal::Options& options, Witness& w, std::string& error)
{
    w.version = 8; w.inode = w.volume_object_id = prepared.VolumeObjectId(); w.volume_uuid = prepared.VolumeUuid();
    w.source = prepared.SourceIdentity(); w.original_journal = prepared.OriginalJournalIdentity(); w.plan = prepared.Publication();
    w.transition_before = w.transition_after = 1;
    w.transition_owners = EncodeTransitionOwners(prepared.RetainedOwners());
    if (!Nonzero(w.original_journal) || w.original_journal != options.maintenance_original_journal_identity ||
        w.source != options.preimage_source_identity || prepared.SourceBinding() != options.witness.protected_persistence->source_binding ||
        w.plan.fusion_tier2_anchor_write || !Hash(w.transition_owners, w.transition_owners_sha256))
        return Fail(error, "EncryptedPublicationKeyRotationScopeMismatch");
    return ValidateTransitionEnvelope(w, options, error);
}
}
bool EncryptedPublicationJournal::AcceptKeyRotation(TransactionManager& tx,
    const catalog::SoftwareVolumeKeyRotationPublication& prepared, std::uint64_t& accepted, std::string& error)
{
    accepted = 0; error.clear();
    try {
        Witness w;
        if (!KeyRotationWitness(prepared, options_, w, error)) return false;
        auto original = MaintenanceTemplate(w, options_); TransitionBytesWipe wipe{original};
        return AcceptRetainedRewrite(tx, original, accepted, error);
    } catch (...) { return Fail(error, "EncryptedPublicationKeyRotationAcceptInvalid"); }
}
bool EncryptedPublicationJournal::StageKeyRotation(TransactionManager& tx, std::uint64_t accepted,
    const catalog::SoftwareVolumeKeyRotationPublication& prepared, std::string& error)
{
    error.clear();
    try {
        Witness w;
        if (!KeyRotationWitness(prepared, options_, w, error)) return false;
        auto original = MaintenanceTemplate(w, options_); TransitionBytesWipe wipe{original};
        return StageRetainedRewrite(tx, accepted, original, error);
    } catch (...) { return Fail(error, "EncryptedPublicationKeyRotationStageInvalid"); }
}
bool EncryptedPublicationJournal::RestageKeyRotation(TransactionManager& tx, std::uint64_t accepted, std::string& error)
{ return RestageRetainedRewrite(tx, accepted, 8, error); }
