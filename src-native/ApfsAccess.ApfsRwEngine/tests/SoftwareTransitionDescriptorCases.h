namespace
{
int TransitionDescriptorDamage(const std::filesystem::path& run)
{
    const auto image = run / Profile{false}.Name(); const auto before = DigestFile(image);
    auto password = Receive(); std::string identity, error; std::uint64_t block = 0;
    std::vector<std::byte> original;
    const auto jid = Binding("transition-descriptor-damage-original-v6");
    {
        auto source = std::make_shared<TransitionSource>(image); identity = source->SourceIdentity();
        c::PasswordUnlockBudget budget;
        auto baseline = c::SoftwareVolumeTransition::PrepareDecryption(source, identity, source->Revision(), 1026,
            c::KeybagLength::IncludesHeader, password, budget, jid, error);
        Check(static_cast<bool>(baseline), ("TransitionDescriptorUndamagedSourceAdmitted:" + error).c_str());
        const auto xid = baseline->Publication().expected_checkpoint_xid;
        for (const auto& generation : baseline->RetainedOwners().Generations())
            if (generation.checkpoint.superblock.xid < xid && (!block || generation.checkpoint.superblock.xid < c::ReadU64LE(original, 0x10).value_or(UINT64_MAX))) {
                block = generation.checkpoint.superblock_physical_block; original = generation.checkpoint.superblock_bytes;
            }
        Check(block && original.size() == 4096 && c::ParseNxSuperblock(original), "TransitionDescriptorActualOlderCanonicalGeneration");
    }
    bool all_refused = true;
    for (const bool repair_checksum : {false, true}) {
        auto damaged = original; damaged[0x20] ^= std::byte{1};
        if (repair_checksum) Check(r::FinalizeAppleObjectChecksum(damaged, error), "TransitionDescriptorRepairOnlyChecksum");
        {
            TransitionTarget target(image, identity);
            Check(target.WriteBlock(block, damaged) && target.Flush(), "TransitionDescriptorOwnedFaultSetup");
        }
        bool admitted = false;
        {
            auto source = std::make_shared<TransitionSource>(image); c::PasswordUnlockBudget budget;
            auto prepared = c::SoftwareVolumeTransition::PrepareDecryption(source, identity, source->Revision(), 1026,
                c::KeybagLength::IncludesHeader, password, budget, jid, error);
            admitted = static_cast<bool>(prepared);
        }
        const auto observed = error;
        {
            TransitionTarget target(image, identity);
            Check(target.WriteBlock(block, original) && target.Flush(), "TransitionDescriptorExactFaultRestore");
        }
        Check(DigestFile(image) == before, "TransitionDescriptorAllImageBytesRestored");
        all_refused = all_refused && !admitted && observed == (repair_checksum ? "SoftwareTransitionDescriptorStructureInvalid" : "SoftwareTransitionDescriptorChecksumInvalid");
        std::cout << "{\"checksumRepaired\":" << (repair_checksum ? "true" : "false") << ",\"capabilityAdmitted\":" << (admitted ? "true" : "false")
            << ",\"error\":\"" << observed << "\",\"sourceRestoredExactly\":true}\n";
    }
    password.Clear();
    Check(all_refused, "TransitionDescriptorDamageCannotEraseGeneration");
    std::cout << "{\"oldNxMagicDamageRefused\":true,\"checksumRepairedMagicDamageRefused\":true,\"sourceRestoredExactly\":true,\"publicationWrites\":0}\n";
    return 0;
}
int TransitionDescriptorDriver(const std::filesystem::path& executable, const std::filesystem::path& run)
{
    Check(run.wstring().starts_with(std::wstring(transition_root) + L"\\run-") && std::filesystem::create_directory(run), "TransitionDescriptorPrivateRun");
    const auto original = std::filesystem::path(fixtures) / Profile{false}.Name();
    Check(DigestFile(original) == Profile{false}.Pin() && CopyFileW(original.c_str(), (run / Profile{false}.Name()).c_str(), TRUE),
        "TransitionDescriptorPreservedAuthenticInput");
    auto password = NoteCredential(Profile{false});
    const auto result = Child(executable, L"transition-descriptor-damage " + Quoted(run), password.Bytes(), run / L"descriptor-damage.log");
    Check(DigestFile(original) == Profile{false}.Pin(), "TransitionDescriptorOriginalPreserved");
    return result;
}
}
