// Reuse the independently exercised sparse fixture and native-write helpers.
#define wmain FormatStreamedFixtureMain
#include "VolumeFormatStreamedTests.cpp"
#undef wmain

VolumeImageRequest EraseImage(const std::string& name)
{
    auto r = Large(name); r.operation = VolumeImageOperation::Erase;
    Change(r, 30000, [](auto& b) { std::fill(b.begin(), b.end(), std::byte{0x5a}); });
    Change(r, 70000, [](auto& b) { std::fill(b.begin(), b.end(), std::byte{0xc3}); });
    return r;
}
void Erased(const VolumeImageRequest& r)
{
    const auto source = Source(); auto plan = vi::BuildFormatPublicationV2(source, r, mc::Load(source));
    vi::FinishFormatSource(source, r, plan);
    Check(plan.cleanup.empty() && plan.postimage.empty(), "no image-sized zero-write plan or postimage");
    Target target(r.image); const auto cp = mc::Load(target); mc::Verify(target, cp);
    std::map<std::uint64_t, Bytes> writes;
    for (const auto& w : plan.publication.before_superblock_writes) writes[w.physical_block] = w.bytes;
    writes[plan.publication.superblock_write.physical_block] = plan.publication.superblock_write.bytes; writes[0] = plan.anchor;
    for (std::uint64_t offset = 0; offset < target.SizeBytes(); offset += fe::Chunk) {
        Bytes bytes; const auto count = static_cast<std::size_t>((std::min)(fe::Chunk, target.SizeBytes() - offset));
        Check(target.Read(offset, count, bytes), "independent final range read");
        for (std::size_t at = 0; at < bytes.size(); at += 4096) {
            const auto it = writes.find((offset + at) / 4096);
            const auto span = std::span<const std::byte>(bytes).subspan(at, 4096);
            if (it == writes.end()) {
                if (!std::all_of(span.begin(), span.end(), [](auto b) { return b == std::byte{}; })) throw std::runtime_error("nonzero free range after logical Erase");
            } else if (!std::equal(span.begin(), span.end(), it->second.begin())) throw std::runtime_error("new topology changed by cleanup");
        }
    }
}
void ErasePositive()
{
    auto r = EraseImage("erase-positive"); const auto before = Digests(r.image); const auto p = Prepare(r);
    Check(p.outcome == VolumeImageOutcome::Prepared && Digests(r.image) == before, "prepare exact original unchanged: " + p.error);
    const auto frame = Read(p.journal);
    Check(ReadU64LE(frame, 0) == fe::FlaggedStreamedMagic &&
        ReadU64LE(frame, 48) == static_cast<std::uint64_t>(r.operation), "flagged streamed Erase frame and exact operation");
    const auto a = Apply(r, p.token); Check(a.outcome == VolumeImageOutcome::Committed, "actual larger Erase: " + a.error);
    Erased(r); Check(Recover(r).outcome == VolumeImageOutcome::Committed, "Erase idempotent reopen");
    Check(InspectVolumeKeeperImage(r.image, 0, r.journal_directory).admitted, "completed Erase ordinary admission");
    { Target target(r.image); auto history = AcquireVolumeKeeperHistory(p.source_identity, target, r.journal_directory, {});
      mc::NativeWrite(target); }
    Check(Recover(r).outcome == VolumeImageOutcome::Committed, "ordinary native write and completed-history reopen");
    Pass("larger logical Erase exact free-range oracle and native write/reopen");
}
void EraseCuts()
{
    const std::vector<std::string> stages = {"after-image-accept", "before-image-anchor", "after-image-anchor",
        "after-image-erase-authorize", "after-image-erase-write", "after-image-erase-chunk", "before-image-complete"};
    for (std::size_t i = 0; i < stages.size(); ++i) {
        auto r = EraseImage("erase-cut-" + std::to_string(i)); const auto p = Prepare(r); Check(p.outcome == VolumeImageOutcome::Prepared, p.error);
        bool hit = false; unsigned chunks = 0;
        const auto a = Apply(r, p.token, [&](auto s) {
            if (s == "after-image-erase-chunk") ++chunks;
            if (s == stages[i] && (s != "after-image-erase-chunk" || chunks == 4)) { hit = true; return false; } return true;
        });
        Check(hit && a.outcome == VolumeImageOutcome::RecoveryRequired, "actual erase cut: " + a.error);
        if (i == 3) Change(r, 1, [](auto& b) { std::fill_n(b.begin(), 1999, std::byte{}); });
        const auto done = Recover(r); Check(done.outcome == VolumeImageOutcome::Committed, "forward erase recovery: " + done.error); Erased(r);
    }
    Pass("publication and durable cleanup cursor interruptions including torn old header");
}
void EraseControls()
{
    for (unsigned variant = 0; variant < 7; ++variant) {
        auto r = EraseImage("erase-control-" + std::to_string(variant)); const auto p = Prepare(r); Check(p.outcome == VolumeImageOutcome::Prepared, p.error);
        if (variant == 0) { const auto before = Digests(r.image); Check(Cancel(r, p.token).outcome == VolumeImageOutcome::Cancelled && Digests(r.image) == before, "cancel unchanged"); continue; }
        if (variant == 1) { Change(r, 40000, [](auto& b) { b[3] ^= std::byte{1}; }); const auto before = Digests(r.image);
            Check(Apply(r, p.token).error == "VolumeImageStaleSource" && Digests(r.image) == before, "stale source unchanged"); continue; }
        if (variant == 2) { Save(r.sibling_wals.at(201), {std::byte{1}}); const auto before = Digests(r.image);
            Check(Apply(r, p.token).outcome == VolumeImageOutcome::Refused && Digests(r.image) == before, "stale WAL unchanged"); continue; }
        const auto a = Apply(r, p.token, [](auto s) { return s != "after-image-erase-authorize"; });
        Check(a.outcome == VolumeImageOutcome::RecoveryRequired, a.error);
        if (variant == 3) { const auto source = Source(); Change(r, 1, [&](auto& b) {
            b = source.blocks.at(0); vi::Put(b, 0x10, 991); vi::Checksum(b); Check(ParseNxSuperblock(b).has_value(), "genuine foreign NX fixture"); }); }
        if (variant == 4) Change(r, 70000, [](auto& b) { b[5] ^= std::byte{1}; });
        if (variant == 5) { auto frame = Read(p.journal); Bytes binding(frame.begin() + 16, frame.begin() + 48);
            fe::Number(binding, fe::CursorTag | 3); const auto hash = fe::Hash(binding); fe::Number(frame, fe::CursorTag | 3);
            frame.insert(frame.end(), hash.begin(), hash.end()); Save(p.journal, frame); }
        if (variant == 6) { auto frame = Read(p.journal); frame.back() ^= std::byte{1}; Save(p.journal, frame); }
        const auto before = Digests(r.image); const auto done = Recover(r);
        Check(done.outcome == VolumeImageOutcome::RecoveryRequired && Digests(r.image) == before,
            "foreign/future/cursor corruption refuses unchanged variant=" + std::to_string(variant) + ": " + done.error);
    }
    Pass("cancel stale source WAL foreign checkpoint and cleanup cursor corruption boundaries");
}
int wmain(int argc, wchar_t** argv)
{
    try { Check(argc == 2, "private artifact root"); root = argv[1]; std::filesystem::create_directories(root);
        ErasePositive(); EraseCuts(); EraseControls(); std::cout << "PASS groups=" << groups << " checks=" << checks << '\n'; return 0;
    } catch (const std::exception& ex) { std::cerr << "FAIL checks=" << checks << " " << ex.what() << '\n'; return 1; }
}
