#define wmain FormatStreamedFixtureMain
#include "VolumeFormatStreamedTests.cpp"
#undef wmain
VolumeImageRequest ResizeImage(const std::string& name, VolumeImageOperation operation)
{
    auto r = Large(name); r.operation = operation; r.new_container_uuid.clear(); r.new_volume_uuid.clear();
    r.new_volume_wal.clear(); r.name_utf8.clear(); r.case_sensitive = false;
    r.target_bytes = (operation == VolumeImageOperation::Grow ? 6 * mc::ChunkBlocks - 9 : 3 * mc::ChunkBlocks - 25) * 4096;
    return r;
}
void ResizePositive()
{
    for (const auto operation : {VolumeImageOperation::Grow, VolumeImageOperation::Shrink}) {
        auto r = ResizeImage(operation == VolumeImageOperation::Grow ? "grow-positive" : "shrink-positive", operation);
        const auto p = PrepareVolumeResize(r); Check(p.outcome == VolumeImageOutcome::Prepared, "larger resize prepare: " + p.error);
        const auto a = ApplyVolumeResize(r, p.token); Check(a.outcome == VolumeImageOutcome::Committed, "larger resize apply: " + a.error);
        Check(std::filesystem::file_size(r.image) == r.target_bytes, "actual target EOF");
        Check(RecoverVolumeResize(r).outcome == VolumeImageOutcome::Committed, "fresh exact resize recovery");
        { Target target(r.image); auto cp = mc::Load(target); mc::Verify(target, cp);
          Check(cp.container.superblock.uuid_hex == r.container_uuid && cp.spaceman.chunks.size() == (r.target_bytes / 4096 + mc::ChunkBlocks - 1) / mc::ChunkBlocks,
              "canonical resized identity and dynamic chunks");
          auto history = AcquireVolumeKeeperHistory(p.source_identity, target, r.journal_directory, {}); mc::NativeWrite(target); }
        Check(RecoverVolumeResize(r).outcome == VolumeImageOutcome::Committed, "native ordinary write and old history recovery after resize");
    }
    Pass("larger grow/shrink canonical readback native write and reopen");
}
void ResizeCuts()
{
    for (const auto operation : {VolumeImageOperation::Grow, VolumeImageOperation::Shrink}) {
        const std::vector<std::string> stages = {"after-image-accept", "after-image-grow", "before-image-anchor", "after-image-anchor", "after-image-truncate"};
        for (std::size_t i = 0; i < stages.size(); ++i) {
            auto r = ResizeImage("resize-cut-" + std::to_string(static_cast<unsigned>(operation)) + "-" + std::to_string(i), operation);
            const auto p = PrepareVolumeResize(r); Check(p.outcome == VolumeImageOutcome::Prepared, p.error); bool hit = false;
            const auto a = ApplyVolumeResize(r, p.token, [&](auto s) { if (s == stages[i]) { hit = true; return false; } return true; });
            Check(hit && a.outcome == VolumeImageOutcome::RecoveryRequired, "actual resize cut: " + a.error);
            const auto done = RecoverVolumeResize(r); Check(done.outcome == VolumeImageOutcome::Committed, "forward resize recovery: " + done.error);
            Target target(r.image); mc::Verify(target, mc::Load(target));
        }
    }
    Pass("grow and shrink length/publication interruptions and forward recovery");
}
void ResizeControls()
{
    for (const auto operation : {VolumeImageOperation::Grow, VolumeImageOperation::Shrink}) for (unsigned variant = 0; variant < 7; ++variant) {
        auto r = ResizeImage("resize-control-" + std::to_string(static_cast<unsigned>(operation)) + "-" + std::to_string(variant), operation);
        const auto p = PrepareVolumeResize(r); Check(p.outcome == VolumeImageOutcome::Prepared, p.error);
        if (variant == 0) {
            const auto before = Digests(r.image);
            Check(CancelVolumeResize(r, p.token).outcome == VolumeImageOutcome::Cancelled && Digests(r.image) == before,
                "cancel preserves complete original");
            Check(InspectVolumeKeeperImage(r.image, 0, r.journal_directory).admitted, "cancel permits ordinary admission"); continue;
        }
        if (variant == 1) {
            Change(r, 40000, [](auto& b) { b[7] ^= std::byte{1}; }); const auto before = Digests(r.image);
            Check(ApplyVolumeResize(r, p.token).error == "VolumeImageStaleSource" && Digests(r.image) == before,
                "stale resize original refuses without target writes"); continue;
        }
        if (variant == 2) {
            Save(r.sibling_wals.at(201), {std::byte{1}}); const auto before = Digests(r.image);
            Check(ApplyVolumeResize(r, p.token).outcome == VolumeImageOutcome::Refused && Digests(r.image) == before,
                "stale resize WAL refuses without target writes"); continue;
        }
        const auto a = ApplyVolumeResize(r, p.token, [variant](auto s) {
            return s != (variant == 5 ? "after-image-anchor" : "after-image-accept"); });
        Check(a.outcome == VolumeImageOutcome::RecoveryRequired, a.error);
        if (variant == 3) {
            const auto source = Source(); Change(r, 40000, [&](auto& b) {
                b = source.blocks.at(0); vi::Put(b, 0x10, 991); vi::Checksum(b);
                Check(ParseNxSuperblock(b).has_value(), "genuine foreign resize checkpoint"); });
        }
        if (variant == 4) { auto frame = Read(p.journal); frame.back() ^= std::byte{1}; Save(p.journal, frame); }
        if (variant == 5) {
            { Target target(r.image); Check(mc::Load(target).container.superblock.xid == p.post_xid,
                "new checkpoint actually published before final receipt tear"); }
            auto frame = Read(p.journal); frame.resize(frame.size() - 3); Save(p.journal, frame);
        }
        if (variant == 6) { auto frame = Read(p.journal); frame.resize(frame.size() - 3); Save(p.journal, frame); }
        const auto before = Digests(r.image); const auto recovered = RecoverVolumeResize(r);
        if (variant == 5) {
            Check(recovered.outcome == VolumeImageOutcome::Committed, "exact authorized torn final receipt forward recovery: " + recovered.error);
            Target target(r.image); mc::Verify(target, mc::Load(target));
        } else if (variant == 6) {
            Check(recovered.outcome == VolumeImageOutcome::Cancelled && Digests(r.image) == before,
                "incomplete first acceptance cancels unchanged original");
            Check(InspectVolumeKeeperImage(r.image, 0, r.journal_directory).admitted, "incomplete acceptance leaves no replay authority");
        } else Check(recovered.outcome == VolumeImageOutcome::RecoveryRequired && Digests(r.image) == before,
            "foreign or corrupt receipt refuses without target writes: " + recovered.error);
    }
    Pass("resize cancel stale source WAL foreign checkpoint corrupt and torn receipts");
}
void CibBoundary()
{
    auto source = Source(); const auto old = mc::Load(source); source.block_count = 126 * mc::ChunkBlocks;
    for (auto& [physical, bytes] : source.blocks) { (void)physical;
        if (ParseNxSuperblock(bytes)) { vi::Put(bytes, 0x28, source.block_count); vi::Checksum(bytes); } }
    const auto used = old.spaceman.devices[0].block_count - old.spaceman.devices[0].free_count;
    auto sm = old.spaceman.bytes; vi::Put(sm, 0x30, source.block_count); vi::Put(sm, 0x38, 126); vi::Put(sm, 0x48, source.block_count - used);
    vi::Checksum(sm); source.blocks[old.spaceman.object.physical_block] = sm;
    auto cib = old.spaceman.devices[0].cibs[0].bytes; vi::Put(cib, 0x24, 126, 4); std::fill(cib.begin() + 0x28, cib.end(), std::byte{});
    for (std::size_t i = 0; i < 126; ++i) { const auto at = 0x28 + i * 0x20; vi::Put(cib, at, old.container.superblock.xid);
        vi::Put(cib, at + 8, i * mc::ChunkBlocks); vi::Put(cib, at + 16, mc::ChunkBlocks, 4);
        vi::Put(cib, at + 20, mc::ChunkBlocks - (i ? 0 : used), 4); vi::Put(cib, at + 24, i ? 0 : old.spaceman.chunks[0].bitmap_block); }
    vi::Checksum(cib); source.blocks[old.spaceman.devices[0].cibs[0].object.physical_block] = cib;
    mc::Verify(source, mc::Load(source));
    auto r = Request(root, VolumeImageOperation::Grow, Fixture()); r.expected_bytes = source.SizeBytes(); r.target_bytes = (127 * mc::ChunkBlocks + 67) * 4096;
    const auto plan = vi::BuildResizePublication(source, r, mc::Load(source));
    Check(plan.after.spaceman.devices[0].cibs.size() == 2, "grow across direct CIB boundary");
    source.block_count = r.target_bytes / 4096; std::string error;
    Check(ExecuteAppleCheckpointPublication(source, plan.publication, error) && source.WriteBlock(0, plan.anchor), "actual sparse CIB publication: " + error);
    const auto cp = mc::Load(source); mc::Verify(source, cp);
    r.checkpoint_xid = cp.container.superblock.xid; r.expected_bytes = source.SizeBytes();
    r.target_bytes = (253 * mc::ChunkBlocks + 67) * 4096;
    const auto third = vi::BuildResizePublication(source, r, cp);
    source.block_count = r.target_bytes / 4096;
    Check(ExecuteAppleCheckpointPublication(source, third.publication, error) && source.WriteBlock(0, third.anchor),
        "three-CIB sparse publication: " + error);
    auto three = mc::Load(source); mc::Verify(source, three);
    Check(three.spaceman.devices[0].cibs.size() == 3, "three direct CIBs admitted");
    auto middle = three.spaceman.devices[0].cibs[1];
    Check(0x28 + middle.chunk_indices.size() * 0x20 < middle.bytes.size(), "middle CIB has unused padding");
    middle.bytes.back() = std::byte{0x5a}; vi::Checksum(middle.bytes);
    source.blocks[middle.object.physical_block] = middle.bytes;
    three = mc::Load(source); mc::Verify(source, three);
    r.checkpoint_xid = three.container.superblock.xid; r.expected_bytes = source.SizeBytes();
    r.target_bytes += 41 * 4096;
    const auto padded = vi::BuildResizePublication(source, r, three);
    Check(padded.after.spaceman.devices[0].cibs[1].bytes == middle.bytes,
        "unchanged middle CIB preserves its nonzero canonical padding");
    r.operation = VolumeImageOperation::Shrink; r.checkpoint_xid = three.container.superblock.xid; r.expected_bytes = source.SizeBytes();
    r.target_bytes = (125 * mc::ChunkBlocks - 39) * 4096;
    const auto shrink = vi::BuildResizePublication(source, r, three);
    Check(shrink.after.spaceman.devices[0].cibs.size() == 1, "shrink removes direct CIB without discarding owners");
    Pass("canonical sparse-source multi-CIB growth and shrink proof");
}
int wmain(int argc, wchar_t** argv)
{
    try { Check(argc == 2 || (argc == 3 && (std::wstring_view(argv[2]) == L"--plan-only" ||
            std::wstring_view(argv[2]) == L"--controls-only")), "private root and known selector");
        root = argv[1]; std::filesystem::create_directories(root);
        if (argc == 3 && std::wstring_view(argv[2]) == L"--controls-only") ResizeControls();
        else if (argc == 3) { CibBoundary(); const auto source = Source(); auto r = ResizeImage("plan", VolumeImageOperation::Grow);
            const auto plan = vi::BuildResizePublication(source, r, mc::Load(source));
            Check(plan.postimage.empty() && plan.after.spaceman.chunks.size() == 6, "bounded streamed resize proof");
        } else { ResizePositive(); ResizeCuts(); ResizeControls(); }
        std::cout << "PASS groups=" << groups << " checks=" << checks << '\n'; return 0;
    } catch (const std::exception& ex) { std::cerr << "FAIL checks=" << checks << " " << ex.what() << '\n'; return 1; }
}
