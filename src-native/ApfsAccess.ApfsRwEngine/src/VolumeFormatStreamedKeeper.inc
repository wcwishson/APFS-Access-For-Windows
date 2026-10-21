class ImageSource final : public catalog::RandomAccessSource
{
public:
    explicit ImageSource(const KeeperTarget& file) : file_(file) {}
    std::uint64_t SizeBytes() const override { return file_.Size(); }
    bool Read(std::uint64_t offset, std::size_t size, Bytes& out) const override { return file_.ReadRange(offset, size, out); }
private:
    const KeeperTarget& file_;
};
void StreamBinding(const Session& s, const Journal& j)
{
    if(s.image.geometry){
        Require(j.geometry && !j.physical && j.geometry->snapshot.original.binding==s.image.geometry->OriginalBinding() &&
            j.geometry->snapshot.original.instance==s.image.geometry->InstanceId() && j.identity==s.identity,"VolumeGeometryJournalBindingMismatch");
        VolumePhysicalGeometryAccess::BindPlan(s.image.geometry,*j.geometry);
        volume_geometry::Verify(*s.image.geometry,*j.geometry,static_cast<unsigned>(j.state));return;
    }
    Require(!j.geometry,"VolumeGeometryHeldSourceRequired");
    Require(!!s.image.physical == j.physical.has_value(), "VolumePhysicalJournalModeMismatch");
    if (j.physical) Require(j.physical->binding == s.image.physical->Binding() && j.physical->instance == s.image.physical->InstanceId() &&
        j.identity == s.identity && s.image.physical->Revalidate(), "VolumePhysicalJournalBindingMismatch");
}
std::vector<VolumeKeeperHistoryMember> StreamMembers(const Session& s, const Plan& plan)
{
    std::vector<VolumeKeeperHistoryMember> result;
    for (const auto& volume : plan.before.volumes)
        result.push_back({plan.before.container.superblock.uuid_hex, volume.superblock.uuid_hex,
            volume.superblock.object_id, s.r.sibling_wals.at(volume.superblock.object_id)});
    return result;
}
Plan StreamBuild(Session& s, const Journal& j, const catalog::RandomAccessSource& original, bool create = false,
    bool completed_history = false)
{
    Require(!completed_history || (!create && j.state == 3), "VolumeImageCompletedHistoryRequired");
    Require(j.evidence && Encode(j.request) == Encode(s.r) && j.identity.substr(0, 64) == s.identity.substr(0, 64), "VolumeImageJournalBindingMismatch");
    StreamBinding(s, j);
    const auto cp = AdmitSource(original, s.r, StreamAdmission(s.r));
    AppleSnapshotRetentionView snapshots; std::string error;
    Require(LoadAppleSnapshotRetention(original, cp, snapshots, error) && snapshots.identities.empty() &&
        !cp.container_object_map.snapshot_tree_oid, "VolumeImageSnapshotHistoryAuthorityUnproven");
    // Capture the same original metadata that admission/history must later walk.
    std::vector<std::uint64_t> metadata; std::vector<ApplePhysicalExtentRecord> payload;
    Require(LoadAppleSnapshotCheckpointOwners(original, cp, metadata, payload, error) && !metadata.empty(),
        "VolumeImageSnapshotHistoryAuthorityUnproven");
    if (!completed_history) (void)s.Census(cp, create);
    const auto clean = [&](const std::filesystem::path& path, std::uint64_t oid, const std::string& container) {
        const VolumeKeeperWalIdentities ids{"apfs-vol:" + container + ":" + std::to_string(oid),
            s.image.PhysicalBinding() ? DeriveVolumePhysicalRecoveryIdentity(*s.image.PhysicalBinding(), container, oid) :
                DerivePartitionlessVolumeRecoveryIdentity(container, oid)};
        const auto marks = InspectVolumeKeeperWal(std::filesystem::path(Extended(path)), ids, "VolumeImage", "WalDebtOrPins");
        const auto records = WriteAheadLog::ReadAll(std::filesystem::path(Extended(path)), "");
        Require(records.status == WriteAheadLog::ReadStatus::Ok && !records.recovered_torn_tail &&
            VolumeKeeperWalHasCleanBoundary(records.records, marks.cleanup_sequence), "VolumeImageWalDebtOrPins");
    };
    if (!completed_history) {
        for (const auto& [oid, path] : s.r.sibling_wals) clean(path, oid, s.r.container_uuid);
        if (IsFormat(s.r.operation)) clean(s.r.new_volume_wal, 1024, s.r.new_container_uuid);
    }
    auto plan = IsFormat(s.r.operation) ? (j.flagged_format ? BuildFormatPublicationV2(original, s.r, cp) : BuildFormatPublication(original, s.r, cp)) :
        j.physical_snapshot_relocation ? BuildResizeRelocationPublicationV2(original, s.r) :
        j.relocation ? BuildResizeRelocationPublication(original, s.r) : BuildResizePublication(original, s.r, cp);
    if (IsFormat(s.r.operation)) FinishFormatSource(original, s.r, plan);
    // Destinations include the anchor; every destination chunk must be stored,
    // even if the deterministic planner never read its previous free bytes.
    for (const auto block : plan.destinations) {
        Bytes bytes; Require(original.Read(block * Block, Block, bytes) && bytes.size() == Block,
            "VolumeFormatEvidenceDestinationMissing");
    }
    for (const auto& guard : plan.publication.guard_blocks) {
        Bytes bytes; Require(original.Read(guard.physical_block * Block, Block, bytes) && bytes == guard.bytes,
            "VolumeFormatEvidenceGuardMismatch");
    }
    if (s.r.operation == VolumeImageOperation::Shrink) { Bytes bytes;
        Require(original.Read(s.r.target_bytes - Block, Block, bytes), "VolumeResizeEvidenceBoundaryMissing"); }
    return plan;
}
void StreamFill(VolumeImageResult& result, const Session& s, const Journal& j, const Plan& plan)
{
    result.source_identity = s.identity; result.journal = s.journal; result.pre_xid = plan.before.container.superblock.xid;
    result.post_xid = plan.after.container.superblock.xid; result.expires_unix_seconds = j.expiry;
    result.free_blocks_before = plan.before.spaceman.devices[0].free_count;
    result.free_blocks_after = plan.after.spaceman.devices[0].free_count;
}
void StreamStage(const AppleCheckpointStageHook& hook, std::string_view stage)
{ Require(!hook || hook(stage), "VolumeImageInterrupted:" + std::string(stage)); }
enum class StreamComparison { Original, Accepted, Final };
void StreamCompareResize(const catalog::RandomAccessSource& live, const Journal& j,
    const std::map<std::uint64_t, const Bytes*>& writes, StreamComparison mode)
{
    const auto size = live.SizeBytes(); const auto& original = *j.evidence;
    Require(mode == StreamComparison::Original ? size == j.request.expected_bytes :
        (mode == StreamComparison::Final ? size == j.request.target_bytes :
            size == j.request.expected_bytes || (size == j.request.target_bytes &&
                (j.request.operation == VolumeImageOperation::Grow || j.state >= 2))), "VolumeImageRecoveryLengthConflict");
    for (std::uint64_t index = 0; index < original.digests.size() && index * format_evidence::Chunk < size; ++index) {
        Bytes current; const auto length = static_cast<std::size_t>((std::min<std::uint64_t>)(original.Length(index), size - index * format_evidence::Chunk));
        Require(live.Read(index * format_evidence::Chunk, length, current) && current.size() == length, "VolumeResizeRecoveryChunkReadFailed");
        const auto stored = original.chunks.find(index);
        if (mode == StreamComparison::Original || stored == original.chunks.end()) {
            Require(length == original.Length(index) && Hash(current) == original.digests.at(static_cast<std::size_t>(index)),
                mode == StreamComparison::Original ? "VolumeImageStaleSource" : "VolumeImageRecoveryUnrelatedBytesChanged"); continue;
        }
        for (std::size_t at = 0; at < length; at += Block) {
            const auto block = (index * format_evidence::Chunk + at) / Block; const auto write = writes.find(block);
            const auto bytes = std::span<const std::byte>(current).subspan(at, Block);
            if (write != writes.end() && mode == StreamComparison::Accepted && j.state == 1) {
                if (catalog::ReadU32LE(bytes, 0x20).value_or(0) == 0x4253584e) {
                    const Bytes header(bytes.begin(), bytes.end());
                    Require(!catalog::ParseNxSuperblock(header) || std::equal(bytes.begin(), bytes.end(), stored->second.begin() + at) ||
                        std::equal(bytes.begin(), bytes.end(), write->second->begin()), "VolumeImageRecoveryForeignCheckpoint");
                }
                continue;
            }
            const auto expected = write == writes.end() ? stored->second.begin() + at : write->second->begin();
            Require(std::equal(bytes.begin(), bytes.end(), expected), "VolumeImageRecoveryUnrelatedBytesChanged");
        }
    }
    for (auto offset = original.size; offset < size; offset += format_evidence::Chunk) {
        Bytes bytes; const auto length = static_cast<std::size_t>((std::min)(format_evidence::Chunk, size - offset));
        Require(live.Read(offset, length, bytes) && bytes.size() == length, "VolumeResizeRecoveryGrowthReadFailed");
        if (mode == StreamComparison::Accepted && j.state == 1) {
            for (std::size_t at = 0; at < length; at += Block) if (catalog::ReadU32LE(bytes, at + 0x20).value_or(0) == 0x4253584e) {
                const Bytes header(bytes.begin() + at, bytes.begin() + at + Block);
                Require(!catalog::ParseNxSuperblock(header), "VolumeImageRecoveryForeignCheckpoint");
            }
        } else Require(std::all_of(bytes.begin(), bytes.end(), [](auto b) { return b == std::byte{}; }), "VolumeImageRecoveryGrowthChanged");
    }
}
void StreamCompareErase(const catalog::RandomAccessSource& live, const Journal& j,
    const std::map<std::uint64_t, const Bytes*>& writes, StreamComparison mode)
{
    const auto& original = *j.evidence;
    for (std::uint64_t index = 0; index < original.digests.size(); ++index) {
        Bytes current; const auto length = original.Length(index);
        Require(live.Read(index * format_evidence::Chunk, length, current) && current.size() == length,
            "VolumeEraseRecoveryChunkReadFailed");
        const bool final = mode == StreamComparison::Final || (j.state == 2 && index + 1 < j.erase_cursor);
        const bool pending = mode == StreamComparison::Accepted && j.state == 2 && index + 1 == j.erase_cursor;
        const auto stored = original.chunks.find(index);
        if (mode == StreamComparison::Original || (!final && !pending && stored == original.chunks.end())) {
            Require(Hash(current) == original.digests.at(static_cast<std::size_t>(index)),
                mode == StreamComparison::Original ? "VolumeImageStaleSource" : "VolumeImageRecoveryUnrelatedBytesChanged");
            continue;
        }
        for (std::size_t at = 0; at < length; at += Block) {
            const auto block = (index * format_evidence::Chunk + at) / Block;
            const auto write = writes.find(block);
            const auto bytes = std::span<const std::byte>(current).subspan(at, Block);
            const bool prior = stored != original.chunks.end() &&
                std::equal(bytes.begin(), bytes.end(), stored->second.begin() + at);
            const bool planned = write != writes.end() && std::equal(bytes.begin(), bytes.end(), write->second->begin());
            if ((write != writes.end() && j.state == 1 && mode == StreamComparison::Accepted) ||
                (write == writes.end() && pending)) {
                if (catalog::ReadU32LE(bytes, 0x20).value_or(0) == 0x4253584e) {
                    const Bytes header(bytes.begin(), bytes.end());
                    Require(!catalog::ParseNxSuperblock(header) || prior || planned, "VolumeImageRecoveryForeignCheckpoint");
                }
                continue;
            }
            const bool zero = std::all_of(bytes.begin(), bytes.end(), [](auto b) { return b == std::byte{}; });
            Require(write != writes.end() ? planned : (final ? zero : prior), "VolumeImageRecoveryUnrelatedBytesChanged");
        }
    }
}
void StreamCompare(const catalog::RandomAccessSource& live, const Journal& j, const Plan& plan, StreamComparison mode)
{
    const auto& original = *j.evidence;
    std::map<std::uint64_t, const Bytes*> writes;
    for (const auto& write : plan.publication.before_superblock_writes) writes.emplace(write.physical_block, &write.bytes);
    writes.emplace(plan.publication.superblock_write.physical_block, &plan.publication.superblock_write.bytes);
    writes.emplace(0, &plan.anchor);
    Require(writes.size() == plan.destinations.size(), "VolumeFormatRecoveryDestinationMismatch");
    if (!IsFormat(j.request.operation)) { StreamCompareResize(live, j, writes, mode); return; }
    Require(live.SizeBytes() == original.size, "VolumeImageRecoveryLengthConflict");
    if (j.request.operation == VolumeImageOperation::Erase) { StreamCompareErase(live, j, writes, mode); return; }
    for (std::uint64_t index = 0; index < original.digests.size(); ++index) {
        Bytes current; const auto length = original.Length(index);
        Require(live.Read(index * format_evidence::Chunk, length, current) && current.size() == length,
            "VolumeFormatRecoveryChunkReadFailed");
        if (mode == StreamComparison::Original || !original.chunks.contains(index)) {
            Require(Hash(current) == original.digests.at(static_cast<std::size_t>(index)),
                mode == StreamComparison::Original ? "VolumeImageStaleSource" : "VolumeImageRecoveryUnrelatedBytesChanged");
            continue;
        }
        const auto& prior = original.chunks.at(index);
        for (std::size_t at = 0; at < length; at += Block) {
            const auto block = (index * format_evidence::Chunk + at) / Block;
            const auto write = writes.find(block);
            if (write != writes.end() && mode == StreamComparison::Accepted) {
                const Bytes bytes(current.begin() + at, current.begin() + at + Block);
                const auto nx = catalog::ParseNxSuperblock(bytes);
                Require(!nx || std::equal(bytes.begin(), bytes.end(), prior.begin() + at) ||
                    std::equal(bytes.begin(), bytes.end(), write->second->begin()), "VolumeImageRecoveryForeignCheckpoint");
                continue;
            }
            const auto begin = write == writes.end() ? prior.begin() + at : write->second->begin();
            Require(std::equal(current.begin() + at, current.begin() + at + Block, begin),
                "VolumeImageRecoveryUnrelatedBytesChanged");
        }
    }
}
void StreamErase(KeeperTarget& image, File& file, Journal& j, const Plan& plan, const AppleCheckpointStageHook& hook)
{
    const auto count = j.evidence->digests.size();
    // The cursor grants one bounded chunk before any cleanup write. Every
    // earlier chunk has already been flushed and compared with its final bytes.
    for (auto index = j.erase_cursor ? j.erase_cursor - 1 : 0; index < count; ++index) {
        if (j.erase_cursor == index) {
            file.Append(Receipt(j.digest, format_evidence::CursorTag | (index + 1))); j.erase_cursor = index + 1;
        }
        StreamStage(hook, "after-image-erase-authorize");
        const auto begin = index * format_evidence::Chunk / Block;
        const auto end = begin + j.evidence->Length(index) / Block;
        for (auto block = begin; block < end;) {
            if (plan.destinations.contains(block)) { ++block; continue; }
            auto to = block + 1; while (to < end && !plan.destinations.contains(to)) ++to;
            const Bytes zero(static_cast<std::size_t>((to - block) * Block));
            Require(image.ZeroRange(block * Block, zero.size()), "VolumeEraseRangeWriteFailed");
            StreamStage(hook, "after-image-erase-write");
            Require(image.Flush(), "VolumeEraseRangeFlushFailed");
            Bytes readback; Require(image.ReadRange(block * Block, zero.size(), readback) && readback == zero,
                "VolumeEraseRangeReadbackFailed"); block = to;
        }
        StreamStage(hook, "after-image-erase-chunk");
    }
}
void StreamArchive(Session& s)
{
    if (!Exists(s.journal)) return;
    File file; file.Open(s.journal, GENERIC_READ | GENERIC_WRITE, 0, OPEN_EXISTING); const auto prior = Decode(file.ReadAll());
    if(prior.geometry && prior.state==3 && s.image.PhysicalBinding() && prior.geometry->after==*s.image.PhysicalBinding()){
        if(s.image.geometry)volume_geometry::Verify(*s.image.geometry,*prior.geometry,3);
        else{std::string error;Require(s.image.physical->VerifyCompletedGeometry(volume_geometry::Encode(*prior.geometry),error),error);}
    }else if(s.image.geometry && prior.physical && prior.state>=3){
        Require(prior.physical->binding==s.image.geometry->OriginalBinding() && prior.physical->instance==s.image.geometry->InstanceId(),
            "VolumeGeometryArchiveBindingMismatch");
    }else StreamBinding(s, prior);
    Require(!prior.partial && (prior.state == 3 || prior.state == 4), "VolumeImageUnfinishedJournal");
    file.Close(); auto archive = s.journal; archive += L"." + Wide(prior.token) + L".completed";
    Require(MoveFileExW(Extended(s.journal).c_str(), Extended(archive).c_str(), MOVEFILE_WRITE_THROUGH) != FALSE,
        "VolumeImageArchiveFailed:" + std::to_string(GetLastError()));
    Require(s.directory.Flush(), "VolumeImageDirectoryFlushFailed");
}
void GeometryTail(const Session& s,const Journal& j)
{
    if(!j.geometry)return;
    const auto& original=*j.evidence;const auto target=j.request.target_bytes;
    if(target>original.size){
        for(auto at=original.size;at<target;at+=format_evidence::Chunk){Bytes bytes;const auto n=static_cast<std::size_t>((std::min)(format_evidence::Chunk,target-at));
            Require(VolumePhysicalGeometryAccess::ReadWindow(*s.image.geometry,at,n,bytes) && bytes.size()==n &&
                std::all_of(bytes.begin(),bytes.end(),[](auto b){return b==std::byte{};}),"VolumeGeometryGrowthOriginalNotZero");}
    }else{
        for(auto index=target/format_evidence::Chunk;index<original.digests.size();++index){
            const auto at=index*format_evidence::Chunk;const auto n=original.Length(index);Bytes bytes;
            Require(VolumePhysicalGeometryAccess::ReadWindow(*s.image.geometry,at,n,bytes) && bytes.size()==n,"VolumeGeometryRemovedTailUnreadable");
            const auto skip=at<target?static_cast<std::size_t>(target-at):0;const auto stored=original.chunks.find(index);
            if(stored==original.chunks.end())Require(!skip && Hash(bytes)==original.digests.at(static_cast<std::size_t>(index)),"VolumeGeometryRemovedTailChanged");
            else Require(std::equal(bytes.begin()+skip,bytes.end(),stored->second.begin()+skip),"VolumeGeometryRemovedTailChanged");
        }
    }
}
VolumeImageResult PrepareStreamed(const VolumeImageRequest& input, std::shared_ptr<VolumePhysicalSource> physical = {},
    std::shared_ptr<VolumePhysicalGeometrySource> geometry = {})
{
    VolumeImageResult result;
    try {
        Session s(input, std::move(physical),std::move(geometry)); result.source_identity = s.identity; result.journal = s.journal; StreamArchive(s);
        ImageSource live(s.image); Require(live.SizeBytes() == s.r.expected_bytes, "VolumeImageCapacityMismatch");
        Journal j; j.request = s.r; j.identity = s.identity; j.flagged_format = IsFormat(s.r.operation);
        if(s.image.geometry){j.geometry=volume_geometry::Capture(*s.image.geometry,
            {s.image.geometry->OriginalBinding(),s.image.geometry->InstanceId()},s.r.target_bytes);}
        if (s.image.physical) j.physical = volume_physical::Envelope{s.image.physical->Binding(), s.image.physical->InstanceId()};
        j.evidence = format_evidence::Scan(live, s.r.operation == VolumeImageOperation::Erase);
        format_evidence::Capture capture(live, *j.evidence);
        if (s.r.operation == VolumeImageOperation::Shrink) {
            const auto inventory = InspectResizeRelocationSource(capture, s.r);
            j.relocation = inventory.reserved_region_crosses_target || !inventory.blocks.empty();
            j.physical_snapshot_relocation = inventory.physical_snapshot_root_in_tail;
            if (j.physical_snapshot_relocation && j.geometry && j.geometry->snapshot.profile == volume_geometry::Profile::LegacyPartition) {
                auto snapshot = j.geometry->snapshot; snapshot.profile = volume_geometry::Profile::Partition;
                j.geometry = volume_geometry::Build(std::move(snapshot));
            }
        }
        const auto plan = StreamBuild(s, j, capture, true); j.census = s.Census(plan.before, true);
        GeometryTail(s,j);
        std::array<std::byte, 32> random{};
        Require(BCryptGenRandom(nullptr, reinterpret_cast<PUCHAR>(random.data()), 32, BCRYPT_USE_SYSTEM_PREFERRED_RNG) >= 0,
            "VolumeImageRandomFailed");
        j.token = Hex(random); j.expiry = Now() + 300;
        const auto frame = Frame(j);
        (void)DecodeVolumeKeeperHistoryBinding(frame, s.journal, s.r.journal_directory, s.identity);
        File file; file.Open(s.journal, GENERIC_READ | GENERIC_WRITE, 0, CREATE_NEW); file.Append(frame);
        Require(s.directory.Flush(), "VolumeImageDirectoryFlushFailed");
        const auto readback = file.ReadAll(); Require(readback == frame, "VolumeImagePreparedReadbackFailed");
        j.digest = Decode(readback).digest;
        format_evidence::Snapshot saved(*j.evidence);
        try { s.HoldStreamHistory(saved, StreamMembers(s, plan), frame); }
        catch (...) {
            // This session still owns the exact, clean original WAL census and
            // has never accepted an APFS write. Do not strand a failed prepare.
            PersistVolumeKeeperHistoryProof(s.journal, frame, s.identity, s.HeldWals());
            Transition(file, j, 4);
            throw;
        }
        PersistVolumeKeeperHistoryProof(s.journal, frame, s.identity, s.HeldWals());
        StreamFill(result, s, j, plan); result.token = j.token; result.outcome = VolumeImageOutcome::Prepared;
    } catch (const std::exception& ex) { result.error = ex.what(); }
    return result;
}
VolumeImageResult RunStreamed(const VolumeImageRequest& input, std::string_view token, bool recovery, bool cancel,
    const AppleCheckpointStageHook& hook, std::shared_ptr<VolumePhysicalSource> physical = {},
    std::shared_ptr<VolumePhysicalGeometrySource> geometry = {})
{
    VolumeImageResult result; bool accepted = recovery;
    try {
        Session s(input, std::move(physical),std::move(geometry)); result.source_identity = s.identity; result.journal = s.journal;
        File file; file.Open(s.journal, GENERIC_READ | GENERIC_WRITE, 0, OPEN_EXISTING); auto j = Decode(file.ReadAll());
        accepted = recovery && (j.state >= 1 && j.state <= 3);
        Require(j.evidence && j.identity.substr(0, 64) == s.identity.substr(0, 64) && Encode(j.request) == Encode(s.r), "VolumeImageJournalBindingMismatch");
        StreamBinding(s, j);
        if(s.image.geometry && j.state>=2 && j.state<=3)s.image.logical_size=s.r.target_bytes;
        ImageSource live(s.image); format_evidence::Snapshot original(*j.evidence);
        if (!recovery) {
            Require(j.state == 0 && !j.partial, "VolumeImageConfirmationConsumed");
            if (token != j.token || Now() >= j.expiry || cancel) {
                s.HoldCancellation(live, HistoryFrame(file, j));
                Transition(file, j, 4); Require(token == j.token, "VolumeImageConfirmationMismatch");
                Require(Now() < j.expiry, "VolumeImageConfirmationExpired"); result.outcome = VolumeImageOutcome::Cancelled; return result;
            }
        }
        // A completed destination is now an ordinary member. Its current WAL
        // authority is proved by held terminal history, not the old empty census.
        const auto plan = StreamBuild(s, j, original, false, recovery && j.state == 3); StreamFill(result, s, j, plan);
        if (recovery && j.state == 3) {
            std::string error; const auto current = catalog::LoadAppleCheckpointView(live, 0, live.SizeBytes(), error);
            if (current && current->container.superblock.xid > plan.after.container.superblock.xid) {
                s.HoldStreamHistory(live, {}, HistoryFrame(file, j), true);
                if(j.geometry){VolumePhysicalGeometryAccess::Authorize(s.image.geometry,*j.geometry);VolumePhysicalGeometryAccess::MarkComplete(s.image.geometry);}
                result.outcome = VolumeImageOutcome::Committed; return result;
            }
        }
        GeometryTail(s,j);
        if (recovery && j.state == 3) {
            StreamCompare(live, j, plan, StreamComparison::Final); VerifySource(live, plan.after);
            s.HoldStreamHistory(live, {}, HistoryFrame(file, j), true);
            if(j.geometry){VolumePhysicalGeometryAccess::Authorize(s.image.geometry,*j.geometry);VolumePhysicalGeometryAccess::MarkComplete(s.image.geometry);}
            result.outcome = VolumeImageOutcome::Committed; return result;
        }
        if (recovery && (j.state == 0 || j.state == 4)) {
            StreamCompare(live, j, plan, StreamComparison::Original);
            Require(s.Census(plan.before) == j.census, "VolumeImageStaleWalCensus");
            s.HoldCancellation(live, HistoryFrame(file, j));
            if (j.state == 0) {
                // This still-unaccepted original has just passed the exact
                // source and WAL census. Retain its reservation identity before
                // cancelling, including for a pre-upgrade prepared journal.
                PersistVolumeKeeperHistoryProof(s.journal, HistoryFrame(file, j), j.identity, s.HeldWals());
                if (j.partial) file.Resize(j.valid_bytes); Transition(file, j, 4);
            }
            result.outcome = VolumeImageOutcome::Cancelled; return result;
        }
        if (!recovery) {
            try { StreamCompare(live, j, plan, StreamComparison::Original); }
            catch (...) { Transition(file, j, 4); throw; }
        }
        if (s.Census(plan.before) != j.census) { if (!recovery) Transition(file, j, 4); throw std::runtime_error("VolumeImageStaleWalCensus"); }
        if (recovery) StreamCompare(live, j, plan, j.state == 3 ? StreamComparison::Final : StreamComparison::Accepted);
        s.HoldStreamHistory(original, StreamMembers(s, plan), HistoryFrame(file, j));
        if (j.partial) file.Resize(j.valid_bytes);
        if (!recovery) {
            if (hook && !hook("before-image-accept")) {
                s.history.reset();
                s.HoldCancellation(live, HistoryFrame(file, j));
                Transition(file, j, 4); result.outcome = VolumeImageOutcome::Cancelled; return result;
            }
            PersistVolumeKeeperHistoryProof(s.journal, HistoryFrame(file, j), j.identity, s.HeldWals(), hook);
            accepted = true; Transition(file, j, 1);
        } else {
            // An accepted replay must retain its previously durable WAL proof.
            ConfirmVolumeKeeperHistoryProof(s.journal, HistoryFrame(file, j), j.identity, s.HeldWals());
        }
        Require(file.Flush(), "VolumeImageJournalDurabilityFailed");
        if(j.geometry)VolumePhysicalGeometryAccess::Authorize(s.image.geometry,*j.geometry);
        StreamStage(hook, "after-image-accept");
        if (s.r.operation == VolumeImageOperation::Grow && j.state == 1) {
            if (s.image.Size() < s.r.target_bytes) s.image.Resize(s.r.target_bytes);
            for (auto offset = s.r.expected_bytes; offset < s.r.target_bytes; offset += format_evidence::Chunk) {
                const auto length = static_cast<std::size_t>((std::min)(format_evidence::Chunk, s.r.target_bytes - offset));
                Require(s.image.ZeroRange(offset, length) && s.image.Flush(), "VolumeResizeGrowthZeroFailed");
                Bytes bytes; Require(s.image.ReadRange(offset, length, bytes) &&
                    std::all_of(bytes.begin(), bytes.end(), [](auto b) { return b == std::byte{}; }), "VolumeResizeGrowthReadbackFailed");
            }
        }
        StreamStage(hook, "after-image-grow");
        if (j.state == 1 || s.r.operation == VolumeImageOperation::Format) {
            auto publication = plan.publication;
            if (recovery) for (auto& guard : publication.guard_blocks) if (plan.destinations.contains(guard.physical_block))
                Require(s.image.ReadBlock(guard.physical_block, Block, guard.bytes), "VolumeImageRecoveryGuardReadFailed");
            std::string error; Require(ExecuteAppleCheckpointPublication(s.image, publication, error, hook), error);
            StreamStage(hook, "before-image-anchor");
            Require(s.image.WriteBlock(0, plan.anchor) && s.image.Flush(), "VolumeImageAnchorDurabilityFailed");
            Bytes anchor; Require(s.image.ReadBlock(0, Block, anchor) && anchor == plan.anchor, "VolumeImageAnchorReadbackFailed");
            if (j.state == 1) Transition(file, j, 2);
        }
        StreamStage(hook, "after-image-anchor");
        if (s.r.operation == VolumeImageOperation::Erase) StreamErase(s.image, file, j, plan, hook);
        StreamStage(hook, "after-image-cleanup");
        if (s.r.operation == VolumeImageOperation::Shrink && s.image.Size() > s.r.target_bytes) s.image.Resize(s.r.target_bytes);
        StreamStage(hook, "after-image-truncate");
        StreamCompare(live, j, plan, StreamComparison::Final); VerifySource(live, plan.after);
        GeometryTail(s,j);
        if(j.geometry)VolumePhysicalGeometryAccess::PublishGpt(s.image.geometry,hook);
        StreamStage(hook, "before-image-complete"); Transition(file, j, 3); result.outcome = VolumeImageOutcome::Committed;
        if(j.geometry)VolumePhysicalGeometryAccess::MarkComplete(s.image.geometry);
    } catch (const std::exception& ex) {
        result.error = ex.what(); result.outcome = accepted ? VolumeImageOutcome::RecoveryRequired : VolumeImageOutcome::Refused;
    }
    return result;
}
