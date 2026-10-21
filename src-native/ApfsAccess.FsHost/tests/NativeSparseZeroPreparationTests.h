#pragma once

bool TestNativeSparseZeroTransactionBounds()
{
    namespace protocol = apfsaccess::fshost::sparse_control;
    using Store = apfsaccess::rw::MetadataStore;
    HostNativeSparse340Fixture owned;
    if (!Require(owned.Initialize(false, false, 112), "zero batch image has seven allocated chunks and a hole")) return false;
    auto& c = *owned.fixture.context; auto fs = BuildFileSystem(&c);
    c.args.write_max_dirty_transactions = 64;
    PVOID writer = nullptr; FSP_FSCTL_FILE_INFO info{};
    ScopeExit close{[&] { if (writer) CB_Close(&fs, writer); }};
    if (!Require(CB_Open(&fs, const_cast<PWSTR>(L"\\original"), FILE_OPEN << 24,
        GENERIC_READ | GENERIC_WRITE, &writer, &info) == STATUS_SUCCESS, "zero batch handle opens")) return false;
    protocol::RangeRequest request; request.length = 7 * 64 * 1024;
    protocol::Reply reply; ULONG transferred = 999;
    const auto control = [&](UINT32 code) {
        return CB_Control(&fs, writer, code, &request, sizeof(request), &reply, sizeof(reply), &transferred);
    };
    const auto recovery_files = [&] {
        std::map<std::filesystem::path, std::vector<std::byte>> result;
        for (const auto& file : std::filesystem::recursive_directory_iterator(c.session_root))
            if (file.is_regular_file()) result.emplace(file.path().lexically_relative(c.session_root), ReadFileBytes(file.path()));
        return result;
    };
    const auto image = ReadFileBytes(owned.fixture.image.path);
    const auto recovery = recovery_files();
    const auto watermarks = c.tx_manager->Watermarks();
    const auto xid = c.metadata_store->CheckpointXid();
    const auto unchanged = [&] {
        const auto now = c.tx_manager->Watermarks();
        return image == ReadFileBytes(owned.fixture.image.path) && recovery == recovery_files() &&
            now.accepted_sequence == watermarks.accepted_sequence && now.apfs_durable_sequence == watermarks.apfs_durable_sequence &&
            now.cleanup_sequence == watermarks.cleanup_sequence && c.metadata_store->CheckpointXid() == xid &&
            c.metadata_store->PendingMutationCount() == 0 && !c.metadata_store->IsRecoveryRequired() && !c.write_degraded;
    };
    const auto rejected = control(protocol::Zero);
    std::wcerr << L"Zero seven-chunk status=" << std::hex << static_cast<unsigned>(rejected) << std::dec
        << L" degraded=" << c.write_degraded << L'\n';
    if (!Require(rejected == STATUS_NOT_SUPPORTED && transferred == 0 && unchanged(),
        "zero exceeding complete preview bound refuses without source, recovery, WAL, XID or admission changes")) return false;
    c.fs = &fs;
    const auto mounted = control(protocol::Zero);
    c.fs = nullptr;
    if (!Require(mounted == STATUS_NOT_SUPPORTED && transferred == 0 && unchanged(), "mounted zero still refuses without cache authority")) return false;
    for (const auto code : {FSCTL_SET_SPARSE, FSCTL_SET_ZERO_DATA, FSCTL_QUERY_ALLOCATED_RANGES})
        if (!Require(control(code) == STATUS_INVALID_DEVICE_REQUEST && transferred == 0 && unchanged(),
            "eligible native handle still refuses each standard sparse FSCTL without mutation")) return false;
    request.offset = 112 * 4096 + 17; request.length = 1ULL << 20;
    if (!Require(control(protocol::Zero) == STATUS_SUCCESS && reply.zeroed_bytes == 0 && unchanged(),
        "hole-only zero is a durable no-op without companions or checkpoint")) return false;
    request.offset = 17; request.length = 6 * 64 * 1024 - 17;
    if (!Require(control(protocol::Zero) == STATUS_SUCCESS && reply.zeroed_bytes == request.length &&
        c.metadata_store->PendingMutationCount() == 0 && !c.write_degraded, "exact eight-request zero batch commits")) return false;
    Store fresh(owned.fixture.volume); std::vector<std::byte> bytes;
    if (!Require(fresh.PrepareNativeWritePath() && fresh.ReplayOrRecover() && fresh.VerifyIntegrity(), "bounded zero fresh owner verifies")) return false;
    const auto inode = fresh.LookupCommittedInodeByPath(L"\\original");
    if (!Require(inode && inode->logical_size == owned.tail + 12288 && inode->allocation_size == 115 * 4096 &&
        fresh.ReadCommittedFileRange(L"\\original", 0, 17, bytes) && bytes == std::vector<std::byte>(17, std::byte{0x31}) &&
        fresh.ReadCommittedFileRange(L"\\original", 17, static_cast<std::size_t>(request.length), bytes) && bytes == std::vector<std::byte>(request.length) &&
        fresh.ReadCommittedFileRange(L"\\original", 6 * 64 * 1024, 4096, bytes) && bytes == std::vector<std::byte>(4096, std::byte{0x31}) &&
        fresh.ReadCommittedFileRange(L"\\original", owned.tail, 4096, bytes) && bytes == std::vector<std::byte>(4096, std::byte{0xa7}),
        "fresh image has exact zeros, outside canaries, unchanged EOF and retained allocation")) return false;
    return true;
}

bool TestNativeSparseRangeCompleteValidation()
{
    namespace protocol = apfsaccess::fshost::sparse_control;
    using Store = apfsaccess::rw::MetadataStore;
    NativeSparseRangeView view;
    auto extents = std::make_shared<std::vector<Store::FileExtent>>();
    for (std::uint64_t i = 0; i < 66; ++i) extents->push_back({i * 8192, (100 + i) * 4096, 4096});
    view.plan.extents_snapshot = extents; view.plan.logical_size = 66 * 8192; view.allocation = 66 * 4096;
    protocol::RangeRequest request; request.length = view.plan.logical_size;
    protocol::Reply reply;
    if (!Require(CollectNativeAllocatedRanges(view, request, reply) == STATUS_SUCCESS && reply.range_count == 64 &&
        reply.more_ranges == 1 && reply.next_offset == 63 * 8192 + 4096, "validated query keeps bounded pagination")) return false;
    extents->back().logical_offset = 0; reply = {};
    if (!Require(CollectNativeAllocatedRanges(view, request, reply) == STATUS_FILE_CORRUPT_ERROR,
        "corrupt tail after pagination limit is rejected before a successful reply")) return false;
    extents->back().logical_offset = 65 * 8192; view.allocation += 4096; reply = {};
    if (!Require(CollectNativeAllocatedRanges(view, request, reply) == STATUS_FILE_CORRUPT_ERROR,
        "allocation mismatch cannot become a successful truncated projection")) return false;
    view.allocation -= 4096; request.offset = 64 * 8192; request.length = 2 * 8192; reply = {};
    return Require(CollectNativeAllocatedRanges(view, request, reply) == STATUS_SUCCESS && reply.range_count == 2 &&
        reply.more_ranges == 0 && reply.ranges[0].offset == 64 * 8192, "query resumes without inventing or omitting storage");
}
