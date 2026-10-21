#pragma once

// BlockDevice already translates relative reads through its held base offset.
// Expose only the admitted container, even when device geometry includes a tail.
class RetainedSnapshotInventorySource final : public apfsaccess::catalog::RandomAccessSource
{
public:
    using Clock = std::chrono::steady_clock;
    using Now = std::function<Clock::time_point()>;
    RetainedSnapshotInventorySource(const apfsaccess::rw::BlockDevice& device, std::uint64_t size,
        Clock::time_point deadline, Now now = Clock::now)
        : device_(device), size_(device.IsRawWriterAccepted() ? device.RawWriteLimitBytes() : size), deadline_(deadline),
          now_(std::move(now)),
          budget_(std::make_shared<apfsaccess::catalog::ApfsReadBudget>(65536, 268435456, 1000000, 268435456)) {}
    std::uint64_t SizeBytes() const override { return size_; }
    std::shared_ptr<apfsaccess::catalog::ApfsReadBudget> ReadBudget() const override { return budget_; }
    bool WithinDeadline() const
    {
        if (now_() >= deadline_) return budget_->Refuse("SnapshotInventoryDeadlineExpired");
        return !budget_->Failed();
    }
    bool Read(std::uint64_t offset, std::size_t count, std::vector<std::byte>& out) const override
    {
        out.clear();
        if (!WithinDeadline() || offset > size_ || count > size_ - offset) return false;
        if (!budget_->Read(count)) return false;
        const bool read = device_.Read(offset, count, out);
        // This rejects late success; it cannot cancel a synchronous device read.
        if (!WithinDeadline()) { out.clear(); return false; }
        return read;
    }
private:
    const apfsaccess::rw::BlockDevice& device_;
    std::uint64_t size_;
    std::chrono::steady_clock::time_point deadline_;
    Now now_;
    std::shared_ptr<apfsaccess::catalog::ApfsReadBudget> budget_;
};

bool EnumerateRetainedSnapshotWindow(const apfsaccess::rw::BlockDevice& device,
    const apfsaccess::catalog::ApfsSnapshotScope& physical_scope, LiveSnapshotInventory& out, std::string& error,
    RetainedSnapshotInventorySource::Clock::time_point deadline =
        RetainedSnapshotInventorySource::Clock::now() + std::chrono::seconds(5),
    RetainedSnapshotInventorySource::Now now = RetainedSnapshotInventorySource::Clock::now)
{
    out = {};
    error = "SnapshotInventoryWindowInvalid";
    if (!physical_scope.store_size_bytes || device.BaseOffsetBytes() != physical_scope.store_offset_bytes ||
        physical_scope.store_offset_bytes > UINT64_MAX - physical_scope.store_size_bytes ||
        device.GetGeometry().total_bytes < physical_scope.store_size_bytes ||
        (device.IsRawWriterAccepted() && device.RawWriteLimitBytes() != physical_scope.store_size_bytes)) return false;
    auto relative = physical_scope;
    relative.store_offset_bytes = 0;
    RetainedSnapshotInventorySource source(device, physical_scope.store_size_bytes, deadline, std::move(now));
    std::vector<apfsaccess::catalog::ApfsSnapshotInfo> snapshots;
    if (!apfsaccess::catalog::ApfsSnapshotStore::Enumerate(source, relative, snapshots, error)) {
        if (source.ReadBudget()->Failed()) error = source.ReadBudget()->Failure();
        return false;
    }
    if (snapshots.size() > 64) { error = "SnapshotInventoryBound"; return false; }
    for (auto& snapshot : snapshots) snapshot.identity.scope = physical_scope;
    if (!source.WithinDeadline()) { error = source.ReadBudget()->Failure(); return false; }
    out.scope = physical_scope;
    out.snapshots = std::move(snapshots);
    error.clear();
    return true;
}
