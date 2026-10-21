#pragma once
#include "RandomAccessSource.h"
#include <algorithm>
#include <array>
#include <chrono>
#include <cstring>
#include <functional>
#include <limits>
#include <stdexcept>

namespace apfsaccess::rw::physical_observer
{
class ReadCache final : public apfsaccess::catalog::RandomAccessSource
{
public:
    static constexpr std::size_t Block = 4096, Slots = 1024, MaxRead = 4u << 20;
    static constexpr std::uint64_t MaxMissBytes = 256ull << 20;
    struct Counters
    {
        std::uint64_t logical_reads = 0, logical_bytes = 0, hit_blocks = 0;
        std::uint64_t miss_blocks = 0, source_calls = 0, miss_bytes = 0, source_us = 0;
        std::uint64_t lease_checks = 0, full_checks = 0, full_us = 0, evictions = 0;
        std::size_t allocated_bytes = 0, peak_scratch_bytes = 0;
    };
    ReadCache(const RandomAccessSource& source, std::function<bool()> lease,
        std::function<bool()> full, std::size_t slots = Slots, std::uint64_t miss_limit = MaxMissBytes)
        : source_(source), lease_(std::move(lease)), full_(std::move(full)), size_(source.SizeBytes()), miss_limit_(miss_limit)
    {
        if (!slots || slots > Slots || slots % 2 || miss_limit > MaxMissBytes)
            throw std::invalid_argument("ObserverCacheBoundsInvalid");
        entries_.resize(slots);
        counters_.allocated_bytes = entries_.size() * sizeof(Entry);
        if (!size_ || size_ % Block || source.ReadBudget() || !lease_ || !full_)
            Refuse("ObserverCacheSourceInvalid");
    }
    std::uint64_t SizeBytes() const override { return size_; }
    bool Begin()
    {
        if (begun_ || failed_ || finished_) return Refuse("ObserverCacheBeginInvalid");
        begun_ = true;
        return Lease() && Full() && Lease();
    }
    bool Finish()
    {
        if (!begun_ || failed_ || finished_) return Refuse("ObserverCacheFinishInvalid");
        const bool ok = Lease() && Full() && Lease();
        finished_ = true;
        return ok;
    }
    bool Read(std::uint64_t offset, std::size_t count, std::vector<std::byte>& out) const override
    {
        out.clear();
        if (!begun_ || finished_ || failed_) return Refuse("ObserverCacheNotActive");
        ++counters_.logical_reads; counters_.logical_bytes += count;
        if (count > MaxRead || offset > size_ || count > size_ - offset)
            return Refuse("ObserverCacheRangeInvalid");
        if (!Lease()) return false;
        try
        {
            out.resize(count);
            if (count)
            {
                const auto last = (offset + count - 1) / Block;
                for (auto block = offset / Block; block <= last;)
                {
                    if (auto* entry = Find(block))
                    {
                        ++counters_.hit_blocks;
                        entry->age = ++clock_;
                        Copy(block, entry->data.data(), offset, count, out);
                        ++block;
                        continue;
                    }
                    std::uint64_t blocks = 1;
                    while (block + blocks <= last && blocks < MaxRead / Block && !Find(block + blocks)) ++blocks;
                    const auto bytes = blocks * Block;
                    if (bytes > miss_limit_ - counters_.miss_bytes)
                    { out.clear(); return Refuse("ObserverCacheMissBudget"); }
                    // Reserve attempted miss bytes before dispatch; failures never refund.
                    counters_.miss_bytes += bytes; counters_.miss_blocks += blocks; ++counters_.source_calls;
                    std::vector<std::byte> fill;
                    const auto started = std::chrono::steady_clock::now();
                    const bool ok = source_.Read(block * Block, static_cast<std::size_t>(bytes), fill);
                    counters_.source_us += Micros(started);
                    counters_.peak_scratch_bytes = (std::max)(counters_.peak_scratch_bytes, fill.size());
                    if (!ok || fill.size() != bytes || !Lease())
                    { out.clear(); return Refuse("ObserverCacheIncompleteOrRetiredRead"); }
                    for (std::uint64_t i = 0; i < blocks; ++i)
                    {
                        const auto* data = fill.data() + static_cast<std::size_t>(i) * Block;
                        Store(block + i, data);
                        Copy(block + i, data, offset, count, out);
                    }
                    block += blocks;
                }
            }
            if (!Lease()) { out.clear(); return false; }
            return true;
        }
        catch (...) { out.clear(); return Refuse("ObserverCacheReadException"); }
    }
    const Counters& Stats() const { return counters_; }
    const char* Error() const { return failure_ ? failure_ : ""; }
    bool Failed() const { return failed_; }
    std::size_t ResidentBlocks() const
    { return static_cast<std::size_t>(std::count_if(entries_.begin(), entries_.end(), [](const auto& e) { return e.valid; })); }
private:
    struct Entry { std::array<std::byte, Block> data{}; std::uint64_t block = 0, age = 0; bool valid = false; };
    const RandomAccessSource& source_;
    std::function<bool()> lease_, full_;
    const std::uint64_t size_, miss_limit_;
    mutable std::vector<Entry> entries_;
    mutable Counters counters_;
    mutable std::uint64_t clock_ = 0;
    bool begun_ = false, finished_ = false;
    mutable bool failed_ = false;
    mutable const char* failure_ = nullptr;
    static std::uint64_t Micros(std::chrono::steady_clock::time_point start)
    { return static_cast<std::uint64_t>(std::chrono::duration_cast<std::chrono::microseconds>(std::chrono::steady_clock::now() - start).count()); }
    bool Refuse(const char* why) const
    {
        if (!failure_) failure_ = why;
        failed_ = true;
        for (auto& entry : entries_) entry.valid = false;
        return false;
    }
    bool Lease() const
    {
        if (failed_) return false;
        ++counters_.lease_checks;
        try { if (lease_()) return true; } catch (...) {}
        return Refuse("ObserverCacheOriginalLeaseRetired");
    }
    bool Full() const
    {
        if (failed_) return false;
        ++counters_.full_checks;
        const auto started = std::chrono::steady_clock::now();
        bool ok = false;
        try { ok = full_(); } catch (...) {}
        counters_.full_us += Micros(started);
        return ok || Refuse("ObserverCacheFullValidationFailed");
    }
    Entry* Find(std::uint64_t block) const
    {
        const auto base = static_cast<std::size_t>(block % (entries_.size() / 2)) * 2;
        for (std::size_t i = base; i < base + 2; ++i)
            if (entries_[i].valid && entries_[i].block == block) return &entries_[i];
        return nullptr;
    }
    void Store(std::uint64_t block, const std::byte* bytes) const
    {
        const auto base = static_cast<std::size_t>(block % (entries_.size() / 2)) * 2;
        auto& a = entries_[base]; auto& b = entries_[base + 1];
        auto& entry = !a.valid ? a : !b.valid ? b : a.age <= b.age ? a : b;
        if (entry.valid) ++counters_.evictions;
        std::memcpy(entry.data.data(), bytes, Block);
        entry.block = block; entry.age = ++clock_; entry.valid = true;
    }
    static void Copy(std::uint64_t block, const std::byte* bytes, std::uint64_t offset,
        std::size_t count, std::vector<std::byte>& out)
    {
        const auto start = (std::max)(block * Block, offset);
        const auto end = (std::min)((block + 1) * Block, offset + count);
        std::memcpy(out.data() + static_cast<std::size_t>(start - offset),
            bytes + static_cast<std::size_t>(start - block * Block), static_cast<std::size_t>(end - start));
    }
};
}
