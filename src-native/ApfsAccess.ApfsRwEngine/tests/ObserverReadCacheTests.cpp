#include "../tools/ObserverReadCache.h"
#include <iostream>

using Cache = apfsaccess::rw::physical_observer::ReadCache;
using namespace apfsaccess::catalog;
namespace {
unsigned checks = 0, failures = 0;
void Check(bool ok, const char* name) { ++checks; if (!ok) ++failures; std::cout << (ok ? "PASS " : "FAIL ") << name << '\n'; }
struct Source final : RandomAccessSource
{
    std::vector<std::byte> data;
    mutable unsigned reads = 0;
    bool short_read = false, fail = false, throws = false;
    std::function<void()> on_read;
    Source(std::size_t blocks = 6) : data(blocks * Cache::Block)
    { for (std::size_t i = 0; i < data.size(); ++i) data[i] = std::byte((i * 17 + i / Cache::Block) % 251); }
    std::uint64_t SizeBytes() const override { return data.size(); }
    bool Read(std::uint64_t at, std::size_t count, std::vector<std::byte>& out) const override
    {
        ++reads; if (throws) throw std::runtime_error("private source failure");
        if (on_read) on_read();
        if (fail) { out.assign(3, std::byte{1}); return false; }
        out.assign(data.begin() + static_cast<std::ptrdiff_t>(at), data.begin() + static_cast<std::ptrdiff_t>(at + count));
        if (short_read) out.pop_back();
        return true;
    }
    std::vector<std::byte> Slice(std::size_t at, std::size_t count) const
    { return {data.begin() + at, data.begin() + at + count}; }
};
void Reuse()
{
    Source source; bool lease = true; unsigned full = 0;
    Cache cache(source, [&] { return lease; }, [&] { ++full; return true; }); std::vector<std::byte> out;
    Check(cache.Begin(), "full initial validation required");
    Check(cache.Read(0, 32, out) && out == source.Slice(0, 32), "partial object header returns exact original bytes");
    Check(cache.Read(0, 4096, out) && out == source.Slice(0, 4096) && source.reads == 1, "body reuses full original block without repeated heavy Current");
    Check(cache.Read(4090, 20, out) && out == source.Slice(4090, 20) && source.reads == 2, "unaligned crossing combines cached and cold original blocks exactly");
    Check(cache.Stats().miss_bytes == 8192 && cache.Stats().hit_blocks == 2 && cache.Stats().lease_checks >= 8, "miss payload accounting and cheap lease checks include cache hits");
    Check(cache.Finish() && full == 2, "full final validation runs despite cache hits");
    Check(!cache.Read(0, 32, out) && out.empty() && source.reads == 2, "completed operation cannot reuse its cache");
    Check(cache.Stats().allocated_bytes < (5u << 20), "fixed retained payload and entry memory below 5 MiB");
}
void CoalescingAndEviction()
{
    Source source; Cache cache(source, [] { return true; }, [] { return true; }); std::vector<std::byte> out;
    Check(cache.Begin() && cache.Read(19, 3 * 4096 - 40, out) && out == source.Slice(19, 3 * 4096 - 40), "large unaligned logical request has exact payload");
    Check(source.reads == 1 && cache.Stats().miss_blocks == 3 && cache.Stats().miss_bytes == 12288, "adjacent cold blocks coalesce into one backing read");
    Source small; Cache bounded(small, [] { return true; }, [] { return true; }, 2);
    Check(bounded.Begin() && bounded.Read(0, 4096, out) && bounded.Read(4096, 4096, out) && bounded.Read(8192, 4096, out), "bounded two-slot cache accepts three original blocks");
    Check(bounded.ResidentBlocks() == 2 && bounded.Stats().evictions == 1, "replacement evicts without growing retained memory");
    Check(bounded.Read(0, 4096, out) && out == small.Slice(0, 4096) && small.reads == 4, "evicted block is freshly read from same source");
}
void Failures()
{
    for (unsigned kind = 0; kind < 3; ++kind)
    {
        Source source; Cache cache(source, [] { return true; }, [] { return true; }); std::vector<std::byte> out;
        Check(cache.Begin() && cache.Read(0, 4096, out), "failure fixture warms original block");
        source.short_read = kind == 0; source.fail = kind == 1; source.throws = kind == 2;
        Check(!cache.Read(4090, 20, out) && out.empty() && cache.Failed() && cache.ResidentBlocks() == 0, "short/failed/exception miss discards even preceding cached partial output");
        const auto reads = source.reads;
        Check(!cache.Read(0, 32, out) && out.empty() && source.reads == reads && !cache.Finish(), "poisoned operation cannot resume from cached bytes or finalize");
    }
    Source source; bool lease = true; Cache cache(source, [&] { return lease; }, [] { return true; }); std::vector<std::byte> out;
    Check(cache.Begin() && cache.Read(0, 32, out), "lease fixture warms header"); lease = false;
    Check(!cache.Read(0, 32, out) && out.empty() && source.reads == 1 && cache.Failed(), "original lease retirement refuses a cache hit without any reopen");
    Source during; lease = true; Cache changed(during, [&] { return lease; }, [] { return true; });
    during.on_read = [&] { lease = false; };
    Check(changed.Begin() && !changed.Read(0, 32, out) && out.empty() && changed.ResidentBlocks() == 0, "lease change during otherwise successful source read refuses all payload");
}
void FinalIdentityAndBudgets()
{
    Source source; unsigned full = 0; Cache cache(source, [] { return true; }, [&] { return ++full == 1; }); std::vector<std::byte> out;
    Check(cache.Begin() && cache.Read(0, 32, out) && cache.Read(0, 4096, out), "final identity fixture uses cache");
    Check(!cache.Finish() && full == 2 && cache.Failed(), "final full identity/media failure cannot publish success");
    Source missing; Cache start(missing, [] { return true; }, [] { return false; });
    Check(!start.Begin() && !start.Read(0, 32, out) && missing.reads == 0, "failed initial validation permits no read");
    Source limited; Cache cap(limited, [] { return true; }, [] { return true; }, 2, 4096);
    Check(cap.Begin() && cap.Read(0, 32, out) && cap.Read(0, 4096, out), "cache hit does not spend miss allowance");
    Check(!cap.Read(4096, 32, out) && out.empty() && limited.reads == 1 && cap.Stats().miss_bytes == 4096, "miss budget refuses before dispatch and remains sticky");
    Source logical; Cache inner(logical, [] { return true; }, [] { return true; });
    auto budget = std::make_shared<ApfsReadBudget>(2, 8192, 100, 10000); BudgetedRandomAccessSource outer(inner, budget);
    Check(inner.Begin() && outer.Read(0, 4096, out) && outer.Read(0, 4096, out) && logical.reads == 1, "outer logical budget charges both miss and hit");
    Check(!outer.Read(0, 1, out) && out.empty() && budget->Failed() && budget->Consumed().reads == 2 && logical.reads == 1, "cache cannot bypass or replenish logical budget");
    Source raw; auto inherited = std::make_shared<ApfsReadBudget>(10, 8192, 10, 8192); BudgetedRandomAccessSource budgeted(raw, inherited);
    Cache invalid(budgeted, [] { return true; }, [] { return true; });
    Check(!invalid.Begin() && invalid.Failed() && raw.reads == 0, "already-budgeted inner source fails rather than replacing budget identity");
}
void BoundsAndLifetime()
{
    for (unsigned kind = 0; kind < 3; ++kind)
    {
        Source source; Cache cache(source, [] { return true; }, [] { return true; }); std::vector<std::byte> out(3);
        const auto at = kind == 0 ? std::numeric_limits<std::uint64_t>::max() : kind == 1 ? source.SizeBytes() : 0;
        const auto n = kind == 2 ? Cache::MaxRead + 1 : 1;
        Check(cache.Begin() && !cache.Read(at, n, out) && out.empty() && source.reads == 0, "overflow/past-end/oversize refuses before allocation or source I/O");
    }
    Source first, second; second.data[0] = std::byte{99}; std::vector<std::byte> out;
    { Cache cache(first, [] { return true; }, [] { return true; }); Check(cache.Begin() && cache.Read(0, 32, out) && cache.Finish(), "first source operation completes"); }
    Cache fresh(second, [] { return true; }, [] { return true; });
    Check(fresh.Begin() && fresh.Read(0, 32, out) && out.front() == std::byte{99} && second.reads == 1, "fresh operation and owner cannot inherit previous cached bytes");
}
}
int main()
{
    try { Reuse(); CoalescingAndEviction(); Failures(); FinalIdentityAndBudgets(); BoundsAndLifetime(); }
    catch (const std::exception& error) { std::cerr << error.what() << '\n'; return 2; }
    std::cout << "RESULT checks=" << checks << " failures=" << failures << '\n'; return failures ? 1 : 0;
}
