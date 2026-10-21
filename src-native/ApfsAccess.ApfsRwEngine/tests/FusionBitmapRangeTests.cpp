#include "FusionBitmapRange.h"
#include <algorithm>
#include <array>
#include <iostream>
#include <stdexcept>
#include <vector>
#include <Windows.h>

namespace {
using apfsaccess::catalog::ApfsReadBudget;
using apfsaccess::rw::fusion_bitmap::RangeAllocated;
using Bytes = std::vector<std::byte>;
unsigned checks = 0, groups = 0;
void Check(bool value, const char* why) { ++checks; if (!value) throw std::runtime_error(why); }
auto Budget(std::uint64_t records) { return std::make_shared<ApfsReadBudget>(0, 0, records, 0); }
bool Oracle(std::span<const std::byte> bytes, std::uint64_t start, std::uint64_t count) {
    for (auto i = start; i < start + count; ++i)
        if (!(std::to_integer<unsigned>(bytes[static_cast<std::size_t>(i / 8)]) & (1u << (i % 8)))) return false;
    return true;
}
void Compare(const Bytes& bytes, std::uint64_t start, std::uint64_t count) {
    const auto before = bytes;
    const auto charge = (start + count - 1) / 8 - start / 8 + 1;
    auto budget = Budget(charge); std::string error = "stale";
    const bool expected = Oracle(bytes, start, count);
    Check(RangeAllocated(bytes, start, count, budget, error) == expected, "per-bit oracle mismatch");
    Check(error == (expected ? "" : "FusionVolumeOwnerFree"), "exact result reason");
    const auto used = budget->Consumed();
    Check(used.records == charge && !used.record_bytes && !used.reads && !used.read_bytes && !budget->Failed(), "exact byte count only");
    Check(bytes == before, "bitmap unchanged");
}
template<class F> void Group(const char* name, F body) { body(); ++groups; std::cout << "PASS " << name << '\n'; }
void Tests() {
    Group("all 256 byte patterns and every nonempty partial mask", [] {
        for (unsigned pattern = 0; pattern < 256; ++pattern)
            for (unsigned start = 0; start < 8; ++start)
                for (unsigned count = 1; count <= 8 - start; ++count)
                    Compare({std::byte(pattern)}, start, count);
    });
    Group("every four-byte range with each individual cleared bit inside or outside", [] {
        for (unsigned start = 0; start < 32; ++start) for (unsigned count = 1; count <= 32 - start; ++count) {
            Compare(Bytes(4, std::byte{0xff}), start, count);
            Compare(Bytes(4, std::byte{0}), start, count);
            for (unsigned clear = 0; clear < 32; ++clear) {
                Bytes bytes(4, std::byte{0xff});
                bytes[clear / 8] &= std::byte(0xffu ^ (1u << (clear % 8)));
                Compare(bytes, start, count);
            }
        }
    });
    Group("nonzero starts exact end and outside-bit noise", [] {
        Compare({std::byte{0}, std::byte{0x80}, std::byte{0xff}, std::byte{0x01}, std::byte{0}}, 15, 10);
        Compare({std::byte{0}, std::byte{0x80}}, 15, 1);
        Compare({std::byte{0x7f}, std::byte{0}}, 0, 7);
        Compare({std::byte{0xfe}}, 1, 7);
        Compare({std::byte{0x80}, std::byte{0x01}}, 7, 2);
        Compare({std::byte{0x80}, std::byte{0x01}}, 7, 3);
    });
    Group("5000 deterministic randomized ranges match independent per-block enumeration", [] {
        std::uint64_t state = 0xd8731a2564c9bef1ULL;
        const auto random = [&]() {
            state ^= state << 13; state ^= state >> 7; state ^= state << 17; return state;
        };
        for (unsigned trial = 0; trial < 5000; ++trial) {
            Bytes bytes(static_cast<std::size_t>(1 + random() % 513));
            const auto bits = static_cast<std::uint64_t>(bytes.size()) * 8;
            const auto start = random() % bits, count = 1 + random() % (bits - start);
            if (trial % 4 == 0) {
                for (auto& value : bytes) value = std::byte(random() & 255);
            } else {
                std::fill(bytes.begin(), bytes.end(), std::byte{0xff});
                if (trial % 4 == 1) {
                    // Only outside bits are zero: the admitted range must pass.
                    for (std::uint64_t bit = 0; bit < bits; ++bit)
                        if (bit < start || bit - start >= count)
                            bytes[static_cast<std::size_t>(bit / 8)] &= std::byte(0xffu ^ (1u << (bit % 8)));
                } else {
                    const auto clear = start + random() % count;
                    bytes[static_cast<std::size_t>(clear / 8)] &= std::byte(0xffu ^ (1u << (clear % 8)));
                }
            }
            Compare(bytes, start, count);
        }
    });
    Group("65536 allocated blocks charge 8192 finite byte inspections", [] {
        Bytes bitmap(8192, std::byte{0xff}); const auto before = bitmap;
        auto budget = Budget(8192); std::string error;
        Check(RangeAllocated(bitmap, 0, 65536, budget, error), "large coalesced owner range");
        Check(budget->Consumed().records == 8192 && !budget->Consumed().record_bytes, "eightfold exact inspection count");
        Check(bitmap == before, "large bitmap unchanged");
        for (const auto clear : {0u, 1u, 7u, 8u, 32767u, 32768u, 65528u, 65535u}) {
            auto bad = bitmap; bad[clear / 8] &= std::byte(0xffu ^ (1u << (clear % 8)));
            auto fresh = Budget(8192);
            Check(!RangeAllocated(bad, 0, 65536, fresh, error) && error == "FusionVolumeOwnerFree", "full-byte loop catches every sampled location");
            Check(fresh->Consumed().records == 8192 && !fresh->Failed(), "clear-bit refusal preserves cumulative accounting");
        }
    });
    Group("malformed bounds refuse before any byte reservation", [] {
        const Bytes bytes(4, std::byte{0xff});
        for (const auto [start, count] : std::array<std::pair<std::uint64_t, std::uint64_t>, 9>{{
            {0, 0}, {32, 1}, {31, 2}, {0, 33}, {UINT64_MAX, 1}, {UINT64_MAX - 7, 8},
            {1, UINT64_MAX}, {UINT64_MAX / 2, UINT64_MAX / 2}, {UINT64_MAX - 1, 1}}}) {
            auto budget = Budget(100); std::string error;
            Check(!RangeAllocated(bytes, start, count, budget, error) && error == "FusionBitmapRangeInvalid", "invalid bounds reject");
            Check(!budget->Failed() && !budget->Consumed().records, "invalid bounds do not consume or reset allowance");
        }
        auto budget = Budget(100); std::string error;
        Check(!RangeAllocated({}, 0, 1, budget, error) && error == "FusionBitmapRangeInvalid", "empty span refuses");
        Check(!budget->Consumed().records, "empty span no charge");
        Check(!RangeAllocated(bytes, 0, 1, {}, error) && error == "FusionBitmapBudgetRequired", "budget required");
    });
    Group("shared exact boundary failure stays sticky across later chunks", [] {
        const Bytes bytes(3, std::byte{0xff}); auto budget = Budget(3); std::string error;
        Check(RangeAllocated(bytes, 7, 2, budget, error), "first range covers two bytes");
        Check(RangeAllocated(bytes, 16, 8, budget, error), "second range consumes last byte allowance");
        Check(budget->Consumed().records == 3, "one shared cumulative allowance");
        Check(!RangeAllocated(bytes, 0, 1, budget, error) && error == "ApfsReadBudgetRecordLimit", "shared allowance exhausted");
        const auto failure = budget->ReservationFailure();
        Check(failure.count == 1 && failure.bytes == 0, "exact refused byte step");
        Check(!RangeAllocated(bytes, 0, 1, budget, error) && budget->Consumed().records == 3, "retry no renewal");
        Check(!RangeAllocated({}, UINT64_MAX, 1, budget, error) && error == "ApfsReadBudgetRecordLimit", "sticky failure precedes invalid later input");
        auto insufficient = Budget(1);
        Check(!RangeAllocated(bytes, 7, 2, insufficient, error), "unaligned two-byte request cannot fit one step");
        Check(insufficient->Consumed().records == 0 && insufficient->ReservationFailure().count == 2, "whole reservation fails atomically");
        auto source_failed = Budget(10); Check(!source_failed->Read(1), "seed actual source failure");
        Check(!RangeAllocated(bytes, 0, 1, source_failed, error) && error == "ApfsReadBudgetSourceLimit", "foreign sticky reason preserved");
    });
    Group("budget refusal and out of bounds do not inspect an inaccessible page", [] {
        SYSTEM_INFO info{}; GetSystemInfo(&info);
        void* address = VirtualAlloc(nullptr, info.dwPageSize, MEM_RESERVE | MEM_COMMIT, PAGE_NOACCESS);
        Check(address != nullptr, "guard page allocation");
        struct Release { void* address; ~Release() { VirtualFree(address, 0, MEM_RELEASE); } } release{address};
        const std::span<const std::byte> inaccessible(static_cast<const std::byte*>(address), 1);
        std::string error; auto empty = Budget(0);
        Check(!RangeAllocated(inaccessible, 0, 1, empty, error) && error == "ApfsReadBudgetRecordLimit", "zero allowance refuses before dereference");
        auto valid = Budget(1);
        Check(!RangeAllocated(inaccessible, 8, 1, valid, error) && error == "FusionBitmapRangeInvalid", "bounds refuse before dereference");
        Check(valid->Consumed().records == 0, "invalid inaccessible input uncharged");
    });
}
}
int RunFusionBitmapRangeTests() {
    try { Tests(); std::cout << "PASS groups=" << groups << " assertions=" << checks << '\n'; return 0; }
    catch (const std::exception& e) { std::cerr << "FAIL groups=" << groups << " assertions=" << checks << " " << e.what() << '\n'; return 1; }
}
#ifndef FUSION_BITMAP_RANGE_NO_MAIN
int main() { return RunFusionBitmapRangeTests(); }
#endif
