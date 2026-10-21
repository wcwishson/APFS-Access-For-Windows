#include "FusionExtentCoalescing.h"
#include <iostream>
#include <map>
#include <stdexcept>
#include <tuple>

namespace {
using namespace apfsaccess;
using namespace apfsaccess::rw;
using Record = catalog::BtreeRecord;
using Records = std::vector<Record>;
unsigned checks = 0, groups = 0;
void Check(bool value, const char* message) { ++checks; if (!value) throw std::runtime_error(message); }
bool Equal(const Records& a, const Records& b) {
    if (a.size() != b.size()) return false;
    for (std::size_t i = 0; i < a.size(); ++i)
        if (a[i].key != b[i].key || a[i].value != b[i].value) return false;
    return true;
}
void Put(std::vector<std::byte>& bytes, std::size_t at, std::uint64_t n) {
    for (unsigned i = 0; i < 8; ++i) bytes.at(at + i) = std::byte(n >> (8 * i));
}
Record File(std::uint64_t object, std::uint64_t logical, std::uint64_t physical,
    std::uint64_t length = 4096, std::uint64_t crypto = 0) {
    Record out; std::string error;
    Check(EncodeAppleFileExtentRecord({object, logical, length, physical, crypto, 4096}, out, error), "encode file");
    return out;
}
Record Physical(std::uint64_t physical, std::uint64_t owner = 30, std::int32_t refs = 1,
    std::uint64_t count = 1, std::uint8_t kind = kApplePhysicalExtentKindNew) {
    Record out; std::string error;
    Check(EncodeApplePhysicalExtentRecord({physical, count, kind, owner, refs}, out, error), "encode ref");
    return out;
}
Record Opaque() { return {{std::byte{0x37}}, {std::byte{0}, std::byte{0xff}, std::byte{0x61}}}; }
using FileMap = std::map<std::pair<std::uint64_t, std::uint64_t>, std::pair<std::uint64_t, std::uint64_t>>;
FileMap FileMeaning(const Records& records) {
    FileMap result; std::string error;
    for (const auto& record : records) {
        if ((catalog::ReadU64LE(record.key, 0).value_or(0) >> 60) != 8) continue;
        AppleFileExtentRecord e; Check(DecodeAppleFileExtentRecord(record, 4096, e, error), "meaning file decode");
        Check(e.length_bytes / 4096 <= 20000, "finite file expansion");
        for (std::uint64_t n = 0; n < e.length_bytes / 4096; ++n)
            Check(result.emplace(std::make_pair(e.object_id, e.logical_address / 4096 + n),
                std::make_pair(e.physical_block ? e.physical_block + n : 0, e.crypto_id)).second, "unique logical block");
    }
    return result;
}
using RefMap = std::map<std::uint64_t, std::tuple<std::uint64_t, std::uint8_t, std::int32_t>>;
RefMap PhysicalMeaning(const Records& records) {
    RefMap result; std::string error;
    for (const auto& record : records) {
        if ((catalog::ReadU64LE(record.key, 0).value_or(0) >> 60) != 2) continue;
        ApplePhysicalExtentRecord e; Check(DecodeApplePhysicalExtentRecord(record, e, error), "meaning ref decode");
        Check(e.block_count <= 20000, "finite ref expansion");
        for (std::uint64_t n = 0; n < e.block_count; ++n)
            Check(result.emplace(e.physical_block + n, std::make_tuple(e.owning_object_id, e.kind, e.reference_count)).second,
                "unique physical block");
    }
    return result;
}
template<class F> void Group(const char* name, F body) { body(); ++groups; std::cout << "PASS " << name << '\n'; }
void FileRefuses(Records records) {
    const auto before = records; std::string error;
    Check(!fusion_compact::FileRecords(records, 4096, error), "invalid file refuses");
    Check(!error.empty() && Equal(records, before), "file refusal atomic");
}
void PhysicalRefuses(Records records) {
    const auto before = records; std::string error;
    Check(!fusion_compact::PhysicalRecords(records, error), "invalid ref refuses");
    Check(!error.empty() && Equal(records, before), "ref refusal atomic");
}
void Tests() {
    Group("2750 existing blocks compact with exact logical and physical ownership", [] {
        Records files{Opaque()}, refs{Opaque()};
        for (std::uint64_t i = 0; i < 2750; ++i) { files.push_back(File(30, i * 4096, 100 + i)); refs.push_back(Physical(100 + i)); }
        const auto file_meaning = FileMeaning(files); const auto ref_meaning = PhysicalMeaning(refs);
        std::string error;
        auto budget = std::make_shared<catalog::ApfsReadBudget>(0, 0, 6000, 1u << 20);
        Check(fusion_compact::FileRecords(files, 4096, error, budget), "compact large file");
        Check(fusion_compact::PhysicalRecords(refs, error, budget), "compact large refs");
        Check(files.size() == 2 && refs.size() == 2, "one existing range each");
        Check(Equal({files.front()}, {Opaque()}) && Equal({refs.front()}, {Opaque()}), "opaque bytes preserved");
        Check(FileMeaning(files) == file_meaning && PhysicalMeaning(refs) == ref_meaning, "all per-block semantics unchanged");
        Check(budget->Consumed().records == 5500 && budget->Consumed().record_bytes > 0, "temporary materialization charged");
        auto same_files = files, same_refs = refs;
        Check(fusion_compact::FileRecords(files, 4096, error) && Equal(files, same_files), "file idempotence");
        Check(fusion_compact::PhysicalRecords(refs, error) && Equal(refs, same_refs), "ref idempotence");
    });
    Group("unsorted inputs preserve nonextent bytes and complete semantics", [] {
        Records files{File(40, 4096, 201), Opaque(), File(30, 0, 100), File(40, 0, 200), Opaque(), File(30, 4096, 101)};
        Records refs{Physical(201, 40), Opaque(), Physical(100), Physical(200, 40), Opaque(), Physical(101)};
        const auto fm = FileMeaning(files); const auto pm = PhysicalMeaning(refs); std::string error;
        Check(fusion_compact::FileRecords(files, 4096, error) && files.size() == 4, "unordered file ranges");
        Check(fusion_compact::PhysicalRecords(refs, error) && refs.size() == 4, "unordered physical ranges");
        Check(FileMeaning(files) == fm && PhysicalMeaning(refs) == pm, "unordered meanings preserved");
        Check(Equal({files[0], files[3]}, {Opaque(), Opaque()}) && Equal({refs[0], refs[3]}, {Opaque(), Opaque()}), "opaque order retained");
    });
    Group("file gaps owner crypto holes and member boundary stay separate", [] {
        constexpr auto tier = catalog::kFusionTier2ByteAddress / 4096;
        for (Records records : {
            Records{File(30, 0, 100), File(30, 8192, 101)},
            Records{File(30, 0, 100), File(30, 4096, 102)},
            Records{File(30, 0, 100), File(31, 4096, 101)},
            Records{File(30, 0, 100, 4096, 9), File(30, 4096, 101, 4096, 9)},
            Records{File(30, 0, 100), File(30, 4096, 101, 4096, 9)},
            Records{File(30, 0, 0), File(30, 4096, 0)},
            Records{File(30, 0, tier - 1), File(30, 4096, tier)}}) {
            const auto before = records; std::string error;
            Check(fusion_compact::FileRecords(records, 4096, error) && Equal(records, before), "file semantic boundary no-op");
        }
    });
    Group("physical kind owner refcount gaps and member boundary stay separate", [] {
        constexpr auto tier = catalog::kFusionTier2ByteAddress / 4096;
        for (Records records : {
            Records{Physical(100), Physical(102)}, Records{Physical(100), Physical(101, 31)},
            Records{Physical(100), Physical(101, 30, 2)},
            Records{Physical(100), Physical(101, 30, 1, 1, kApplePhysicalExtentKindUpdate)},
            Records{Physical(tier - 1), Physical(tier)}}) {
            const auto before = records; std::string error;
            Check(fusion_compact::PhysicalRecords(records, error) && Equal(records, before), "physical semantic boundary no-op");
        }
        Records update{Physical(100, 30, -1, 1, kApplePhysicalExtentKindUpdate), Physical(101, 30, -1, 1, kApplePhysicalExtentKindUpdate)};
        const auto meaning = PhysicalMeaning(update); std::string error;
        Check(fusion_compact::PhysicalRecords(update, error) && update.size() == 1 && PhysicalMeaning(update) == meaning,
            "matching update deltas preserved without granting canonical admission");
    });
    Group("late malformed or overlapping file records never partly commit", [] {
        FileRefuses({File(30, 0, 100), File(30, 4096, 101), File(30, 4096, 102)});
        FileRefuses({File(30, 0, 100, 8192), File(30, 4096, 102)});
        for (const auto fault : {0, 1, 2, 3, 4, 5, 6}) {
            auto bad = File(31, 0, 200);
            if (fault == 0) bad.key.pop_back();
            if (fault == 1) bad.value.push_back(std::byte{0});
            if (fault == 2) Put(bad.value, 0, 0);
            if (fault == 3) Put(bad.value, 0, 4096ull | (1ull << 56));
            if (fault == 4) Put(bad.key, 8, UINT64_MAX - 4095);
            if (fault == 5) Put(bad.value, 8, UINT64_MAX);
            if (fault == 6) Put(bad.key, 8, 1);
            FileRefuses({File(30, 0, 100), File(30, 4096, 101), bad});
        }
    });
    Group("late malformed or overlapping references never partly commit", [] {
        PhysicalRefuses({Physical(100), Physical(101), Physical(101)});
        PhysicalRefuses({Physical(100, 30, 1, 3), Physical(102)});
        for (const auto fault : {0, 1, 2, 3, 4, 5}) {
            auto bad = Physical(200);
            if (fault == 0) bad.value.pop_back();
            if (fault == 1) Put(bad.value, 0, 1ull << 60);
            if (fault == 2) Put(bad.key, 0, 2ull << 60);
            if (fault == 3) Put(bad.value, 8, 0);
            if (fault == 4) Put(bad.value, 0, 3ull << 60 | 1);
            if (fault == 5) Put(bad.key, 0, 2ull << 60 | 0x0fffffffffffffffULL), Put(bad.value, 0, 1ull << 60 | 2);
            PhysicalRefuses({Physical(100), Physical(101), bad});
        }
    });
    Group("length encoding maximum and exact boundary are checked", [] {
        constexpr auto max_length = 0x00fffffffffff000ULL;
        Records files{File(30, 0, 100, max_length), File(30, max_length, 100 + max_length / 4096)};
        const auto before = files; std::string error;
        Check(fusion_compact::FileRecords(files, 4096, error) && Equal(files, before), "length overflow is nonmerging");
        constexpr auto mask = 0x0fffffffffffffffULL;
        Records refs{Physical(mask - 1), Physical(mask)};
        Check(fusion_compact::PhysicalRecords(refs, error) && refs.size() == 1, "last physical block exact boundary");
        ApplePhysicalExtentRecord decoded; Check(DecodeApplePhysicalExtentRecord(refs.front(), decoded, error) && decoded.block_count == 2, "boundary codec roundtrip");
        for (const auto block : {0u, 1u, 2048u, 4097u, 131072u}) {
            files = {File(30, 0, 100), File(30, 4096, 101)}; const auto original = files;
            Check(!fusion_compact::FileRecords(files, block, error) && Equal(files, original), "bad block geometry atomic");
        }
    });
    Group("shared exhausted budgets refuse without replenishment or vector writes", [] {
        for (const bool bytes : {false, true}) {
            auto budget = std::make_shared<catalog::ApfsReadBudget>(0, 0, bytes ? 100 : 1, bytes ? 1 : 10000);
            Records files{File(30, 0, 100), File(30, 4096, 101)}; const auto original = files; std::string error;
            Check(!fusion_compact::FileRecords(files, 4096, error, budget) && Equal(files, original), "file budget refuses atomically");
            Check(budget->Failed() && budget->Consumed().records == 0, "failed reservation sticky");
            Check(!fusion_compact::FileRecords(files, 4096, error, budget) && Equal(files, original), "retry cannot reset allowance");
            auto other = std::make_shared<catalog::ApfsReadBudget>(0, 0, bytes ? 100 : 1, bytes ? 1 : 10000);
            Records refs{Physical(100), Physical(101)}; const auto prior = refs;
            Check(!fusion_compact::PhysicalRecords(refs, error, other) && Equal(refs, prior), "physical budget refuses atomically");
        }
    });
    Group("new payload stays per block with identical estimated and actual tree shapes", [] {
        Records existing_files, existing_refs;
        for (std::uint64_t n = 0; n < 2750; ++n) { existing_files.push_back(File(30, n * 4096, 100 + n)); existing_refs.push_back(Physical(100 + n)); }
        std::string error;
        Check(fusion_compact::FileRecords(existing_files, 4096, error) && fusion_compact::PhysicalRecords(existing_refs, error), "compact only old records");
        auto estimated = existing_files, actual = existing_files;
        for (std::uint64_t n = 0; n < 64; ++n) {
            estimated.push_back(File(30, (2750 + n) * 4096, 1));
            actual.push_back(File(30, (2750 + n) * 4096, 5000 + n));
        }
        Check(estimated.size() == 65 && actual.size() == 65, "64 new file records unmerged");
        AppleBtreeOptions options; options.block_size = 4096; options.xid = 66; options.root_object_id = 1000;
        options.root_physical_block = 10000; options.first_child_object_id = 2000;
        options.subtype = catalog::kObjectTypeFsTree; options.key_order = AppleBtreeKeyOrder::FileSystemCaseSensitive;
        AppleSerializedBtree a, b;
        Check(SerializeAppleBtree(estimated, options, a, error), "estimated serialize");
        Check(SerializeAppleBtree(actual, options, b, error), "actual serialize");
        Check(a.objects.size() == b.objects.size(), "estimated actual node count identical");
        auto er = existing_refs, ar = existing_refs;
        for (std::uint64_t n = 0; n < 64; ++n) { er.push_back(Physical(20000 + n)); ar.push_back(Physical(5000 + n)); }
        options.root_object_id = 1; options.first_child_object_id = 2;
        options.subtype = catalog::kObjectTypeBlockRefTree; options.key_order = AppleBtreeKeyOrder::PhysicalExtent;
        Check(SerializeAppleBtree(er, options, a, error) && SerializeAppleBtree(ar, options, b, error), "reference estimate actual serialize");
        Check(er.size() == 65 && ar.size() == 65 && a.objects.size() == b.objects.size(), "new refs unchanged sizing");
    });
    Group("empty and nonextent-only input are exact no-ops", [] {
        for (Records records : {Records{}, Records{Opaque(), Opaque()}}) {
            auto before = records; std::string error;
            Check(fusion_compact::FileRecords(records, 4096, error) && Equal(records, before), "nonfile no-op");
            Check(fusion_compact::PhysicalRecords(records, error) && Equal(records, before), "nonref no-op");
        }
    });
}
}
int RunFusionExtentCoalescingTests() {
    try { Tests(); std::cout << "PASS groups=" << groups << " assertions=" << checks << '\n'; return 0; }
    catch (const std::exception& e) { std::cerr << "FAIL groups=" << groups << " assertions=" << checks << " " << e.what() << '\n'; return 1; }
}
#ifndef FUSION_EXTENT_COALESCING_NO_MAIN
int main() { return RunFusionExtentCoalescingTests(); }
#endif
