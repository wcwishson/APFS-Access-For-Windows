#include "MutationCompactor.h"

#include "ApfsNameCodec.h"

#include <algorithm>
#include <iostream>
#include <string>
#include <utility>
#include <vector>

namespace
{
using apfsaccess::rw::MutationCompactor;
using apfsaccess::rw::ApfsCaseMode;
using apfsaccess::rw::ApfsNamePolicy;
using apfsaccess::rw::ApfsNormalizationMode;

bool Require(bool condition, const char* message)
{
    if (!condition)
    {
        std::cerr << "[FAIL] " << message << std::endl;
        return false;
    }
    return true;
}

MutationCompactor::MutationView Mutation(
    MutationCompactor::MutationKind kind,
    std::wstring path,
    std::wstring secondary_path = L"",
    std::uint64_t length = 0)
{
    return MutationCompactor::MutationView{
        kind,
        std::move(path),
        std::move(secondary_path),
        length,
    };
}

bool HasPayloadPath(
    const MutationCompactor::Summary& summary,
    const std::wstring& path)
{
    return std::find(summary.payload_paths.begin(), summary.payload_paths.end(), path) != summary.payload_paths.end();
}

std::wstring CanonicalPath(
    std::wstring_view path,
    const ApfsNamePolicy& policy = {
        ApfsCaseMode::Insensitive,
        ApfsNormalizationMode::Insensitive})
{
    const auto result = apfsaccess::rw::ApfsNameCodec::CanonicalWindowsPathKey(path, policy);
    return result.ok() ? *result.value : std::wstring{};
}

bool TestDirectoryRestoreBarrierSummary()
{
    using Kind = MutationCompactor::MutationKind;
    static_assert(static_cast<int>(Kind::RestoreDirectoryFromSymbolicLink) == 14);
    const auto restore = Mutation(Kind::RestoreDirectoryFromSymbolicLink, L"\\directory");
    const auto alone = MutationCompactor::Summarize({restore});
    const auto mixed = MutationCompactor::Summarize({
        Mutation(Kind::SetSymbolicLinkTarget, L"\\directory", L"target"), restore,
        Mutation(Kind::Write, L"\\file", L"", 4),
        Mutation(Kind::Write, L"\\file", L"", 8)});
    const auto old = MutationCompactor::Summarize({Mutation(Kind::RemoveSymbolicLinkTarget, L"\\file")});
    return Require(alone.compacted_mutation_count == 1 && alone.payload_paths.empty(),
               "directory restore is a payload-free barrier") &&
        Require(mixed.compacted_mutation_count == 4 && mixed.payload_paths.size() == 1 &&
                HasPayloadPath(mixed, CanonicalPath(L"\\file")),
               "restore prevents coalescing without inventing a directory payload") &&
        Require(old.compacted_mutation_count == 0 && old.payload_paths.empty(),
               "old symlink removal summary is unchanged");
}

bool TestAllocationSizeBarrierSummary()
{
    using Kind = MutationCompactor::MutationKind;
    static_assert(static_cast<int>(Kind::SetAllocationSize) == 13);
    const std::vector<MutationCompactor::MutationView> mutations{
        Mutation(Kind::Write, L"\\file.bin", L"", 8192),
        Mutation(Kind::SetFileSize, L"\\file.bin", L"", 2048),
        Mutation(Kind::SetAllocationSize, L"\\file.bin", L"", 0),
        Mutation(Kind::SetFileSize, L"\\file.bin", L"", 16384),
        Mutation(Kind::Write, L"\\file.bin", L"", 4),
        Mutation(Kind::SetAllocationSize, L"\\file.bin", L"", 0),
    };
    const auto summary = MutationCompactor::Summarize(mutations);
    const auto only_allocation = MutationCompactor::Summarize({mutations[2]});
    const auto truncate_after = MutationCompactor::Summarize({mutations[0], mutations[2],
        Mutation(Kind::SetFileSize, L"\\file.bin", L"", 0)});
    return Require(summary.compacted_mutation_count == mutations.size(),
               "allocation barriers prohibit reporting writes and size changes as coalesced") &&
        Require(HasPayloadPath(summary, CanonicalPath(L"\\file.bin")),
               "allocation barrier does not discard preceding payload or later growth") &&
        Require(only_allocation.compacted_mutation_count == 1 && only_allocation.payload_paths.empty(),
               "zero allocation remains an operation without inventing payload") &&
        Require(truncate_after.compacted_mutation_count == 3 && truncate_after.payload_paths.empty(),
               "later EOF zero cannot erase the allocation barrier from the count");
}

bool TestWritesCollapseToFinalPayloadPath()
{
    const std::vector<MutationCompactor::MutationView> mutations{
        Mutation(MutationCompactor::MutationKind::Write, L"\\Folder\\File.bin", L"", 4),
        Mutation(MutationCompactor::MutationKind::Write, L"/folder/file.bin", L"", 8),
        Mutation(MutationCompactor::MutationKind::SetBasicInfo, L"\\Folder\\File.bin"),
    };

    const auto summary = MutationCompactor::Summarize(mutations);

    return Require(summary.raw_mutation_count == 3, "raw count should include ignored metadata") &&
           Require(summary.compacted_mutation_count == 1, "same file writes should compact to one payload path") &&
           Require(summary.payload_paths.size() == 1, "same file writes should emit one path") &&
           Require(summary.payload_paths[0] == CanonicalPath(L"\\folder\\file.bin"), "payload path should be normalized and canonical");
}

bool TestTruncateDropsPayloadPastEof()
{
    const std::vector<MutationCompactor::MutationView> mutations{
        Mutation(MutationCompactor::MutationKind::Write, L"\\file.bin", L"", 4096),
        Mutation(MutationCompactor::MutationKind::SetFileSize, L"\\file.bin", L"", 0),
    };

    const auto summary = MutationCompactor::Summarize(mutations);

    return Require(summary.payload_paths.empty(), "truncate to zero should remove pending payload path") &&
           Require(summary.compacted_mutation_count == 0, "truncate to zero should leave no payload compaction target");
}

bool TestSetFileSizeGrowthRequiresPayload()
{
    const std::vector<MutationCompactor::MutationView> mutations{
        Mutation(MutationCompactor::MutationKind::SetFileSize, L"file.bin", L"", 8192),
    };

    const auto summary = MutationCompactor::Summarize(mutations);

    return Require(summary.payload_paths.size() == 1, "growth should require final payload materialization") &&
           Require(summary.payload_paths[0] == CanonicalPath(L"\\file.bin"), "relative growth path should normalize to rooted path");
}

bool TestRenameChainsRemapPayloadPaths()
{
    const std::vector<MutationCompactor::MutationView> mutations{
        Mutation(MutationCompactor::MutationKind::Write, L"\\a\\file.bin", L"", 4),
        Mutation(MutationCompactor::MutationKind::Rename, L"\\a", L"\\b"),
        Mutation(MutationCompactor::MutationKind::Rename, L"\\b\\file.bin", L"\\c\\final.bin"),
    };

    const auto summary = MutationCompactor::Summarize(mutations);

    return Require(summary.payload_paths.size() == 1, "rename chain should leave one final payload path") &&
           Require(summary.payload_paths[0] == CanonicalPath(L"\\c\\final.bin"), "rename chain should remap to final destination");
}

bool TestDeleteSubtreeRemovesPayloadPaths()
{
    const std::vector<MutationCompactor::MutationView> mutations{
        Mutation(MutationCompactor::MutationKind::Write, L"\\tree\\child.bin", L"", 4),
        Mutation(MutationCompactor::MutationKind::Write, L"\\tree\\nested\\leaf.bin", L"", 4),
        Mutation(MutationCompactor::MutationKind::Delete, L"\\tree"),
    };

    const auto summary = MutationCompactor::Summarize(mutations);

    return Require(summary.payload_paths.empty(), "subtree delete should remove descendant payload paths");
}

bool TestMixedWorkloadKeepsOnlyFinalLivePayloads()
{
    const std::vector<MutationCompactor::MutationView> mutations{
        Mutation(MutationCompactor::MutationKind::CreateFile, L"\\temp.bin"),
        Mutation(MutationCompactor::MutationKind::Write, L"\\temp.bin", L"", 4),
        Mutation(MutationCompactor::MutationKind::Delete, L"\\temp.bin"),
        Mutation(MutationCompactor::MutationKind::Write, L"\\keep.bin", L"", 2),
        Mutation(MutationCompactor::MutationKind::Rename, L"\\keep.bin", L"\\Kept\\final.bin"),
        Mutation(MutationCompactor::MutationKind::SetBasicInfo, L"\\Kept\\final.bin"),
    };

    const auto summary = MutationCompactor::Summarize(mutations);

    return Require(summary.raw_mutation_count == 6, "mixed workload should report raw count") &&
           Require(summary.compacted_mutation_count == 1, "mixed workload should keep only one live payload") &&
           Require(HasPayloadPath(summary, CanonicalPath(L"\\kept\\final.bin")), "mixed workload should keep renamed live payload");
}

bool TestCompactionHonorsApfsNamePolicy()
{
    const std::vector<MutationCompactor::MutationView> mutations{
        Mutation(MutationCompactor::MutationKind::Write, L"\\File.bin", L"", 4),
        Mutation(MutationCompactor::MutationKind::Write, L"\\file.bin", L"", 8),
    };

    const auto exact = MutationCompactor::Summarize(
        mutations,
        ApfsNamePolicy{ApfsCaseMode::Sensitive, ApfsNormalizationMode::Sensitive});
    const auto folded = MutationCompactor::Summarize(
        mutations,
        ApfsNamePolicy{ApfsCaseMode::Insensitive, ApfsNormalizationMode::Insensitive});
    const auto exact_policy = ApfsNamePolicy{
        ApfsCaseMode::Sensitive,
        ApfsNormalizationMode::Sensitive};

    return Require(exact.compacted_mutation_count == 2, "case-sensitive APFS paths must not coalesce") &&
           Require(HasPayloadPath(exact, CanonicalPath(L"\\File.bin", exact_policy)), "case-sensitive compaction should retain uppercase path") &&
           Require(HasPayloadPath(exact, CanonicalPath(L"\\file.bin", exact_policy)), "case-sensitive compaction should retain lowercase path") &&
           Require(folded.compacted_mutation_count == 1, "case-insensitive APFS paths should coalesce");
}
}

int main()
{
    if (!TestDirectoryRestoreBarrierSummary() || !TestAllocationSizeBarrierSummary() ||
        !TestWritesCollapseToFinalPayloadPath() ||
        !TestTruncateDropsPayloadPastEof() ||
        !TestSetFileSizeGrowthRequiresPayload() ||
        !TestRenameChainsRemapPayloadPaths() ||
        !TestDeleteSubtreeRemovesPayloadPaths() ||
        !TestMixedWorkloadKeepsOnlyFinalLivePayloads() ||
        !TestCompactionHonorsApfsNamePolicy())
    {
        return 1;
    }

    std::cout << "[PASS] MutationCompactor tests passed." << std::endl;
    return 0;
}
