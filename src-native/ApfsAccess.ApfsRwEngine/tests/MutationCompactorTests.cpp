#include "MutationCompactor.h"

#include <algorithm>
#include <iostream>
#include <string>
#include <utility>
#include <vector>

namespace
{
using apfsaccess::rw::MutationCompactor;

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
           Require(summary.payload_paths[0] == L"\\folder\\file.bin", "payload path should be normalized and canonical");
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
           Require(summary.payload_paths[0] == L"\\file.bin", "relative growth path should normalize to rooted path");
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
           Require(summary.payload_paths[0] == L"\\c\\final.bin", "rename chain should remap to final destination");
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
           Require(HasPayloadPath(summary, L"\\kept\\final.bin"), "mixed workload should keep renamed live payload");
}
}

int main()
{
    if (!TestWritesCollapseToFinalPayloadPath() ||
        !TestTruncateDropsPayloadPastEof() ||
        !TestSetFileSizeGrowthRequiresPayload() ||
        !TestRenameChainsRemapPayloadPaths() ||
        !TestDeleteSubtreeRemovesPayloadPaths() ||
        !TestMixedWorkloadKeepsOnlyFinalLivePayloads())
    {
        return 1;
    }

    std::cout << "[PASS] MutationCompactor tests passed." << std::endl;
    return 0;
}
