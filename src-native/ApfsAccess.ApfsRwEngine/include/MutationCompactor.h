#pragma once

#include "ApfsNameCodec.h"

#include <cstddef>
#include <cstdint>
#include <string>
#include <vector>

namespace apfsaccess::rw
{
class MutationCompactor
{
public:
    enum class MutationKind
    {
        CreateFile,
        CreateDirectory,
        Write,
        SetFileSize,
        Rename,
        Delete,
        SetBasicInfo,
        SetSymbolicLinkTarget,
        RemoveSymbolicLinkTarget,
        SetExtendedAttribute,
        RemoveExtendedAttribute,
        SetInodeMetadata = 12,
        SetAllocationSize = 13,
        RestoreDirectoryFromSymbolicLink = 14,
        RewriteCompressedContent = 15,
        CloneFile = 16,
        RenameVolume = 17,
        CreateSnapshot = 18,
        DeleteSnapshot = 19,
        RepairVolumeFileCount = 24,
        SetVolumeQuotaReserve = 20,
    };

    struct MutationView
    {
        MutationKind kind = MutationKind::Write;
        std::wstring path;
        std::wstring secondary_path;
        std::uint64_t length = 0;
    };

    struct Summary
    {
        std::size_t raw_mutation_count = 0;
        std::size_t compacted_mutation_count = 0;
        std::vector<std::wstring> payload_paths;
    };

    [[nodiscard]] static Summary Summarize(const std::vector<MutationView>& mutations);
    [[nodiscard]] static Summary Summarize(
        const std::vector<MutationView>& mutations,
        const ApfsNamePolicy& name_policy);
};
}
