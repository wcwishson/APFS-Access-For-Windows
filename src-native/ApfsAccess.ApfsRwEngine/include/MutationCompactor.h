#pragma once

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
};
}
