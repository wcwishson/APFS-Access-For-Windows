#include "MutationCompactor.h"

#include <algorithm>
#include <cwctype>
#include <unordered_set>
#include <utility>

namespace apfsaccess::rw
{
namespace
{
std::wstring NormalizePath(std::wstring_view input)
{
    std::wstring normalized;
    normalized.reserve(input.size() + 1);

    bool previous_separator = false;
    for (const auto ch : input)
    {
        const auto mapped = ch == L'/' ? L'\\' : ch;
        if (mapped == L'\\')
        {
            if (previous_separator)
            {
                continue;
            }
            previous_separator = true;
            normalized.push_back(mapped);
            continue;
        }

        previous_separator = false;
        normalized.push_back(mapped);
    }

    while (normalized.size() > 1 && normalized.back() == L'\\')
    {
        normalized.pop_back();
    }

    if (normalized.empty())
    {
        return {};
    }

    if (normalized.front() != L'\\')
    {
        normalized.insert(normalized.begin(), L'\\');
    }

    return normalized;
}

std::wstring CanonicalPathKey(std::wstring_view path)
{
    auto key = NormalizePath(path);
    std::transform(
        key.begin(),
        key.end(),
        key.begin(),
        [](wchar_t ch)
        {
            return static_cast<wchar_t>(std::towlower(ch));
        });
    return key;
}

bool IsDescendantPath(const std::wstring& candidate_key, const std::wstring& parent_key)
{
    if (candidate_key.empty() || parent_key.empty() || candidate_key == parent_key)
    {
        return false;
    }

    auto parent_prefix = parent_key;
    if (!parent_prefix.empty() && parent_prefix.back() != L'\\')
    {
        parent_prefix.push_back(L'\\');
    }

    return candidate_key.rfind(parent_prefix, 0) == 0;
}

void RemapPayloadSubtree(
    std::unordered_set<std::wstring>& payload_paths,
    const std::wstring& source_key,
    const std::wstring& destination_key)
{
    if (source_key.empty() || destination_key.empty())
    {
        return;
    }

    std::vector<std::wstring> pending_removals;
    std::vector<std::wstring> pending_additions;
    pending_removals.reserve(payload_paths.size());
    pending_additions.reserve(payload_paths.size());

    for (const auto& payload_path : payload_paths)
    {
        if (payload_path == source_key)
        {
            pending_removals.push_back(payload_path);
            pending_additions.push_back(destination_key);
            continue;
        }

        if (!IsDescendantPath(payload_path, source_key))
        {
            continue;
        }

        auto remapped_path = destination_key;
        remapped_path.append(payload_path.substr(source_key.size()));
        pending_removals.push_back(payload_path);
        pending_additions.push_back(std::move(remapped_path));
    }

    for (const auto& payload_path : pending_removals)
    {
        payload_paths.erase(payload_path);
    }
    for (auto& payload_path : pending_additions)
    {
        if (!payload_path.empty())
        {
            payload_paths.insert(std::move(payload_path));
        }
    }
}

void ErasePayloadSubtree(
    std::unordered_set<std::wstring>& payload_paths,
    const std::wstring& deleted_key)
{
    if (deleted_key.empty())
    {
        return;
    }

    std::vector<std::wstring> pending_removals;
    pending_removals.reserve(payload_paths.size());
    for (const auto& payload_path : payload_paths)
    {
        if (payload_path == deleted_key || IsDescendantPath(payload_path, deleted_key))
        {
            pending_removals.push_back(payload_path);
        }
    }

    for (const auto& payload_path : pending_removals)
    {
        payload_paths.erase(payload_path);
    }
}
}

MutationCompactor::Summary MutationCompactor::Summarize(const std::vector<MutationView>& mutations)
{
    Summary summary{};
    summary.raw_mutation_count = mutations.size();

    std::unordered_set<std::wstring> payload_paths;
    payload_paths.reserve(mutations.size());

    for (const auto& mutation : mutations)
    {
        const auto path_key = CanonicalPathKey(mutation.path);
        switch (mutation.kind)
        {
        case MutationKind::Write:
            if (mutation.length > 0)
            {
                payload_paths.insert(path_key);
            }
            break;
        case MutationKind::SetFileSize:
            if (mutation.length > 0)
            {
                payload_paths.insert(path_key);
            }
            else
            {
                payload_paths.erase(path_key);
            }
            break;
        case MutationKind::Rename:
            RemapPayloadSubtree(payload_paths, path_key, CanonicalPathKey(mutation.secondary_path));
            break;
        case MutationKind::Delete:
            ErasePayloadSubtree(payload_paths, path_key);
            break;
        case MutationKind::CreateFile:
        case MutationKind::CreateDirectory:
        case MutationKind::SetBasicInfo:
            break;
        }
    }

    summary.payload_paths.assign(payload_paths.begin(), payload_paths.end());
    std::sort(summary.payload_paths.begin(), summary.payload_paths.end());
    summary.compacted_mutation_count = summary.payload_paths.size();
    return summary;
}
}
