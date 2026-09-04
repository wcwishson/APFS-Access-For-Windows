#pragma once

#include <cstddef>
#include <cstdint>
#include <optional>
#include <span>
#include <string>
#include <string_view>
#include <vector>

namespace apfsaccess::rw
{

enum class ApfsCaseMode
{
    Sensitive,
    Insensitive,
};

enum class ApfsNormalizationMode
{
    Sensitive,
    Insensitive,
};

struct ApfsNamePolicy
{
    ApfsCaseMode case_mode = ApfsCaseMode::Sensitive;
    ApfsNormalizationMode normalization_mode = ApfsNormalizationMode::Sensitive;

    [[nodiscard]] static ApfsNamePolicy FromIncompatibleFeatures(
        std::uint64_t incompatible_features) noexcept;

    [[nodiscard]] bool UsesHashedDirectoryKeys() const noexcept
    {
        return normalization_mode == ApfsNormalizationMode::Insensitive;
    }
};

enum class ApfsNameError
{
    None,
    InvalidUtf8,
    UnassignedCodePoint,
    InvalidApfsName,
    NameTooLong,
    InvalidWindowsName,
    AmbiguousWindowsName,
    NormalizationFailure,
};

template <typename T>
struct ApfsNameResult
{
    std::optional<T> value;
    ApfsNameError error = ApfsNameError::None;
    std::string detail;

    [[nodiscard]] bool ok() const noexcept { return value.has_value(); }
};

struct ApfsName
{
    std::string original_utf8;
    std::wstring windows_display;
    std::vector<std::byte> lookup_key;
    std::optional<std::uint32_t> directory_hash;
};

class ApfsNameCodec
{
public:
    static constexpr std::size_t kMaxApfsNameBytes = 255;

    [[nodiscard]] static ApfsNameResult<ApfsName> Decode(
        std::span<const std::byte> utf8,
        const ApfsNamePolicy& policy);

    [[nodiscard]] static ApfsNameResult<std::string> EncodeWindowsName(
        std::wstring_view name);

    [[nodiscard]] static ApfsNameResult<std::wstring> CanonicalWindowsComponentKey(
        std::wstring_view name,
        const ApfsNamePolicy& policy);

    [[nodiscard]] static ApfsNameResult<std::wstring> CanonicalWindowsPathKey(
        std::wstring_view path,
        const ApfsNamePolicy& policy);

    [[nodiscard]] static bool MatchesHashedDirectoryKey(
        const ApfsName& name,
        std::uint32_t name_length_and_hash) noexcept;

    [[nodiscard]] static constexpr std::wstring_view EscapePrefix() noexcept
    {
        return L"~APFS~";
    }
};

} // namespace apfsaccess::rw
