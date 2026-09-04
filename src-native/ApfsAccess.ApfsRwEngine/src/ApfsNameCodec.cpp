#include "ApfsNameCodec.h"

#include "utf8proc.h"

#include <algorithm>
#include <array>
#include <cstdlib>
#include <limits>
#include <utility>

namespace apfsaccess::rw
{
namespace
{
constexpr std::uint64_t kCaseInsensitiveFeature = 0x1;
constexpr std::uint64_t kNormalizationInsensitiveFeature = 0x8;
constexpr wchar_t kEscapeDigitBase = static_cast<wchar_t>(0x4e00);
constexpr unsigned int kEscapeDigitBits = 14;
constexpr unsigned int kEscapeDigitMask = (1u << kEscapeDigitBits) - 1u;

struct FullFoldOverride
{
    utf8proc_int32_t source;
    std::array<utf8proc_int32_t, 2> mapped;
};

// utf8proc 2.1.1 pins the Unicode 9 data APFS needs, but its generator lets
// a later Simple mapping replace a Full mapping for these 28 code points.
// Expand them before utf8proc applies decomposition and the remaining fold.
constexpr std::array<FullFoldOverride, 28> kUnicode9FullFoldOverrides = {{
    {0x1e9e, {0x0073, 0x0073}},
    {0x1f88, {0x1f00, 0x03b9}},
    {0x1f89, {0x1f01, 0x03b9}},
    {0x1f8a, {0x1f02, 0x03b9}},
    {0x1f8b, {0x1f03, 0x03b9}},
    {0x1f8c, {0x1f04, 0x03b9}},
    {0x1f8d, {0x1f05, 0x03b9}},
    {0x1f8e, {0x1f06, 0x03b9}},
    {0x1f8f, {0x1f07, 0x03b9}},
    {0x1f98, {0x1f20, 0x03b9}},
    {0x1f99, {0x1f21, 0x03b9}},
    {0x1f9a, {0x1f22, 0x03b9}},
    {0x1f9b, {0x1f23, 0x03b9}},
    {0x1f9c, {0x1f24, 0x03b9}},
    {0x1f9d, {0x1f25, 0x03b9}},
    {0x1f9e, {0x1f26, 0x03b9}},
    {0x1f9f, {0x1f27, 0x03b9}},
    {0x1fa8, {0x1f60, 0x03b9}},
    {0x1fa9, {0x1f61, 0x03b9}},
    {0x1faa, {0x1f62, 0x03b9}},
    {0x1fab, {0x1f63, 0x03b9}},
    {0x1fac, {0x1f64, 0x03b9}},
    {0x1fad, {0x1f65, 0x03b9}},
    {0x1fae, {0x1f66, 0x03b9}},
    {0x1faf, {0x1f67, 0x03b9}},
    {0x1fbc, {0x03b1, 0x03b9}},
    {0x1fcc, {0x03b7, 0x03b9}},
    {0x1ffc, {0x03c9, 0x03b9}},
}};

template <typename T>
ApfsNameResult<T> Success(T value)
{
    ApfsNameResult<T> result;
    result.value.emplace(std::move(value));
    return result;
}

template <typename T>
ApfsNameResult<T> Failure(ApfsNameError error, std::string detail)
{
    ApfsNameResult<T> result;
    result.error = error;
    result.detail = std::move(detail);
    return result;
}

bool StartsWithEscapePrefixInsensitive(std::wstring_view value)
{
    const auto prefix = ApfsNameCodec::EscapePrefix();
    if (value.size() < prefix.size())
    {
        return false;
    }
    for (std::size_t index = 0; index < prefix.size(); ++index)
    {
        auto ch = value[index];
        if (ch >= L'a' && ch <= L'z')
        {
            ch = static_cast<wchar_t>(ch - L'a' + L'A');
        }
        if (ch != prefix[index])
        {
            return false;
        }
    }
    return true;
}

bool IsReservedDosName(std::wstring_view name)
{
    const auto dot = name.find(L'.');
    std::wstring base(name.substr(0, dot));
    while (!base.empty() && base.back() == L' ')
    {
        base.pop_back();
    }
    for (std::size_t index = 0; index < base.size(); ++index)
    {
        auto& ch = base[index];
        if (ch > 0x7f)
        {
            const bool superscriptDeviceDigit = index == 3 &&
                (ch == static_cast<wchar_t>(0x00b9) ||
                 ch == static_cast<wchar_t>(0x00b2) ||
                 ch == static_cast<wchar_t>(0x00b3));
            if (!superscriptDeviceDigit)
            {
                return false;
            }
            continue;
        }
        if (ch >= L'a' && ch <= L'z')
        {
            ch = static_cast<wchar_t>(ch - L'a' + L'A');
        }
    }
    if (base == L"CON" || base == L"PRN" || base == L"AUX" ||
        base == L"NUL" || base == L"CLOCK$" || base == L"CONIN$" ||
        base == L"CONOUT$")
    {
        return true;
    }
    if (base.size() != 4 ||
        (!base.starts_with(L"COM") && !base.starts_with(L"LPT")))
    {
        return false;
    }
    return (base[3] >= L'1' && base[3] <= L'9') ||
           base[3] == static_cast<wchar_t>(0x00b9) ||
           base[3] == static_cast<wchar_t>(0x00b2) ||
           base[3] == static_cast<wchar_t>(0x00b3);
}

bool IsLiteralWindowsName(std::wstring_view name)
{
    if (name.empty() || name == L"." || name == L".." ||
        StartsWithEscapePrefixInsensitive(name) ||
        name.back() == L'.' || name.back() == L' ' ||
        IsReservedDosName(name))
    {
        return false;
    }
    for (const auto ch : name)
    {
        if (ch <= 0x1f || ch == L'<' || ch == L'>' || ch == L':' ||
            ch == L'"' || ch == L'/' || ch == L'\\' || ch == L'|' ||
            ch == L'?' || ch == L'*')
        {
            return false;
        }
    }
    return true;
}

bool AppendUtf8(utf8proc_int32_t code_point, std::string& output)
{
    std::array<utf8proc_uint8_t, 4> encoded{};
    const auto count = utf8proc_encode_char(code_point, encoded.data());
    if (count <= 0)
    {
        return false;
    }
    output.append(
        reinterpret_cast<const char*>(encoded.data()),
        static_cast<std::size_t>(count));
    return true;
}

bool ExpandUnicode9FullFolds(
    std::span<const std::byte> input,
    std::string& output)
{
    output.clear();
    output.reserve(input.size());
    std::size_t offset = 0;
    while (offset < input.size())
    {
        utf8proc_int32_t code_point = 0;
        const auto consumed = utf8proc_iterate(
            reinterpret_cast<const utf8proc_uint8_t*>(input.data() + offset),
            static_cast<utf8proc_ssize_t>(input.size() - offset),
            &code_point);
        if (consumed <= 0)
        {
            return false;
        }
        offset += static_cast<std::size_t>(consumed);
        const auto override_it = std::lower_bound(
            kUnicode9FullFoldOverrides.begin(),
            kUnicode9FullFoldOverrides.end(),
            code_point,
            [](const FullFoldOverride& candidate, utf8proc_int32_t value)
            {
                return candidate.source < value;
            });
        if (override_it == kUnicode9FullFoldOverrides.end() ||
            override_it->source != code_point)
        {
            if (!AppendUtf8(code_point, output))
            {
                return false;
            }
            continue;
        }
        for (const auto mapped : override_it->mapped)
        {
            if (!AppendUtf8(mapped, output))
            {
                return false;
            }
        }
    }
    return true;
}

bool Utf8ToWide(std::span<const std::byte> input, std::wstring& output)
{
    output.clear();
    output.reserve(input.size());
    std::size_t offset = 0;
    while (offset < input.size())
    {
        utf8proc_int32_t code_point = 0;
        const auto consumed = utf8proc_iterate(
            reinterpret_cast<const utf8proc_uint8_t*>(input.data() + offset),
            static_cast<utf8proc_ssize_t>(input.size() - offset),
            &code_point);
        if (consumed <= 0)
        {
            return false;
        }
        offset += static_cast<std::size_t>(consumed);
        if constexpr (sizeof(wchar_t) == 2)
        {
            if (code_point <= 0xffff)
            {
                output.push_back(static_cast<wchar_t>(code_point));
            }
            else
            {
                const auto scalar = static_cast<std::uint32_t>(code_point) - 0x10000u;
                output.push_back(static_cast<wchar_t>(0xd800u + (scalar >> 10)));
                output.push_back(static_cast<wchar_t>(0xdc00u + (scalar & 0x3ffu)));
            }
        }
        else
        {
            output.push_back(static_cast<wchar_t>(code_point));
        }
    }
    return true;
}

bool WideToUtf8(std::wstring_view input, std::string& output)
{
    output.clear();
    output.reserve(input.size() * 3);
    for (std::size_t index = 0; index < input.size(); ++index)
    {
        std::uint32_t code_point = static_cast<std::uint32_t>(input[index]);
        if constexpr (sizeof(wchar_t) == 2)
        {
            if (code_point >= 0xd800u && code_point <= 0xdbffu)
            {
                if (++index >= input.size())
                {
                    return false;
                }
                const auto low = static_cast<std::uint32_t>(input[index]);
                if (low < 0xdc00u || low > 0xdfffu)
                {
                    return false;
                }
                code_point = 0x10000u +
                    ((code_point - 0xd800u) << 10) + (low - 0xdc00u);
            }
            else if (code_point >= 0xdc00u && code_point <= 0xdfffu)
            {
                return false;
            }
        }
        if (code_point > 0x10ffffu ||
            (code_point >= 0xd800u && code_point <= 0xdfffu) ||
            !AppendUtf8(static_cast<utf8proc_int32_t>(code_point), output))
        {
            return false;
        }
    }
    return true;
}

std::wstring ProjectBytes(std::span<const std::byte> input)
{
    std::wstring projected(ApfsNameCodec::EscapePrefix());
    projected.push_back(static_cast<wchar_t>(kEscapeDigitBase + input.size()));
    std::uint32_t bits = 0;
    unsigned int bit_count = 0;
    for (const auto item : input)
    {
        bits = (bits << 8) | std::to_integer<std::uint8_t>(item);
        bit_count += 8;
        while (bit_count >= kEscapeDigitBits)
        {
            bit_count -= kEscapeDigitBits;
            projected.push_back(static_cast<wchar_t>(
                kEscapeDigitBase + ((bits >> bit_count) & kEscapeDigitMask)));
            bits &= bit_count == 0 ? 0u : ((1u << bit_count) - 1u);
        }
    }
    if (bit_count != 0)
    {
        projected.push_back(static_cast<wchar_t>(
            kEscapeDigitBase +
            ((bits << (kEscapeDigitBits - bit_count)) & kEscapeDigitMask)));
    }
    return projected;
}

bool UnprojectBytes(std::wstring_view input, std::vector<std::byte>& output)
{
    const auto prefix = ApfsNameCodec::EscapePrefix();
    if (!input.starts_with(prefix) || input.size() <= prefix.size())
    {
        return false;
    }
    const auto length_digit = static_cast<unsigned int>(input[prefix.size()]);
    if (length_digit <= static_cast<unsigned int>(kEscapeDigitBase) ||
        length_digit > static_cast<unsigned int>(kEscapeDigitBase) +
            ApfsNameCodec::kMaxApfsNameBytes)
    {
        return false;
    }
    const auto output_length = length_digit - static_cast<unsigned int>(kEscapeDigitBase);
    const auto expected_digits =
        (output_length * 8u + kEscapeDigitBits - 1u) / kEscapeDigitBits;
    if (input.size() != prefix.size() + 1 + expected_digits)
    {
        return false;
    }

    output.clear();
    output.reserve(output_length);
    std::uint32_t bits = 0;
    unsigned int bit_count = 0;
    for (std::size_t index = prefix.size() + 1; index < input.size(); ++index)
    {
        const auto ch = static_cast<unsigned int>(input[index]);
        if (ch < static_cast<unsigned int>(kEscapeDigitBase) ||
            ch > static_cast<unsigned int>(kEscapeDigitBase) + kEscapeDigitMask)
        {
            return false;
        }
        bits = (bits << kEscapeDigitBits) |
            (ch - static_cast<unsigned int>(kEscapeDigitBase));
        bit_count += kEscapeDigitBits;
        while (bit_count >= 8 && output.size() < output_length)
        {
            bit_count -= 8;
            output.push_back(static_cast<std::byte>((bits >> bit_count) & 0xffu));
            bits &= bit_count == 0 ? 0u : ((1u << bit_count) - 1u);
        }
    }
    return output.size() == output_length && bits == 0;
}

ApfsNameError MapUtf8ProcError(utf8proc_ssize_t error)
{
    if (error == UTF8PROC_ERROR_NOTASSIGNED)
    {
        return ApfsNameError::UnassignedCodePoint;
    }
    if (error == UTF8PROC_ERROR_INVALIDUTF8)
    {
        return ApfsNameError::InvalidUtf8;
    }
    return ApfsNameError::NormalizationFailure;
}

std::uint32_t Crc32cScalar(std::uint32_t crc, std::uint32_t scalar) noexcept
{
    for (unsigned int shift = 0; shift < 32; shift += 8)
    {
        crc ^= (scalar >> shift) & 0xffu;
        for (int bit = 0; bit < 8; ++bit)
        {
            crc = (crc >> 1) ^ ((crc & 1u) != 0 ? 0x82f63b78u : 0u);
        }
    }
    return crc;
}

std::optional<std::uint32_t> DirectoryHash(
    std::span<const std::byte> normalized_utf8)
{
    std::uint32_t crc = 0xffffffffu;
    std::size_t offset = 0;
    while (offset < normalized_utf8.size())
    {
        utf8proc_int32_t code_point = 0;
        const auto consumed = utf8proc_iterate(
            reinterpret_cast<const utf8proc_uint8_t*>(normalized_utf8.data() + offset),
            static_cast<utf8proc_ssize_t>(normalized_utf8.size() - offset),
            &code_point);
        if (consumed <= 0)
        {
            return std::nullopt;
        }
        offset += static_cast<std::size_t>(consumed);
        crc = Crc32cScalar(crc, static_cast<std::uint32_t>(code_point));
    }
    return crc & 0x3fffffu;
}
} // namespace

ApfsNamePolicy ApfsNamePolicy::FromIncompatibleFeatures(
    std::uint64_t incompatible_features) noexcept
{
    ApfsNamePolicy policy;
    if ((incompatible_features & kCaseInsensitiveFeature) != 0)
    {
        policy.case_mode = ApfsCaseMode::Insensitive;
        policy.normalization_mode = ApfsNormalizationMode::Insensitive;
    }
    else if ((incompatible_features & kNormalizationInsensitiveFeature) != 0)
    {
        policy.normalization_mode = ApfsNormalizationMode::Insensitive;
    }
    return policy;
}

ApfsNameResult<ApfsName> ApfsNameCodec::Decode(
    std::span<const std::byte> utf8,
    const ApfsNamePolicy& policy)
{
    if (utf8.empty())
    {
        return Failure<ApfsName>(
            ApfsNameError::InvalidApfsName, "APFS names cannot be empty");
    }
    if (utf8.size() > kMaxApfsNameBytes)
    {
        return Failure<ApfsName>(
            ApfsNameError::NameTooLong, "APFS names are limited to 255 bytes");
    }
    if (std::find(utf8.begin(), utf8.end(), std::byte{0}) != utf8.end() ||
        std::find(utf8.begin(), utf8.end(), static_cast<std::byte>('/')) != utf8.end())
    {
        return Failure<ApfsName>(
            ApfsNameError::InvalidApfsName, "APFS names cannot contain NUL or slash");
    }

    const std::string original(
        reinterpret_cast<const char*>(utf8.data()), utf8.size());
    if (original == "." || original == "..")
    {
        return Failure<ApfsName>(
            ApfsNameError::InvalidApfsName, "dot components are not file names");
    }

    std::string full_fold_input;
    std::span<const std::byte> map_input = utf8;
    if (policy.case_mode == ApfsCaseMode::Insensitive)
    {
        if (!ExpandUnicode9FullFolds(utf8, full_fold_input))
        {
            return Failure<ApfsName>(
                ApfsNameError::InvalidUtf8, "invalid UTF-8 file name");
        }
        map_input = std::span(
            reinterpret_cast<const std::byte*>(full_fold_input.data()),
            full_fold_input.size());
    }

    auto options = UTF8PROC_STABLE | UTF8PROC_REJECTNA;
    if (policy.normalization_mode == ApfsNormalizationMode::Insensitive)
    {
        options |= UTF8PROC_DECOMPOSE;
    }
    if (policy.case_mode == ApfsCaseMode::Insensitive)
    {
        options |= UTF8PROC_CASEFOLD;
    }
    utf8proc_uint8_t* mapped = nullptr;
    const auto mapped_length = utf8proc_map(
        reinterpret_cast<const utf8proc_uint8_t*>(map_input.data()),
        static_cast<utf8proc_ssize_t>(map_input.size()),
        &mapped,
        static_cast<utf8proc_option_t>(options));
    if (mapped_length < 0)
    {
        return Failure<ApfsName>(
            MapUtf8ProcError(mapped_length), utf8proc_errmsg(mapped_length));
    }

    std::wstring wide;
    if (!Utf8ToWide(utf8, wide))
    {
        std::free(mapped);
        return Failure<ApfsName>(
            ApfsNameError::InvalidUtf8, "invalid UTF-8 file name");
    }

    ApfsName decoded;
    decoded.original_utf8 = original;
    if (policy.normalization_mode == ApfsNormalizationMode::Sensitive)
    {
        decoded.lookup_key.assign(utf8.begin(), utf8.end());
    }
    else
    {
        decoded.lookup_key.assign(
            reinterpret_cast<const std::byte*>(mapped),
            reinterpret_cast<const std::byte*>(mapped) + mapped_length);
    }
    std::free(mapped);
    decoded.windows_display = IsLiteralWindowsName(wide) ? wide : ProjectBytes(utf8);
    if (policy.UsesHashedDirectoryKeys())
    {
        decoded.directory_hash = DirectoryHash(decoded.lookup_key);
        if (!decoded.directory_hash.has_value())
        {
            return Failure<ApfsName>(
                ApfsNameError::NormalizationFailure,
                "normalized APFS name could not be hashed");
        }
    }
    return Success(std::move(decoded));
}

ApfsNameResult<std::string> ApfsNameCodec::EncodeWindowsName(
    std::wstring_view name)
{
    const auto exact = ApfsNamePolicy::FromIncompatibleFeatures(0);
    if (StartsWithEscapePrefixInsensitive(name))
    {
        if (!name.starts_with(EscapePrefix()))
        {
            return Failure<std::string>(
                ApfsNameError::AmbiguousWindowsName,
                "escape prefix must use its canonical spelling");
        }
        std::vector<std::byte> raw;
        if (!UnprojectBytes(name, raw))
        {
            return Failure<std::string>(
                ApfsNameError::AmbiguousWindowsName,
                "malformed APFS Windows-name escape");
        }
        const auto decoded = Decode(raw, exact);
        if (!decoded.ok() || decoded.value->windows_display != name)
        {
            return Failure<std::string>(
                ApfsNameError::AmbiguousWindowsName,
                "non-canonical APFS Windows-name escape");
        }
        return Success(decoded.value->original_utf8);
    }

    std::string utf8;
    if (!WideToUtf8(name, utf8))
    {
        return Failure<std::string>(
            ApfsNameError::InvalidWindowsName, "invalid UTF-16 file name");
    }
    const auto bytes = std::span(
        reinterpret_cast<const std::byte*>(utf8.data()), utf8.size());
    const auto decoded = Decode(bytes, exact);
    if (!decoded.ok())
    {
        return Failure<std::string>(decoded.error, decoded.detail);
    }
    if (decoded.value->windows_display != name)
    {
        return Failure<std::string>(
            ApfsNameError::AmbiguousWindowsName,
            "Windows-only spelling is not the canonical APFS projection");
    }
    return Success(std::move(utf8));
}

ApfsNameResult<std::wstring> ApfsNameCodec::CanonicalWindowsComponentKey(
    std::wstring_view name,
    const ApfsNamePolicy& policy)
{
    const auto encoded = EncodeWindowsName(name);
    if (!encoded.ok())
    {
        return Failure<std::wstring>(encoded.error, encoded.detail);
    }
    const auto bytes = std::span(
        reinterpret_cast<const std::byte*>(encoded.value->data()),
        encoded.value->size());
    const auto decoded = Decode(bytes, policy);
    if (!decoded.ok())
    {
        return Failure<std::wstring>(decoded.error, decoded.detail);
    }

    std::wstring key;
    key.reserve(decoded.value->lookup_key.size());
    for (const auto item : decoded.value->lookup_key)
    {
        key.push_back(static_cast<wchar_t>(
            0x0100u + std::to_integer<unsigned int>(item)));
    }
    return Success(std::move(key));
}

ApfsNameResult<std::wstring> ApfsNameCodec::CanonicalWindowsPathKey(
    std::wstring_view path,
    const ApfsNamePolicy& policy)
{
    std::wstring key(1, L'\\');
    std::size_t cursor = 0;
    while (cursor < path.size() && (path[cursor] == L'\\' || path[cursor] == L'/'))
    {
        ++cursor;
    }
    while (cursor < path.size())
    {
        auto end = path.find_first_of(L"\\/", cursor);
        if (end == std::wstring_view::npos)
        {
            end = path.size();
        }
        const auto component = path.substr(cursor, end - cursor);
        if (!component.empty())
        {
            const auto component_key = CanonicalWindowsComponentKey(component, policy);
            if (!component_key.ok())
            {
                return Failure<std::wstring>(component_key.error, component_key.detail);
            }
            if (key.size() > 1)
            {
                key.push_back(L'\\');
            }
            key.append(*component_key.value);
        }
        cursor = end;
        while (cursor < path.size() && (path[cursor] == L'\\' || path[cursor] == L'/'))
        {
            ++cursor;
        }
    }
    return Success(std::move(key));
}

bool ApfsNameCodec::MatchesHashedDirectoryKey(
    const ApfsName& name,
    std::uint32_t name_length_and_hash) noexcept
{
    if (!name.directory_hash.has_value() ||
        name.original_utf8.size() >= 0x3ffu)
    {
        return false;
    }
    const auto serialized_length =
        static_cast<std::uint32_t>(name.original_utf8.size() + 1);
    return (name_length_and_hash & 0x3ffu) == serialized_length &&
           (name_length_and_hash >> 10) == name.directory_hash.value();
}

} // namespace apfsaccess::rw
