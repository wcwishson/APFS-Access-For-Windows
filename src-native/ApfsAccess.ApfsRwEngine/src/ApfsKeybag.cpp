#include "ApfsKeybag.h"
#include "ApfsFormat.h"

#define WIN32_LEAN_AND_MEAN
#define NOMINMAX
#include <windows.h>
#include <algorithm>
#include <limits>
#include <new>

namespace apfsaccess::catalog
{
namespace
{
KeybagMetadataResult Fail(KeybagError error) { return {error, {}}; }
bool Zero(const std::vector<std::byte>& bytes, std::size_t start, std::size_t count)
{
    // Callers prove the range is within the capped exact frame before use.
    return std::all_of(bytes.begin() + start, bytes.begin() + start + count,
        [](std::byte value) { return value == std::byte{0}; });
}
struct WipeVector
{
    std::vector<std::byte>& bytes;
    ~WipeVector() { if (!bytes.empty()) SecureZeroMemory(bytes.data(), bytes.size()); }
};
bool ValidProfile(KeybagKind kind, KeybagLength length)
{
    return (kind == KeybagKind::Container || kind == KeybagKind::Volume) &&
        (length == KeybagLength::EntriesOnly || length == KeybagLength::IncludesHeader);
}
} // namespace

KeybagMetadataResult ParseKeybagMetadata(const std::vector<std::byte>& locker,
    KeybagKind kind, KeybagLength length, ApfsReadBudget* budget)
{
    if (!ValidProfile(kind, length)) return Fail(KeybagError::InvalidArgument);
    if (budget && budget->Failed()) return Fail(KeybagError::ResourceLimit);
    if (locker.size() > kMaxKeybagLockerBytes) return Fail(KeybagError::ResourceLimit);
    if (locker.size() < 16) return Fail(KeybagError::Malformed);
    if (ReadU16LE(locker, 0).value() != 2) return Fail(KeybagError::UnsupportedVersion);
    const auto count = ReadU16LE(locker, 2).value();
    const auto declared = ReadU32LE(locker, 4).value();
    // Subtraction avoids adding a hostile u32 length to a platform-sized value.
    const auto expected = length == KeybagLength::EntriesOnly ? locker.size() - 16 : locker.size();
    if (declared != expected) return Fail(KeybagError::Malformed);
    if (count > kMaxKeybagEntries) return Fail(KeybagError::ResourceLimit);
    if (!Zero(locker, 8, 8)) return Fail(KeybagError::UnsupportedPadding);
    bool unsupported_payload = false;
    std::size_t cursor = 16;
    // First pass validates every byte/range before returning any entry metadata.
    for (std::size_t i = 0; i < count; ++i)
    {
        if (locker.size() - cursor < 24) return Fail(KeybagError::Malformed);
        const auto tag = ReadU16LE(locker, cursor + 16).value();
        const auto bytes = ReadU16LE(locker, cursor + 18).value();
        if (bytes >= 512) return Fail(KeybagError::Malformed);
        const std::size_t stride = (24 + static_cast<std::size_t>(bytes) + 15) & ~std::size_t{15};
        if (stride > locker.size() - cursor) return Fail(KeybagError::Malformed);
        if ((kind == KeybagKind::Container && tag == 2) ||
            (kind == KeybagKind::Volume && tag == 3))
        {
            if (bytes == 0) return Fail(KeybagError::Malformed);
            unsupported_payload = true; // Never inspect/accept DER key classes.
        }
        else if (kind == KeybagKind::Container && tag == 3)
        {
            if (bytes != 16) return Fail(KeybagError::Malformed);
            const auto start = ReadU64LE(locker, cursor + 24).value();
            const auto blocks = ReadU64LE(locker, cursor + 32).value();
            // paddr_t is signed int64; require a positive, representable range.
            constexpr auto max = static_cast<std::uint64_t>(std::numeric_limits<std::int64_t>::max());
            if (start == 0 || start > max || blocks == 0 || blocks > max - start)
                return Fail(KeybagError::Malformed);
        }
        else if (kind != KeybagKind::Volume || tag != 4)
            return Fail(KeybagError::UnsupportedTag);
        if (!Zero(locker, cursor + 20, 4) || !Zero(locker, cursor + 24 + bytes, stride - 24 - bytes))
            return Fail(KeybagError::UnsupportedPadding);
        cursor += stride;
    }
    if (cursor != locker.size()) return Fail(KeybagError::Malformed);
    if (unsupported_payload) return Fail(KeybagError::UnsupportedKeyPayload);
    if (budget && !budget->Materialize(count, count * sizeof(KeybagMetadataEntry)))
        return Fail(KeybagError::ResourceLimit);
    try
    {
        KeybagMetadataResult result;
        result.entries.reserve(count);
        cursor = 16;
        for (std::size_t i = 0; i < count; ++i)
        {
            KeybagMetadataEntry entry;
            std::copy_n(locker.begin() + cursor, 16, entry.uuid.begin());
            entry.tag = ReadU16LE(locker, cursor + 16).value();
            entry.payload_bytes = ReadU16LE(locker, cursor + 18).value();
            if (kind == KeybagKind::Container)
            {
                entry.keybag_start_block = ReadU64LE(locker, cursor + 24).value();
                entry.keybag_block_count = ReadU64LE(locker, cursor + 32).value();
            }
            result.entries.push_back(entry);
            cursor += (24 + static_cast<std::size_t>(entry.payload_bytes) + 15) & ~std::size_t{15};
        }
        return result;
    }
    catch (const std::bad_alloc&) { return Fail(KeybagError::AllocationFailure); }
}

KeybagMetadataResult ReadKeybagMetadata(const RandomAccessSource& source,
    std::uint64_t offset, std::size_t exact_bytes, KeybagKind kind, KeybagLength length)
{
    if (!ValidProfile(kind, length)) return Fail(KeybagError::InvalidArgument);
    if (exact_bytes > kMaxKeybagLockerBytes) return Fail(KeybagError::ResourceLimit);
    if (exact_bytes < 16) return Fail(KeybagError::Malformed);
    const auto size = source.SizeBytes();
    if (offset > size || exact_bytes > size - offset) return Fail(KeybagError::ReadFailure);
    const auto budget = source.ReadBudget();
    if (budget && budget->Failed()) return Fail(KeybagError::ResourceLimit);
    std::vector<std::byte> bytes;
    const WipeVector wipe{bytes};
    try
    {
        if (!source.Read(offset, exact_bytes, bytes) || bytes.size() != exact_bytes)
            return Fail(budget && budget->Failed() ? KeybagError::ResourceLimit : KeybagError::ReadFailure);
        return ParseKeybagMetadata(bytes, kind, length, budget.get());
    }
    catch (const std::bad_alloc&) { return Fail(KeybagError::AllocationFailure); }
}
} // namespace apfsaccess::catalog
