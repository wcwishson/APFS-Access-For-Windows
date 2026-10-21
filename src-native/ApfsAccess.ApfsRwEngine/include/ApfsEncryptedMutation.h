#pragma once
#include <cstddef>
#include <cstdint>
#include <span>
#include <string_view>

namespace apfsaccess::catalog
{
enum class EncryptedMutationKind { Overwrite, Write, Resize, Create, Rename, Unlink,
    MakeDirectory = 6, SetInodeMetadata = 7, ReplaceRename = 8,
    SetExtendedAttribute = 9, RemoveExtendedAttribute = 10 };

// Borrowed inputs live only for preparation. Create allocates its inode internally.
// Names use the selected volume's canonical APFS comparison and hash policy.
struct EncryptedMutationRequest
{
    EncryptedMutationKind kind = EncryptedMutationKind::Write;
    std::uint64_t inode = 0;
    std::uint64_t offset = 0;
    std::span<const std::byte> data;
    std::uint64_t size = 0;
    std::uint64_t parent = 0, destination_parent = 0;
    std::string_view name, destination_name;
    std::uint16_t permissions = 0644;
};
}
