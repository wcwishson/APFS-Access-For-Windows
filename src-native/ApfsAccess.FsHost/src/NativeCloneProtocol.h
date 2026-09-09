#pragma once
#include <array>
#include <cstdint>

// Private WinFsp METHOD_BUFFERED protocol, little endian, fixed width, no pointers.
// This is whole-file creation, not FSCTL_DUPLICATE_EXTENTS_TO_FILE. Keep the source
// handle open, export once, then import on a FILE_ADD_FILE directory handle.
namespace apfsaccess::fshost::clone_control
{
inline constexpr std::uint32_t Version = 1;
inline constexpr std::uint32_t Export = (0x8000u << 16) | (0x800u << 2);
inline constexpr std::uint32_t Import = (0x8000u << 16) | (0x801u << 2);
using Ticket = std::array<std::uint8_t, 32>;
struct ExportRequest { std::uint32_t version = Version, reserved = 0; };
struct ExportReply { std::uint32_t version = Version, reserved = 0; Ticket ticket{}; };
struct ImportRequest
{
    std::uint32_t version = Version, leaf_chars = 0;
    Ticket ticket{};
    // Exactly leaf_chars UTF-16 code units; remainder must be zero, no terminator
    // in the counted portion. No path, ADS, separator, dot/dotdot or raw handle.
    std::array<std::uint16_t, 255> leaf{};
    std::uint16_t reserved = 0;
};
static_assert(sizeof(ExportRequest) == 8 && sizeof(ExportReply) == 40);
static_assert(sizeof(ImportRequest) == 552);
}
