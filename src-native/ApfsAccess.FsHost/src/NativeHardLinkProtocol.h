#pragma once
#include <array>
#include <cstdint>

namespace apfsaccess::fshost::hardlink_control
{
// Explicit mounted helper controls, distinct from the Windows hard-link API.
// Fixed-width METHOD_BUFFERED messages carry no path or process pointers.
inline constexpr std::uint32_t Version = 1;
inline constexpr std::uint32_t Export = (0x8000u << 16) | (1u << 14) | (0x820u << 2);
inline constexpr std::uint32_t Import = (0x8000u << 16) | (2u << 14) | (0x821u << 2);
using Ticket = std::array<std::uint8_t, 32>;
struct ExportRequest { std::uint32_t version = Version, reserved = 0; };
struct ExportReply { std::uint32_t version = Version, reserved = 0; Ticket ticket{}; };
struct ImportRequest
{
    std::uint32_t version = Version, leaf_chars = 0;
    Ticket ticket{};
    std::array<std::uint16_t, 255> leaf{};
    std::uint16_t reserved = 0;
};
struct ImportReply
{
    std::uint32_t version = Version, links = 0;
    std::uint64_t object_id = 0, accepted_sequence = 0, checkpoint_xid = 0;
};
static_assert(sizeof(ExportRequest) == 8 && sizeof(ExportReply) == 40);
static_assert(sizeof(ImportRequest) == 552 && sizeof(ImportReply) == 32);
}
