#pragma once
#include "ApfsKeybagUnlock.h"

namespace apfsaccess::catalog
{
// Observations only. No wrapped keys, source owners or construction authority;
// factories never accept a caller-supplied instance of this structure.
struct SoftwareKeyRecordEncoding
{
    std::uint64_t vek_envelope_integer = 0, vek_body_integer = 0;
    std::uint64_t kek_envelope_integer = 0, kek_body_integer = 0;
    std::vector<std::byte> vek_info, kek_info;
    std::uint64_t iterations = 0;
    std::size_t vek_key_bytes = 0, kek_key_bytes = 0;
};
std::optional<SoftwareKeyRecordEncoding> ObserveSoftwareKeyRecordEncoding(
    std::span<const std::byte> vek, std::span<const std::byte> kek);
}
