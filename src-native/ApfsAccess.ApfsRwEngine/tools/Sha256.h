#pragma once

// Streaming SHA-256 for evidence source hashing (observer-side only; never
// APFS parsing). Exactly one implementation object links into a binary:
//   - Windows production observer: CNG/BCrypt (tools/Sha256Win32.cpp)
//   - every other platform: self-contained portable code
//     (tools/Sha256Portable.cpp, also unit-tested everywhere)
// Both produce identical lowercase hex digests for the same bytes.

#include <cstddef>
#include <memory>
#include <string>
#include <vector>

namespace apfsaccess::observer
{

class Sha256Stream
{
public:
    virtual ~Sha256Stream() = default;
    [[nodiscard]] virtual bool Update(const std::byte* data, std::size_t size) = 0;
    [[nodiscard]] virtual bool FinalHex(std::string& out_hex_lower) = 0;

    // Factory defined by the linked implementation translation unit.
    [[nodiscard]] static std::unique_ptr<Sha256Stream> Create(std::string& out_error);
};

} // namespace apfsaccess::observer
