#pragma once
#include <cstddef>
#include <span>
#include <string>
#include <vector>

namespace apfsaccess::rw
{
struct FirmlinkTablePathPair {std::string system_path, data_relative_path;};
// Conservative profile demonstrated by Apple's files-974.120.2 distribution:
// absolute ASCII path, one TAB, matching root-relative path, LF terminator.
// No synthetic.conf grammar, opaque xattr payload or built-in route fallback.
// Parsing alone authenticates no volume, directory or routing authority.
bool ParseAppleFirmlinkTable(std::span<const std::byte> bytes,
    std::vector<FirmlinkTablePathPair>& out, std::string& error);
}
