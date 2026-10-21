#pragma once
#include <algorithm>
#include "ApfsExtendedRecordCodec.h"

namespace apfsaccess::rw::fusion_private {
inline std::string Name(std::uint64_t inode, std::uint64_t xid) {
    return "apfsaccess-fusion-orphan-" + std::to_string(inode) + "-" + std::to_string(xid);
}
inline void PrimaryName(AppleInodeRecord& inode, std::string_view name) {
    std::erase_if(inode.extended_fields, [](const auto& field) { return field.type == 4; });
    std::vector<std::byte> bytes;
    bytes.reserve(name.size() + 1);
    for (const auto c : name) bytes.push_back(std::byte(static_cast<unsigned char>(c)));
    bytes.push_back(std::byte{});
    inode.extended_fields.push_back({4, 0, std::move(bytes)});
}
inline bool PrimaryNameIs(const AppleInodeRecord& inode, std::string_view name) {
    const auto field = std::find_if(inode.extended_fields.begin(), inode.extended_fields.end(),
        [](const auto& value) { return value.type == 4; });
    return field != inode.extended_fields.end() && field->data.size() == name.size() + 1 &&
        field->data.back() == std::byte{} && std::equal(name.begin(), name.end(), field->data.begin(),
            [](char a, std::byte b) { return static_cast<unsigned char>(a) == std::to_integer<unsigned char>(b); });
}
}
